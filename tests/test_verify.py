"""Tests for comparing a browser observed response with a replayed one, structurally."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import pytest
from pydantic import ValidationError

from trace2api.analyze import (
    CaptureVerification,
    Mismatch,
    MismatchKind,
    VerificationOutcome,
    compare_responses,
    render_verification,
    verify_capture,
)
from trace2api.models import (
    Body,
    Capture,
    CaptureMetadata,
    CaptureSource,
    Entry,
    Headers,
    Request,
    ResourceType,
    Response,
)
from trace2api.replay import MissingSecretError


def response(
    status: int = 200,
    *,
    content_type: str | None = "application/json",
    text: str | None = None,
) -> Response:
    """Build one response with a JSON body by default, or ``text`` as given."""
    body = None
    if content_type is not None:
        body = Body(mime_type=content_type, text=text)
    return Response(status=status, headers=Headers(), body=body)


def mismatch_kinds(comparison) -> list[MismatchKind]:
    return [item.kind for item in comparison.mismatches]


# Status and content type


def test_matches_when_status_and_body_shape_agree() -> None:
    comparison = compare_responses(
        response(text='{"id": 1, "name": "first"}'),
        response(text='{"id": 2, "name": "second"}'),
    )
    assert comparison.matches
    assert comparison.mismatches == []


def test_reports_a_status_mismatch() -> None:
    comparison = compare_responses(response(200), response(404))
    assert not comparison.matches
    mismatch = comparison.mismatches[0]
    assert mismatch.kind is MismatchKind.STATUS
    assert mismatch.location == "response.status"
    assert mismatch.observed == "200"
    assert mismatch.replayed == "404"
    assert comparison.observed_status == 200
    assert comparison.replayed_status == 404


def test_reports_a_content_type_mismatch() -> None:
    comparison = compare_responses(
        response(content_type="application/json", text="{}"),
        response(content_type="text/html", text="<html></html>"),
    )
    assert MismatchKind.CONTENT_TYPE in mismatch_kinds(comparison)
    mismatch = next(m for m in comparison.mismatches if m.kind is MismatchKind.CONTENT_TYPE)
    assert mismatch.observed == "application/json"
    assert mismatch.replayed == "text/html"


def test_content_type_comparison_ignores_the_charset() -> None:
    comparison = compare_responses(
        response(content_type="application/json; charset=utf-8", text="{}"),
        response(content_type="application/json", text="{}"),
    )
    assert comparison.matches


def test_missing_content_type_is_reported_as_none() -> None:
    left = Response(status=200, headers=Headers())
    right = response(text="{}")
    comparison = compare_responses(left, right)
    mismatch = next(m for m in comparison.mismatches if m.kind is MismatchKind.CONTENT_TYPE)
    assert mismatch.observed == "(none)"


# Body presence


def test_matches_when_both_bodies_are_empty() -> None:
    comparison = compare_responses(
        Response(status=204, headers=Headers()), Response(status=204, headers=Headers())
    )
    assert comparison.matches


def test_reports_a_body_presence_mismatch() -> None:
    comparison = compare_responses(
        response(text='{"ok": true}'), Response(status=200, headers=Headers())
    )
    mismatch = next(m for m in comparison.mismatches if m.kind is MismatchKind.BODY_PRESENCE)
    assert mismatch.location == "response.body"
    assert mismatch.observed == "present"
    assert mismatch.replayed == "absent"


# Structure over value


def test_does_not_report_a_mismatch_for_a_leaf_value_that_merely_differs() -> None:
    comparison = compare_responses(
        response(text='{"session_id": "abc123", "issued_at": "2026-09-04T09:15:00Z"}'),
        response(text='{"session_id": "zzz999", "issued_at": "2026-09-23T00:00:00Z"}'),
    )
    assert comparison.matches


def test_reports_a_missing_key() -> None:
    comparison = compare_responses(
        response(text='{"id": 1, "confirmation_ref": "CNF-1"}'), response(text='{"id": 1}')
    )
    mismatch = next(
        m for m in comparison.mismatches if m.location == "response.body.confirmation_ref"
    )
    assert mismatch.kind is MismatchKind.BODY_SHAPE
    assert mismatch.observed == "string"
    assert mismatch.replayed == "absent"


def test_reports_an_added_key() -> None:
    comparison = compare_responses(
        response(text='{"id": 1}'), response(text='{"id": 1, "extra": true}')
    )
    mismatch = next(m for m in comparison.mismatches if m.location == "response.body.extra")
    assert mismatch.observed == "absent"
    assert mismatch.replayed == "boolean"


def test_reports_a_type_mismatch_on_a_leaf() -> None:
    comparison = compare_responses(response(text='{"id": 1}'), response(text='{"id": "one"}'))
    mismatch = next(m for m in comparison.mismatches if m.location == "response.body.id")
    assert mismatch.kind is MismatchKind.BODY_SHAPE
    assert mismatch.observed == "number"
    assert mismatch.replayed == "string"


def test_reports_an_array_length_mismatch() -> None:
    comparison = compare_responses(
        response(text='{"orders": [1, 2, 3]}'), response(text='{"orders": [1, 2]}')
    )
    mismatch = next(m for m in comparison.mismatches if m.location == "response.body.orders")
    assert mismatch.observed == "array of 3"
    assert mismatch.replayed == "array of 2"


def test_recurses_into_nested_objects_and_arrays() -> None:
    comparison = compare_responses(
        response(text='{"orders": [{"id": 1, "total": 10}]}'),
        response(text='{"orders": [{"id": 1, "total": "10"}]}'),
    )
    mismatch = next(
        m for m in comparison.mismatches if m.location == "response.body.orders[0].total"
    )
    assert mismatch.observed == "number"
    assert mismatch.replayed == "string"


def test_a_null_and_a_missing_field_are_different_shapes() -> None:
    comparison = compare_responses(response(text='{"note": null}'), response(text='{"note": "hi"}'))
    mismatch = next(m for m in comparison.mismatches if m.location == "response.body.note")
    assert mismatch.observed == "null"
    assert mismatch.replayed == "string"


# Bodies that are not JSON


def test_non_json_bodies_are_only_checked_for_presence() -> None:
    comparison = compare_responses(
        response(content_type="text/html", text="<p>one</p>"),
        response(content_type="text/html", text="<p>two, entirely different markup</p>"),
    )
    assert comparison.matches


def test_a_body_that_fails_to_parse_as_json_on_both_sides_is_not_compared_further() -> None:
    comparison = compare_responses(response(text="not json"), response(text="also not json"))
    assert comparison.matches


def test_a_body_that_fails_to_parse_as_json_on_one_side_is_a_shape_mismatch() -> None:
    comparison = compare_responses(response(text='{"ok": true}'), response(text="not json"))
    mismatch = next(m for m in comparison.mismatches if m.location == "response.body")
    assert mismatch.observed == "object"
    assert mismatch.replayed == "invalid-json"


# Never leaks a value


def test_a_mismatch_never_carries_the_leaf_value_that_triggered_it() -> None:
    secret = "super-secret-token-value"
    comparison = compare_responses(
        response(text=f'{{"token": "{secret}"}}'), response(text='{"token": 12345}')
    )
    mismatch = next(m for m in comparison.mismatches if m.location == "response.body.token")
    assert secret not in mismatch.observed
    assert secret not in mismatch.replayed
    assert mismatch.observed == "string"
    assert mismatch.replayed == "number"


# JSON output


def test_as_json_round_trips_through_json() -> None:
    comparison = compare_responses(response(200), response(500))
    document = json.loads(comparison.as_json())
    assert document["observed_status"] == 200
    assert document["replayed_status"] == 500
    assert document["mismatches"][0]["kind"] == "status"


def test_mismatch_model_is_frozen() -> None:
    mismatch = Mismatch(
        location="response.status", kind=MismatchKind.STATUS, observed="200", replayed="500"
    )
    with pytest.raises(ValidationError):
        mismatch.location = "response.other"  # type: ignore[misc]


# Replaying and verifying a whole capture


STARTED_AT = datetime(2026, 9, 4, 9, 15, tzinfo=UTC)


def entry(
    entry_id: str,
    url: str,
    *,
    method: str = "GET",
    headers: list[tuple[str, str]] | None = None,
    observed: Response | None = None,
) -> Entry:
    """Build one observed exchange, with an observed JSON response by default."""
    if observed is None:
        observed = response(text='{"id": 1}')
    return Entry(
        id=entry_id,
        started_at=STARTED_AT,
        request=Request(method=method, url=url, headers=Headers.from_pairs(headers or [])),
        response=observed,
    )


def capture(*entries: Entry) -> Capture:
    """Build a capture holding ``entries``."""
    return Capture(
        metadata=CaptureMetadata(source=CaptureSource.HAR, created_at=STARTED_AT),
        entries=list(entries),
    )


def verify_against(handler, capture: Capture, secrets: dict[str, str] | None = None, **kwargs):
    """Verify ``capture`` against a stub transport, without touching the network."""

    def handle(request: httpx.Request) -> httpx.Response:
        return handler(request)

    with httpx.Client(transport=httpx.MockTransport(handle), follow_redirects=False) as client:
        return verify_capture(capture, secrets or {}, client=client, **kwargs)


def test_reports_matched_when_the_replay_reproduces_the_observed_shape() -> None:
    verification = verify_against(
        lambda request: httpx.Response(200, json={"id": 2}),
        capture(entry("a", "https://shop.example.com/api/orders")),
    )
    assert len(verification.requests) == 1
    item = verification.requests[0]
    assert item.position == 1
    assert item.method == "GET"
    assert item.host == "shop.example.com"
    assert item.path == "/api/orders"
    assert item.outcome is VerificationOutcome.MATCHED
    assert item.comparison is not None
    assert item.comparison.matches
    assert verification.passed


def test_reports_mismatched_when_the_replay_differs_in_shape() -> None:
    verification = verify_against(
        lambda request: httpx.Response(200, json={"id": "one"}),
        capture(entry("a", "https://shop.example.com/api/orders")),
    )
    item = verification.requests[0]
    assert item.outcome is VerificationOutcome.MISMATCHED
    assert item.comparison is not None
    assert not item.comparison.matches
    assert not verification.passed


def test_reports_failed_when_the_request_could_not_be_sent() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    verification = verify_against(
        handler, capture(entry("a", "https://shop.example.com/api/orders"))
    )
    item = verification.requests[0]
    assert item.outcome is VerificationOutcome.FAILED
    assert item.error is not None
    assert item.comparison is None
    assert not verification.passed


def test_reports_not_observed_when_the_capture_never_saw_a_response() -> None:
    unobserved = entry("a", "https://shop.example.com/api/orders").model_copy(
        update={"response": None, "failure": "net::ERR_TIMED_OUT"}
    )
    verification = verify_against(
        lambda request: httpx.Response(200, json={"id": 2}), capture(unobserved)
    )
    item = verification.requests[0]
    assert item.outcome is VerificationOutcome.NOT_OBSERVED
    assert item.comparison is None
    assert not verification.passed


def test_positions_match_what_inspect_numbers_over_the_whole_capture() -> None:
    noise = entry("noise", "https://cdn.example.com/app.css").model_copy(
        update={"resource_type": ResourceType.STYLESHEET}
    )
    kept = entry("kept", "https://shop.example.com/api/orders")
    verification = verify_against(
        lambda request: httpx.Response(200, json={"id": 2}), capture(noise, kept)
    )
    assert [item.position for item in verification.requests] == [2]


def test_passed_is_false_when_there_is_nothing_to_replay() -> None:
    verification = verify_against(lambda request: httpx.Response(200), capture())
    assert verification.requests == []
    assert not verification.passed


def test_a_missing_secret_stops_verification_before_anything_is_sent() -> None:
    secret_entry = entry(
        "a",
        "https://shop.example.com/api/orders",
        headers=[("Authorization", "Bearer super-secret-token")],
    )
    with pytest.raises(MissingSecretError, match="TRACE2API_AUTHORIZATION"):
        verify_against(lambda request: httpx.Response(200), capture(secret_entry))


def test_a_credential_in_the_replayed_response_is_redacted_before_comparison() -> None:
    observed = response(text='{"token": "the-original-session-token-value"}')
    verification = verify_against(
        lambda request: httpx.Response(200, json={"token": "a-brand-new-session-token-value"}),
        capture(entry("a", "https://shop.example.com/api/orders", observed=observed)),
    )
    item = verification.requests[0]
    assert item.outcome is VerificationOutcome.MATCHED
    assert verification.redacted_values >= 2


def test_as_json_round_trips_a_capture_verification() -> None:
    verification = verify_against(
        lambda request: httpx.Response(200, json={"id": 2}),
        capture(entry("a", "https://shop.example.com/api/orders")),
    )
    document = json.loads(verification.as_json())
    assert document["requests"][0]["outcome"] == "matched"
    assert CaptureVerification.model_validate(document) == verification


def test_render_verification_reports_the_outcome_of_each_request() -> None:
    verification = verify_against(
        lambda request: httpx.Response(200, json={"id": "one"}),
        capture(entry("a", "https://shop.example.com/api/orders")),
    )
    text = render_verification(verification)
    assert "shop.example.com/api/orders" in text
    assert "mismatched" in text
    assert "response.body.id" in text
    assert "number -> string" in text
    assert "1 request replayed: 1 mismatched." in text


def test_render_verification_reports_when_nothing_was_kept() -> None:
    text = render_verification(verify_against(lambda request: httpx.Response(200), capture()))
    assert "No kept request to replay." in text
