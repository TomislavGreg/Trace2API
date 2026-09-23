"""Tests for comparing a browser observed response with a replayed one, structurally."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from trace2api.analyze import Mismatch, MismatchKind, compare_responses
from trace2api.models import Body, Headers, Response


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
