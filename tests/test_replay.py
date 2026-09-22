"""Tests for sending the requests a sanitized capture holds, secrets supplied explicitly."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from urllib.parse import parse_qsl

import httpx
import pytest

from trace2api.analyze import Relevance
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
from trace2api.replay import MissingSecretError, ReplayOutcome, replay_capture

STARTED_AT = datetime(2026, 9, 4, 9, 15, tzinfo=UTC)

ACCESS_TOKEN = "example-access-token-not-a-real-credential"


def entry(
    entry_id: str,
    url: str,
    *,
    method: str = "GET",
    headers: list[tuple[str, str]] | None = None,
    body: Body | None = None,
    resource_type: ResourceType = ResourceType.XHR,
) -> Entry:
    """Build one observed exchange that the relevance rules keep by default."""
    return Entry(
        id=entry_id,
        started_at=STARTED_AT,
        request=Request(
            method=method,
            url=url,
            headers=Headers.from_pairs(headers or []),
            body=body,
        ),
        response=Response(status=200, headers=Headers(), body=Body(mime_type="application/json")),
        resource_type=resource_type,
    )


def capture(*entries: Entry) -> Capture:
    """Build a capture holding ``entries``."""
    return Capture(
        metadata=CaptureMetadata(source=CaptureSource.HAR, created_at=STARTED_AT),
        entries=list(entries),
    )


def replay_against(
    handler,
    capture: Capture,
    secrets: dict[str, str] | None = None,
    **kwargs,
):
    """Replay ``capture`` against a stub transport, returning the result and requests sent."""
    sent: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return handler(request)

    with httpx.Client(transport=httpx.MockTransport(handle), follow_redirects=False) as client:
        result = replay_capture(capture, secrets or {}, client=client, **kwargs)
    return result, sent


def ok(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"ok": True})


# Sending in order


def test_sends_the_kept_requests_in_order_and_reports_the_responses() -> None:
    result, sent = replay_against(
        ok,
        capture(
            entry("a", "https://shop.example.com/api/orders"),
            entry("b", "https://shop.example.com/api/orders/1"),
        ),
    )
    assert [request.url.path for request in sent] == ["/api/orders", "/api/orders/1"]
    assert len(result) == 2
    assert result.captured == 2
    for item, source in zip(result.entries, ["a", "b"], strict=True):
        assert item.entry_id == source
        assert item.outcome is ReplayOutcome.RESPONDED
        assert item.response is not None
        assert item.response.status == 200
        assert item.response.body is not None
        assert item.response.body.text == '{"ok":true}'


def test_leaves_out_requests_the_relevance_rules_filter_as_noise() -> None:
    result, sent = replay_against(
        ok,
        capture(
            entry("a", "https://shop.example.com/api/orders"),
            entry("b", "https://cdn.example.com/app.css", resource_type=ResourceType.STYLESHEET),
        ),
    )
    assert [request.url.path for request in sent] == ["/api/orders"]
    assert len(result) == 1
    assert result.captured == 2


def test_all_reads_the_requests_filtered_as_noise_too() -> None:
    result, sent = replay_against(
        ok,
        capture(
            entry("a", "https://shop.example.com/api/orders"),
            entry("b", "https://cdn.example.com/app.css", resource_type=ResourceType.STYLESHEET),
        ),
        keep=list(Relevance),
    )
    assert len(sent) == 2
    assert len(result) == 2


# Secrets


def test_a_missing_secret_stops_the_replay_before_anything_is_sent() -> None:
    with pytest.raises(MissingSecretError, match="TRACE2API_AUTHORIZATION") as failure:
        replay_against(
            ok,
            capture(
                entry(
                    "a",
                    "https://shop.example.com/api/orders",
                    headers=[("Authorization", f"Bearer {ACCESS_TOKEN}")],
                ),
            ),
        )
    assert ACCESS_TOKEN not in str(failure.value)


def test_a_missing_secret_is_checked_before_any_earlier_request_is_sent() -> None:
    sent: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return ok(request)

    with (
        pytest.raises(MissingSecretError),
        httpx.Client(transport=httpx.MockTransport(handle)) as client,
    ):
        replay_capture(
            capture(
                entry("a", "https://shop.example.com/api/orders"),
                entry(
                    "b",
                    "https://shop.example.com/api/orders/1/confirm",
                    method="POST",
                    headers=[("Authorization", f"Bearer {ACCESS_TOKEN}")],
                ),
            ),
            {},
            client=client,
        )
    assert sent == []


def test_resolves_a_secret_into_the_authorization_header() -> None:
    result, sent = replay_against(
        ok,
        capture(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                headers=[("Authorization", f"Bearer {ACCESS_TOKEN}")],
            ),
        ),
        {"TRACE2API_AUTHORIZATION": ACCESS_TOKEN},
    )
    assert sent[0].headers["authorization"] == f"Bearer {ACCESS_TOKEN}"
    assert result.entries[0].outcome is ReplayOutcome.RESPONDED


def test_resolves_a_secret_into_a_cookie_header() -> None:
    _, sent = replay_against(
        ok,
        capture(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                headers=[("Cookie", "session=abc123; locale=en")],
            ),
        ),
        {
            "TRACE2API_COOKIE_SESSION": "the-real-session-value",
            "TRACE2API_COOKIE_LOCALE": "en",
        },
    )
    assert sent[0].headers["cookie"] == "session=the-real-session-value; locale=en"


def test_resolves_a_secret_into_a_query_parameter() -> None:
    _, sent = replay_against(
        ok,
        capture(entry("a", f"https://shop.example.com/api/orders?token={ACCESS_TOKEN}")),
        {"TRACE2API_QUERY_TOKEN": "value with spaces & special=chars"},
    )
    assert sent[0].url.params["token"] == "value with spaces & special=chars"


def test_resolves_a_secret_into_a_json_body_field_with_proper_escaping() -> None:
    tricky = 'value with "quotes" and a backslash \\'
    body = Body(
        mime_type="application/json",
        text=f'{{"api_key":"{ACCESS_TOKEN}","note":"hi"}}',
    )
    _, sent = replay_against(
        ok,
        capture(entry("a", "https://shop.example.com/api/orders", method="POST", body=body)),
        {"TRACE2API_API_KEY": tricky},
    )
    sent_body = json.loads(sent[0].content)
    assert sent_body == {"api_key": tricky, "note": "hi"}


def test_resolves_a_secret_into_a_form_encoded_body_field() -> None:
    body = Body(
        mime_type="application/x-www-form-urlencoded",
        text=f"csrf_token={ACCESS_TOKEN}&amount=10",
    )
    _, sent = replay_against(
        ok,
        capture(entry("a", "https://shop.example.com/api/orders", method="POST", body=body)),
        {"TRACE2API_BODY_CSRF_TOKEN": "value&with=special/chars"},
    )
    assert dict(parse_qsl(sent[0].content.decode())) == {
        "csrf_token": "value&with=special/chars",
        "amount": "10",
    }


def test_a_binary_body_is_sent_as_observed() -> None:
    raw = b"\x00\x01binary"
    body = Body(
        mime_type="application/octet-stream",
        text=base64.b64encode(raw).decode("ascii"),
        encoding="base64",
    )
    _, sent = replay_against(
        ok,
        capture(entry("a", "https://shop.example.com/api/upload", method="POST", body=body)),
    )
    assert sent[0].content == raw


# Headers httpx computes for itself


def test_does_not_send_a_stale_content_length_from_the_capture() -> None:
    body = Body(mime_type="application/json", text='{"a":1}')
    _, sent = replay_against(
        ok,
        capture(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                method="POST",
                # The capture recorded a length that no longer matches the body below.
                headers=[("Content-Length", "999"), ("Content-Type", "application/json")],
                body=body,
            ),
        ),
    )
    assert sent[0].headers["content-length"] == str(len(body.as_bytes()))


# Failures


def test_a_network_failure_is_reported_without_the_url_or_secret() -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    result, _ = replay_against(
        fail,
        capture(
            entry(
                "a",
                f"https://shop.example.com/api/orders?token={ACCESS_TOKEN}",
            ),
        ),
        {"TRACE2API_QUERY_TOKEN": "the-real-token"},
    )
    assert result.entries[0].outcome is ReplayOutcome.FAILED
    assert result.entries[0].response is None
    assert result.entries[0].error is not None
    assert "the-real-token" not in result.entries[0].error
    assert "shop.example.com" in result.entries[0].error


def test_replays_the_requests_after_a_failed_one() -> None:
    calls = []

    def flaky(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if len(calls) == 1:
            raise httpx.ConnectError("boom", request=request)
        return ok(request)

    result, sent = replay_against(
        flaky,
        capture(
            entry("a", "https://shop.example.com/api/orders"),
            entry("b", "https://shop.example.com/api/orders/1"),
        ),
    )
    assert len(sent) == 2
    assert result.entries[0].outcome is ReplayOutcome.FAILED
    assert result.entries[1].outcome is ReplayOutcome.RESPONDED


# Client lifecycle


def test_opens_and_closes_its_own_client_when_none_is_supplied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed = []
    real_client = httpx.Client

    class TrackedClient(real_client):
        def __init__(self, *args, **kwargs) -> None:
            kwargs["transport"] = httpx.MockTransport(ok)
            super().__init__(*args, **kwargs)

        def close(self) -> None:
            closed.append(True)
            super().close()

    monkeypatch.setattr("trace2api.replay.replay.httpx.Client", TrackedClient)
    result = replay_capture(capture(entry("a", "https://shop.example.com/api/orders")), {})
    assert len(result) == 1
    assert closed == [True]
