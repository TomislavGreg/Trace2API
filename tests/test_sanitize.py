"""Tests for credential redaction.

Every value used here is synthetic and was written for this repository.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from trace2api.models import (
    Body,
    Capture,
    CaptureMetadata,
    CaptureSource,
    Entry,
    Headers,
    Request,
    Response,
)
from trace2api.sanitize import (
    RedactionRule,
    is_jwt_shaped,
    is_redacted,
    is_sensitive_header,
    is_sensitive_name,
    is_sensitive_query_name,
    redact_capture,
)

STARTED_AT = datetime(2026, 9, 1, 9, 0, 0, tzinfo=UTC)
SALT = b"fixed-salt-for-tests"

# A structurally valid token made of meaningless segments.
FAKE_JWT = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkZW1vIn0.c2lnbmF0dXJl"


def make_capture(
    *,
    url: str = "https://api.example.test/v1/orders",
    method: str = "GET",
    request_headers: list[tuple[str, str]] | None = None,
    request_body: Body | None = None,
    response: Response | None = None,
) -> Capture:
    request = Request(
        method=method,
        url=url,
        headers=Headers.from_pairs(request_headers or []),
        body=request_body,
    )
    entry = Entry(
        id="e0001",
        started_at=STARTED_AT,
        request=request,
        response=response if response is not None else Response(status=200),
    )
    metadata = CaptureMetadata(source=CaptureSource.HAR, created_at=STARTED_AT)
    return Capture(metadata=metadata, entries=[entry])


def redact(capture: Capture) -> tuple[Entry, list[str]]:
    """Return the single redacted entry and the locations that were redacted."""
    result = redact_capture(capture, salt=SALT)
    return result.capture.entries[0], [item.location for item in result.report.redactions]


def json_body(payload: object) -> Body:
    return Body(mime_type="application/json", text=json.dumps(payload))


class TestPolicy:
    @pytest.mark.parametrize(
        "name",
        [
            "authorization",
            "X-CSRF-Token",
            "csrfmiddlewaretoken",
            "client_secret",
            "apiKey",
            "session_id",
            "PASSWORD",
        ],
    )
    def test_credential_names_are_recognized(self, name: str) -> None:
        assert is_sensitive_name(name)

    @pytest.mark.parametrize(
        "name",
        ["order_id", "page", "content-type", "customer", "tokenizer", "", "locale"],
    )
    def test_ordinary_names_are_left_alone(self, name: str) -> None:
        assert not is_sensitive_name(name)

    def test_query_only_names_do_not_apply_elsewhere(self) -> None:
        assert is_sensitive_query_name("code")
        assert is_sensitive_query_name("key")
        assert not is_sensitive_name("code")
        assert not is_sensitive_name("key")

    def test_cookie_and_scheme_headers_are_partially_redacted_instead(self) -> None:
        assert not is_sensitive_header("Cookie")
        assert not is_sensitive_header("Authorization")
        assert is_sensitive_header("X-Api-Key")

    @pytest.mark.parametrize("value", [FAKE_JWT, "eyJhIjoxfQ.eyJiIjoyfQ."])
    def test_jwt_shape_is_recognized(self, value: str) -> None:
        assert is_jwt_shaped(value)

    @pytest.mark.parametrize(
        "value",
        ["example.test.com", "1.2.3", "not.a.token", "eyJhbGci", ""],
    )
    def test_ordinary_dotted_values_are_not_tokens(self, value: str) -> None:
        assert not is_jwt_shaped(value)


class TestHeaderRedaction:
    def test_authorization_keeps_its_scheme(self) -> None:
        entry, locations = redact(
            make_capture(request_headers=[("Authorization", "Bearer sk-test-abc123")])
        )
        value = entry.request.headers.get("authorization")
        assert value is not None
        scheme, _, credential = value.partition(" ")
        assert scheme == "Bearer"
        assert is_redacted(credential)
        assert "sk-test-abc123" not in value
        assert locations == ["request.headers.authorization"]

    def test_authorization_without_a_scheme_is_fully_redacted(self) -> None:
        entry, _ = redact(make_capture(request_headers=[("Authorization", "sk-test-abc123")]))
        value = entry.request.headers.get("authorization")
        assert value is not None
        assert is_redacted(value)

    def test_cookie_names_survive_and_values_do_not(self) -> None:
        entry, locations = redact(
            make_capture(request_headers=[("Cookie", "session=abc123; theme=dark; csrf=xyz789")])
        )
        value = entry.request.headers.get("cookie") or ""
        assert [pair.split("=", 1)[0] for pair in value.split("; ")] == [
            "session",
            "theme",
            "csrf",
        ]
        assert all(is_redacted(pair.split("=", 1)[1]) for pair in value.split("; "))
        assert "abc123" not in value and "dark" not in value and "xyz789" not in value
        assert locations == [
            "request.headers.cookie[session]",
            "request.headers.cookie[theme]",
            "request.headers.cookie[csrf]",
        ]

    def test_set_cookie_keeps_its_attributes(self) -> None:
        response = Response(
            status=200,
            headers=Headers.from_pairs(
                [("Set-Cookie", "session=abc123; Path=/; HttpOnly; SameSite=Lax")]
            ),
        )
        entry, locations = redact(make_capture(response=response))
        assert entry.response is not None
        value = entry.response.headers.get("set-cookie") or ""
        assert value.endswith("; Path=/; HttpOnly; SameSite=Lax")
        assert value.startswith("session=<redacted:")
        assert "abc123" not in value
        assert locations == ["response.headers.set-cookie[session]"]

    def test_named_credential_headers_are_removed_whole(self) -> None:
        entry, locations = redact(
            make_capture(
                request_headers=[("X-Api-Key", "key-abc123"), ("Accept", "application/json")]
            )
        )
        api_key = entry.request.headers.get("x-api-key")
        assert api_key is not None and is_redacted(api_key)
        assert entry.request.headers.get("accept") == "application/json"
        assert locations == ["request.headers.x-api-key"]

    def test_token_shaped_value_is_removed_from_an_unremarkable_header(self) -> None:
        entry, locations = redact(make_capture(request_headers=[("X-Client-State", FAKE_JWT)]))
        value = entry.request.headers.get("x-client-state")
        assert value is not None and is_redacted(value)
        assert locations == ["request.headers.x-client-state"]

    def test_unrelated_headers_are_untouched(self) -> None:
        headers = [("Accept", "application/json"), ("User-Agent", "trace2api-tests/1.0")]
        entry, locations = redact(make_capture(request_headers=headers))
        assert entry.request.headers.names() == ("Accept", "User-Agent")
        assert entry.request.headers.get("user-agent") == "trace2api-tests/1.0"
        assert locations == []


class TestUrlRedaction:
    def test_credential_query_parameters_are_replaced(self) -> None:
        url = "https://api.example.test/v1/orders?access_token=abc123&status=open&page=2"
        entry, locations = redact(make_capture(url=url))
        query = entry.request.query
        assert query.get("status") == "open"
        assert query.get("page") == "2"
        token = query.get("access_token")
        assert token is not None and is_redacted(token)
        assert "abc123" not in entry.request.url
        assert locations == ["request.url.query[access_token]"]

    def test_query_without_credentials_keeps_its_exact_spelling(self) -> None:
        url = "https://api.example.test/v1/orders?filter=a%2Bb&status=open"
        entry, locations = redact(make_capture(url=url))
        assert entry.request.url == url
        assert locations == []

    def test_url_credentials_are_removed(self) -> None:
        url = "https://demo:hunter2@api.example.test/v1/orders"
        entry, locations = redact(make_capture(url=url))
        assert "hunter2" not in entry.request.url
        assert "demo" not in entry.request.url
        assert entry.request.host == "api.example.test"
        assert entry.request.path == "/v1/orders"
        assert locations == ["request.url.userinfo"]

    def test_redirect_target_is_redacted(self) -> None:
        response = Response(
            status=302,
            redirect_url="https://app.example.test/callback?code=abc123&state=xyz",
        )
        entry, locations = redact(make_capture(response=response))
        assert entry.response is not None
        assert entry.response.redirect_url is not None
        assert "abc123" not in entry.response.redirect_url
        assert "state=xyz" in entry.response.redirect_url
        assert locations == ["response.redirect_url.query[code]"]


class TestBodyRedaction:
    def test_json_fields_are_replaced_by_name(self) -> None:
        body = json_body({"username": "demo", "password": "hunter2", "remember": True})
        entry, locations = redact(make_capture(method="POST", request_body=body))
        assert entry.request.body is not None
        payload = json.loads(entry.request.body.text or "")
        assert payload["username"] == "demo"
        assert payload["remember"] is True
        assert is_redacted(payload["password"])
        assert locations == ["request.body.password"]

    def test_nested_and_repeated_fields_are_reached(self) -> None:
        body = json_body(
            {
                "user": {"name": "demo", "api_key": "key-abc123"},
                "sessions": [{"id": 1, "token": "t-1"}, {"id": 2, "token": "t-2"}],
            }
        )
        entry, locations = redact(make_capture(method="POST", request_body=body))
        assert entry.request.body is not None
        payload = json.loads(entry.request.body.text or "")
        assert payload["user"]["name"] == "demo"
        assert is_redacted(payload["user"]["api_key"])
        assert [item["id"] for item in payload["sessions"]] == [1, 2]
        assert all(is_redacted(item["token"]) for item in payload["sessions"])
        assert locations == [
            "request.body.user.api_key",
            "request.body.sessions[0].token",
            "request.body.sessions[1].token",
        ]

    def test_a_numeric_secret_is_replaced_and_a_flag_is_not(self) -> None:
        body = json_body({"otp": 123456, "attempts": 2, "password_saved": False})
        entry, locations = redact(make_capture(method="POST", request_body=body))
        assert entry.request.body is not None
        payload = json.loads(entry.request.body.text or "")
        assert payload["attempts"] == 2
        assert payload["password_saved"] is False
        assert is_redacted(payload["otp"])
        assert "123456" not in (entry.request.body.text or "")
        assert locations == ["request.body.otp"]

    def test_a_credential_named_object_is_walked_into(self) -> None:
        body = json_body({"auth": {"scheme": "basic", "password": "hunter2"}})
        entry, locations = redact(make_capture(method="POST", request_body=body))
        assert entry.request.body is not None
        payload = json.loads(entry.request.body.text or "")
        assert payload["auth"]["scheme"] == "basic"
        assert is_redacted(payload["auth"]["password"])
        assert locations == ["request.body.auth.password"]

    def test_response_tokens_are_replaced(self) -> None:
        response = Response(
            status=200,
            body=json_body({"access_token": FAKE_JWT, "expires_in": 3600}),
        )
        entry, locations = redact(make_capture(response=response))
        assert entry.response is not None and entry.response.body is not None
        payload = json.loads(entry.response.body.text or "")
        assert payload["expires_in"] == 3600
        assert is_redacted(payload["access_token"])
        assert FAKE_JWT not in (entry.response.body.text or "")
        assert locations == ["response.body.access_token"]

    def test_token_shaped_value_under_an_unremarkable_field(self) -> None:
        response = Response(status=200, body=json_body({"context": FAKE_JWT}))
        entry, locations = redact(make_capture(response=response))
        assert entry.response is not None and entry.response.body is not None
        assert FAKE_JWT not in (entry.response.body.text or "")
        assert locations == ["response.body.context"]

    def test_form_fields_are_replaced_by_name(self) -> None:
        body = Body(
            mime_type="application/x-www-form-urlencoded",
            text="username=demo&password=hunter2&csrfmiddlewaretoken=xyz789",
        )
        entry, locations = redact(make_capture(method="POST", request_body=body))
        assert entry.request.body is not None
        text = entry.request.body.text or ""
        assert "username=demo" in text
        assert "hunter2" not in text and "xyz789" not in text
        assert locations == ["request.body[password]", "request.body[csrfmiddlewaretoken]"]

    def test_body_without_credentials_is_returned_unchanged(self) -> None:
        body = json_body({"status": "open", "page": 2})
        entry, locations = redact(make_capture(method="POST", request_body=body))
        assert entry.request.body == body
        assert locations == []

    def test_malformed_json_is_left_as_observed(self) -> None:
        body = Body(mime_type="application/json", text='{"password": "hunter2"')
        entry, locations = redact(make_capture(method="POST", request_body=body))
        assert entry.request.body == body
        assert locations == []

    def test_binary_bodies_are_left_as_observed(self) -> None:
        body = Body(mime_type="image/png", text="aGVsbG8=", encoding="base64")
        entry, locations = redact(make_capture(response=Response(status=200, body=body)))
        assert entry.response is not None
        assert entry.response.body == body
        assert locations == []


class TestReport:
    def test_report_describes_redactions_without_quoting_them(self) -> None:
        capture = make_capture(
            url="https://api.example.test/v1/orders?api_key=key-abc123",
            request_headers=[("Authorization", "Bearer sk-test-abc123")],
        )
        report = redact_capture(capture, salt=SALT).report
        serialized = report.model_dump_json()
        assert "sk-test-abc123" not in serialized
        assert "key-abc123" not in serialized
        assert len(report) == 2
        assert {item.rule for item in report.redactions} == {
            RedactionRule.CREDENTIAL_SCHEME,
            RedactionRule.SENSITIVE_PARAMETER,
        }
        assert all(item.entry_id == "e0001" for item in report.redactions)

    def test_counts_are_grouped_by_rule(self) -> None:
        capture = make_capture(
            request_headers=[("Cookie", "session=abc123; theme=dark"), ("X-Api-Key", "key-abc")]
        )
        report = redact_capture(capture, salt=SALT).report
        assert report.counts_by_rule() == {
            RedactionRule.COOKIE_VALUE: 2,
            RedactionRule.SENSITIVE_HEADER: 1,
        }
        assert not report.is_empty
        assert len(report.for_entry("e0001")) == 3
        assert report.for_entry("missing") == ()

    def test_empty_capture_produces_an_empty_report(self) -> None:
        metadata = CaptureMetadata(source=CaptureSource.HAR, created_at=STARTED_AT)
        result = redact_capture(Capture(metadata=metadata), salt=SALT)
        assert result.report.is_empty
        assert result.capture.entries == []


class TestFingerprints:
    def test_one_secret_used_twice_gets_one_placeholder(self) -> None:
        capture = make_capture(
            url="https://api.example.test/v1/orders?access_token=abc123",
            request_headers=[("X-Api-Key", "abc123"), ("X-Other-Key", "different")],
        )
        result = redact_capture(capture, salt=SALT)
        entry = result.capture.entries[0]
        assert entry.request.query.get("access_token") == entry.request.headers.get("x-api-key")
        assert entry.request.headers.get("x-other-key") != entry.request.headers.get("x-api-key")

    def test_a_different_salt_gives_different_placeholders(self) -> None:
        capture = make_capture(request_headers=[("X-Api-Key", "abc123")])
        first = redact_capture(capture, salt=b"salt-one").capture.entries[0]
        second = redact_capture(capture, salt=b"salt-two").capture.entries[0]
        assert first.request.headers.get("x-api-key") != second.request.headers.get("x-api-key")

    def test_an_unsalted_run_still_redacts(self) -> None:
        capture = make_capture(request_headers=[("X-Api-Key", "abc123")])
        entry = redact_capture(capture).capture.entries[0]
        value = entry.request.headers.get("x-api-key")
        assert value is not None and is_redacted(value)
        assert "abc123" not in value

    def test_redacting_twice_changes_nothing_further(self) -> None:
        capture = make_capture(
            url="https://demo:hunter2@api.example.test/v1/orders?api_key=key-abc123",
            method="POST",
            request_headers=[("Authorization", "Bearer sk-test-abc"), ("Cookie", "session=abc")],
            request_body=json_body({"password": "hunter2", "status": "open"}),
        )
        once = redact_capture(capture, salt=SALT)
        twice = redact_capture(once.capture, salt=SALT)
        assert twice.capture == once.capture

    def test_an_already_redacted_capture_still_reports_where_its_secrets_are(self) -> None:
        """A capture read back from disk arrives sanitized, and later stages need the report."""
        capture = make_capture(
            url="https://api.example.test/v1/orders?api_key=key-abc123",
            request_headers=[("Authorization", "Bearer sk-test-abc"), ("Cookie", "session=abc")],
        )
        once = redact_capture(capture, salt=SALT)
        twice = redact_capture(once.capture, salt=SALT)
        assert twice.report == once.report

    def test_redacting_twice_does_not_fingerprint_the_placeholder(self) -> None:
        """A second pass must report the value's own fingerprint, not one of the placeholder."""
        capture = make_capture(request_headers=[("X-Api-Key", "key-abc123")])
        once = redact_capture(capture, salt=SALT)
        twice = redact_capture(once.capture, salt=SALT)
        assert twice.report.redactions[0].fingerprint == once.report.redactions[0].fingerprint


class TestCaptureIsPreserved:
    def test_everything_that_is_not_a_credential_survives(self) -> None:
        capture = make_capture(
            url="https://api.example.test/v1/orders?status=open",
            method="POST",
            request_headers=[("Authorization", "Bearer sk-test-abc"), ("Accept", "text/plain")],
        )
        result = redact_capture(capture, salt=SALT)
        entry = result.capture.entries[0]
        original = capture.entries[0]
        assert result.capture.metadata == capture.metadata
        assert entry.id == original.id
        assert entry.started_at == original.started_at
        assert entry.request.method == "POST"
        assert entry.request.url_without_query == original.request.url_without_query
        assert entry.request.query.get("status") == "open"
        assert entry.request.headers.names() == original.request.headers.names()
        assert entry.response == original.response

    def test_the_original_capture_is_not_modified(self) -> None:
        capture = make_capture(request_headers=[("Authorization", "Bearer sk-test-abc")])
        redact_capture(capture, salt=SALT)
        assert capture.entries[0].request.headers.get("authorization") == "Bearer sk-test-abc"

    def test_a_failed_entry_is_handled(self) -> None:
        metadata = CaptureMetadata(source=CaptureSource.BROWSER, created_at=STARTED_AT)
        entry = Entry(
            id="e0002",
            started_at=STARTED_AT,
            request=Request(
                method="GET",
                url="https://api.example.test/v1/orders",
                headers=Headers.from_pairs([("Authorization", "Bearer sk-test-abc")]),
            ),
            failure="net::ERR_CONNECTION_RESET",
        )
        result = redact_capture(Capture(metadata=metadata, entries=[entry]), salt=SALT)
        redacted = result.capture.entries[0]
        assert redacted.failure == "net::ERR_CONNECTION_RESET"
        assert redacted.response is None
        value = redacted.request.headers.get("authorization")
        assert value is not None and "sk-test-abc" not in value
