"""Tests for writing a capture out as a runnable JavaScript client using fetch.

The generated module is checked by running it. A stub replaces the global ``fetch``,
records what the client asked for, and answers with an empty JSON document, so a test can
assert what actually went out rather than what the rendered text looks like. Node runs
the module, and the tests that need it are skipped where it is not installed.
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from trace2api.analyze import Relevance
from trace2api.capture import load_har
from trace2api.generate import HeaderRule, generate_javascript
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

EXAMPLE_HAR = Path(__file__).resolve().parent.parent / "examples" / "storefront-orders.har"

STARTED_AT = datetime(2026, 9, 4, 9, 15, tzinfo=UTC)

ACCESS_TOKEN = "example-access-token-not-a-real-credential"
SESSION_VALUE = "example-session-value"

NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="running the generated client needs node")

HARNESS = """\
import { pathToFileURL } from "node:url";

const sent = [];
globalThis.fetch = async (input, init = {}) => {
  const request = new Request(input, init);
  sent.push({
    method: request.method,
    url: request.url,
    headers: [...request.headers],
    body: await request.text(),
  });
  return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
};

const module = await import(pathToFileURL(process.argv[2]).href);
const responses = await module.run();
process.stdout.write(JSON.stringify({ sent, responses: responses.length }));
"""


def entry(
    entry_id: str,
    url: str,
    *,
    method: str = "GET",
    headers: list[tuple[str, str]] | None = None,
    body: Body | None = None,
    resource_type: ResourceType = ResourceType.XHR,
) -> Entry:
    """Build one observed exchange that the relevance rules keep."""
    return Entry(
        id=entry_id,
        started_at=STARTED_AT,
        request=Request(
            method=method,
            url=url,
            headers=Headers.from_pairs(headers or []),
            body=body,
        ),
        response=Response(
            status=200,
            headers=Headers.from_pairs([("Content-Type", "application/json")]),
            body=Body(mime_type="application/json", text="{}"),
        ),
        resource_type=resource_type,
    )


def capture(*entries: Entry, start_url: str | None = None) -> Capture:
    """Build a capture holding ``entries``."""
    return Capture(
        metadata=CaptureMetadata(
            source=CaptureSource.HAR,
            created_at=STARTED_AT,
            start_url=start_url,
        ),
        entries=list(entries),
    )


@pytest.fixture
def execute(tmp_path: Path) -> Callable[..., subprocess.CompletedProcess[str]]:
    """Return a function that runs generated code under the stub fetch and reports how it went."""

    def run(code: str, environment: dict[str, str] | None = None) -> subprocess.CompletedProcess:
        module = tmp_path / "client.mjs"
        module.write_text(code, encoding="utf-8")
        harness = tmp_path / "harness.mjs"
        harness.write_text(HARNESS, encoding="utf-8")
        assert NODE is not None
        return subprocess.run(
            [NODE, str(harness), str(module)],
            capture_output=True,
            text=True,
            env=environment or {},
            timeout=60,
            check=False,
        )

    return run


@pytest.fixture
def send(
    execute: Callable[..., subprocess.CompletedProcess[str]],
) -> Callable[..., list[dict[str, Any]]]:
    """Return a function that runs generated code and returns the requests it sent."""

    def sent(code: str, environment: dict[str, str] | None = None) -> list[dict[str, Any]]:
        finished = execute(code, environment)
        assert finished.returncode == 0, finished.stderr
        report = json.loads(finished.stdout)
        assert report["responses"] == len(report["sent"])
        return report["sent"]

    return sent


def header(request: dict[str, Any], name: str) -> str | None:
    """Return the value the client sent for ``name``, or ``None`` if it sent none."""
    values = [value for sent, value in request["headers"] if sent == name.lower()]
    return ", ".join(values) if values else None


# What the module says


def test_the_header_names_the_recording_and_what_is_reproduced() -> None:
    client = generate_javascript(capture(entry("a", "https://shop.example.com/api/orders")))
    assert client.code.startswith("// Direct client for a workflow recorded ")
    assert "recorded 2026-09-04T09:15:00+00:00 (source: har)" in client.code
    assert "// Reproducing 1 of 1 captured request." in client.code


def test_the_header_names_where_the_recording_started() -> None:
    recorded = capture(
        entry("a", "https://shop.example.com/api/orders"),
        start_url="https://shop.example.com/orders",
    )
    assert "// Recorded from https://shop.example.com/orders" in generate_javascript(recorded).code


def test_a_capture_holding_no_credentials_says_so() -> None:
    client = generate_javascript(capture(entry("a", "https://shop.example.com/api/orders")))
    assert client.secrets.is_empty
    assert "held no credentials" in client.code
    assert "requireEnv" not in client.code


def test_each_request_is_numbered_as_the_capture_numbers_it() -> None:
    client = generate_javascript(
        capture(
            entry("a", "https://cdn.example.com/app.css", resource_type=ResourceType.STYLESHEET),
            entry("b", "https://shop.example.com/api/orders"),
        )
    )
    assert [call.position for call in client.calls] == [2]
    assert "// 2  GET https://shop.example.com/api/orders" in client.code
    assert "const response2 = await fetch(" in client.code
    assert "return [response2];" in client.code


# Which requests are written


def test_noise_is_left_out_and_accounted_for() -> None:
    client = generate_javascript(
        capture(
            entry("a", "https://shop.example.com/api/orders"),
            entry("b", "https://cdn.example.com/app.css", resource_type=ResourceType.STYLESHEET),
        )
    )
    assert len(client) == 1
    assert client.captured == 2
    assert client.skipped == 1
    assert "app.css" not in client.code


def test_noise_can_be_written_out_as_well() -> None:
    recorded = capture(
        entry("a", "https://shop.example.com/api/orders"),
        entry("b", "https://cdn.example.com/app.css", resource_type=ResourceType.STYLESHEET),
    )
    client = generate_javascript(recorded, keep=tuple(Relevance))
    assert len(client) == 2
    assert "app.css" in client.code


@needs_node
def test_a_capture_with_nothing_worth_keeping_still_writes_a_module(
    send: Callable[..., list[dict[str, Any]]],
) -> None:
    client = generate_javascript(
        capture(
            entry("a", "https://cdn.example.com/app.css", resource_type=ResourceType.STYLESHEET)
        )
    )
    assert len(client) == 0
    assert "// Reproducing 0 of 1 captured request." in client.code
    assert "await fetch(" not in client.code
    assert send(client.code) == []


# The shape of a call


def test_a_request_is_sent_with_its_observed_method_and_url() -> None:
    client = generate_javascript(
        capture(entry("a", "https://shop.example.com/api/orders?status=open", method="DELETE"))
    )
    assert 'method: "DELETE",' in client.code
    assert 'await fetch("https://shop.example.com/api/orders?status=open", {' in client.code
    assert "URLSearchParams" not in client.code


def test_a_body_is_sent_as_the_text_that_was_observed() -> None:
    client = generate_javascript(
        capture(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                method="POST",
                headers=[("Content-Type", "application/json")],
                body=Body(mime_type="application/json", text='{"note":"hi"}'),
            )
        )
    )
    assert """body: '{"note":"hi"}',""" in client.code


def test_headers_are_sent_as_an_object_in_the_observed_order() -> None:
    client = generate_javascript(
        capture(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                headers=[("Accept", "application/json"), ("X-Request-Id", "r-1")],
            )
        )
    )
    assert '"Accept": "application/json",' in client.code
    assert '"X-Request-Id": "r-1",' in client.code


@needs_node
def test_a_header_the_request_repeated_is_sent_as_pairs(
    send: Callable[..., list[dict[str, Any]]],
) -> None:
    client = generate_javascript(
        capture(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                headers=[("X-Tag", "one"), ("X-Tag", "two")],
            )
        )
    )
    assert "headers: [" in client.code
    assert '["X-Tag", "one"],' in client.code
    assert '["X-Tag", "two"],' in client.code
    [request] = send(client.code)
    assert header(request, "X-Tag") == "one, two"


@needs_node
def test_a_redirect_is_not_followed_because_the_capture_recorded_it_separately(
    send: Callable[..., list[dict[str, Any]]],
) -> None:
    client = generate_javascript(capture(entry("a", "https://shop.example.com/api/orders")))
    assert 'redirect: "manual",' in client.code
    assert send(client.code)


# Headers fetch has to handle itself


@pytest.mark.parametrize(
    ("name", "value", "rule"),
    [
        ("Content-Length", "42", HeaderRule.COMPUTED_BY_CLIENT),
        ("Host", "shop.example.com", HeaderRule.COMPUTED_BY_CLIENT),
        ("Connection", "keep-alive", HeaderRule.HOP_BY_HOP),
        (":authority", "shop.example.com", HeaderRule.PSEUDO_HEADER),
        ("Accept-Encoding", "gzip, br", HeaderRule.NEGOTIATED_BY_CLIENT),
    ],
)
def test_headers_fetch_derives_are_left_out_with_a_stated_reason(
    name: str, value: str, rule: HeaderRule
) -> None:
    client = generate_javascript(
        capture(entry("a", "https://shop.example.com/api/orders", headers=[(name, value)]))
    )
    call = client.calls[0]
    assert [(item.name, item.rule) for item in call.omitted_headers] == [(name, rule)]
    assert call.omitted_headers[0].reason
    assert f'"{name}":' not in client.code
    assert name in client.code  # accounted for in the header comment rather than dropped silently


@needs_node
def test_a_stale_content_length_is_not_sent(send: Callable[..., list[dict[str, Any]]]) -> None:
    client = generate_javascript(
        capture(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                method="POST",
                headers=[("Content-Type", "application/json"), ("Content-Length", "9999")],
                body=Body(mime_type="application/json", text='{"note":"hi"}'),
            )
        )
    )
    [request] = send(client.code)
    assert header(request, "Content-Length") is None
    assert request["body"] == '{"note":"hi"}'


# Credentials


def test_a_credential_header_becomes_a_variable_and_keeps_its_scheme() -> None:
    client = generate_javascript(
        capture(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                headers=[("Authorization", f"Bearer {ACCESS_TOKEN}")],
            )
        )
    )
    assert ACCESS_TOKEN not in client.code
    assert '"Authorization": "Bearer " + TRACE2API_AUTHORIZATION,' in client.code
    assert 'const TRACE2API_AUTHORIZATION = requireEnv("TRACE2API_AUTHORIZATION");' in client.code
    assert "//   TRACE2API_AUTHORIZATION  request.headers.authorization" in client.code


@needs_node
def test_a_cookie_keeps_its_names_and_reads_each_value_from_the_environment(
    send: Callable[..., list[dict[str, Any]]],
) -> None:
    client = generate_javascript(
        capture(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                headers=[("Cookie", f"session={SESSION_VALUE}; locale=en-GB")],
            )
        )
    )
    assert SESSION_VALUE not in client.code
    assert "TRACE2API_COOKIE_SESSION" in client.code
    assert "TRACE2API_COOKIE_LOCALE" in client.code
    [request] = send(
        client.code,
        {
            "TRACE2API_COOKIE_SESSION": "supplied-session",
            "TRACE2API_COOKIE_LOCALE": "en-GB",
        },
    )
    assert header(request, "Cookie") == "session=supplied-session; locale=en-GB"


@needs_node
def test_a_credential_in_a_body_becomes_a_variable(
    send: Callable[..., list[dict[str, Any]]],
) -> None:
    client = generate_javascript(
        capture(
            entry(
                "a",
                "https://shop.example.com/api/session",
                method="POST",
                headers=[("Content-Type", "application/json")],
                body=Body(mime_type="application/json", text='{"password":"live-pw"}'),
            )
        )
    )
    assert "live-pw" not in client.code
    assert "TRACE2API_PASSWORD" in client.code
    [request] = send(client.code, {"TRACE2API_PASSWORD": "supplied-pw"})
    assert '"supplied-pw"' in request["body"]


def test_one_token_used_twice_is_exported_once() -> None:
    credential = ("Authorization", f"Bearer {ACCESS_TOKEN}")
    client = generate_javascript(
        capture(
            entry("a", "https://shop.example.com/api/orders", headers=[credential]),
            entry("b", "https://shop.example.com/api/orders/1", headers=[credential]),
        )
    )
    assert len(client.secrets) == 1
    assert client.code.count("const TRACE2API_AUTHORIZATION = requireEnv(") == 1
    assert client.code.count('"Bearer " + TRACE2API_AUTHORIZATION') == 2


@needs_node
def test_the_client_stops_before_sending_anything_when_a_credential_is_missing(
    execute: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    client = generate_javascript(
        capture(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                headers=[("Authorization", f"Bearer {ACCESS_TOKEN}")],
            )
        )
    )
    finished = execute(client.code)
    assert finished.returncode != 0
    assert "TRACE2API_AUTHORIZATION is not set" in finished.stderr
    assert finished.stdout == ""


# Credentials in a query string, which fetch has to encode


def test_a_credential_in_the_query_string_is_rebuilt_through_search_params() -> None:
    client = generate_javascript(
        capture(entry("a", "https://shop.example.com/api/orders?api_key=live-key&status=open"))
    )
    assert "live-key" not in client.code
    assert "<redacted:" not in client.code
    assert 'const url1 = new URL("https://shop.example.com/api/orders");' in client.code
    assert "url1.search = new URLSearchParams([" in client.code
    assert '["api_key", TRACE2API_QUERY_API_KEY],' in client.code
    assert '["status", "open"],' in client.code
    assert "await fetch(url1, {" in client.code


@needs_node
def test_a_credential_in_the_query_string_is_encoded_by_search_params(
    send: Callable[..., list[dict[str, Any]]],
) -> None:
    client = generate_javascript(
        capture(entry("a", "https://shop.example.com/api/orders?api_key=live-key"))
    )
    assert client.calls[0].notes == [
        "TRACE2API_QUERY_API_KEY is sent as a search parameter, "
        "so URLSearchParams encodes the supplied value"
    ]
    [request] = send(client.code, {"TRACE2API_QUERY_API_KEY": "a key/with symbols&more"})
    assert request["url"].endswith("?api_key=a+key%2Fwith+symbols%26more")


@needs_node
def test_a_query_string_without_credentials_is_sent_as_it_was_observed(
    send: Callable[..., list[dict[str, Any]]],
) -> None:
    client = generate_javascript(
        capture(entry("a", "https://shop.example.com/api/orders?status=open&status=paid"))
    )
    [request] = send(client.code)
    assert request["url"] == "https://shop.example.com/api/orders?status=open&status=paid"


# Credentials in a form payload, which the client has to encode itself


FORM = "application/x-www-form-urlencoded"


def form_entry(text: str) -> Entry:
    """Build an exchange posting ``text`` as a form encoded payload."""
    return entry(
        "a",
        "https://shop.example.com/api/orders",
        method="POST",
        headers=[("Content-Type", FORM)],
        body=Body(mime_type=FORM, text=text),
    )


@needs_node
def test_a_credential_in_a_form_payload_reaches_the_request_encoded(
    send: Callable[..., list[dict[str, Any]]],
) -> None:
    client = generate_javascript(capture(form_entry(f"ref=CNF-998172&csrf_token={ACCESS_TOKEN}")))
    assert ACCESS_TOKEN not in client.code
    assert "<redacted:" not in client.code
    assert client.calls[0].notes == [
        "TRACE2API_BODY_CSRF_TOKEN is encoded into the form payload where the capture observed it"
    ]
    [request] = send(client.code, {"TRACE2API_BODY_CSRF_TOKEN": "a+b/c=d&e"})
    assert request["body"] == "ref=CNF-998172&csrf_token=a%2Bb%2Fc%3Dd%26e"


@needs_node
def test_a_form_payload_keeps_every_field_the_client_did_not_have_to_supply(
    send: Callable[..., list[dict[str, Any]]],
) -> None:
    client = generate_javascript(
        capture(form_entry(f"csrf_token={ACCESS_TOKEN}&note=hello+world%21&page=1"))
    )
    [request] = send(client.code, {"TRACE2API_BODY_CSRF_TOKEN": "supplied"})
    assert request["body"] == "csrf_token=supplied&note=hello+world%21&page=1"


@needs_node
def test_a_form_payload_without_credentials_is_sent_as_it_was_observed(
    send: Callable[..., list[dict[str, Any]]],
) -> None:
    client = generate_javascript(capture(form_entry("q=shoes&page=1")))
    assert "encodeURIComponent" not in client.code
    [request] = send(client.code)
    assert request["body"] == "q=shoes&page=1"


# Bodies the client cannot reproduce


def test_a_binary_body_is_reported_rather_than_guessed_at() -> None:
    client = generate_javascript(
        capture(
            entry(
                "a",
                "https://shop.example.com/api/upload",
                method="POST",
                headers=[("Content-Type", "application/octet-stream")],
                body=Body(
                    mime_type="application/octet-stream",
                    text=base64.b64encode(b"\x00\x01\x02").decode(),
                    encoding="base64",
                    size=3,
                ),
            )
        )
    )
    assert "body:" not in client.code
    assert client.calls[0].notes == [
        "a binary body of 3 bytes was observed here and is not reproduced"
    ]
    assert "// note: a binary body of 3 bytes" in client.code


@needs_node
def test_a_body_observed_on_a_read_request_is_reported_rather_than_sent(
    send: Callable[..., list[dict[str, Any]]],
) -> None:
    client = generate_javascript(
        capture(
            entry(
                "a",
                "https://shop.example.com/api/search",
                method="GET",
                headers=[("Content-Type", "application/json")],
                body=Body(mime_type="application/json", text='{"query":"boots"}'),
            )
        )
    )
    assert "body:" not in client.code
    assert client.calls[0].notes == [
        "fetch cannot send a body with a GET request, so the observed body is not reproduced"
    ]
    [request] = send(client.code)
    assert request["body"] == ""


def test_a_body_the_capture_only_sampled_is_flagged() -> None:
    client = generate_javascript(
        capture(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                method="POST",
                headers=[("Content-Type", "application/json")],
                body=Body(mime_type="application/json", text='{"note":"tru', truncated=True),
            )
        )
    )
    assert "the capture recorded only part of this body" in client.calls[0].notes[0]
    assert "body:" in client.code


def test_an_empty_body_adds_no_body_property() -> None:
    client = generate_javascript(
        capture(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                method="POST",
                body=Body(mime_type="application/json", text=""),
            )
        )
    )
    assert "body:" not in client.code


# Quoting, which decides whether the module runs at all


@needs_node
@pytest.mark.parametrize(
    "text",
    [
        """{"note":"it's here"}""",
        '{"path":"C:\\\\logs\\\\app.log"}',
        '{"note":"line\\nbreak"}',
        '{"note":"quote \\" inside"}',
        '{"note":"emoji \U0001f600 and accents éà"}',
        '{"note":"separators \u2028 and \u2029"}',
        '{"note":"a `backtick` and ${not_a_variable}"}',
        "{}",
    ],
)
def test_a_body_reaches_the_server_as_it_was_observed(
    text: str, send: Callable[..., list[dict[str, Any]]]
) -> None:
    client = generate_javascript(
        capture(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                method="POST",
                headers=[("Content-Type", "application/json")],
                body=Body(mime_type="application/json", text=text),
            )
        )
    )
    [request] = send(client.code)
    assert request["body"] == text


@needs_node
def test_a_comment_cannot_be_ended_early_by_what_a_capture_recorded(
    send: Callable[..., list[dict[str, Any]]],
) -> None:
    recorded = capture(
        entry("a", "https://shop.example.com/api/orders"),
        start_url="https://shop.example.com/*/\nprocess.exit(9)",
    )
    client = generate_javascript(recorded)
    assert "// Recorded from https://shop.example.com/*/ process.exit(9)" in client.code
    assert len(send(client.code)) == 1


# The example capture


def test_the_example_capture_carries_no_observed_credential_into_the_client() -> None:
    client = generate_javascript(load_har(EXAMPLE_HAR))
    for observed in (ACCESS_TOKEN, SESSION_VALUE, "example-csrf-value"):
        assert observed not in client.code
    assert "<redacted:" not in client.code


def test_a_salt_makes_the_client_reproducible() -> None:
    recorded = load_har(EXAMPLE_HAR)
    first = generate_javascript(recorded, salt=b"fixed-salt")
    second = generate_javascript(recorded, salt=b"fixed-salt")
    assert first.code == second.code


@needs_node
def test_the_example_capture_produces_a_client_that_sends_the_observed_requests(
    send: Callable[..., list[dict[str, Any]]],
) -> None:
    client = generate_javascript(load_har(EXAMPLE_HAR))
    sent = send(client.code, {binding.variable: "supplied" for binding in client.secrets})
    assert [(request["method"], request["url"]) for request in sent] == [
        ("GET", "https://shop.example.com/orders"),
        ("GET", "https://shop.example.com/api/v1/orders?status=open&limit=20"),
        ("GET", "https://shop.example.com/api/v1/orders/4711"),
        ("POST", "https://shop.example.com/api/v1/orders/4711/confirm"),
    ]
    assert header(sent[1], "Authorization") == "Bearer supplied"
