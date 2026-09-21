"""Tests for writing a capture out as a runnable Python client using httpx."""

from __future__ import annotations

import base64
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest import mock

import httpx
import pytest

from trace2api.analyze import Relevance
from trace2api.capture import load_har
from trace2api.generate import HeaderRule, compile_python, generate_python
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


def load_module(code: str, environment: dict[str, str]) -> dict[str, Any]:
    """Import generated code with ``environment`` as the whole environment it can read."""
    namespace: dict[str, Any] = {"__name__": "generated_client"}
    with mock.patch.dict(os.environ, environment, clear=True):
        exec(compile(code, "generated_client.py", "exec"), namespace)
    return namespace


def send(code: str, environment: dict[str, str] | None = None) -> list[httpx.Request]:
    """Run generated code against a stub transport and return the requests it sent."""
    namespace = load_module(code, environment or {})
    sent: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, json={})

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        responses = namespace["run"](client)
    assert len(responses) == len(sent)
    return sent


def answer(
    code: str,
    answers: dict[str, Any],
    environment: dict[str, str] | None = None,
) -> list[httpx.Request]:
    """Run generated code against a server answering ``answers`` by path.

    A compiled client reads what it sends next out of what came back, so the answers are
    deliberately not the ones the capture recorded: a client that replayed the observed
    values would send the wrong requests and the test would say so.
    """
    namespace = load_module(code, environment or {})
    sent: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, json=answers.get(request.url.path, {}))

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        namespace["run"](client)
    return sent


# What the module says


def test_the_docstring_names_the_recording_and_what_is_reproduced() -> None:
    client = generate_python(capture(entry("a", "https://shop.example.com/api/orders")))
    assert client.code.startswith('"""Direct client for a workflow recorded ')
    assert "recorded 2026-09-04T09:15:00+00:00 (source: har)" in client.code
    assert "Reproducing 1 of 1 captured request." in client.code


def test_the_docstring_names_where_the_recording_started() -> None:
    recorded = capture(
        entry("a", "https://shop.example.com/api/orders"),
        start_url="https://shop.example.com/orders",
    )
    assert "Recorded from https://shop.example.com/orders" in generate_python(recorded).code


def test_a_capture_holding_no_credentials_says_so() -> None:
    client = generate_python(capture(entry("a", "https://shop.example.com/api/orders")))
    assert client.secrets.is_empty
    assert "held no credentials" in client.code
    assert "import os" not in client.code


def test_each_request_is_numbered_as_the_capture_numbers_it() -> None:
    client = generate_python(
        capture(
            entry("a", "https://cdn.example.com/app.css", resource_type=ResourceType.STYLESHEET),
            entry("b", "https://shop.example.com/api/orders"),
        )
    )
    assert [call.position for call in client.calls] == [2]
    assert "# 2  GET https://shop.example.com/api/orders" in client.code
    assert "response_2 = client.request(" in client.code
    assert "return [response_2]" in client.code


# Which requests are written


def test_noise_is_left_out_and_accounted_for() -> None:
    client = generate_python(
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
    client = generate_python(recorded, keep=tuple(Relevance))
    assert len(client) == 2
    assert "app.css" in client.code


def test_a_capture_with_nothing_worth_keeping_still_writes_a_module() -> None:
    client = generate_python(
        capture(
            entry("a", "https://cdn.example.com/app.css", resource_type=ResourceType.STYLESHEET)
        )
    )
    assert len(client) == 0
    assert "Reproducing 0 of 1 captured request." in client.code
    assert "client.request(" not in client.code
    assert send(client.code) == []


# The shape of a call


def test_a_request_is_sent_with_its_observed_method_and_url() -> None:
    client = generate_python(
        capture(entry("a", "https://shop.example.com/api/orders?status=open", method="DELETE"))
    )
    assert '"DELETE",' in client.code
    assert '"https://shop.example.com/api/orders?status=open",' in client.code
    assert "params=" not in client.code


def test_a_body_is_sent_as_the_text_that_was_observed() -> None:
    client = generate_python(
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
    assert """content='{"note":"hi"}',""" in client.code


def test_headers_are_sent_as_a_dict_in_the_observed_order() -> None:
    client = generate_python(
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


def test_a_header_the_request_repeated_is_sent_as_pairs() -> None:
    client = generate_python(
        capture(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                headers=[("X-Tag", "one"), ("X-Tag", "two")],
            )
        )
    )
    assert "headers=[" in client.code
    assert '("X-Tag", "one"),' in client.code
    assert '("X-Tag", "two"),' in client.code
    [request] = send(client.code)
    assert request.headers.get_list("x-tag") == ["one", "two"]


# Headers httpx has to handle itself


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
def test_headers_httpx_derives_are_left_out_with_a_stated_reason(
    name: str, value: str, rule: HeaderRule
) -> None:
    client = generate_python(
        capture(entry("a", "https://shop.example.com/api/orders", headers=[(name, value)]))
    )
    call = client.calls[0]
    assert [(item.name, item.rule) for item in call.omitted_headers] == [(name, rule)]
    assert call.omitted_headers[0].reason
    assert f'"{name}":' not in client.code
    assert name in client.code  # accounted for in the docstring rather than dropped silently


def test_a_stale_content_length_is_replaced_by_the_one_the_client_sends() -> None:
    client = generate_python(
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
    assert request.headers["content-length"] == "13"


# Credentials


def test_a_credential_header_becomes_a_variable_and_keeps_its_scheme() -> None:
    client = generate_python(
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
    assert 'TRACE2API_AUTHORIZATION = os.environ["TRACE2API_AUTHORIZATION"]' in client.code
    assert "  TRACE2API_AUTHORIZATION  request.headers.authorization" in client.code


def test_a_cookie_keeps_its_names_and_reads_each_value_from_the_environment() -> None:
    client = generate_python(
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
    assert request.headers["cookie"] == "session=supplied-session; locale=en-GB"


def test_a_credential_in_a_body_becomes_a_variable() -> None:
    client = generate_python(
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
    assert b'"supplied-pw"' in request.content


def test_one_token_used_twice_is_exported_once() -> None:
    header = ("Authorization", f"Bearer {ACCESS_TOKEN}")
    client = generate_python(
        capture(
            entry("a", "https://shop.example.com/api/orders", headers=[header]),
            entry("b", "https://shop.example.com/api/orders/1", headers=[header]),
        )
    )
    assert len(client.secrets) == 1
    assert client.code.count("TRACE2API_AUTHORIZATION = os.environ") == 1
    assert client.code.count('"Bearer " + TRACE2API_AUTHORIZATION') == 2


def test_the_client_stops_before_sending_anything_when_a_credential_is_missing() -> None:
    client = generate_python(
        capture(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                headers=[("Authorization", f"Bearer {ACCESS_TOKEN}")],
            )
        )
    )
    with pytest.raises(KeyError, match="TRACE2API_AUTHORIZATION"):
        send(client.code)


# Credentials in a query string, which httpx has to encode


def test_a_credential_in_the_query_string_is_sent_as_a_parameter() -> None:
    client = generate_python(
        capture(entry("a", "https://shop.example.com/api/orders?api_key=live-key&status=open"))
    )
    assert "live-key" not in client.code
    assert "<redacted:" not in client.code
    assert '"https://shop.example.com/api/orders",' in client.code
    assert '("api_key", TRACE2API_QUERY_API_KEY),' in client.code
    assert '("status", "open"),' in client.code


def test_a_credential_in_the_query_string_is_encoded_by_httpx() -> None:
    client = generate_python(
        capture(entry("a", "https://shop.example.com/api/orders?api_key=live-key"))
    )
    assert client.calls[0].notes == [
        "TRACE2API_QUERY_API_KEY is sent as a query parameter, so httpx encodes the supplied value"
    ]
    [request] = send(client.code, {"TRACE2API_QUERY_API_KEY": "a key/with symbols&more"})
    assert dict(request.url.params)["api_key"] == "a key/with symbols&more"


def test_a_query_string_without_credentials_is_sent_as_it_was_observed() -> None:
    client = generate_python(
        capture(entry("a", "https://shop.example.com/api/orders?status=open&status=paid"))
    )
    [request] = send(client.code)
    assert str(request.url) == "https://shop.example.com/api/orders?status=open&status=paid"


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


def test_a_credential_in_a_form_payload_reaches_the_request_encoded() -> None:
    client = generate_python(capture(form_entry(f"ref=CNF-998172&csrf_token={ACCESS_TOKEN}")))
    assert ACCESS_TOKEN not in client.code
    assert "<redacted:" not in client.code
    assert "import urllib.parse" in client.code
    assert client.calls[0].notes == [
        "TRACE2API_BODY_CSRF_TOKEN is encoded into the form payload where the capture observed it"
    ]
    [request] = send(client.code, {"TRACE2API_BODY_CSRF_TOKEN": "a+b/c=d&e"})
    assert request.content == b"ref=CNF-998172&csrf_token=a%2Bb%2Fc%3Dd%26e"


def test_a_form_payload_keeps_every_field_the_client_did_not_have_to_supply() -> None:
    client = generate_python(
        capture(form_entry(f"csrf_token={ACCESS_TOKEN}&note=hello+world%21&page=1"))
    )
    [request] = send(client.code, {"TRACE2API_BODY_CSRF_TOKEN": "supplied"})
    assert request.content == b"csrf_token=supplied&note=hello+world%21&page=1"


def test_a_form_payload_without_credentials_is_sent_as_it_was_observed() -> None:
    client = generate_python(capture(form_entry("q=shoes&page=1")))
    assert "import urllib.parse" not in client.code
    [request] = send(client.code)
    assert request.content == b"q=shoes&page=1"


# Bodies the client cannot reproduce


def test_a_binary_body_is_reported_rather_than_guessed_at() -> None:
    client = generate_python(
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
    assert "content=" not in client.code
    assert client.calls[0].notes == [
        "a binary body of 3 bytes was observed here and is not reproduced"
    ]
    assert "# note: a binary body of 3 bytes" in client.code


def test_a_body_the_capture_only_sampled_is_flagged() -> None:
    client = generate_python(
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
    assert "content=" in client.code


def test_an_empty_body_adds_no_content_argument() -> None:
    client = generate_python(
        capture(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                method="POST",
                body=Body(mime_type="application/json", text=""),
            )
        )
    )
    assert "content=" not in client.code


# Quoting, which decides whether the module runs at all


@pytest.mark.parametrize(
    "text",
    [
        """{"note":"it's here"}""",
        '{"path":"C:\\\\logs\\\\app.log"}',
        '{"note":"line\\nbreak"}',
        '{"note":"quote \\" inside"}',
        '{"note":"emoji \U0001f600 and accents éà"}',
        "{}",
    ],
)
def test_a_body_reaches_the_server_as_it_was_observed(text: str) -> None:
    client = generate_python(
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
    assert request.content.decode() == text


def test_a_docstring_cannot_be_ended_early_by_what_a_capture_recorded() -> None:
    recorded = capture(
        entry("a", "https://shop.example.com/api/orders"),
        start_url='https://shop.example.com/"""',
    )
    client = generate_python(recorded)
    assert 'Recorded from https://shop.example.com/"""' in load_module(client.code, {})["__doc__"]


# The example capture


def test_the_example_capture_carries_no_observed_credential_into_the_client() -> None:
    client = generate_python(load_har(EXAMPLE_HAR))
    for observed in (ACCESS_TOKEN, SESSION_VALUE, "example-csrf-value"):
        assert observed not in client.code
    assert "<redacted:" not in client.code


def test_a_salt_makes_the_client_reproducible() -> None:
    recorded = load_har(EXAMPLE_HAR)
    first = generate_python(recorded, salt=b"fixed-salt")
    second = generate_python(recorded, salt=b"fixed-salt")
    assert first.code == second.code


def test_the_example_capture_produces_a_client_that_sends_the_observed_requests() -> None:
    client = generate_python(load_har(EXAMPLE_HAR))
    sent = send(client.code, {binding.variable: "supplied" for binding in client.secrets})
    assert [(request.method, str(request.url)) for request in sent] == [
        ("GET", "https://shop.example.com/orders"),
        ("GET", "https://shop.example.com/api/v1/orders?status=open&limit=20"),
        ("GET", "https://shop.example.com/api/v1/orders/4711"),
        ("POST", "https://shop.example.com/api/v1/orders/4711/confirm"),
    ]
    assert sent[1].headers["authorization"] == "Bearer supplied"


# Compiled clients, which read what the workflow depends on


def answering(entry_id: str, url: str, payload: str, **arguments: Any) -> Entry:
    """Build an exchange whose response hands out a JSON payload."""
    built = entry(entry_id, url, **arguments)
    return built.model_copy(
        update={
            "response": built.response.model_copy(
                update={"body": Body(mime_type="application/json", text=payload)}
            )
        }
    )


def test_the_docstring_reports_the_workflow_and_what_the_client_reads() -> None:
    client = compile_python(
        capture(
            answering("a", "https://shop.example.com/api/orders", '{"orders":[{"id":"4711998"}]}'),
            entry("b", "https://shop.example.com/api/orders/4711998"),
        )
    )
    assert "The workflow runs in 2 stages: 1 of 2 requests waits for an earlier response." in (
        client.code
    )
    assert "1 value read from a response as the client runs" in client.code
    assert "orders_id  1  response.body.orders[0].id  sent on by 2" in client.code


def test_a_capture_with_nothing_to_read_says_so() -> None:
    client = compile_python(
        capture(
            entry("a", "https://shop.example.com/api/orders"),
            entry("b", "https://shop.example.com/api/customers"),
        )
    )
    assert "No value a request sent came from an earlier response." in client.code
    assert client.dependencies.is_empty
    assert client.graph is not None


def test_an_identifier_is_read_from_the_response_rather_than_replayed() -> None:
    client = compile_python(
        capture(
            answering("a", "https://shop.example.com/api/orders", '{"orders":[{"id":"4711998"}]}'),
            entry("b", "https://shop.example.com/api/orders/4711998/items"),
        )
    )
    assert 'orders_id = response_1.json()["orders"][0]["id"]' in client.code
    sent = answer(client.code, {"/api/orders": {"orders": [{"id": "8899001"}]}})
    assert [str(request.url) for request in sent] == [
        "https://shop.example.com/api/orders",
        "https://shop.example.com/api/orders/8899001/items",
    ]


def test_a_value_read_into_a_query_string_is_encoded_by_httpx() -> None:
    client = compile_python(
        capture(
            answering("a", "https://shop.example.com/api/page", '{"cursor":"c-9981723"}'),
            entry("b", "https://shop.example.com/api/page?cursor=c-9981723&limit=20"),
        )
    )
    sent = answer(client.code, {"/api/page": {"cursor": "a b&c"}})
    assert str(sent[1].url) == "https://shop.example.com/api/page?cursor=a+b%26c&limit=20"


def test_a_value_read_into_a_header_keeps_the_text_around_it() -> None:
    client = compile_python(
        capture(
            answering("a", "https://shop.example.com/api/page", '{"trace":"tr-9981723"}'),
            entry(
                "b",
                "https://shop.example.com/api/next",
                headers=[("X-Trace", "span tr-9981723 end")],
            ),
        )
    )
    sent = answer(client.code, {"/api/page": {"trace": "tr-0000001"}})
    assert sent[1].headers["x-trace"] == "span tr-0000001 end"


def test_a_value_read_into_a_payload_leaves_the_other_fields_alone() -> None:
    client = compile_python(
        capture(
            answering("a", "https://shop.example.com/api/page", '{"ref":"CNF-998172"}'),
            entry(
                "b",
                "https://shop.example.com/api/confirm",
                method="POST",
                headers=[("Content-Type", "application/json")],
                body=Body(
                    mime_type="application/json",
                    text='{"method":"invoice","ref":"CNF-998172","note":"see CNF-998172"}',
                ),
            ),
        )
    )
    sent = answer(client.code, {"/api/page": {"ref": 'CNF-"01"'}})
    assert json.loads(sent[1].content) == {
        "method": "invoice",
        "ref": 'CNF-"01"',
        "note": 'see CNF-"01"',
    }


def test_a_payload_field_that_held_a_number_keeps_holding_one() -> None:
    client = compile_python(
        capture(
            answering("a", "https://shop.example.com/api/page", '{"id":4711998}'),
            entry(
                "b",
                "https://shop.example.com/api/confirm",
                method="POST",
                headers=[("Content-Type", "application/json")],
                body=Body(mime_type="application/json", text='{"order":4711998}'),
            ),
        )
    )
    sent = answer(client.code, {"/api/page": {"id": 8899001}})
    assert json.loads(sent[1].content) == {"order": 8899001}


def test_a_credential_carried_between_requests_stays_an_environment_variable() -> None:
    client = compile_python(
        capture(
            answering("a", "https://shop.example.com/api/login", f'{{"token":"{ACCESS_TOKEN}"}}'),
            entry(
                "b",
                "https://shop.example.com/api/orders",
                headers=[("Authorization", f"Bearer {ACCESS_TOKEN}")],
            ),
        )
    )
    assert ACCESS_TOKEN not in client.code
    assert "TRACE2API_AUTHORIZATION = os.environ" in client.code
    assert "1 value the workflow took from a response is replayed as observed:" in client.code
    assert "the value is a credential the client is given from the environment" in client.code
    sent = answer(client.code, {}, {"TRACE2API_AUTHORIZATION": "supplied"})
    assert sent[1].headers["authorization"] == "Bearer supplied"


def confirming(entry_id: str, payload: str) -> Entry:
    """Build an exchange posting ``payload`` as a form encoded body."""
    return entry(
        entry_id,
        "https://shop.example.com/api/confirm",
        method="POST",
        headers=[("Content-Type", FORM)],
        body=Body(mime_type=FORM, text=payload),
    )


def test_a_link_into_a_form_payload_is_read_back_and_encoded_where_it_was_sent() -> None:
    client = compile_python(
        capture(
            answering("a", "https://shop.example.com/api/page", '{"ref":"CNF-998172"}'),
            confirming("b", "ref=CNF-998172&note=two+items&qty=2"),
        )
    )
    assert "# note: ref is encoded into the form payload where the capture observed it" in (
        client.code
    )
    sent = answer(client.code, {"/api/page": {"ref": "CNF-8899001 02"}})
    # The field the client supplies is encoded around what the response handed it, and the
    # fields it was not asked to change keep the spelling the capture recorded.
    assert sent[1].content == b"ref=CNF-8899001+02&note=two+items&qty=2"


def test_a_link_into_a_repeated_form_field_rewrites_the_one_that_carried_it() -> None:
    client = compile_python(
        capture(
            answering("a", "https://shop.example.com/api/page", '{"tag":"CNF-998172"}'),
            confirming("b", "tag=new&tag=CNF-998172"),
        )
    )
    sent = answer(client.code, {"/api/page": {"tag": "sale"}})
    assert sent[1].content == b"tag=new&tag=sale"


def test_a_value_standing_inside_a_form_field_is_rewritten_where_it_stands() -> None:
    client = compile_python(
        capture(
            answering("a", "https://shop.example.com/api/page", '{"id":"88990012"}'),
            confirming("b", "ref=CNF-88990012-02"),
        )
    )
    sent = answer(client.code, {"/api/page": {"id": "47119983"}})
    assert sent[1].content == b"ref=CNF-47119983-02"


def test_a_credential_and_a_read_value_in_one_payload_are_both_supplied() -> None:
    client = compile_python(
        capture(
            answering("a", "https://shop.example.com/api/page", '{"ref":"CNF-998172"}'),
            confirming("b", f"ref=CNF-998172&csrf_token={ACCESS_TOKEN}"),
        )
    )
    assert ACCESS_TOKEN not in client.code
    sent = answer(
        client.code,
        {"/api/page": {"ref": "CNF-8899001"}},
        {"TRACE2API_BODY_CSRF_TOKEN": "supplied token"},
    )
    assert sent[1].content == b"ref=CNF-8899001&csrf_token=supplied+token"


# The example capture, compiled


def test_the_example_capture_compiles_into_a_client_that_follows_the_server() -> None:
    client = compile_python(load_har(EXAMPLE_HAR))
    sent = answer(
        client.code,
        {
            "/api/v1/orders": {"orders": [{"id": "8899001"}]},
            "/api/v1/orders/8899001": {"confirmation_ref": "CNF-8899001-02"},
        },
        {binding.variable: "supplied" for binding in client.secrets},
    )
    assert [str(request.url) for request in sent] == [
        "https://shop.example.com/orders",
        "https://shop.example.com/api/v1/orders?status=open&limit=20",
        "https://shop.example.com/api/v1/orders/8899001",
        "https://shop.example.com/api/v1/orders/8899001/confirm",
    ]
    assert json.loads(sent[3].content) == {
        "payment_method": "invoice",
        "confirmation_ref": "CNF-8899001-02",
    }


def test_the_compiled_example_carries_no_observed_credential() -> None:
    client = compile_python(load_har(EXAMPLE_HAR))
    for observed in (ACCESS_TOKEN, SESSION_VALUE, "example-csrf-value"):
        assert observed not in client.code
    assert "<redacted:" not in client.code


def test_a_salt_makes_the_compiled_client_reproducible() -> None:
    recorded = load_har(EXAMPLE_HAR)
    first = compile_python(recorded, salt=b"fixed-salt")
    second = compile_python(recorded, salt=b"fixed-salt")
    assert first.code == second.code


def test_a_compiled_client_with_nothing_to_send_makes_no_claim_about_a_workflow() -> None:
    client = compile_python(
        capture(
            entry("a", "https://cdn.example.com/app.css", resource_type=ResourceType.STYLESHEET)
        )
    )
    assert "Reproducing 0 of 1 captured request." in client.code
    assert "The workflow runs in" not in client.code
    assert send(client.code) == []
