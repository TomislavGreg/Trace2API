"""Tests for writing a capture out as a runnable cURL script."""

from __future__ import annotations

import base64
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from trace2api.analyze import Relevance
from trace2api.capture import load_har
from trace2api.generate import HeaderOmission, generate_curl
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


# What the script says


def test_the_preamble_names_the_recording_and_what_is_reproduced() -> None:
    script = generate_curl(capture(entry("a", "https://shop.example.com/api/orders")))
    assert script.code.startswith("#!/bin/sh\n")
    assert "recorded 2026-09-04T09:15:00+00:00 (source: har)" in script.code
    assert "# Reproducing 1 of 1 captured request." in script.code
    assert "set -eu" in script.code


def test_the_preamble_names_where_the_recording_started() -> None:
    recorded = capture(
        entry("a", "https://shop.example.com/api/orders"),
        start_url="https://shop.example.com/orders",
    )
    assert "# Recorded from https://shop.example.com/orders" in generate_curl(recorded).code


def test_a_capture_holding_no_credentials_says_so() -> None:
    script = generate_curl(capture(entry("a", "https://shop.example.com/api/orders")))
    assert script.secrets.is_empty
    assert "held no credentials" in script.code
    assert "Export them before running" not in script.code


def test_each_command_is_numbered_as_the_capture_numbers_it() -> None:
    script = generate_curl(
        capture(
            entry("a", "https://cdn.example.com/app.css", resource_type=ResourceType.STYLESHEET),
            entry("b", "https://shop.example.com/api/orders"),
        )
    )
    assert [command.position for command in script.commands] == [2]
    assert "# 2  GET https://shop.example.com/api/orders" in script.code


# Which requests are written


def test_noise_is_left_out_and_accounted_for() -> None:
    script = generate_curl(
        capture(
            entry("a", "https://shop.example.com/api/orders"),
            entry("b", "https://cdn.example.com/app.css", resource_type=ResourceType.STYLESHEET),
        )
    )
    assert len(script) == 1
    assert script.captured == 2
    assert script.skipped == 1
    assert "app.css" not in script.code


def test_noise_can_be_written_out_as_well() -> None:
    recorded = capture(
        entry("a", "https://shop.example.com/api/orders"),
        entry("b", "https://cdn.example.com/app.css", resource_type=ResourceType.STYLESHEET),
    )
    script = generate_curl(recorded, keep=tuple(Relevance))
    assert len(script) == 2
    assert "app.css" in script.code


def test_a_capture_with_nothing_worth_keeping_still_writes_a_script() -> None:
    script = generate_curl(
        capture(
            entry("a", "https://cdn.example.com/app.css", resource_type=ResourceType.STYLESHEET)
        )
    )
    assert len(script) == 0
    assert "# Reproducing 0 of 1 captured request." in script.code
    assert "curl" not in script.code


# The shape of a command


def test_a_plain_read_leaves_the_method_to_curl() -> None:
    script = generate_curl(capture(entry("a", "https://shop.example.com/api/orders")))
    assert "curl 'https://shop.example.com/api/orders'" in script.code
    assert "--request" not in script.code


def test_a_write_states_its_method() -> None:
    script = generate_curl(
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
    assert "--request POST" in script.code
    assert """--data-raw '{"note":"hi"}'""" in script.code


def test_a_read_carrying_a_body_states_its_method_so_curl_does_not_change_it() -> None:
    script = generate_curl(
        capture(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                headers=[("Content-Type", "application/json")],
                body=Body(mime_type="application/json", text='{"filter":"open"}'),
            )
        )
    )
    assert "--request GET" in script.code


def test_the_query_string_is_kept_because_the_request_needs_it() -> None:
    script = generate_curl(
        capture(entry("a", "https://shop.example.com/api/orders?status=open&limit=20"))
    )
    assert "curl 'https://shop.example.com/api/orders?status=open&limit=20'" in script.code


# Headers curl has to handle itself


@pytest.mark.parametrize(
    ("name", "value", "rule"),
    [
        ("Content-Length", "42", HeaderOmission.COMPUTED_BY_CURL),
        ("Host", "shop.example.com", HeaderOmission.COMPUTED_BY_CURL),
        ("Connection", "keep-alive", HeaderOmission.HOP_BY_HOP),
        ("Transfer-Encoding", "chunked", HeaderOmission.HOP_BY_HOP),
        (":authority", "shop.example.com", HeaderOmission.PSEUDO_HEADER),
        ("Accept-Encoding", "gzip, br", HeaderOmission.NEGOTIATED_BY_CURL),
    ],
)
def test_headers_curl_derives_are_left_out_with_a_stated_reason(
    name: str, value: str, rule: HeaderOmission
) -> None:
    script = generate_curl(
        capture(entry("a", "https://shop.example.com/api/orders", headers=[(name, value)]))
    )
    command = script.commands[0]
    assert [(item.name, item.rule) for item in command.omitted_headers] == [(name, rule)]
    assert command.omitted_headers[0].reason
    assert f"--header '{name}" not in script.code
    assert name in script.code  # accounted for in the preamble rather than dropped silently


def test_an_observed_encoding_is_asked_for_on_curl_terms() -> None:
    script = generate_curl(
        capture(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                headers=[("Accept-Encoding", "gzip, br")],
            )
        )
    )
    assert "--compressed" in script.code


def test_a_request_asking_for_no_encoding_is_left_alone() -> None:
    script = generate_curl(
        capture(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                headers=[("Accept-Encoding", "identity")],
            )
        )
    )
    assert "--compressed" not in script.code
    assert "--header 'Accept-Encoding: identity'" in script.code


def test_ordinary_headers_are_sent_as_they_were_observed() -> None:
    script = generate_curl(
        capture(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                headers=[("Accept", "application/json"), ("X-Request-Id", "r-1")],
            )
        )
    )
    assert "--header 'Accept: application/json'" in script.code
    assert "--header 'X-Request-Id: r-1'" in script.code


# Credentials


def test_a_credential_header_becomes_a_variable_and_keeps_its_scheme() -> None:
    script = generate_curl(
        capture(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                headers=[("Authorization", f"Bearer {ACCESS_TOKEN}")],
            )
        )
    )
    assert ACCESS_TOKEN not in script.code
    assert """--header 'Authorization: Bearer '"$TRACE2API_AUTHORIZATION\"""" in script.code
    assert "#   TRACE2API_AUTHORIZATION  request.headers.authorization" in script.code


def test_a_cookie_keeps_its_names_and_reads_each_value_from_the_environment() -> None:
    script = generate_curl(
        capture(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                headers=[("Cookie", f"session={SESSION_VALUE}; locale=en-GB")],
            )
        )
    )
    assert SESSION_VALUE not in script.code
    assert '"$TRACE2API_COOKIE_SESSION"' in script.code
    assert '"$TRACE2API_COOKIE_LOCALE"' in script.code
    assert "Cookie: session=" in script.code


def test_a_credential_in_the_query_string_becomes_a_variable() -> None:
    script = generate_curl(
        capture(entry("a", "https://shop.example.com/api/orders?api_key=live-key&status=open"))
    )
    assert "live-key" not in script.code
    assert "<redacted:" not in script.code
    assert '?api_key=\'"$TRACE2API_QUERY_API_KEY"' in script.code
    assert "status=open" in script.code


def test_a_credential_in_the_query_string_is_flagged_as_needing_encoding() -> None:
    script = generate_curl(
        capture(entry("a", "https://shop.example.com/api/orders?api_key=live-key"))
    )
    assert script.commands[0].notes == [
        "TRACE2API_QUERY_API_KEY goes into the query string, so its value has to be URL encoded"
    ]
    assert "# note: TRACE2API_QUERY_API_KEY goes into the query string" in script.code


def test_a_credential_in_a_body_becomes_a_variable() -> None:
    script = generate_curl(
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
    assert "live-pw" not in script.code
    assert '"$TRACE2API_PASSWORD"' in script.code


def test_one_token_used_twice_is_exported_once() -> None:
    header = ("Authorization", f"Bearer {ACCESS_TOKEN}")
    script = generate_curl(
        capture(
            entry("a", "https://shop.example.com/api/orders", headers=[header]),
            entry("b", "https://shop.example.com/api/orders/1", headers=[header]),
        )
    )
    assert len(script.secrets) == 1
    assert script.code.count("#   TRACE2API_AUTHORIZATION") == 1
    assert script.code.count('"$TRACE2API_AUTHORIZATION"') == 2


def test_the_example_capture_carries_no_observed_credential_into_the_script() -> None:
    script = generate_curl(load_har(EXAMPLE_HAR))
    for observed in (ACCESS_TOKEN, SESSION_VALUE, "example-csrf-value"):
        assert observed not in script.code
    assert "<redacted:" not in script.code


def test_a_salt_makes_the_script_reproducible() -> None:
    recorded = load_har(EXAMPLE_HAR)
    first = generate_curl(recorded, salt=b"fixed-salt")
    second = generate_curl(recorded, salt=b"fixed-salt")
    assert first.code == second.code


# Bodies the script cannot reproduce


def test_a_binary_body_is_reported_rather_than_guessed_at() -> None:
    script = generate_curl(
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
    assert "--data-raw" not in script.code
    assert script.commands[0].notes == [
        "a binary body of 3 bytes was observed here and is not reproduced"
    ]


def test_a_body_the_capture_only_sampled_is_flagged() -> None:
    script = generate_curl(
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
    assert "the capture recorded only part of this body" in script.commands[0].notes[0]
    assert "--data-raw" in script.code


def test_an_empty_body_adds_no_data_argument() -> None:
    script = generate_curl(
        capture(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                method="POST",
                body=Body(mime_type="application/json", text=""),
            )
        )
    )
    assert "--data-raw" not in script.code


# Quoting, which decides whether the script runs at all


def test_a_value_holding_a_quote_stays_one_argument() -> None:
    script = generate_curl(
        capture(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                method="POST",
                headers=[("Content-Type", "application/json")],
                body=Body(mime_type="application/json", text="""{"note":"it's here"}"""),
            )
        )
    )
    assert """--data-raw '{"note":"it'\\''s here"}'""" in script.code


needs_shell = pytest.mark.skipif(shutil.which("sh") is None, reason="no POSIX shell available")


def run_script(script: str, environment: dict[str, str]) -> list[list[str]]:
    """Run ``script`` with curl stubbed out, and return the arguments each command got."""
    stub = 'curl() {\n  for word in "$@"; do printf "%s\\n" "$word"; done\n  printf "==\\n"\n}\n'
    done = subprocess.run(
        ["sh"],
        input=stub + script,
        env={"PATH": "/usr/bin:/bin", **environment},
        capture_output=True,
        text=True,
        check=True,
    )
    commands = done.stdout.split("==\n")
    return [block.splitlines() for block in commands if block]


@needs_shell
def test_the_script_hands_curl_the_observed_request() -> None:
    script = generate_curl(
        capture(
            entry(
                "a",
                "https://shop.example.com/api/orders?api_key=live-key",
                method="POST",
                headers=[
                    ("Content-Type", "application/json"),
                    ("Authorization", f"Bearer {ACCESS_TOKEN}"),
                    ("Cookie", f"session={SESSION_VALUE}"),
                    ("Content-Length", "9999"),
                ],
                body=Body(mime_type="application/json", text="""{"note":"it's $safe"}"""),
            )
        )
    )
    [arguments] = run_script(
        script.code,
        {
            "TRACE2API_QUERY_API_KEY": "supplied-key",
            "TRACE2API_AUTHORIZATION": "supplied token",
            "TRACE2API_COOKIE_SESSION": "supplied-session",
        },
    )
    assert arguments == [
        "https://shop.example.com/api/orders?api_key=supplied-key",
        "--request",
        "POST",
        "--header",
        "Content-Type: application/json",
        "--header",
        "Authorization: Bearer supplied token",
        "--header",
        "Cookie: session=supplied-session",
        "--data-raw",
        """{"note":"it's $safe"}""",
    ]


@needs_shell
def test_the_script_stops_rather_than_sending_a_missing_credential() -> None:
    script = generate_curl(
        capture(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                headers=[("Authorization", f"Bearer {ACCESS_TOKEN}")],
            )
        )
    )
    with pytest.raises(subprocess.CalledProcessError) as failure:
        run_script(script.code, {})
    assert "TRACE2API_AUTHORIZATION" in failure.value.stderr


@needs_shell
def test_the_example_capture_produces_a_script_a_shell_accepts() -> None:
    script = generate_curl(load_har(EXAMPLE_HAR))
    commands = run_script(
        script.code,
        {binding.variable: "supplied" for binding in script.secrets},
    )
    assert len(commands) == len(script)
