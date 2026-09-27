"""Tests for writing a capture out as a Pytest regression test."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any
from unittest import mock

import pytest

import trace2api.analyze as analyze_module
import trace2api.capture as capture_module
from trace2api.analyze import CaptureVerification, VerificationOutcome, VerifiedRequest
from trace2api.generate import generate_pytest_test
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

STARTED_AT = datetime(2026, 9, 4, 9, 15, tzinfo=UTC)
ACCESS_TOKEN = "example-access-token-not-a-real-credential"


def entry(entry_id: str, url: str, *, headers: list[tuple[str, str]] | None = None) -> Entry:
    """Build one observed exchange the relevance rules keep."""
    return Entry(
        id=entry_id,
        started_at=STARTED_AT,
        request=Request(method="GET", url=url, headers=Headers.from_pairs(headers or [])),
        response=Response(
            status=200,
            headers=Headers.from_pairs([("Content-Type", "application/json")]),
            body=Body(mime_type="application/json", text="{}"),
        ),
    )


def capture(*entries: Entry) -> Capture:
    """Build a capture holding ``entries``."""
    return Capture(
        metadata=CaptureMetadata(source=CaptureSource.HAR, created_at=STARTED_AT),
        entries=list(entries),
    )


def load_module(code: str) -> dict[str, Any]:
    """Compile and exec generated code, returning its namespace without calling anything."""
    namespace: dict[str, Any] = {"__name__": "generated_regression_test"}
    exec(compile(code, "generated_regression_test.py", "exec"), namespace)
    return namespace


# Content


def test_reports_the_source_and_the_request_counts() -> None:
    module = generate_pytest_test(
        capture(entry("1", "https://shop.example.com/api/v1/orders")), "orders.har"
    )
    assert module.code.startswith('"""Regression test for the workflow recorded ')
    assert "trace2api test orders.har" in module.code
    assert "replays 1 kept request of 1 captured request" in module.code
    assert 'CAPTURE = Path("orders.har")' in module.code
    assert module.captured == 1
    assert module.kept == 1


def test_noise_is_left_out_of_the_count_unless_it_is_asked_for() -> None:
    entries = capture(
        entry("1", "https://shop.example.com/api/v1/orders"),
        entry("2", "https://cdn.example.com/static/app.css"),
    )
    kept_only = generate_pytest_test(entries, "capture.json")
    with_noise = generate_pytest_test(entries, "capture.json", keep=analyze_module.Relevance)
    assert kept_only.kept == 1 and kept_only.captured == 2
    assert with_noise.kept == 2
    assert "KEEP = (Relevance.APPLICATION, Relevance.UNKNOWN)" in kept_only.code
    assert "KEEP = (Relevance.APPLICATION, Relevance.NOISE, Relevance.UNKNOWN)" in with_noise.code


def test_credentials_become_variable_names_rather_than_values() -> None:
    module = generate_pytest_test(
        capture(
            entry(
                "1",
                "https://shop.example.com/api/v1/orders",
                headers=[("Authorization", f"Bearer {ACCESS_TOKEN}")],
            )
        ),
        "orders.har",
    )
    assert ACCESS_TOKEN not in module.code
    assert "<redacted:" not in module.code
    assert '"TRACE2API_AUTHORIZATION",' in module.code
    assert "TRACE2API_AUTHORIZATION  request.headers.authorization" in module.code


def test_a_capture_with_no_credentials_says_so() -> None:
    module = generate_pytest_test(
        capture(entry("1", "https://shop.example.com/api/v1/orders")), "orders.har"
    )
    assert "The capture held no credentials, so nothing has to be exported." in module.code
    assert "REQUIRED_SECRETS: tuple[str, ...] = ()" in module.code


def test_the_generated_code_is_valid_python() -> None:
    module = generate_pytest_test(
        capture(
            entry(
                "1",
                "https://shop.example.com/api/v1/orders",
                headers=[("Authorization", f"Bearer {ACCESS_TOKEN}")],
            )
        ),
        "orders.har",
    )
    compile(module.code, "generated_regression_test.py", "exec")


# Behaviour


def test_the_test_skips_when_a_credential_is_missing() -> None:
    module = generate_pytest_test(
        capture(
            entry(
                "1",
                "https://shop.example.com/api/v1/orders",
                headers=[("Authorization", f"Bearer {ACCESS_TOKEN}")],
            )
        ),
        "orders.har",
    )
    namespace = load_module(module.code)
    with (
        mock.patch.dict(os.environ, {}, clear=True),
        pytest.raises(pytest.skip.Exception, match="TRACE2API_AUTHORIZATION"),
    ):
        namespace["test_workflow_still_verifies"]()


def loaded_module(
    code: str, *, read: Any = None, verify: Any = None, monkeypatch: pytest.MonkeyPatch
) -> dict[str, Any]:
    """Load generated code after patching what it imports, not before.

    The generated module does ``from trace2api.capture import read_capture`` and
    ``from trace2api.analyze import ... verify_capture``, which binds a reference to
    whichever function is installed at that moment. Patching after loading would have no
    effect, so this patches first and loads second.
    """
    if read is not None:
        monkeypatch.setattr(capture_module, "read_capture", read)
    if verify is not None:
        monkeypatch.setattr(analyze_module, "verify_capture", verify)
    return load_module(code)


def test_it_skips_rather_than_fails_on_an_empty_capture(monkeypatch: pytest.MonkeyPatch) -> None:
    module = generate_pytest_test(
        capture(entry("1", "https://cdn.example.com/static/app.css")), "orders.har"
    )
    namespace = loaded_module(module.code, read=lambda path: capture(), monkeypatch=monkeypatch)
    with pytest.raises(pytest.skip.Exception, match="no kept request to replay"):
        namespace["test_workflow_still_verifies"]()


def test_it_passes_when_the_replay_verifies(monkeypatch: pytest.MonkeyPatch) -> None:
    module = generate_pytest_test(
        capture(entry("1", "https://shop.example.com/api/v1/orders")), "orders.har"
    )
    matched = CaptureVerification(
        source=CaptureSource.HAR,
        created_at=STARTED_AT,
        total_requests=1,
        requests=[
            VerifiedRequest(
                position=1,
                method="GET",
                host="shop.example.com",
                path="/api/v1/orders",
                outcome=VerificationOutcome.MATCHED,
            )
        ],
    )
    namespace = loaded_module(
        module.code,
        read=lambda path: capture(),
        verify=lambda recorded, secrets, **kwargs: matched,
        monkeypatch=monkeypatch,
    )
    namespace["test_workflow_still_verifies"]()  # does not raise


def test_it_fails_with_the_mismatch_when_the_replay_does_not_verify(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = generate_pytest_test(
        capture(entry("1", "https://shop.example.com/api/v1/orders")), "orders.har"
    )
    mismatched = CaptureVerification(
        source=CaptureSource.HAR,
        created_at=STARTED_AT,
        total_requests=1,
        requests=[
            VerifiedRequest(
                position=1,
                method="GET",
                host="shop.example.com",
                path="/api/v1/orders",
                outcome=VerificationOutcome.MISMATCHED,
            )
        ],
    )
    namespace = loaded_module(
        module.code,
        read=lambda path: capture(),
        verify=lambda recorded, secrets, **kwargs: mismatched,
        monkeypatch=monkeypatch,
    )
    with pytest.raises(AssertionError, match="mismatched"):
        namespace["test_workflow_still_verifies"]()
