"""Tests for binding removed credentials to environment variables."""

from __future__ import annotations

import pytest

from trace2api.generate import (
    ENVIRONMENT_PREFIX,
    SecretBindings,
    bind_secrets,
    environment_variable,
)
from trace2api.sanitize import Redaction, RedactionReport, RedactionRule


def redaction(location: str, fingerprint: str = "abcd1234") -> Redaction:
    """Build one recorded removal."""
    return Redaction(
        entry_id="entry-1",
        location=location,
        rule=RedactionRule.SENSITIVE_HEADER,
        fingerprint=fingerprint,
    )


@pytest.mark.parametrize(
    ("location", "expected"),
    [
        ("request.headers.authorization", "TRACE2API_AUTHORIZATION"),
        ("request.headers.cookie[session]", "TRACE2API_COOKIE_SESSION"),
        ("request.headers.x-csrf-token", "TRACE2API_X_CSRF_TOKEN"),
        ("request.url.query[api_key]", "TRACE2API_QUERY_API_KEY"),
        ("request.url.userinfo", "TRACE2API_USERINFO"),
        ("request.body.account.password", "TRACE2API_PASSWORD"),
        ("request.body.tokens[0]", "TRACE2API_TOKENS_0"),
    ],
)
def test_the_variable_is_named_after_where_the_value_came_from(
    location: str, expected: str
) -> None:
    assert environment_variable(location) == expected


def test_a_location_with_nothing_nameable_still_yields_a_variable() -> None:
    assert environment_variable("request.headers.--") == f"{ENVIRONMENT_PREFIX}SECRET"


def test_every_removed_request_value_is_bound() -> None:
    report = RedactionReport(
        redactions=[
            redaction("request.headers.authorization", "aaaaaaaa"),
            redaction("request.headers.cookie[session]", "bbbbbbbb"),
        ]
    )
    bindings = bind_secrets(report)
    assert [binding.variable for binding in bindings] == [
        "TRACE2API_AUTHORIZATION",
        "TRACE2API_COOKIE_SESSION",
    ]
    assert [binding.location for binding in bindings] == [
        "request.headers.authorization",
        "request.headers.cookie[session]",
    ]


def test_one_value_reused_across_requests_shares_one_variable() -> None:
    report = RedactionReport(
        redactions=[
            redaction("request.headers.authorization", "aaaaaaaa"),
            Redaction(
                entry_id="entry-2",
                location="request.headers.authorization",
                rule=RedactionRule.CREDENTIAL_SCHEME,
                fingerprint="aaaaaaaa",
            ),
        ]
    )
    bindings = bind_secrets(report)
    assert len(bindings) == 1
    assert bindings.variable_for("aaaaaaaa") == "TRACE2API_AUTHORIZATION"


def test_two_different_values_wanting_one_name_are_kept_apart() -> None:
    report = RedactionReport(
        redactions=[
            redaction("request.headers.authorization", "aaaaaaaa"),
            redaction("request.body.authorization", "bbbbbbbb"),
        ]
    )
    bindings = bind_secrets(report)
    assert [binding.variable for binding in bindings] == [
        "TRACE2API_AUTHORIZATION",
        "TRACE2API_AUTHORIZATION_2",
    ]


def test_values_a_server_sent_back_are_not_bound() -> None:
    report = RedactionReport(
        redactions=[
            Redaction(
                entry_id="entry-1",
                location="response.headers.set-cookie[session]",
                rule=RedactionRule.COOKIE_VALUE,
                fingerprint="aaaaaaaa",
            )
        ]
    )
    assert bind_secrets(report).is_empty


def test_an_unbound_fingerprint_still_names_a_variable() -> None:
    variable = SecretBindings().variable_for("abcd1234")
    assert variable == f"{ENVIRONMENT_PREFIX}SECRET_ABCD1234"
