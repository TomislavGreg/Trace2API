"""Tests for the header rules every generated client shares."""

from __future__ import annotations

import pytest

from trace2api.generate.headers import HeaderRule, omission_rule, partition_headers
from trace2api.models import Header, Headers

REASONS = {rule: f"reason for {rule.value}" for rule in HeaderRule}


@pytest.mark.parametrize(
    ("name", "value", "rule"),
    [
        ("Content-Length", "42", HeaderRule.COMPUTED_BY_CLIENT),
        ("host", "shop.example.com", HeaderRule.COMPUTED_BY_CLIENT),
        ("Connection", "keep-alive", HeaderRule.HOP_BY_HOP),
        ("Upgrade", "websocket", HeaderRule.HOP_BY_HOP),
        (":method", "GET", HeaderRule.PSEUDO_HEADER),
        ("Accept-Encoding", "gzip, br", HeaderRule.NEGOTIATED_BY_CLIENT),
    ],
)
def test_a_header_the_client_handles_itself_names_its_rule(
    name: str, value: str, rule: HeaderRule
) -> None:
    assert omission_rule(Header(name=name, value=value)) is rule


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("Accept", "application/json"),
        ("Accept-Encoding", "identity"),
        ("X-Request-Id", "r-1"),
        ("Content-Type", "application/json"),
    ],
)
def test_a_header_the_request_chose_is_sent(name: str, value: str) -> None:
    assert omission_rule(Header(name=name, value=value)) is None


def test_partitioning_keeps_the_observed_order_on_both_sides() -> None:
    headers = Headers.from_pairs(
        [
            ("Accept", "application/json"),
            ("Content-Length", "42"),
            ("X-Request-Id", "r-1"),
            ("Connection", "keep-alive"),
        ]
    )
    sent, omitted = partition_headers(headers, REASONS)
    assert [header.name for header in sent] == ["Accept", "X-Request-Id"]
    assert [item.name for item in omitted] == ["Content-Length", "Connection"]


def test_an_omission_carries_the_wording_of_the_target_that_asked() -> None:
    headers = Headers.from_pairs([("Content-Length", "42")])
    reasons = {**REASONS, HeaderRule.COMPUTED_BY_CLIENT: "the client sets it itself"}
    _, omitted = partition_headers(headers, reasons)
    assert [(item.name, item.reason) for item in omitted] == [
        ("Content-Length", "the client sets it itself")
    ]
