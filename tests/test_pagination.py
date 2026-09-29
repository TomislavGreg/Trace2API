"""Tests for detecting pagination across two recordings of a workflow."""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from trace2api.analyze import (
    DEFAULT_KEPT,
    PaginationDetection,
    PaginationRule,
    PaginationStyle,
    Relevance,
    detect_pagination,
    render_pagination,
)
from trace2api.capture import load_har
from trace2api.models import (
    Capture,
    CaptureMetadata,
    CaptureSource,
    Entry,
    Headers,
    Request,
    Response,
)

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
FIRST_RUN = EXAMPLES / "storefront-orders.har"
SECOND_RUN = EXAMPLES / "storefront-orders-second-run.har"

STARTED_AT = datetime(2026, 9, 4, 9, 15, tzinfo=UTC)
SALT = b"test-salt"


def entry(entry_id: str, url: str, *, method: str = "GET") -> Entry:
    """Build one observed exchange, kept by the relevance rules unless said otherwise."""
    return Entry(
        id=entry_id,
        started_at=STARTED_AT,
        request=Request(method=method, url=url, headers=Headers()),
        response=Response(status=200, headers=Headers.from_pairs([("Content-Type", "text/plain")])),
    )


def capture(*entries: Entry) -> Capture:
    """Build a capture holding ``entries``."""
    return Capture(
        metadata=CaptureMetadata(source=CaptureSource.HAR, created_at=STARTED_AT),
        entries=list(entries),
    )


def detection_of(
    left: tuple[Entry, ...],
    right: tuple[Entry, ...],
    *,
    keep: Iterable[Relevance] = DEFAULT_KEPT,
) -> PaginationDetection:
    """Detect pagination across two captures built from entries, with a fixed salt."""
    return detect_pagination(capture(*left), capture(*right), keep=keep, salt=SALT)


def values_of(left: Entry, right: Entry) -> dict[str, PaginationStyle]:
    """Return the pagination style reached for each recognized value of one request."""
    detected = detection_of((left,), (right,))
    return {value.location: value.style for value in detected.requests[0].values}


class TestPageNumber:
    def test_a_page_query_parameter_is_page_number(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders")
        right = entry("b", "https://shop.example.com/api/orders?page=2")
        styles = values_of(left, right)
        assert styles["request.query[page]"] is PaginationStyle.PAGE_NUMBER

    def test_a_differently_spelled_page_name_is_recognized(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders?pageNumber=1")
        right = entry("b", "https://shop.example.com/api/orders?pageNumber=2")
        styles = values_of(left, right)
        assert styles["request.query[pageNumber]"] is PaginationStyle.PAGE_NUMBER

    def test_a_page_value_that_is_not_a_number_is_not_recognized(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders?page=one")
        right = entry("b", "https://shop.example.com/api/orders?page=two")
        assert values_of(left, right) == {}

    def test_the_rule_is_reported(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders?page=1")
        right = entry("b", "https://shop.example.com/api/orders?page=2")
        value = detection_of((left,), (right,)).requests[0].values[0]
        assert value.rule is PaginationRule.PAGE_NUMBER_NAME
        assert value.name == "page"
        assert "whole number" in value.reason


class TestOffset:
    def test_an_offset_query_parameter_is_offset(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders?offset=0")
        right = entry("b", "https://shop.example.com/api/orders?offset=20")
        assert values_of(left, right)["request.query[offset]"] is PaginationStyle.OFFSET

    def test_skip_is_recognized_as_offset(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders?skip=0")
        right = entry("b", "https://shop.example.com/api/orders?skip=20")
        assert values_of(left, right)["request.query[skip]"] is PaginationStyle.OFFSET

    def test_an_offset_value_that_is_not_a_number_is_not_recognized(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders?offset=none")
        right = entry("b", "https://shop.example.com/api/orders?offset=some")
        assert values_of(left, right) == {}


class TestCursor:
    def test_a_cursor_query_parameter_is_a_cursor(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders?cursor=eyJpZCI6MX0")
        right = entry("b", "https://shop.example.com/api/orders?cursor=eyJpZCI6Mn0")
        assert values_of(left, right)["request.query[cursor]"] is PaginationStyle.CURSOR

    def test_relay_style_after_is_a_cursor(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders?after=cursor-1")
        right = entry("b", "https://shop.example.com/api/orders?after=cursor-2")
        assert values_of(left, right)["request.query[after]"] is PaginationStyle.CURSOR

    def test_a_page_token_is_a_cursor(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders?pageToken=abc")
        right = entry("b", "https://shop.example.com/api/orders?pageToken=def")
        assert values_of(left, right)["request.query[pageToken]"] is PaginationStyle.CURSOR

    def test_a_cursor_need_not_be_a_number(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders?cursor=1")
        right = entry("b", "https://shop.example.com/api/orders?cursor=2")
        assert values_of(left, right)["request.query[cursor]"] is PaginationStyle.CURSOR


class TestNoPagination:
    def test_a_value_that_held_still_is_not_pagination(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders?page=1")
        right = entry("b", "https://shop.example.com/api/orders?page=1")
        assert values_of(left, right) == {}

    def test_an_ordinary_input_is_not_pagination(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders?status=open")
        right = entry("b", "https://shop.example.com/api/orders?status=shipped")
        assert values_of(left, right) == {}

    def test_an_ambiguous_name_is_not_pagination(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders?start=2026-09-04")
        right = entry("b", "https://shop.example.com/api/orders?start=2026-09-11")
        assert values_of(left, right) == {}

    def test_a_request_with_no_counterpart_is_not_read(self) -> None:
        shared = entry("a", "https://shop.example.com/api/orders?page=1")
        alone = entry("b", "https://shop.example.com/api/customers?page=1")
        detected = detection_of((shared, alone), (shared,))
        assert len(detected.requests) == 1


class TestWholeCaptures:
    def test_only_kept_requests_are_read_by_default(self) -> None:
        from trace2api.models import ResourceType

        application = entry("a", "https://shop.example.com/api/orders?page=1")
        noise = Entry(
            id="n",
            started_at=STARTED_AT,
            request=Request(method="GET", url="https://cdn.example.com/logo.png?page=1"),
            response=Response(
                status=200, headers=Headers.from_pairs([("Content-Type", "image/png")])
            ),
            resource_type=ResourceType.IMAGE,
        )
        detected = detection_of((application, noise), (application, noise))
        assert len(detected.requests) == 1
        with_noise = detection_of((application, noise), (application, noise), keep=tuple(Relevance))
        assert len(with_noise.requests) == 2

    def test_the_redaction_count_is_reported(self) -> None:
        left = Entry(
            id="a",
            started_at=STARTED_AT,
            request=Request(
                method="GET",
                url="https://shop.example.com/api/orders?page=1",
                headers=Headers.from_pairs([("Authorization", "Bearer s3cret-token-value")]),
            ),
            response=Response(
                status=200, headers=Headers.from_pairs([("Content-Type", "text/plain")])
            ),
        )
        right = Entry(
            id="b",
            started_at=STARTED_AT,
            request=Request(
                method="GET",
                url="https://shop.example.com/api/orders?page=2",
                headers=Headers.from_pairs([("Authorization", "Bearer s3cret-token-value")]),
            ),
            response=Response(
                status=200, headers=Headers.from_pairs([("Content-Type", "text/plain")])
            ),
        )
        assert detection_of((left,), (right,)).redacted_values == 2


class TestRenderPagination:
    def test_a_recognized_value_is_shown(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders")
        right = entry("b", "https://shop.example.com/api/orders?page=2")
        rendered = render_pagination(detection_of((left,), (right,)))
        assert 'request.query[page]  page-number  "2" (second recording only)' in rendered
        assert "Recognized 1 pagination value in 1 request: 1 page-number value." in rendered

    def test_a_request_with_nothing_recognized_is_left_out(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders?status=open")
        right = entry("b", "https://shop.example.com/api/orders?status=shipped")
        rendered = render_pagination(detection_of((left,), (right,)))
        assert "shop.example.com/api/orders" not in rendered
        assert "No pagination was recognized between the two recordings." in rendered

    def test_explain_adds_the_rule_behind_a_value(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders?offset=0")
        right = entry("b", "https://shop.example.com/api/orders?offset=20")
        rendered = render_pagination(detection_of((left,), (right,)), explain=True)
        assert "named after a count of results already seen" in rendered

    def test_no_credential_appears_in_the_rendered_output(self) -> None:
        left = Entry(
            id="a",
            started_at=STARTED_AT,
            request=Request(
                method="GET",
                url="https://shop.example.com/api/orders?page=1",
                headers=Headers.from_pairs([("Authorization", "Bearer s3cret-token-value")]),
            ),
            response=Response(
                status=200, headers=Headers.from_pairs([("Content-Type", "text/plain")])
            ),
        )
        right = Entry(
            id="b",
            started_at=STARTED_AT,
            request=Request(
                method="GET",
                url="https://shop.example.com/api/orders?page=2",
                headers=Headers.from_pairs([("Authorization", "Bearer s3cret-token-value")]),
            ),
            response=Response(
                status=200, headers=Headers.from_pairs([("Content-Type", "text/plain")])
            ),
        )
        rendered = render_pagination(detection_of((left,), (right,)))
        assert "s3cret-token-value" not in rendered


class TestAsJson:
    def test_the_document_reads_back_as_a_detection(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders")
        right = entry("b", "https://shop.example.com/api/orders?page=2")
        detected = detection_of((left,), (right,))
        assert PaginationDetection.model_validate_json(detected.as_json()) == detected

    def test_the_document_holds_the_style_and_rule(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders")
        right = entry("b", "https://shop.example.com/api/orders?page=2")
        payload = json.loads(detection_of((left,), (right,)).as_json())
        value = payload["requests"][0]["values"][0]
        assert value["style"] == "page-number"
        assert value["rule"] == "page-number-name"
        assert value["name"] == "page"


class TestShippedExamples:
    def test_the_two_archives_recognize_the_added_page(self) -> None:
        detected = detect_pagination(load_har(FIRST_RUN), load_har(SECOND_RUN), salt=SALT)
        paginated = detected.paginated
        assert len(paginated) == 1
        value = paginated[0].values[0]
        assert value.style is PaginationStyle.PAGE_NUMBER
        assert value.location == "request.query[page]"
        assert (value.left, value.right) == (None, "2")
