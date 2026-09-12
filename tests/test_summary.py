"""Tests for the counted account of a capture that ``trace2api summary`` renders."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from trace2api.analyze import (
    UNDECLARED_CONTENT_TYPE,
    CaptureSummary,
    FilterRule,
    Relevance,
    render_summary,
    summarize_capture,
)
from trace2api.capture import load_har
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
"""The synthetic archive shipped with the project, which the README quick start uses."""

STARTED_AT = datetime(2026, 9, 4, 9, 15, tzinfo=UTC)


def entry(
    entry_id: str,
    url: str,
    *,
    method: str = "GET",
    status: int | None = 200,
    content_type: str | None = "application/json",
    declare_in_header: bool = True,
    resource_type: ResourceType = ResourceType.XHR,
    headers: Headers | None = None,
    failure: str | None = None,
) -> Entry:
    """Build one observed exchange."""
    response = None
    if status is not None:
        declared = [("Content-Type", content_type)] if content_type and declare_in_header else []
        response = Response(
            status=status,
            headers=Headers.from_pairs(declared),
            body=Body(mime_type=content_type, text="{}") if content_type else None,
        )
    return Entry(
        id=entry_id,
        started_at=STARTED_AT,
        request=Request(method=method, url=url, headers=headers or Headers()),
        response=response,
        failure=failure,
        resource_type=resource_type,
    )


def capture(*entries: Entry, start_url: str | None = None) -> Capture:
    """Build a capture holding ``entries``."""
    return Capture(
        metadata=CaptureMetadata(
            source=CaptureSource.HAR, created_at=STARTED_AT, start_url=start_url
        ),
        entries=list(entries),
    )


def summary_of(*entries: Entry, start_url: str | None = None) -> CaptureSummary:
    """Summarize a capture built from ``entries``, with a fixed redaction salt."""
    return summarize_capture(capture(*entries, start_url=start_url), salt=b"test-salt")


def asset(entry_id: str, url: str, resource_type: ResourceType) -> Entry:
    """Build one page asset, which the rules filter as noise."""
    return entry(entry_id, url, content_type="text/css", resource_type=resource_type)


class TestSummarizeCapture:
    def test_counts_the_whole_capture(self) -> None:
        summary = summary_of(
            entry("a", "https://shop.example.com/api/v1/orders"),
            entry("b", "https://shop.example.com/orders", resource_type=ResourceType.DOCUMENT),
            asset("c", "https://cdn.example.com/static/app.css", ResourceType.STYLESHEET),
        )
        assert summary.total_requests == 3
        assert summary.counts_by_relevance == {
            Relevance.APPLICATION: 1,
            Relevance.NOISE: 1,
            Relevance.UNKNOWN: 1,
        }

    def test_kept_and_filtered_follow_the_default_verdicts(self) -> None:
        summary = summary_of(
            entry("a", "https://shop.example.com/api/v1/orders"),
            entry("b", "https://shop.example.com/orders", resource_type=ResourceType.DOCUMENT),
            asset("c", "https://cdn.example.com/static/app.css", ResourceType.STYLESHEET),
        )
        assert summary.kept == 2
        assert summary.filtered == 1

    def test_carries_provenance(self) -> None:
        summary = summary_of(
            entry("a", "https://shop.example.com/api/v1/orders"),
            asset("b", "https://cdn.example.com/static/app.css", ResourceType.STYLESHEET),
            start_url="https://shop.example.com/orders",
        )
        assert summary.source is CaptureSource.HAR
        assert summary.created_at == STARTED_AT
        assert summary.start_url == "https://shop.example.com/orders"
        assert summary.hosts == ["cdn.example.com", "shop.example.com"]

    def test_names_the_rule_behind_each_filtered_request(self) -> None:
        summary = summary_of(
            asset("a", "https://cdn.example.com/static/app.css", ResourceType.STYLESHEET),
            asset("b", "https://cdn.example.com/img/logo.png", ResourceType.IMAGE),
            entry("c", "https://www.google-analytics.com/collect", method="POST"),
        )
        assert summary.noise_by_rule == {
            FilterRule.ASSET_RESOURCE_TYPE: 2,
            FilterRule.ANALYTICS_HOST: 1,
        }

    def test_the_most_common_noise_rule_comes_first(self) -> None:
        summary = summary_of(
            entry("a", "https://www.google-analytics.com/collect", method="POST"),
            asset("b", "https://cdn.example.com/static/app.css", ResourceType.STYLESHEET),
            asset("c", "https://cdn.example.com/img/logo.png", ResourceType.IMAGE),
            asset("d", "https://cdn.example.com/img/hero.png", ResourceType.IMAGE),
        )
        assert list(summary.noise_by_rule) == [
            FilterRule.ASSET_RESOURCE_TYPE,
            FilterRule.ANALYTICS_HOST,
        ]

    def test_counts_what_the_kept_requests_answered_with(self) -> None:
        summary = summary_of(
            entry("a", "https://shop.example.com/api/v1/orders"),
            entry("b", "https://shop.example.com/api/v1/orders/4711"),
            entry(
                "c",
                "https://shop.example.com/orders",
                content_type="text/html",
                resource_type=ResourceType.DOCUMENT,
            ),
        )
        assert [(item.media_type, item.count) for item in summary.kept_content_types] == [
            ("application/json", 2),
            ("text/html", 1),
        ]

    def test_content_types_of_equal_count_are_ordered_by_name(self) -> None:
        summary = summary_of(
            entry("a", "https://shop.example.com/api/v1/report", content_type="text/csv"),
            entry("b", "https://shop.example.com/api/v1/orders"),
        )
        assert [item.media_type for item in summary.kept_content_types] == [
            "application/json",
            "text/csv",
        ]

    def test_a_content_type_is_counted_without_its_parameters(self) -> None:
        summary = summary_of(
            entry("a", "https://shop.example.com/api/v1/orders", content_type="APPLICATION/JSON"),
            entry(
                "b",
                "https://shop.example.com/api/v1/orders/4711",
                content_type="application/json; charset=utf-8",
            ),
        )
        assert [(item.media_type, item.count) for item in summary.kept_content_types] == [
            ("application/json", 2)
        ]

    def test_a_content_type_the_payload_declares_still_counts(self) -> None:
        summary = summary_of(
            entry("a", "https://shop.example.com/api/v1/orders", declare_in_header=False)
        )
        assert [item.media_type for item in summary.kept_content_types] == ["application/json"]

    def test_a_response_that_declared_no_content_type_is_counted_as_such(self) -> None:
        summary = summary_of(
            entry("a", "https://shop.example.com/api/v1/orders", content_type=None)
        )
        assert [(item.media_type, item.label) for item in summary.kept_content_types] == [
            (None, UNDECLARED_CONTENT_TYPE)
        ]

    def test_an_undeclared_content_type_is_listed_after_the_named_ones(self) -> None:
        summary = summary_of(
            entry("a", "https://shop.example.com/api/v1/orders", content_type=None),
            entry("b", "https://shop.example.com/api/v1/orders/4711"),
        )
        assert [item.media_type for item in summary.kept_content_types] == [
            "application/json",
            None,
        ]

    def test_filtered_requests_are_left_out_of_the_content_types(self) -> None:
        summary = summary_of(
            entry("a", "https://shop.example.com/api/v1/orders"),
            asset("b", "https://cdn.example.com/static/app.css", ResourceType.STYLESHEET),
        )
        assert [item.media_type for item in summary.kept_content_types] == ["application/json"]

    def test_counts_the_kept_requests_that_never_answered(self) -> None:
        summary = summary_of(
            entry("a", "https://shop.example.com/api/v1/orders"),
            entry("b", "https://shop.example.com/api/v1/stream", status=None),
            entry(
                "c",
                "https://shop.example.com/api/v1/orders/4711",
                status=None,
                failure="net::ERR_CONNECTION_RESET",
            ),
        )
        assert summary.kept_without_response == 2
        assert [(item.media_type, item.count) for item in summary.kept_content_types] == [
            ("application/json", 1)
        ]

    def test_a_filtered_request_without_a_response_is_not_counted_as_kept(self) -> None:
        summary = summary_of(
            entry(
                "a",
                "https://www.google-analytics.com/collect",
                method="POST",
                status=None,
                failure="net::ERR_BLOCKED_BY_CLIENT",
            )
        )
        assert summary.kept_without_response == 0

    def test_redacts_before_counting(self) -> None:
        summary = summary_of(
            entry(
                "a",
                "https://shop.example.com/api/v1/orders?access_token=super-secret",
                headers=Headers.from_pairs([("Authorization", "Bearer super-secret")]),
            )
        )
        assert summary.redacted_values == 2
        assert "super-secret" not in summary.as_json()

    def test_an_empty_capture_counts_nothing(self) -> None:
        summary = summary_of()
        assert summary.total_requests == 0
        assert summary.kept == 0
        assert summary.filtered == 0
        assert summary.kept_content_types == []

    def test_as_json_reports_the_counts_under_readable_names(self) -> None:
        summary = summary_of(
            entry("a", "https://shop.example.com/api/v1/orders"),
            asset("b", "https://cdn.example.com/static/app.css", ResourceType.STYLESHEET),
        )
        payload = json.loads(summary.as_json())
        assert payload["total_requests"] == 2
        assert payload["counts_by_relevance"] == {"application": 1, "noise": 1, "unknown": 0}
        assert payload["noise_by_rule"] == {"asset-resource-type": 1}
        assert payload["kept_content_types"] == [{"media_type": "application/json", "count": 1}]


class TestRenderSummary:
    def test_reports_the_capture_and_its_counts(self) -> None:
        rendered = render_summary(
            summary_of(
                entry("a", "https://shop.example.com/api/v1/orders"),
                entry(
                    "b",
                    "https://shop.example.com/orders",
                    content_type="text/html",
                    resource_type=ResourceType.DOCUMENT,
                ),
                asset("c", "https://cdn.example.com/static/app.css", ResourceType.STYLESHEET),
            )
        )
        assert rendered == (
            "Capture: 3 requests from har, recorded 2026-09-04T09:15:00+00:00\n"
            "Hosts: cdn.example.com, shop.example.com\n"
            "\n"
            "Requests: 3 total, 2 kept, 1 filtered as noise.\n"
            "Kept: 1 application, 1 unknown.\n"
            "Noise: 1 asset-resource-type.\n"
            "Kept content types: 1 application/json, 1 text/html.\n"
        )

    def test_reports_where_a_recorded_session_started(self) -> None:
        rendered = render_summary(
            summary_of(
                entry("a", "https://shop.example.com/api/v1/orders"),
                start_url="https://shop.example.com/orders",
            )
        )
        assert "Started at: https://shop.example.com/orders" in rendered

    def test_a_capture_without_noise_says_nothing_about_it(self) -> None:
        rendered = render_summary(summary_of(entry("a", "https://shop.example.com/api/v1/orders")))
        assert "Requests: 1 total, 1 kept, 0 filtered as noise." in rendered
        assert "Noise:" not in rendered

    def test_a_capture_of_nothing_but_noise_reports_an_empty_workflow(self) -> None:
        rendered = render_summary(
            summary_of(
                asset("a", "https://cdn.example.com/static/app.css", ResourceType.STYLESHEET)
            )
        )
        assert "Requests: 1 total, 0 kept, 1 filtered as noise." in rendered
        assert "Kept:" not in rendered
        assert "Kept content types:" not in rendered

    def test_reports_the_kept_requests_that_never_answered(self) -> None:
        rendered = render_summary(
            summary_of(entry("a", "https://shop.example.com/api/v1/stream", status=None))
        )
        assert "1 kept request never received a response." in rendered

    def test_reports_how_many_credentials_were_removed_first(self) -> None:
        rendered = render_summary(
            summary_of(
                entry(
                    "a",
                    "https://shop.example.com/api/v1/orders",
                    headers=Headers.from_pairs([("Authorization", "Bearer super-secret")]),
                )
            )
        )
        assert "Redacted 1 value before counting this." in rendered
        assert "super-secret" not in rendered

    def test_an_empty_capture_says_so(self) -> None:
        rendered = render_summary(summary_of())
        assert rendered == (
            "Capture: 0 requests from har, recorded 2026-09-04T09:15:00+00:00\n"
            "\n"
            "No requests were recorded.\n"
        )


class TestShippedExample:
    def test_summarizes_the_example_archive(self) -> None:
        rendered = render_summary(summarize_capture(load_har(EXAMPLE_HAR)))
        assert rendered == (
            "Capture: 8 requests from har, recorded 2026-09-04T09:15:00+00:00\n"
            "Hosts: cdn.example.com, shop.example.com, www.google-analytics.com\n"
            "\n"
            "Requests: 8 total, 4 kept, 4 filtered as noise.\n"
            "Kept: 3 application, 1 unknown.\n"
            "Noise: 3 asset-resource-type, 1 analytics-host.\n"
            "Kept content types: 3 application/json, 1 text/html.\n"
            "Redacted 6 values before counting this.\n"
        )
