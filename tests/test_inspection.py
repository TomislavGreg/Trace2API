"""Tests for the account of a capture that ``trace2api inspect`` renders."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from trace2api.analyze import FilterRule, Relevance
from trace2api.capture import load_har
from trace2api.inspection import (
    PATH_DISPLAY_WIDTH,
    Inspection,
    inspect_capture,
    render_inspection,
)
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
    resource_type: ResourceType = ResourceType.XHR,
    headers: Headers | None = None,
    failure: str | None = None,
) -> Entry:
    """Build one observed exchange."""
    response = None
    if status is not None:
        response = Response(
            status=status,
            headers=Headers.from_pairs(
                [("Content-Type", content_type)] if content_type else [],
            ),
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


def inspection_of(*entries: Entry, start_url: str | None = None) -> Inspection:
    """Inspect a capture built from ``entries``, with a fixed redaction salt."""
    return inspect_capture(capture(*entries, start_url=start_url), salt=b"test-salt")


class TestInspectCapture:
    def test_describes_each_exchange(self) -> None:
        inspection = inspection_of(entry("a", "https://shop.example.com/api/v1/orders?limit=20"))
        described = inspection.entries[0]
        assert described.position == 1
        assert described.entry_id == "a"
        assert described.method == "GET"
        assert described.host == "shop.example.com"
        assert described.path == "/api/v1/orders"
        assert described.status == 200
        assert described.resource_type is ResourceType.XHR

    def test_positions_count_from_one_in_observed_order(self) -> None:
        inspection = inspection_of(
            entry("a", "https://shop.example.com/api/first"),
            entry("b", "https://shop.example.com/api/second"),
        )
        assert [item.position for item in inspection.entries] == [1, 2]
        assert [item.entry_id for item in inspection.entries] == ["a", "b"]

    def test_carries_the_relevance_verdict_and_its_rule(self) -> None:
        inspection = inspection_of(entry("a", "https://shop.example.com/api/v1/orders"))
        described = inspection.entries[0]
        assert described.relevance is Relevance.APPLICATION
        assert described.rule is FilterRule.API_PATH
        assert described.reason == "path names an API surface: api"

    def test_carries_provenance(self) -> None:
        inspection = inspection_of(
            entry("a", "https://shop.example.com/api/v1/orders"),
            entry("b", "https://cdn.example.com/img/logo.png", resource_type=ResourceType.IMAGE),
        )
        assert inspection.source is CaptureSource.HAR
        assert inspection.created_at == STARTED_AT
        assert inspection.hosts == ["cdn.example.com", "shop.example.com"]

    def test_redacts_before_describing(self) -> None:
        credentialed = entry(
            "a",
            "https://shop.example.com/api/v1/orders",
            headers=Headers.from_pairs([("Authorization", "Bearer super-secret")]),
        )
        assert inspection_of(credentialed).redacted_values == 1

    def test_counts_nothing_redacted_when_there_was_nothing_to_remove(self) -> None:
        assert (
            inspection_of(entry("a", "https://shop.example.com/api/v1/orders")).redacted_values == 0
        )

    def test_reports_a_failed_exchange_without_a_status(self) -> None:
        failed = entry("a", "https://shop.example.com/api/v1/orders", status=None, failure="reset")
        described = inspection_of(failed).entries[0]
        assert described.status is None
        assert described.failure == "reset"
        assert described.outcome == "failed"

    def test_reports_a_missing_response_that_was_not_explained(self) -> None:
        pending = entry("a", "https://shop.example.com/api/v1/orders", status=None)
        assert inspection_of(pending).entries[0].outcome == "-"

    def test_an_empty_capture_inspects_as_empty(self) -> None:
        inspection = inspection_of()
        assert len(inspection) == 0
        assert inspection.hosts == []


class TestSelectionAndCounts:
    def noisy(self) -> Inspection:
        return inspection_of(
            entry("a", "https://shop.example.com/orders", resource_type=ResourceType.DOCUMENT),
            entry(
                "b", "https://cdn.example.com/static/app.css", resource_type=ResourceType.STYLESHEET
            ),
            entry("c", "https://shop.example.com/api/v1/orders"),
            entry("d", "https://www.google-analytics.com/collect", resource_type=ResourceType.XHR),
        )

    def test_noise_is_left_out_by_default(self) -> None:
        shown = self.noisy().visible(include_noise=False)
        assert [item.entry_id for item in shown] == ["a", "c"]

    def test_noise_is_listed_on_request(self) -> None:
        shown = self.noisy().visible(include_noise=True)
        assert [item.entry_id for item in shown] == ["a", "b", "c", "d"]

    def test_counts_every_verdict_including_the_empty_ones(self) -> None:
        assert self.noisy().counts_by_relevance() == {
            Relevance.APPLICATION: 1,
            Relevance.NOISE: 2,
            Relevance.UNKNOWN: 1,
        }

    def test_accounts_for_the_noise_by_rule(self) -> None:
        assert self.noisy().noise_counts_by_rule() == {
            FilterRule.ANALYTICS_HOST: 1,
            FilterRule.ASSET_RESOURCE_TYPE: 1,
        }

    def test_json_report_holds_every_entry(self) -> None:
        payload = json.loads(self.noisy().as_json())
        assert payload["source"] == "har"
        assert [item["position"] for item in payload["entries"]] == [1, 2, 3, 4]
        assert payload["entries"][3]["classification"] == {
            "entry_id": "d",
            "relevance": "noise",
            "rule": "analytics-host",
            "detail": "google-analytics.com",
        }


class TestRender:
    def test_lists_the_requested_columns(self) -> None:
        rendered = render_inspection(
            inspection_of(entry("a", "https://shop.example.com/api/v1/orders"))
        )
        header, row = rendered.splitlines()[3:5]
        assert header.split() == [
            "#",
            "METHOD",
            "HOST",
            "PATH",
            "STATUS",
            "TYPE",
            "RELEVANCE",
        ]
        assert row.split() == [
            "1",
            "GET",
            "shop.example.com",
            "/api/v1/orders",
            "200",
            "xhr",
            "application",
        ]

    def test_columns_line_up_across_rows(self) -> None:
        rendered = render_inspection(
            inspection_of(
                entry("a", "https://shop.example.com/api/v1/orders"),
                entry("b", "https://a.example.com/api/x", method="DELETE"),
            )
        )
        rows = [line for line in rendered.splitlines() if line.startswith(("#", "1", "2"))]
        assert len({line.index("application") for line in rows[1:]}) == 1

    def test_reports_where_the_capture_came_from(self) -> None:
        rendered = render_inspection(inspection_of(entry("a", "https://shop.example.com/api/x")))
        assert rendered.startswith(
            "Capture: 1 request from har, recorded 2026-09-04T09:15:00+00:00"
        )
        assert "Hosts: shop.example.com" in rendered

    def test_reports_the_recorded_start_url_when_there_is_one(self) -> None:
        inspection = inspection_of(
            entry("a", "https://shop.example.com/api/x"),
            start_url="https://shop.example.com/orders",
        )
        assert "Started at: https://shop.example.com/orders" in render_inspection(inspection)

    def test_accounts_for_everything_the_table_did_not_show(self) -> None:
        rendered = render_inspection(
            inspection_of(
                entry("a", "https://shop.example.com/api/v1/orders"),
                entry(
                    "b",
                    "https://cdn.example.com/static/app.css",
                    resource_type=ResourceType.STYLESHEET,
                ),
            )
        )
        assert "Showing 1 of 2 requests: 1 application, 0 unknown, 1 noise." in rendered
        assert "Filtered as noise (1 asset-resource-type). Pass --all to list them." in rendered

    def test_does_not_offer_all_when_the_noise_is_already_listed(self) -> None:
        rendered = render_inspection(
            inspection_of(
                entry(
                    "a",
                    "https://cdn.example.com/static/app.css",
                    resource_type=ResourceType.STYLESHEET,
                )
            ),
            include_noise=True,
        )
        assert "Pass --all" not in rendered

    def test_reports_what_redaction_removed(self) -> None:
        inspection = inspection_of(
            entry(
                "a",
                "https://shop.example.com/api/v1/orders",
                headers=Headers.from_pairs([("Authorization", "Bearer super-secret")]),
            )
        )
        assert "Redacted 1 value before displaying this." in render_inspection(inspection)

    def test_says_nothing_about_redaction_when_nothing_was_removed(self) -> None:
        rendered = render_inspection(inspection_of(entry("a", "https://shop.example.com/api/x")))
        assert "Redacted" not in rendered

    def test_explain_adds_the_rule_behind_each_verdict(self) -> None:
        rendered = render_inspection(
            inspection_of(entry("a", "https://shop.example.com/api/v1/orders")), explain=True
        )
        assert "WHY" in rendered
        assert "path names an API surface: api" in rendered

    def test_a_long_path_keeps_the_end_that_names_it(self) -> None:
        path = "/api/v1/" + "segment/" * 12 + "orders"
        shown = self.path_cell(path)
        assert shown.startswith(".../segment/")
        assert shown.endswith("/orders")
        assert len(shown) <= PATH_DISPLAY_WIDTH

    def test_a_long_path_is_cut_mid_segment_only_when_it_has_to_be(self) -> None:
        shown = self.path_cell("/" + "x" * (PATH_DISPLAY_WIDTH * 2))
        assert shown == "..." + "x" * (PATH_DISPLAY_WIDTH - 3)

    def path_cell(self, path: str) -> str:
        """Render one request and return the path as the table shows it."""
        rendered = render_inspection(inspection_of(entry("a", f"https://shop.example.com{path}")))
        row = next(line for line in rendered.splitlines() if line.startswith("1 "))
        return row.split()[3]

    def test_query_strings_are_never_rendered(self) -> None:
        rendered = render_inspection(
            inspection_of(entry("a", "https://shop.example.com/api/v1/orders?token=super-secret")),
            explain=True,
        )
        assert "super-secret" not in rendered
        assert "token" not in rendered

    def test_an_empty_capture_renders_without_a_table(self) -> None:
        rendered = render_inspection(inspection_of())
        assert "Capture: 0 requests from har" in rendered
        assert "Showing 0 of 0 requests: 0 application, 0 unknown, 0 noise." in rendered
        assert "METHOD" not in rendered

    def test_ends_with_exactly_one_newline(self) -> None:
        rendered = render_inspection(inspection_of(entry("a", "https://shop.example.com/api/x")))
        assert rendered.endswith("\n")
        assert not rendered.endswith("\n\n")


class TestShippedExample:
    @pytest.fixture
    def inspection(self) -> Inspection:
        return inspect_capture(load_har(EXAMPLE_HAR), salt=b"test-salt")

    def test_the_example_capture_imports(self, inspection: Inspection) -> None:
        assert len(inspection) == 8

    def test_the_example_shows_the_workflow_and_filters_the_rest(
        self, inspection: Inspection
    ) -> None:
        shown = inspection.visible(include_noise=False)
        assert [item.path for item in shown] == [
            "/orders",
            "/api/v1/orders",
            "/api/v1/orders/4711",
            "/api/v1/orders/4711/confirm",
        ]

    def test_the_example_carries_credentials_for_redaction_to_remove(
        self, inspection: Inspection
    ) -> None:
        assert inspection.redacted_values == 6

    def test_the_example_holds_no_credential_after_inspection(self) -> None:
        rendered = render_inspection(
            inspect_capture(load_har(EXAMPLE_HAR)), include_noise=True, explain=True
        )
        assert "example-access-token" not in rendered
        assert "example-session-value" not in rendered
        assert "example-csrf-value" not in rendered
