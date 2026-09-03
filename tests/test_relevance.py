"""Tests for relevance classification and filtering.

Every host, path, and payload used here is synthetic and was written for this
repository.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from trace2api.analyze import (
    FilterRule,
    Relevance,
    classify_capture,
    classify_entry,
    filter_capture,
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

STARTED_AT = datetime(2026, 9, 3, 9, 0, 0, tzinfo=UTC)


def make_entry(
    url: str,
    *,
    entry_id: str = "e0001",
    method: str = "GET",
    resource_type: ResourceType = ResourceType.OTHER,
    request_content_type: str | None = None,
    request_body: str | None = None,
    response_content_type: str | None = None,
    status: int = 200,
    index: int = 0,
) -> Entry:
    request_headers = []
    if request_content_type is not None:
        request_headers.append(("Content-Type", request_content_type))
    response_headers = []
    if response_content_type is not None:
        response_headers.append(("Content-Type", response_content_type))
    return Entry(
        id=entry_id,
        started_at=STARTED_AT + timedelta(seconds=index),
        request=Request(
            method=method,
            url=url,
            headers=Headers.from_pairs(request_headers),
            body=Body(mime_type=request_content_type, text=request_body)
            if request_body is not None
            else None,
        ),
        response=Response(status=status, headers=Headers.from_pairs(response_headers)),
        resource_type=resource_type,
    )


def make_capture(entries: list[Entry]) -> Capture:
    metadata = CaptureMetadata(source=CaptureSource.HAR, created_at=STARTED_AT)
    return Capture(metadata=metadata, entries=entries)


class TestNoiseRules:
    @pytest.mark.parametrize(
        ("host", "domain"),
        [
            ("www.google-analytics.com", "google-analytics.com"),
            ("google-analytics.com", "google-analytics.com"),
            ("o12345.ingest.sentry.io", "sentry.io"),
            ("api.mixpanel.com", "mixpanel.com"),
        ],
    )
    def test_analytics_hosts_are_noise(self, host: str, domain: str) -> None:
        entry = make_entry(
            f"https://{host}/v1/events",
            method="POST",
            resource_type=ResourceType.FETCH,
            request_content_type="application/json",
            request_body='{"event":"viewed"}',
        )
        classification = classify_entry(entry)
        assert classification.relevance is Relevance.NOISE
        assert classification.rule is FilterRule.ANALYTICS_HOST
        assert classification.detail == domain

    def test_a_host_merely_ending_in_the_same_letters_is_not_matched(self) -> None:
        entry = make_entry(
            "https://notsentry.io/api/orders",
            resource_type=ResourceType.FETCH,
            response_content_type="application/json",
        )
        assert classify_entry(entry).relevance is Relevance.APPLICATION

    @pytest.mark.parametrize(
        ("path", "segment"),
        [
            ("/collect", "collect"),
            ("/api/telemetry/batch", "telemetry"),
            ("/internal/csp-report", "cspreport"),
            ("/x/pixel.gif", "pixel"),
        ],
    )
    def test_reporting_paths_are_noise(self, path: str, segment: str) -> None:
        entry = make_entry(
            f"https://app.example.test{path}",
            method="POST",
            resource_type=ResourceType.FETCH,
            request_content_type="application/json",
            request_body='{"count":1}',
        )
        classification = classify_entry(entry)
        assert classification.relevance is Relevance.NOISE
        assert classification.rule is FilterRule.REPORTING_PATH
        assert classification.detail == segment

    @pytest.mark.parametrize(
        "resource_type",
        [
            ResourceType.STYLESHEET,
            ResourceType.IMAGE,
            ResourceType.FONT,
            ResourceType.SCRIPT,
            ResourceType.MEDIA,
            ResourceType.MANIFEST,
        ],
    )
    def test_page_assets_are_noise(self, resource_type: ResourceType) -> None:
        entry = make_entry("https://app.example.test/static/thing", resource_type=resource_type)
        classification = classify_entry(entry)
        assert classification.relevance is Relevance.NOISE
        assert classification.rule is FilterRule.ASSET_RESOURCE_TYPE
        assert classification.detail == resource_type.value

    @pytest.mark.parametrize(
        ("path", "extension"),
        [
            ("/assets/app.7f3c1a.js", ".js"),
            ("/assets/app.css", ".css"),
            ("/img/logo.SVG", ".svg"),
            ("/fonts/inter.woff2", ".woff2"),
            ("/assets/app.js.map", ".map"),
        ],
    )
    def test_asset_suffixes_are_noise_even_without_a_resource_type(
        self, path: str, extension: str
    ) -> None:
        entry = make_entry(f"https://app.example.test{path}")
        classification = classify_entry(entry)
        assert classification.relevance is Relevance.NOISE
        assert classification.rule is FilterRule.ASSET_EXTENSION
        assert classification.detail == extension

    @pytest.mark.parametrize("path", ["/api/orders.json", "/feeds/items.xml", "/v1/orders"])
    def test_data_suffixes_are_not_assets(self, path: str) -> None:
        entry = make_entry(f"https://app.example.test{path}")
        assert classify_entry(entry).relevance is not Relevance.NOISE

    def test_an_asset_query_string_does_not_make_a_request_an_asset(self) -> None:
        entry = make_entry(
            "https://app.example.test/api/orders?redirect=/assets/app.css",
            resource_type=ResourceType.FETCH,
        )
        classification = classify_entry(entry)
        assert classification.relevance is Relevance.APPLICATION
        assert classification.rule is FilterRule.API_PATH

    def test_a_beacon_posted_as_json_is_still_noise(self) -> None:
        entry = make_entry(
            "https://app.example.test/beacon",
            method="POST",
            resource_type=ResourceType.XHR,
            request_content_type="application/json",
            request_body='{"event":"click"}',
            response_content_type="application/json",
        )
        assert classify_entry(entry).relevance is Relevance.NOISE


class TestApplicationRules:
    @pytest.mark.parametrize(
        ("path", "segment"),
        [
            ("/api/orders", "api"),
            ("/graphql", "graphql"),
            ("/v2/orders/17", "v2"),
            ("/shop/rest/basket", "rest"),
        ],
    )
    def test_api_paths_are_application_traffic(self, path: str, segment: str) -> None:
        entry = make_entry(f"https://app.example.test{path}")
        classification = classify_entry(entry)
        assert classification.relevance is Relevance.APPLICATION
        assert classification.rule is FilterRule.API_PATH
        assert classification.detail == segment

    def test_a_trailing_version_segment_is_not_an_api_path(self) -> None:
        entry = make_entry("https://app.example.test/pricing/v2")
        assert classify_entry(entry).rule is not FilterRule.API_PATH

    def test_browser_data_requests_are_application_traffic(self) -> None:
        entry = make_entry("https://app.example.test/basket", resource_type=ResourceType.XHR)
        classification = classify_entry(entry)
        assert classification.relevance is Relevance.APPLICATION
        assert classification.rule is FilterRule.DATA_RESOURCE_TYPE

    @pytest.mark.parametrize(
        "content_type",
        [
            "application/json; charset=utf-8",
            "application/vnd.example.orders+json",
            "application/x-ndjson",
            "text/xml",
        ],
    )
    def test_structured_responses_are_application_traffic(self, content_type: str) -> None:
        entry = make_entry("https://app.example.test/basket", response_content_type=content_type)
        classification = classify_entry(entry)
        assert classification.relevance is Relevance.APPLICATION
        assert classification.rule is FilterRule.STRUCTURED_RESPONSE

    def test_structured_requests_are_application_traffic(self) -> None:
        entry = make_entry(
            "https://app.example.test/basket",
            method="POST",
            request_content_type="application/x-www-form-urlencoded",
            request_body="quantity=2",
            response_content_type="text/html",
        )
        classification = classify_entry(entry)
        assert classification.relevance is Relevance.APPLICATION
        assert classification.rule is FilterRule.STRUCTURED_REQUEST
        assert classification.detail == "application/x-www-form-urlencoded"

    def test_a_failed_request_is_still_classified_by_its_shape(self) -> None:
        entry = Entry(
            id="e0001",
            started_at=STARTED_AT,
            request=Request(method="GET", url="https://app.example.test/api/orders"),
            failure="net::ERR_CONNECTION_RESET",
        )
        classification = classify_entry(entry)
        assert classification.relevance is Relevance.APPLICATION
        assert classification.rule is FilterRule.API_PATH

    def test_an_error_response_is_still_application_traffic(self) -> None:
        entry = make_entry(
            "https://app.example.test/api/orders",
            status=422,
            response_content_type="application/json",
        )
        assert classify_entry(entry).relevance is Relevance.APPLICATION


class TestUnrecognizedTraffic:
    def test_page_documents_are_kept_as_unknown(self) -> None:
        entry = make_entry(
            "https://app.example.test/checkout",
            resource_type=ResourceType.DOCUMENT,
            response_content_type="text/html",
        )
        classification = classify_entry(entry)
        assert classification.relevance is Relevance.UNKNOWN
        assert classification.rule is FilterRule.PAGE_DOCUMENT
        assert "later requests reuse" in classification.reason

    def test_streaming_connections_are_kept_as_unknown(self) -> None:
        entry = make_entry("https://app.example.test/live", resource_type=ResourceType.WEBSOCKET)
        classification = classify_entry(entry)
        assert classification.relevance is Relevance.UNKNOWN
        assert classification.rule is FilterRule.STREAMING_CONNECTION

    def test_traffic_no_rule_recognizes_is_unknown(self) -> None:
        entry = make_entry("https://app.example.test/checkout", response_content_type="text/html")
        classification = classify_entry(entry)
        assert classification.relevance is Relevance.UNKNOWN
        assert classification.rule is FilterRule.NO_RULE_MATCHED
        assert classification.detail is None
        assert classification.reason == "no rule recognized it"


class TestReasons:
    def test_every_rule_has_an_explanation(self) -> None:
        entry = make_entry("https://app.example.test/api/orders")
        for rule in FilterRule:
            classification = classify_entry(entry).model_copy(update={"rule": rule})
            assert classification.reason.strip()

    def test_a_detail_is_appended_to_the_explanation(self) -> None:
        entry = make_entry("https://www.google-analytics.com/collect")
        assert classify_entry(entry).reason == (
            "sent to an analytics or crash reporting host: google-analytics.com"
        )


class TestFiltering:
    def make_mixed_capture(self) -> Capture:
        return make_capture(
            [
                make_entry(
                    "https://app.example.test/checkout",
                    entry_id="document",
                    resource_type=ResourceType.DOCUMENT,
                    index=0,
                ),
                make_entry(
                    "https://app.example.test/assets/app.css",
                    entry_id="stylesheet",
                    resource_type=ResourceType.STYLESHEET,
                    index=1,
                ),
                make_entry(
                    "https://app.example.test/api/basket",
                    entry_id="basket",
                    resource_type=ResourceType.FETCH,
                    response_content_type="application/json",
                    index=2,
                ),
                make_entry(
                    "https://www.google-analytics.com/collect",
                    entry_id="beacon",
                    method="POST",
                    resource_type=ResourceType.FETCH,
                    request_content_type="application/json",
                    request_body='{"event":"checkout"}',
                    index=3,
                ),
            ]
        )

    def test_the_report_covers_every_entry_in_order(self) -> None:
        report = classify_capture(self.make_mixed_capture())
        assert [item.entry_id for item in report.classifications] == [
            "document",
            "stylesheet",
            "basket",
            "beacon",
        ]
        assert len(report) == 4

    def test_noise_is_dropped_and_the_rest_is_kept(self) -> None:
        result = filter_capture(self.make_mixed_capture())
        assert [entry.id for entry in result.capture] == ["document", "basket"]
        assert result.removed == 2
        assert len(result.report) == 4

    def test_keeping_only_application_traffic(self) -> None:
        result = filter_capture(self.make_mixed_capture(), keep=[Relevance.APPLICATION])
        assert [entry.id for entry in result.capture] == ["basket"]
        assert result.removed == 3

    def test_the_report_explains_what_was_dropped(self) -> None:
        result = filter_capture(self.make_mixed_capture())
        dropped = result.report.entry_ids(Relevance.NOISE)
        assert dropped == ("stylesheet", "beacon")
        beacon = result.report.for_entry("beacon")
        assert beacon is not None
        assert beacon.rule is FilterRule.ANALYTICS_HOST

    def test_counts_summarize_the_capture(self) -> None:
        report = classify_capture(self.make_mixed_capture())
        assert report.counts_by_relevance() == {
            Relevance.APPLICATION: 1,
            Relevance.NOISE: 2,
            Relevance.UNKNOWN: 1,
        }
        assert report.counts_by_rule()[FilterRule.ANALYTICS_HOST] == 1

    def test_filtering_keeps_the_capture_metadata(self) -> None:
        capture = self.make_mixed_capture()
        result = filter_capture(capture)
        assert result.capture.metadata == capture.metadata

    def test_an_empty_capture_filters_to_nothing(self) -> None:
        result = filter_capture(make_capture([]))
        assert len(result.capture) == 0
        assert result.removed == 0
        assert result.report.counts_by_relevance()[Relevance.NOISE] == 0

    def test_an_unknown_entry_id_has_no_verdict(self) -> None:
        report = classify_capture(self.make_mixed_capture())
        assert report.for_entry("missing") is None
