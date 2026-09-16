"""Tests for the values a capture carries from one response into a later request."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from trace2api.analyze import CaptureFlows, FlowRule, Relevance, render_flows, trace_flows
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

SALT = b"test-salt"
"""A fixed salt, so a redacted value has the same placeholder in every assertion."""


def entry(
    entry_id: str,
    url: str,
    *,
    method: str = "GET",
    headers: Headers | None = None,
    body: Body | None = None,
    status: int | None = 200,
    response_headers: Headers | None = None,
    response_body: Body | None = None,
    redirect_url: str | None = None,
    resource_type: ResourceType = ResourceType.XHR,
) -> Entry:
    """Build one observed exchange."""
    response = None
    if status is not None:
        response = Response(
            status=status,
            headers=response_headers or Headers(),
            body=response_body,
            redirect_url=redirect_url,
        )
    return Entry(
        id=entry_id,
        started_at=STARTED_AT,
        request=Request(method=method, url=url, headers=headers or Headers(), body=body),
        response=response,
        resource_type=resource_type,
    )


def json_body(text: str) -> Body:
    """Build a JSON payload holding ``text``."""
    return Body(mime_type="application/json", text=text)


def capture(*entries: Entry) -> Capture:
    """Build a capture holding ``entries``."""
    return Capture(
        metadata=CaptureMetadata(source=CaptureSource.HAR, created_at=STARTED_AT),
        entries=list(entries),
    )


def flows_of(*entries: Entry, keep: tuple[Relevance, ...] | None = None) -> CaptureFlows:
    """Trace a capture built from ``entries``, with a fixed redaction salt."""
    traced = capture(*entries)
    if keep is None:
        return trace_flows(traced, salt=SALT)
    return trace_flows(traced, keep=keep, salt=SALT)


def links(traced: CaptureFlows) -> list[tuple[str, int, str]]:
    """Reduce the links to what each one says: where it went, where it came from."""
    return [
        (flow.target.location, flow.source.position, flow.source.location) for flow in traced.flows
    ]


class TestValuesFromAResponseBody:
    def test_an_identifier_becomes_a_path_segment(self) -> None:
        traced = flows_of(
            entry(
                "a", "https://shop.example.com/api/orders", response_body=json_body('{"id":4711}')
            ),
            entry("b", "https://shop.example.com/api/orders/4711"),
        )
        assert links(traced) == [("request.path[3]", 1, "response.body.id")]
        assert traced.flows[0].rule is FlowRule.WHOLE_VALUE
        assert traced.flows[0].value == "4711"

    def test_a_cursor_becomes_a_query_parameter(self) -> None:
        traced = flows_of(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                response_body=json_body('{"next_cursor":"cur-8811"}'),
            ),
            entry("b", "https://shop.example.com/api/orders?cursor=cur-8811"),
        )
        assert links(traced) == [("request.query[cursor]", 1, "response.body.next_cursor")]

    def test_a_value_nested_in_a_list_is_located(self) -> None:
        traced = flows_of(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                response_body=json_body('{"orders":[{"ref":"A-9001"},{"ref":"A-9002"}]}'),
            ),
            entry("b", "https://shop.example.com/api/orders/A-9002"),
        )
        assert links(traced) == [("request.path[3]", 1, "response.body.orders[1].ref")]

    def test_a_value_reaches_a_json_payload_field(self) -> None:
        traced = flows_of(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                response_body=json_body('{"confirmation_ref":"CNF-4711-88"}'),
            ),
            entry(
                "b",
                "https://shop.example.com/api/confirm",
                method="POST",
                body=json_body('{"confirmation_ref":"CNF-4711-88"}'),
            ),
        )
        assert links(traced) == [
            ("request.body.confirmation_ref", 1, "response.body.confirmation_ref")
        ]

    def test_a_value_reaches_a_form_encoded_field(self) -> None:
        traced = flows_of(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                response_body=json_body('{"token_field":"form-value-2211"}'),
            ),
            entry(
                "b",
                "https://shop.example.com/api/confirm",
                method="POST",
                body=Body(
                    mime_type="application/x-www-form-urlencoded",
                    text="ref=form-value-2211",
                ),
            ),
        )
        assert links(traced) == [("request.body[ref]", 1, "response.body.token_field")]

    def test_a_form_encoded_response_hands_out_values_too(self) -> None:
        traced = flows_of(
            entry(
                "a",
                "https://shop.example.com/api/session",
                response_body=Body(
                    mime_type="application/x-www-form-urlencoded", text="ticket=tkt-55120"
                ),
            ),
            entry("b", "https://shop.example.com/api/orders?ticket=tkt-55120"),
        )
        assert links(traced) == [("request.query[ticket]", 1, "response.body[ticket]")]

    def test_a_flag_is_not_a_value_a_workflow_carries(self) -> None:
        traced = flows_of(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                response_body=json_body('{"paid":true,"cancelled":null}'),
            ),
            entry(
                "b",
                "https://shop.example.com/api/confirm",
                method="POST",
                body=json_body('{"paid":true,"cancelled":null}'),
            ),
        )
        assert traced.flows == []

    def test_a_binary_response_is_not_read(self) -> None:
        traced = flows_of(
            entry(
                "a",
                "https://shop.example.com/api/logo",
                response_body=Body(
                    mime_type="image/png", text="aWRlbnRpZmllcg==", encoding="base64"
                ),
            ),
            entry("b", "https://shop.example.com/api/orders?ref=aWRlbnRpZmllcg=="),
        )
        assert traced.flows == []


class TestValuesFromAResponseHeader:
    def test_a_header_a_later_request_sends_back(self) -> None:
        traced = flows_of(
            entry(
                "a",
                "https://shop.example.com/api/session",
                response_headers=Headers.from_pairs([("ETag", 'W/"rev-99120"')]),
            ),
            entry(
                "b",
                "https://shop.example.com/api/orders",
                headers=Headers.from_pairs([("If-None-Match", 'W/"rev-99120"')]),
            ),
        )
        assert links(traced) == [("request.headers.if-none-match", 1, "response.headers.etag")]

    def test_a_cookie_is_read_without_its_attributes(self) -> None:
        traced = flows_of(
            entry(
                "a",
                "https://shop.example.com/api/session",
                response_headers=Headers.from_pairs(
                    [("Set-Cookie", "basket=basket-771209; Path=/; HttpOnly")]
                ),
            ),
            entry(
                "b",
                "https://shop.example.com/api/orders",
                headers=Headers.from_pairs([("Cookie", "basket=basket-771209; locale=en-GB")]),
            ),
        )
        assert links(traced) == [
            ("request.headers.cookie", 1, "response.headers.set-cookie[basket]")
        ]
        assert traced.flows[0].rule is FlowRule.EMBEDDED_VALUE

    def test_a_redirect_target_a_later_request_follows(self) -> None:
        traced = flows_of(
            entry(
                "a",
                "https://shop.example.com/api/session",
                status=302,
                redirect_url="https://shop.example.com/api/orders/A-55120",
            ),
            entry(
                "b",
                "https://shop.example.com/api/next",
                headers=Headers.from_pairs(
                    [("X-Return-To", "https://shop.example.com/api/orders/A-55120")]
                ),
            ),
        )
        assert links(traced) == [("request.headers.x-return-to", 1, "response.redirect_url")]

    def test_the_declared_content_type_is_not_a_source(self) -> None:
        traced = flows_of(
            entry(
                "a",
                "https://shop.example.com/orders",
                response_headers=Headers.from_pairs(
                    [
                        ("Content-Type", "application/json"),
                        ("Date", "Fri, 04 Sep 2026 09:15:00 GMT"),
                    ]
                ),
            ),
            entry(
                "b",
                "https://shop.example.com/api/orders",
                headers=Headers.from_pairs(
                    [
                        ("Accept", "application/json"),
                        ("If-Modified-Since", "Fri, 04 Sep 2026 09:15:00 GMT"),
                    ]
                ),
            ),
        )
        assert traced.flows == []


class TestValuesFromATextBody:
    def test_a_credential_written_into_a_page_is_a_source(self) -> None:
        traced = flows_of(
            entry(
                "a",
                "https://shop.example.com/orders",
                response_body=Body(
                    mime_type="text/html",
                    text='<script>var csrfToken = "wYtR8kQ2mZ1pLxV4nB7c";</script>',
                ),
                resource_type=ResourceType.DOCUMENT,
            ),
            entry(
                "b",
                "https://shop.example.com/api/orders",
                headers=Headers.from_pairs([("X-CSRF-Token", "wYtR8kQ2mZ1pLxV4nB7c")]),
            ),
        )
        assert links(traced) == [("request.headers.x-csrf-token", 1, "response.body")]

    def test_the_page_around_a_credential_is_not_a_source(self) -> None:
        traced = flows_of(
            entry(
                "a",
                "https://shop.example.com/orders",
                response_body=Body(mime_type="text/html", text="<title>Orders</title>"),
                resource_type=ResourceType.DOCUMENT,
            ),
            entry(
                "b",
                "https://shop.example.com/api/orders",
                headers=Headers.from_pairs([("X-Page-Title", "<title>Orders</title>")]),
            ),
        )
        assert traced.flows == []


class TestWhatIsNotALink:
    def test_a_response_that_echoes_the_request_is_not_a_source(self) -> None:
        traced = flows_of(
            entry(
                "a",
                "https://shop.example.com/api/orders?status=pending",
                response_body=json_body('{"status":"pending"}'),
            ),
            entry("b", "https://shop.example.com/api/orders?status=pending"),
        )
        assert traced.flows == []

    def test_a_value_the_workflow_sent_before_is_not_a_source(self) -> None:
        sent = Headers.from_pairs([("X-Tenant", "tenant-40921")])
        traced = flows_of(
            entry("a", "https://shop.example.com/api/orders", headers=sent),
            entry(
                "b",
                "https://shop.example.com/api/orders",
                response_body=json_body('{"tenant":"tenant-40921"}'),
            ),
            entry("c", "https://shop.example.com/api/orders", headers=sent),
        )
        assert traced.flows == []

    def test_a_short_value_is_not_evidence(self) -> None:
        traced = flows_of(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                response_body=json_body('{"page":12}'),
            ),
            entry("b", "https://shop.example.com/api/orders?page=12"),
        )
        assert traced.flows == []

    def test_a_number_inside_a_longer_number_is_not_a_link(self) -> None:
        traced = flows_of(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                response_body=json_body('{"id":"55120918"}'),
            ),
            entry("b", "https://shop.example.com/api/orders?ref=955120918"),
        )
        assert traced.flows == []

    def test_a_short_value_is_not_looked_for_inside_a_longer_one(self) -> None:
        traced = flows_of(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                response_body=json_body('{"id":"A-551"}'),
            ),
            entry("b", "https://shop.example.com/api/orders?ref=order:A-551:open"),
        )
        assert traced.flows == []

    def test_a_response_after_the_request_is_not_a_source(self) -> None:
        traced = flows_of(
            entry("a", "https://shop.example.com/api/orders?ref=order-55120"),
            entry(
                "b",
                "https://shop.example.com/api/orders",
                response_body=json_body('{"ref":"order-55120"}'),
            ),
        )
        assert traced.flows == []

    def test_an_exchange_without_a_response_hands_out_nothing(self) -> None:
        traced = flows_of(
            entry("a", "https://shop.example.com/api/orders", status=None),
            entry("b", "https://shop.example.com/api/orders/A-55120"),
        )
        assert traced.flows == []


class TestChoosingASource:
    def test_the_earliest_response_that_carried_the_value_wins(self) -> None:
        traced = flows_of(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                response_body=json_body('{"ref":"order-55120"}'),
            ),
            entry(
                "b",
                "https://shop.example.com/api/summary",
                response_body=json_body('{"ref":"order-55120"}'),
            ),
            entry("c", "https://shop.example.com/api/orders/order-55120"),
        )
        assert links(traced) == [("request.path[3]", 1, "response.body.ref")]

    def test_a_whole_value_is_preferred_to_a_fragment_of_one(self) -> None:
        traced = flows_of(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                response_body=json_body('{"id":"55120918"}'),
            ),
            entry(
                "b",
                "https://shop.example.com/api/detail",
                response_body=json_body('{"ref":"CNF-55120918-02"}'),
            ),
            entry("c", "https://shop.example.com/api/orders?ref=CNF-55120918-02"),
        )
        assert links(traced) == [("request.query[ref]", 2, "response.body.ref")]
        assert traced.flows[0].rule is FlowRule.WHOLE_VALUE

    def test_one_value_reaching_two_requests_is_reported_twice(self) -> None:
        traced = flows_of(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                response_body=json_body('{"id":"order-55120"}'),
            ),
            entry("b", "https://shop.example.com/api/orders/order-55120"),
            entry("c", "https://shop.example.com/api/orders/order-55120/confirm", method="POST"),
        )
        assert links(traced) == [
            ("request.path[3]", 1, "response.body.id"),
            ("request.path[3]", 1, "response.body.id"),
        ]
        assert traced.dependent_requests == 2


class TestCredentials:
    def test_a_session_handed_out_and_sent_back_is_recognized(self) -> None:
        traced = flows_of(
            entry(
                "a",
                "https://shop.example.com/api/session",
                method="POST",
                response_headers=Headers.from_pairs(
                    [("Set-Cookie", "session=s3cr3t-session-value-9912; HttpOnly")]
                ),
            ),
            entry(
                "b",
                "https://shop.example.com/api/orders",
                headers=Headers.from_pairs([("Cookie", "session=s3cr3t-session-value-9912")]),
            ),
        )
        assert links(traced) == [
            ("request.headers.cookie", 1, "response.headers.set-cookie[session]")
        ]

    def test_neither_the_report_nor_the_rendering_shows_the_credential(self) -> None:
        secret = "s3cr3t-session-value-9912"
        traced = flows_of(
            entry(
                "a",
                "https://shop.example.com/api/session",
                method="POST",
                response_headers=Headers.from_pairs(
                    [("Set-Cookie", f"session={secret}; HttpOnly")]
                ),
            ),
            entry(
                "b",
                "https://shop.example.com/api/orders",
                headers=Headers.from_pairs([("Authorization", f"Bearer {secret}")]),
            ),
        )
        assert traced.flows != []
        assert secret not in traced.as_json()
        rendered = render_flows(traced, explain=True)
        assert secret not in rendered
        assert "(redacted)" in rendered


class TestRelevance:
    def test_noise_is_not_read_by_default(self) -> None:
        traced = flows_of(
            entry(
                "a",
                "https://cdn.example.com/static/app.css",
                response_body=Body(mime_type="text/css", text=".a{content:'order-55120'}"),
                resource_type=ResourceType.STYLESHEET,
            ),
            entry("b", "https://shop.example.com/api/orders/order-55120"),
        )
        assert traced.traced_requests == 1
        assert traced.flows == []

    def test_noise_can_be_read_when_asked_for(self) -> None:
        traced = flows_of(
            entry(
                "a",
                "https://cdn.example.com/static/app.json",
                response_body=json_body('{"build":"order-55120"}'),
                resource_type=ResourceType.STYLESHEET,
            ),
            entry("b", "https://shop.example.com/api/orders/order-55120"),
            keep=tuple(Relevance),
        )
        assert traced.traced_requests == 2
        assert links(traced) == [("request.path[3]", 1, "response.body.build")]

    def test_positions_count_over_the_whole_capture(self) -> None:
        traced = flows_of(
            entry(
                "a",
                "https://cdn.example.com/static/app.css",
                response_body=Body(mime_type="text/css", text="body{}"),
                resource_type=ResourceType.STYLESHEET,
            ),
            entry(
                "b",
                "https://shop.example.com/api/orders",
                response_body=json_body('{"id":"order-55120"}'),
            ),
            entry("c", "https://shop.example.com/api/orders/order-55120"),
        )
        assert traced.total_requests == 3
        assert traced.traced_requests == 2
        assert traced.flows[0].source.position == 2
        assert traced.flows[0].target.position == 3


class TestCaptureFlows:
    def test_an_empty_capture_reports_nothing(self) -> None:
        traced = flows_of()
        assert traced.flows == []
        assert traced.dependent_requests == 0
        assert traced.total_requests == 0

    def test_the_json_report_holds_both_ends_of_every_link(self) -> None:
        traced = flows_of(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                response_body=json_body('{"id":"order-55120"}'),
            ),
            entry("b", "https://shop.example.com/api/orders/order-55120"),
        )
        document = json.loads(traced.as_json())
        assert document["flows"] == [
            {
                "source": {
                    "position": 1,
                    "method": "GET",
                    "host": "shop.example.com",
                    "path": "/api/orders",
                    "location": "response.body.id",
                },
                "target": {
                    "position": 2,
                    "method": "GET",
                    "host": "shop.example.com",
                    "path": "/api/orders/order-55120",
                    "location": "request.path[3]",
                },
                "rule": "whole-value",
                "value": "order-55120",
            }
        ]

    def test_the_capture_is_described_by_where_it_came_from(self) -> None:
        traced = flows_of(entry("a", "https://shop.example.com/api/orders"))
        assert traced.source is CaptureSource.HAR
        assert traced.created_at == STARTED_AT

    def test_every_request_read_is_reported_even_where_no_value_reached_it(self) -> None:
        traced = flows_of(
            entry("a", "https://shop.example.com/api/orders"),
            entry("b", "https://shop.example.com/api/settings", method="POST"),
        )
        assert traced.flows == []
        assert [(item.position, item.method, item.path) for item in traced.requests] == [
            (1, "GET", "/api/orders"),
            (2, "POST", "/api/settings"),
        ]
        assert traced.traced_requests == 2


class TestRenderFlows:
    def test_links_are_grouped_under_the_request_that_needs_them(self) -> None:
        traced = flows_of(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                response_body=json_body('{"id":"order-55120"}'),
            ),
            entry("b", "https://shop.example.com/api/orders/order-55120"),
        )
        rendered = render_flows(traced)
        assert "2  GET shop.example.com/api/orders/order-55120" in rendered
        assert 'request.path[3]  <- 1  response.body.id  "order-55120"' in rendered
        assert "1 value flows from a response into a later request." in rendered
        assert "1 of 2 kept requests depend on a response above them." in rendered

    def test_a_capture_with_no_links_says_so(self) -> None:
        rendered = render_flows(flows_of(entry("a", "https://shop.example.com/api/orders")))
        assert "No value a response carried was sent by a later request." in rendered

    def test_explain_names_the_rule_behind_a_link(self) -> None:
        traced = flows_of(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                response_body=json_body('{"id":"order-55120"}'),
            ),
            entry("b", "https://shop.example.com/api/orders/order-55120"),
        )
        assert "the request sent exactly what the earlier response carried" in render_flows(
            traced, explain=True
        )
        assert "the request sent exactly what" not in render_flows(traced)

    def test_the_count_of_redacted_values_is_reported(self) -> None:
        traced = flows_of(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                headers=Headers.from_pairs([("Authorization", "Bearer token-value-55120")]),
            )
        )
        assert "Redacted 1 value before tracing" in render_flows(traced)


class TestShippedExample:
    def test_the_example_workflow_reads_its_identifier_out_of_a_response(self) -> None:
        traced = trace_flows(load_har(EXAMPLE_HAR), salt=SALT)
        assert links(traced) == [
            ("request.path[4]", 4, "response.body.orders[0].id"),
            ("request.path[4]", 4, "response.body.orders[0].id"),
            ("request.body.confirmation_ref", 6, "response.body.confirmation_ref"),
        ]
        assert traced.dependent_requests == 2
