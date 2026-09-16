"""Tests for reading the links of a capture as a graph of requests."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from trace2api.analyze import Relevance, RequestGraph, graph_capture, render_graph
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
    response_headers: Headers | None = None,
    response_body: Body | None = None,
    resource_type: ResourceType = ResourceType.XHR,
) -> Entry:
    """Build one observed exchange."""
    return Entry(
        id=entry_id,
        started_at=STARTED_AT,
        request=Request(method=method, url=url, headers=headers or Headers(), body=body),
        response=Response(status=200, headers=response_headers or Headers(), body=response_body),
        resource_type=resource_type,
    )


def json_body(text: str) -> Body:
    """Build a JSON payload holding ``text``."""
    return Body(mime_type="application/json", text=text)


def graph_of(*entries: Entry, keep: tuple[Relevance, ...] | None = None) -> RequestGraph:
    """Graph a capture built from ``entries``, with a fixed redaction salt."""
    capture = Capture(
        metadata=CaptureMetadata(source=CaptureSource.HAR, created_at=STARTED_AT),
        entries=list(entries),
    )
    if keep is None:
        return graph_capture(capture, salt=SALT)
    return graph_capture(capture, keep=keep, salt=SALT)


def stages(graph: RequestGraph) -> list[list[int]]:
    """Reduce the graph to the positions it places in each stage."""
    return [[node.position for node in stage] for stage in graph.stages]


def orders_chain() -> tuple[Entry, ...]:
    """Build the workflow the quick start records: a list, an order, a confirmation."""
    return (
        entry("page", "https://shop.example.com/orders", resource_type=ResourceType.DOCUMENT),
        entry(
            "list",
            "https://shop.example.com/api/orders",
            response_body=json_body('{"orders":[{"id":"order-55120"}]}'),
        ),
        entry(
            "order",
            "https://shop.example.com/api/orders/order-55120",
            response_body=json_body('{"confirmation_ref":"CNF-55120-88"}'),
        ),
        entry(
            "confirm",
            "https://shop.example.com/api/orders/order-55120/confirm",
            method="POST",
            body=json_body('{"confirmation_ref":"CNF-55120-88"}'),
        ),
    )


class TestNodes:
    def test_every_read_request_becomes_a_node(self) -> None:
        graph = graph_of(*orders_chain())
        assert [node.position for node in graph.nodes] == [1, 2, 3, 4]
        assert graph.graphed_requests == 4

    def test_a_request_that_carries_nothing_forward_is_still_a_node(self) -> None:
        graph = graph_of(
            entry("a", "https://shop.example.com/api/settings"),
            entry("b", "https://shop.example.com/api/orders"),
        )
        assert [node.position for node in graph.nodes] == [1, 2]
        assert graph.dependencies == []
        assert graph.dependent_requests == 0

    def test_a_node_names_the_request_it_stands_for(self) -> None:
        graph = graph_of(entry("a", "https://shop.example.com/api/orders?status=open"))
        request = graph.nodes[0].request
        assert (request.method, request.host, request.path) == (
            "GET",
            "shop.example.com",
            "/api/orders",
        )

    def test_a_node_names_what_it_waits_for_and_what_waits_for_it(self) -> None:
        graph = graph_of(*orders_chain())
        by_position = {node.position: node for node in graph.nodes}
        assert by_position[2].depends_on == []
        assert by_position[2].needed_by == [3, 4]
        assert by_position[4].depends_on == [2, 3]
        assert by_position[4].needed_by == []


class TestDependencies:
    def test_values_taken_from_one_response_are_one_edge(self) -> None:
        graph = graph_of(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                response_body=json_body('{"id":"order-55120","ref":"CNF-55120-88"}'),
            ),
            entry(
                "b",
                "https://shop.example.com/api/orders/order-55120",
                method="POST",
                body=json_body('{"ref":"CNF-55120-88"}'),
            ),
        )
        assert len(graph.dependencies) == 1
        dependency = graph.dependencies[0]
        assert (dependency.source, dependency.target) == (1, 2)
        assert [link.source_location for link in dependency.links] == [
            "response.body.id",
            "response.body.ref",
        ]
        assert [link.target_location for link in dependency.links] == [
            "request.path[3]",
            "request.body.ref",
        ]

    def test_values_taken_from_two_responses_are_two_edges(self) -> None:
        graph = graph_of(*orders_chain())
        assert [(item.source, item.target) for item in graph.dependencies] == [
            (2, 3),
            (2, 4),
            (3, 4),
        ]

    def test_a_link_carries_the_rule_that_drew_it(self) -> None:
        graph = graph_of(*orders_chain())
        link = graph.dependencies[0].links[0]
        assert link.rule.value == "whole-value"
        assert link.reason == "the request sent exactly what the earlier response carried"

    def test_the_responses_a_client_has_to_read_are_reported(self) -> None:
        graph = graph_of(*orders_chain())
        assert graph.required_responses == [2, 3]


class TestStages:
    def test_a_request_that_needs_nothing_is_in_the_first_stage(self) -> None:
        graph = graph_of(*orders_chain())
        assert stages(graph) == [[1, 2], [3], [4]]

    def test_a_request_is_one_stage_after_the_latest_response_it_needs(self) -> None:
        graph = graph_of(*orders_chain())
        assert [node.stage for node in graph.nodes] == [1, 1, 2, 3]

    def test_independent_requests_share_a_stage(self) -> None:
        graph = graph_of(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                response_body=json_body('{"id":"order-55120"}'),
            ),
            entry("b", "https://shop.example.com/api/orders/order-55120"),
            entry("c", "https://shop.example.com/api/orders/order-55120/items"),
        )
        assert stages(graph) == [[1], [2, 3]]

    def test_a_capture_with_no_links_is_one_stage(self) -> None:
        graph = graph_of(
            entry("a", "https://shop.example.com/api/orders"),
            entry("b", "https://shop.example.com/api/settings"),
        )
        assert stages(graph) == [[1, 2]]


class TestLongestChain:
    def test_the_chain_follows_the_requests_that_cannot_be_sent_at_once(self) -> None:
        graph = graph_of(*orders_chain())
        assert graph.longest_chain == [2, 3, 4]

    def test_a_workflow_with_no_links_has_no_chain_beyond_one_request(self) -> None:
        graph = graph_of(
            entry("a", "https://shop.example.com/api/orders"),
            entry("b", "https://shop.example.com/api/settings"),
        )
        assert graph.longest_chain == [1]

    def test_an_empty_capture_has_no_chain(self) -> None:
        graph = graph_of()
        assert graph.longest_chain == []
        assert graph.nodes == []


class TestRelevance:
    def test_noise_is_left_out_by_default(self) -> None:
        graph = graph_of(
            entry(
                "a",
                "https://cdn.example.com/static/app.css",
                response_body=Body(mime_type="text/css", text="body{}"),
                resource_type=ResourceType.STYLESHEET,
            ),
            entry("b", "https://shop.example.com/api/orders"),
        )
        assert [node.position for node in graph.nodes] == [2]
        assert graph.total_requests == 2

    def test_noise_can_be_read_when_asked_for(self) -> None:
        graph = graph_of(
            entry(
                "a",
                "https://cdn.example.com/static/app.json",
                response_body=json_body('{"build":"order-55120"}'),
                resource_type=ResourceType.STYLESHEET,
            ),
            entry("b", "https://shop.example.com/api/orders/order-55120"),
            keep=tuple(Relevance),
        )
        assert stages(graph) == [[1], [2]]


class TestRendering:
    def test_requests_are_listed_under_the_stage_they_belong_to(self) -> None:
        rendered = render_graph(graph_of(*orders_chain()))
        assert "Stage 1: 2 requests that need nothing earlier" in rendered
        assert "Stage 2: 1 request that waits for stage 1" in rendered
        assert "1  GET   shop.example.com/orders" in rendered

    def test_a_link_is_rendered_as_where_it_came_from_and_where_it_went(self) -> None:
        rendered = render_graph(graph_of(*orders_chain()))
        assert any(
            " ".join(line.split()) == "needs 2 response.body.orders[0].id -> request.path[3]"
            for line in rendered.splitlines()
        )

    def test_the_link_columns_line_up_across_the_whole_graph(self) -> None:
        rendered = render_graph(graph_of(*orders_chain()))
        arrows = {line.index("->") for line in rendered.splitlines() if "needs" in line}
        assert len(arrows) == 1

    def test_the_summary_accounts_for_the_workflow(self) -> None:
        rendered = render_graph(graph_of(*orders_chain()))
        assert "4 kept requests: 2 waiting for an earlier response, 2 able to be sent first."
        assert "2 responses must be read by the client: 2, 3." in rendered
        assert "Longest chain: 2 -> 3 -> 4, 3 requests that cannot be sent at once." in rendered

    def test_a_workflow_with_no_links_reports_no_chain(self) -> None:
        rendered = render_graph(graph_of(entry("a", "https://shop.example.com/api/orders")))
        assert "1 kept request: 0 waiting for an earlier response, 1 able to be sent first."
        assert "Longest chain" not in rendered
        assert "must be read by the client" not in rendered

    def test_explain_names_the_rule_behind_each_link(self) -> None:
        rendered = render_graph(graph_of(*orders_chain()), explain=True)
        assert "the request sent exactly what the earlier response carried" in rendered

    def test_the_redaction_is_reported(self) -> None:
        graph = graph_of(
            entry(
                "a",
                "https://shop.example.com/api/orders",
                headers=Headers.from_pairs([("Authorization", "Bearer token-value-9911")]),
            )
        )
        assert graph.redacted_values == 1
        assert "Redacted 1 value before reading this" in render_graph(graph)


class TestSecrets:
    def test_no_value_is_printed_even_where_one_was_carried_forward(self) -> None:
        secret = "session-value-99117733"
        graph = graph_of(
            entry(
                "a",
                "https://shop.example.com/api/session",
                response_headers=Headers.from_pairs(
                    [("Set-Cookie", f"session={secret}; HttpOnly")]
                ),
            ),
            entry(
                "b",
                "https://shop.example.com/api/orders",
                headers=Headers.from_pairs([("Cookie", f"session={secret}")]),
            ),
        )
        rendered = render_graph(graph, explain=True)
        assert graph.required_responses == [1]
        assert secret not in rendered
        assert "(redacted)" not in rendered
        assert "needs 1  response.headers.set-cookie[session]" in rendered

    def test_a_link_reaches_the_json_document_as_two_places(self) -> None:
        document = json.loads(graph_of(*orders_chain()).as_json())
        link = document["dependencies"][0]["links"][0]
        assert link == {
            "source_location": "response.body.orders[0].id",
            "target_location": "request.path[3]",
            "rule": "whole-value",
        }
        assert "value" not in link


class TestJsonDocument:
    def test_the_document_holds_the_nodes_and_the_edges(self) -> None:
        document = json.loads(graph_of(*orders_chain()).as_json())
        assert [node["request"]["position"] for node in document["nodes"]] == [1, 2, 3, 4]
        assert [node["stage"] for node in document["nodes"]] == [1, 1, 2, 3]
        assert document["dependencies"][0] == {
            "source": 2,
            "target": 3,
            "links": [
                {
                    "source_location": "response.body.orders[0].id",
                    "target_location": "request.path[3]",
                    "rule": "whole-value",
                }
            ],
        }

    def test_the_document_records_where_the_capture_came_from(self) -> None:
        document = json.loads(graph_of(*orders_chain()).as_json())
        assert document["source"] == "har"
        assert document["total_requests"] == 4


class TestExampleArchive:
    def test_the_shipped_archive_graphs_as_the_readme_shows(self) -> None:
        graph = graph_capture(load_har(EXAMPLE_HAR))
        assert stages(graph) == [[1, 4], [6], [7]]
        assert graph.required_responses == [4, 6]
        assert graph.longest_chain == [4, 6, 7]
