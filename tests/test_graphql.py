"""Tests for recognizing GraphQL operations in a capture."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from trace2api.analyze import (
    CaptureOperations,
    GraphQLRule,
    OperationType,
    find_graphql_operations,
    render_graphql,
)
from trace2api.analyze.relevance import Relevance
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

EXAMPLE_HAR = Path(__file__).resolve().parent.parent / "examples" / "storefront-graphql.har"

STARTED_AT = datetime(2026, 9, 10, 11, 0, tzinfo=UTC)
SALT = b"test-salt"


def entry(
    entry_id: str,
    url: str,
    *,
    method: str = "GET",
    headers: Headers | None = None,
    body: Body | None = None,
    resource_type: ResourceType = ResourceType.FETCH,
) -> Entry:
    """Build one observed exchange, kept by the relevance rules unless said otherwise."""
    return Entry(
        id=entry_id,
        started_at=STARTED_AT,
        request=Request(method=method, url=url, headers=headers or Headers(), body=body),
        response=Response(status=200, headers=Headers.from_pairs([("Content-Type", "text/plain")])),
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


def operations_of(*entries: Entry, keep: tuple[Relevance, ...] | None = None) -> CaptureOperations:
    """Find the GraphQL operations of a capture built from ``entries``, with a fixed salt."""
    built = capture(*entries)
    if keep is None:
        return find_graphql_operations(built, salt=SALT)
    return find_graphql_operations(built, keep=keep, salt=SALT)


class TestJsonBody:
    def test_recognizes_an_operation_named_alongside_variables(self) -> None:
        found = operations_of(
            entry(
                "a",
                "https://shop.example.com/graphql",
                method="POST",
                body=json_body(
                    '{"operationName":"ListOrders",'
                    '"query":"query ListOrders($status: String!) '
                    '{ orders(status: $status) { id } }",'
                    '"variables":{"status":"open"}}'
                ),
            )
        )
        assert len(found.operations) == 1
        operation = found.operations[0]
        assert operation.rule is GraphQLRule.JSON_BODY
        assert operation.operation_type is OperationType.QUERY
        assert operation.operation_name == "ListOrders"
        assert operation.variable_names == ("status",)

    def test_recognizes_a_mutation_from_its_keyword_without_siblings(self) -> None:
        found = operations_of(
            entry(
                "a",
                "https://shop.example.com/graphql",
                method="POST",
                body=json_body(
                    '{"query":"mutation ConfirmOrder { confirmOrder(id: 1) { status } }"}'
                ),
            )
        )
        assert len(found.operations) == 1
        operation = found.operations[0]
        assert operation.operation_type is OperationType.MUTATION
        assert operation.operation_name == "ConfirmOrder"
        assert operation.variable_names == ()

    def test_recognizes_an_anonymous_shorthand_query_alongside_variables(self) -> None:
        found = operations_of(
            entry(
                "a",
                "https://shop.example.com/graphql",
                method="POST",
                body=json_body('{"query":"{ me { id } }","variables":{}}'),
            )
        )
        assert len(found.operations) == 1
        operation = found.operations[0]
        assert operation.operation_type is OperationType.QUERY
        assert operation.operation_name is None

    def test_does_not_recognize_an_ordinary_search_payload(self) -> None:
        found = operations_of(
            entry(
                "a",
                "https://shop.example.com/api/search",
                method="POST",
                body=json_body('{"query":"red shoes","page":2}'),
            )
        )
        assert found.operations == []

    def test_does_not_recognize_a_query_field_that_is_not_a_string(self) -> None:
        found = operations_of(
            entry(
                "a",
                "https://shop.example.com/api/search",
                method="POST",
                body=json_body('{"query":{"nested":true},"operationName":"whatever"}'),
            )
        )
        assert found.operations == []


class TestGraphQLMediaType:
    def test_recognizes_a_raw_query_document(self) -> None:
        found = operations_of(
            entry(
                "a",
                "https://shop.example.com/graphql",
                method="POST",
                body=Body(mime_type="application/graphql", text="{ me { id } }"),
            )
        )
        assert len(found.operations) == 1
        operation = found.operations[0]
        assert operation.rule is GraphQLRule.GRAPHQL_MEDIA_TYPE
        assert operation.operation_type is OperationType.QUERY
        assert operation.operation_name is None
        assert operation.variable_names == ()


class TestQueryString:
    def test_recognizes_a_get_request_with_an_operation_name(self) -> None:
        found = operations_of(
            entry(
                "a",
                "https://shop.example.com/graphql"
                "?query=query+ListOrders+%7B+orders+%7B+id+%7D+%7D"
                "&operationName=ListOrders"
                "&variables=%7B%22status%22%3A%22open%22%7D",
                method="GET",
            )
        )
        assert len(found.operations) == 1
        operation = found.operations[0]
        assert operation.rule is GraphQLRule.QUERY_STRING
        assert operation.operation_name == "ListOrders"
        assert operation.variable_names == ("status",)

    def test_does_not_recognize_an_ordinary_search_query_parameter(self) -> None:
        found = operations_of(
            entry("a", "https://shop.example.com/api/search?query=red+shoes", method="GET")
        )
        assert found.operations == []


class TestFiltering:
    def test_a_noise_request_is_not_read_by_default(self) -> None:
        found = operations_of(
            entry(
                "a",
                "https://cdn.example.com/static/app.js",
                resource_type=ResourceType.SCRIPT,
                body=json_body('{"operationName":"X","query":"query X { x }","variables":{}}'),
            )
        )
        assert found.operations == []
        assert found.kept_requests == 0

    def test_all_includes_a_noise_request(self) -> None:
        found = operations_of(
            entry(
                "a",
                "https://cdn.example.com/static/app.js",
                resource_type=ResourceType.SCRIPT,
                body=json_body('{"operationName":"X","query":"query X { x }","variables":{}}'),
            ),
            keep=tuple(Relevance),
        )
        assert len(found.operations) == 1
        assert found.operations[0].operation_name == "X"


class TestRedaction:
    def test_a_credential_reaches_no_output_but_is_still_counted(self) -> None:
        found = operations_of(
            entry(
                "a",
                "https://shop.example.com/graphql",
                method="POST",
                headers=Headers.from_pairs([("Authorization", "Bearer token-value-55120")]),
                body=json_body('{"operationName":"X","query":"query X { x }","variables":{}}'),
            )
        )
        assert found.redacted_values == 1
        assert "Redacted 1 value before reading this" in render_graphql(found)


class TestRendering:
    def test_explain_adds_the_rule_behind_a_recognized_operation(self) -> None:
        found = operations_of(
            entry(
                "a",
                "https://shop.example.com/graphql",
                method="POST",
                body=json_body('{"operationName":"X","query":"query X { x }","variables":{}}'),
            )
        )
        rendered = render_graphql(found, explain=True)
        assert "query X" in rendered
        assert found.operations[0].reason in rendered

    def test_reports_when_nothing_was_recognized(self) -> None:
        found = operations_of(entry("a", "https://shop.example.com/api/v1/orders"))
        assert "No GraphQL operation was recognized." in render_graphql(found)

    def test_as_json_round_trips_through_pydantic(self) -> None:
        found = operations_of(
            entry(
                "a",
                "https://shop.example.com/graphql",
                method="POST",
                body=json_body('{"operationName":"X","query":"query X { x }","variables":{}}'),
            )
        )
        restored = CaptureOperations.model_validate_json(found.as_json())
        assert restored == found


class TestShippedExample:
    def test_the_example_workflow_names_two_operations(self) -> None:
        found = find_graphql_operations(load_har(EXAMPLE_HAR), salt=SALT)
        assert [
            (operation.operation_type, operation.operation_name, operation.variable_names)
            for operation in found.operations
        ] == [
            (OperationType.QUERY, "ListOrders", ("page", "status")),
            (OperationType.MUTATION, "ConfirmOrder", ("orderId", "paymentMethod")),
        ]
