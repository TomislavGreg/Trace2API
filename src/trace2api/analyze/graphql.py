"""Recognize GraphQL requests and read the operation each one names.

A REST endpoint is named by its path; every GraphQL request goes to the same one, and what
it asks for is carried in the payload instead. A client cannot tell two GraphQL requests to
the same path apart the way it tells two different REST resources apart: one might read a
list of orders and the next confirm a payment, and only the query, mutation, or subscription
it names says which. This module reads a single capture and identifies the requests that
carry a GraphQL operation, naming its type and, where the workflow gave it one, its name.

Three shapes are recognized, each by how a GraphQL client is known to send a request:

``json-body``
    The common case: a POST with a JSON body holding a ``query`` field. It is recognized
    either because an ``operationName`` or a ``variables`` field sits alongside it, or
    because the query text itself opens with the ``query``, ``mutation``, or
    ``subscription`` keyword. Either signal is enough on its own, and requiring at least one
    of them is what keeps a workflow's own ``query`` field, such as a search box, from being
    read as a GraphQL request when it names no operation and carries no variables.

``graphql-media-type``
    A request sent with ``Content-Type: application/graphql``, where the body is the query
    document itself rather than a JSON envelope.

``query-string``
    A GET request carrying a ``query`` parameter, the shape a client sends to a cache
    friendly, or persisted, GraphQL endpoint. The same two signals as the JSON body apply:
    an ``operationName`` or a ``variables`` parameter alongside it, or a query text that
    opens with an operation keyword.

Only the shape of an operation is reported: its type, its name where one was given, and the
names of the variables it declared. What the operation actually asks for, and any literal
value its document carries, is never printed, the same restraint ``inspect`` applies to a
query string and ``classify`` applies to a secret.

Redaction runs first, as everywhere else a capture is read.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from datetime import datetime
from enum import StrEnum
from typing import Any, NamedTuple

from pydantic import BaseModel, ConfigDict, Field

from trace2api.analyze.relevance import DEFAULT_KEPT, Relevance, classify_capture
from trace2api.models import Body, Capture, CaptureSource, Request
from trace2api.sanitize import redact_capture

__all__ = [
    "CaptureOperations",
    "GraphQLOperation",
    "GraphQLRule",
    "OperationType",
    "find_graphql_operations",
    "graphql_reason",
    "render_graphql",
]


class OperationType(StrEnum):
    """The three kinds of operation a GraphQL document may declare."""

    QUERY = "query"
    MUTATION = "mutation"
    SUBSCRIPTION = "subscription"


class GraphQLRule(StrEnum):
    """How a request was recognized as carrying a GraphQL operation."""

    JSON_BODY = "json-body"
    GRAPHQL_MEDIA_TYPE = "graphql-media-type"
    QUERY_STRING = "query-string"


_RULE_REASONS: dict[GraphQLRule, str] = {
    GraphQLRule.JSON_BODY: (
        "the JSON body carries a query field alongside an operation name or variables, "
        "or a query field whose text opens with an operation keyword"
    ),
    GraphQLRule.GRAPHQL_MEDIA_TYPE: (
        "the body is sent as application/graphql, the query document itself"
    ),
    GraphQLRule.QUERY_STRING: (
        "the query string carries a query parameter alongside an operation name or "
        "variables, or one whose text opens with an operation keyword"
    ),
}


def graphql_reason(rule: GraphQLRule) -> str:
    """Return why ``rule`` takes a request to carry a GraphQL operation."""
    return _RULE_REASONS[rule]


class GraphQLOperation(BaseModel):
    """One request recognized as carrying a GraphQL operation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    position: int = Field(ge=1)
    """Where the exchange sits in the capture, counting from one as ``inspect`` does."""

    method: str
    host: str
    path: str
    rule: GraphQLRule

    operation_type: OperationType
    """The kind of operation the document declares, or ``query`` for the shorthand form
    the GraphQL language defines as one."""

    operation_name: str | None = None
    """``None`` for an anonymous operation."""

    variable_names: tuple[str, ...] = Field(default_factory=tuple)
    """The names the operation declared, sorted. Never the values supplied for them."""

    @property
    def reason(self) -> str:
        """Return a one line explanation of why this request was recognized."""
        return graphql_reason(self.rule)


class CaptureOperations(BaseModel):
    """Every GraphQL operation a capture was observed to send."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: CaptureSource
    created_at: datetime
    total_requests: int = Field(default=0, ge=0)
    kept_requests: int = Field(default=0, ge=0)
    """How many requests were read, the rest having been filtered as noise."""

    operations: list[GraphQLOperation] = Field(default_factory=list)
    redacted_values: int = Field(default=0, ge=0)
    """How many credentials were removed from the capture before it was read."""

    def as_json(self) -> str:
        """Return the operations as a JSON document."""
        return json.dumps(self.model_dump(mode="json"), indent=2)


def find_graphql_operations(
    capture: Capture,
    *,
    keep: Iterable[Relevance] = DEFAULT_KEPT,
    salt: bytes | None = None,
) -> CaptureOperations:
    """Recognize the requests of ``capture`` that carry a GraphQL operation.

    Only the entries whose relevance is in ``keep`` are read, so a stylesheet is never
    offered as a candidate. Positions are counted over the whole capture, matching
    ``inspect``. The capture is redacted first, the same as every other analysis stage.
    """
    sanitized = redact_capture(capture, salt=salt)
    kept = frozenset(keep)
    verdicts = {
        item.entry_id: item.relevance
        for item in classify_capture(sanitized.capture).classifications
    }
    readable = [
        (position, entry)
        for position, entry in enumerate(sanitized.capture.entries, start=1)
        if verdicts[entry.id] in kept
    ]
    operations = [
        operation
        for position, entry in readable
        for operation in (_detect(position, entry.request),)
        if operation is not None
    ]
    return CaptureOperations(
        source=sanitized.capture.metadata.source,
        created_at=sanitized.capture.metadata.created_at,
        total_requests=len(sanitized.capture),
        kept_requests=len(readable),
        operations=operations,
        redacted_values=len(sanitized.report),
    )


# Detection


_GRAPHQL_MEDIA_TYPE = "application/graphql"

_SIBLING_FIELDS = frozenset({"operationName", "variables"})

_OPERATION_KEYWORD = re.compile(
    r"^\s*(query|mutation|subscription)\b\s*([A-Za-z_][A-Za-z0-9_]*)?", re.IGNORECASE
)


class _Document(NamedTuple):
    """A GraphQL document found in a request, before it is turned into an operation."""

    text: str
    operation_name: str | None
    variables: dict[str, Any] | None


def _detect(position: int, request: Request) -> GraphQLOperation | None:
    """Return the GraphQL operation ``request`` carries, or ``None`` where it carries none."""
    document = _from_json_body(request.body) or _from_graphql_media_type(request.body)
    if document is None:
        document = _from_query_string(request)
    if document is None:
        return None
    rule = (
        GraphQLRule.QUERY_STRING
        if request.method == "GET"
        else (
            GraphQLRule.GRAPHQL_MEDIA_TYPE
            if request.body is not None and request.body.media_type == _GRAPHQL_MEDIA_TYPE
            else GraphQLRule.JSON_BODY
        )
    )
    return _operation(position, request, rule, document)


def _from_json_body(body: Body | None) -> _Document | None:
    """Return the document a JSON body carries, or ``None`` where it carries none."""
    if body is None or not body.is_json:
        return None
    try:
        payload = json.loads(body.text or "")
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    query = payload.get("query")
    if not isinstance(query, str) or not query.strip():
        return None
    has_sibling = any(field in payload for field in _SIBLING_FIELDS)
    if not has_sibling and not _OPERATION_KEYWORD.match(query):
        return None
    operation_name = payload.get("operationName")
    variables = payload.get("variables")
    return _Document(
        text=query,
        operation_name=operation_name if isinstance(operation_name, str) else None,
        variables=variables if isinstance(variables, dict) else None,
    )


def _from_graphql_media_type(body: Body | None) -> _Document | None:
    """Return the document a raw ``application/graphql`` body carries."""
    if body is None or body.is_empty or body.media_type != _GRAPHQL_MEDIA_TYPE:
        return None
    return _Document(text=body.text or "", operation_name=None, variables=None)


def _from_query_string(request: Request) -> _Document | None:
    """Return the document a ``query`` parameter carries, or ``None`` where it carries none."""
    query_param = request.query.get("query")
    if not query_param or not query_param.strip():
        return None
    operation_name = request.query.get("operationName")
    variables_param = request.query.get("variables")
    has_sibling = operation_name is not None or variables_param is not None
    if not has_sibling and not _OPERATION_KEYWORD.match(query_param):
        return None
    return _Document(
        text=query_param,
        operation_name=operation_name,
        variables=_parse_variables(variables_param),
    )


def _parse_variables(text: str | None) -> dict[str, Any] | None:
    """Return a ``variables`` parameter parsed as a JSON object, or ``None`` where it is not one."""
    if text is None:
        return None
    try:
        parsed = json.loads(text)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _operation(
    position: int, request: Request, rule: GraphQLRule, document: _Document
) -> GraphQLOperation:
    """Turn a detected document into the operation it names.

    A document with no operation keyword is the shorthand form, which the GraphQL language
    defines as an anonymous query rather than something this project has to infer.
    """
    match = _OPERATION_KEYWORD.match(document.text)
    operation_type = OperationType(match.group(1).lower()) if match else OperationType.QUERY
    name = document.operation_name or (match.group(2) if match else None)
    variable_names = tuple(sorted(document.variables)) if document.variables else ()
    return GraphQLOperation(
        position=position,
        method=request.method,
        host=request.host,
        path=request.path,
        rule=rule,
        operation_type=operation_type,
        operation_name=name,
        variable_names=variable_names,
    )


# Rendering


def render_graphql(operations: CaptureOperations, *, explain: bool = False) -> str:
    """Render ``operations`` as the text ``trace2api graphql`` writes.

    A request that carries no GraphQL operation is left out entirely, the same restraint
    ``paginate`` applies to a value that never moved. ``explain`` adds the rule behind each
    recognized operation.
    """
    lines = _headline(operations)
    for operation in operations.operations:
        lines.append("")
        lines.extend(_operation_lines(operation, explain=explain))
    lines.append("")
    lines.extend(_summary(operations))
    return "\n".join(lines) + "\n"


def _headline(operations: CaptureOperations) -> list[str]:
    """Return the lines describing the capture the operations were read from."""
    return [
        f"Capture: {_count(operations.total_requests, 'request')} from "
        f"{operations.source.value}, recorded {operations.created_at.isoformat()}",
        f"Reading {_count(operations.kept_requests, 'kept request')} for GraphQL operations.",
    ]


def _operation_lines(operation: GraphQLOperation, *, explain: bool) -> list[str]:
    """Return the heading and the detail of one recognized operation."""
    lines = [f"{operation.position}  {operation.method}  {operation.host}{operation.path}"]
    name = operation.operation_name or "(anonymous)"
    detail = f"  {operation.operation_type.value} {name}"
    if operation.variable_names:
        detail += "  variables: " + ", ".join(operation.variable_names)
    lines.append(detail)
    if explain:
        lines.append(f"      {operation.reason}")
    return lines


def _summary(operations: CaptureOperations) -> list[str]:
    """Return the lines accounting for the capture as a whole."""
    total = len(operations.operations)
    if not total:
        lines = ["No GraphQL operation was recognized."]
    else:
        lines = [f"Recognized {_count(total, 'GraphQL operation')}."]
    if operations.redacted_values:
        lines.append(f"Redacted {_count(operations.redacted_values, 'value')} before reading this.")
    return lines


def _count(number: int, noun: str) -> str:
    """Return ``number`` and ``noun``, pluralized the ordinary way."""
    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"
