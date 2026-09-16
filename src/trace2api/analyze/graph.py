"""Read the values flowing through a capture as a graph of requests.

The links a trace reports are about single values: this field of that response became that
segment of this path. A client has to be built from something coarser. It needs to know
which requests can be sent straight away, which ones have to wait for a response, which
responses have to be read rather than discarded, and how long the chain is that cannot be
shortened. That is the same information seen request by request instead of value by value,
which is what this module assembles.

A node is a request that was read. An edge is everything one request needs from one
earlier response, so two values taken from the same response are one edge carrying two
links rather than two edges.

Every edge points backwards in the capture, because a value can only have been learned
from a response that had already arrived. The graph is therefore acyclic without having
to be checked for cycles, and a stage can be assigned to each request by counting: a
request that needs nothing earlier is in the first stage, and any other request is one
stage after the latest request it depends on. Requests in one stage need nothing from each
other, so a client is free to send them in any order, or at the same time.

The longest chain is the sequence of requests that cannot be collapsed: each one waits for
the one before it. It is the floor on how many round trips a direct client needs, whatever
else it does.

A link is named by where its value sat rather than by what the value was, so a workflow
that carries a credential from one request to the next reads as a place in a response and
a place in a request, with no value and not even a placeholder in between. Requests are
named as ``inspect`` names them, by method, host, and path, so an identifier that sits in
a path is as visible here as it is there.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import NamedTuple

from pydantic import BaseModel, ConfigDict, Field

from trace2api.analyze.flow import (
    CaptureFlows,
    FlowRule,
    TracedRequest,
    ValueFlow,
    flow_reason,
    trace_flows,
)
from trace2api.analyze.relevance import DEFAULT_KEPT, Relevance
from trace2api.models import Capture, CaptureSource

__all__ = [
    "Dependency",
    "DependencyLink",
    "GraphNode",
    "RequestGraph",
    "build_graph",
    "graph_capture",
    "render_graph",
]


class DependencyLink(BaseModel):
    """One value that ties a request to an earlier response."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_location: str
    """Where the value sat in the response, spelled as redaction spells it."""

    target_location: str
    """Where the later request sent it."""

    rule: FlowRule

    @property
    def reason(self) -> str:
        """Return a one line explanation of the link."""
        return flow_reason(self.rule)


class Dependency(BaseModel):
    """Everything one request needs from one earlier response."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: int = Field(ge=1)
    """Position of the exchange whose response has to be read."""

    target: int = Field(ge=1)
    """Position of the request that cannot be sent until it has been."""

    links: list[DependencyLink] = Field(default_factory=list)


class GraphNode(BaseModel):
    """One request, and where it sits in the workflow the capture recorded."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request: TracedRequest
    stage: int = Field(ge=1)
    """How many responses deep the request is, counting from one."""

    depends_on: list[int] = Field(default_factory=list)
    """Positions whose responses this request needs, earliest first."""

    needed_by: list[int] = Field(default_factory=list)
    """Positions that need this response, earliest first."""

    @property
    def position(self) -> int:
        """Return where the request sits in the capture."""
        return self.request.position


class RequestGraph(BaseModel):
    """The requests of a capture and what each one waits for."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: CaptureSource
    created_at: datetime
    total_requests: int = Field(default=0, ge=0)
    nodes: list[GraphNode] = Field(default_factory=list)
    """The requests that were read, in the order they were made."""

    dependencies: list[Dependency] = Field(default_factory=list)
    redacted_values: int = Field(default=0, ge=0)
    """How many credentials were removed from the capture before it was read."""

    @property
    def graphed_requests(self) -> int:
        """Return how many requests the graph holds."""
        return len(self.nodes)

    @property
    def dependent_requests(self) -> int:
        """Return how many requests wait for an earlier response."""
        return sum(1 for node in self.nodes if node.depends_on)

    @property
    def required_responses(self) -> list[int]:
        """Return the positions whose responses a client has to read, earliest first."""
        return sorted({dependency.source for dependency in self.dependencies})

    @property
    def stages(self) -> list[list[GraphNode]]:
        """Return the nodes grouped by stage, the requests that wait for nothing first."""
        grouped: dict[int, list[GraphNode]] = {}
        for node in self.nodes:
            grouped.setdefault(node.stage, []).append(node)
        return [grouped[stage] for stage in sorted(grouped)]

    @property
    def longest_chain(self) -> list[int]:
        """Return the positions of the longest run of requests that must be sent in order."""
        return _longest_chain(self.nodes)

    def as_json(self) -> str:
        """Return the graph as a JSON document."""
        return json.dumps(self.model_dump(mode="json"), indent=2)


def graph_capture(
    capture: Capture,
    *,
    keep: Iterable[Relevance] = DEFAULT_KEPT,
    salt: bytes | None = None,
) -> RequestGraph:
    """Trace ``capture`` and read the links it holds as a graph of requests.

    ``keep`` and ``salt`` are handed to the trace, which is where redaction and relevance
    filtering happen.
    """
    return build_graph(trace_flows(capture, keep=keep, salt=salt))


def build_graph(flows: CaptureFlows) -> RequestGraph:
    """Assemble the graph the links in ``flows`` describe.

    Every request the trace read becomes a node, including one that neither takes a value
    from a response nor hands one out: it is part of the workflow, and a client that left
    it out would not reproduce the same result.
    """
    dependencies = _dependencies(flows.flows)
    return RequestGraph(
        source=flows.source,
        created_at=flows.created_at,
        total_requests=flows.total_requests,
        nodes=_nodes(flows.requests, dependencies),
        dependencies=dependencies,
        redacted_values=flows.redacted_values,
    )


class _Pair(NamedTuple):
    """The two ends of an edge: the response read, and the request that needed it."""

    source: int
    target: int


def _dependencies(flows: Sequence[ValueFlow]) -> list[Dependency]:
    """Gather the links between each pair of requests into one edge apiece."""
    grouped: dict[_Pair, list[DependencyLink]] = {}
    for flow in flows:
        pair = _Pair(flow.source.position, flow.target.position)
        grouped.setdefault(pair, []).append(
            DependencyLink(
                source_location=flow.source.location,
                target_location=flow.target.location,
                rule=flow.rule,
            )
        )
    return [
        Dependency(source=pair.source, target=pair.target, links=links)
        for pair, links in sorted(grouped.items())
    ]


def _nodes(
    requests: Sequence[TracedRequest], dependencies: Sequence[Dependency]
) -> list[GraphNode]:
    """Place each request in the graph, in the order the requests were made."""
    depends_on: dict[int, list[int]] = {}
    needed_by: dict[int, list[int]] = {}
    for dependency in dependencies:
        depends_on.setdefault(dependency.target, []).append(dependency.source)
        needed_by.setdefault(dependency.source, []).append(dependency.target)
    stages: dict[int, int] = {}
    nodes: list[GraphNode] = []
    for request in sorted(requests, key=lambda item: item.position):
        needs = sorted(depends_on.get(request.position, ()))
        # Every edge points backwards, so the stage of each request this one waits for has
        # already been settled. A dependency on a request the trace did not read cannot
        # happen for the same reason, and counting it as the first stage would be wrong
        # rather than merely imprecise, so it is left to fail loudly if it ever does.
        stages[request.position] = 1 + max((stages[position] for position in needs), default=0)
        nodes.append(
            GraphNode(
                request=request,
                stage=stages[request.position],
                depends_on=needs,
                needed_by=sorted(needed_by.get(request.position, ())),
            )
        )
    return nodes


def _longest_chain(nodes: Sequence[GraphNode]) -> list[int]:
    """Return the longest run of requests where each one waits for the one before it.

    Where two runs are as long as each other, the one whose requests were made earliest is
    reported, so the same capture always reports the same chain.
    """
    previous: dict[int, int | None] = {}
    deepest: GraphNode | None = None
    by_position = {node.position: node for node in nodes}
    for node in nodes:
        previous[node.position] = max(
            node.depends_on,
            key=lambda position: (by_position[position].stage, -position),
            default=None,
        )
        if deepest is None or node.stage > deepest.stage:
            deepest = node
    if deepest is None:
        return []
    chain = [deepest.position]
    while (earlier := previous[chain[-1]]) is not None:
        chain.append(earlier)
    return list(reversed(chain))


# Rendering


def render_graph(graph: RequestGraph, *, explain: bool = False) -> str:
    """Render ``graph`` as the text ``trace2api graph`` writes.

    Requests are listed by stage, so what a client can send at once reads as one block and
    what it has to wait for reads as the next. ``explain`` adds the rule behind each link.
    """
    lines = _headline(graph)
    width = _width(graph)
    for stage, nodes in enumerate(graph.stages, start=1):
        lines.append("")
        lines.append(_stage_heading(stage, len(nodes)))
        for node in nodes:
            lines.extend(_node_lines(node, graph, width, explain=explain))
    lines.append("")
    lines.extend(_summary(graph))
    return "\n".join(lines) + "\n"


class _Width(NamedTuple):
    """How wide the aligned columns are, so the whole graph reads as one table."""

    method: int
    source_location: int


def _width(graph: RequestGraph) -> _Width:
    """Return the widths the listed requests and links need."""
    return _Width(
        method=max((len(node.request.method) for node in graph.nodes), default=0),
        source_location=max(
            (len(link.source_location) for item in graph.dependencies for link in item.links),
            default=0,
        ),
    )


def _headline(graph: RequestGraph) -> list[str]:
    """Return the lines describing the capture the graph was read from."""
    return [
        f"Capture: {_count(graph.total_requests, 'request')} from {graph.source.value}, "
        f"recorded {graph.created_at.isoformat()}",
        f"Reading {_count(graph.graphed_requests, 'kept request')} as a dependency graph.",
    ]


def _stage_heading(stage: int, requests: int) -> str:
    """Return the heading of one stage, saying what the requests in it are waiting for.

    A request is only ever one stage after the latest response it needs, so every stage
    after the first waits for the one immediately before it.
    """
    counted = _count(requests, "request")
    if stage == 1:
        needs = "that needs" if requests == 1 else "that need"
        return f"Stage {stage}: {counted} {needs} nothing earlier"
    waits = "that waits" if requests == 1 else "that wait"
    return f"Stage {stage}: {counted} {waits} for stage {stage - 1}"


def _node_lines(node: GraphNode, graph: RequestGraph, width: _Width, *, explain: bool) -> list[str]:
    """Return the line naming one request and the lines naming what it waits for."""
    request = node.request
    lines = [
        f"  {request.position}  {request.method.ljust(width.method)}  {request.host}{request.path}"
    ]
    for dependency in graph.dependencies:
        if dependency.target != request.position:
            continue
        for link in dependency.links:
            lines.append(
                f"       needs {dependency.source}  "
                f"{link.source_location.ljust(width.source_location)}  ->  "
                f"{link.target_location}"
            )
            if explain:
                lines.append(f"           {link.reason}")
    return lines


def _summary(graph: RequestGraph) -> list[str]:
    """Return the lines accounting for the workflow as a whole."""
    independent = graph.graphed_requests - graph.dependent_requests
    lines = [
        f"{_count(graph.graphed_requests, 'kept request')}: {graph.dependent_requests} "
        f"waiting for an earlier response, {independent} able to be sent first."
    ]
    required = graph.required_responses
    if required:
        positions = ", ".join(str(position) for position in required)
        lines.append(
            f"{_count(len(required), 'response')} must be read by the client: {positions}."
        )
    chain = graph.longest_chain
    if len(chain) > 1:
        lines.append(
            f"Longest chain: {' -> '.join(str(position) for position in chain)}, "
            f"{_count(len(chain), 'request')} that cannot be sent at once."
        )
    if graph.redacted_values:
        lines.append(
            f"Redacted {_count(graph.redacted_values, 'value')} before reading this, "
            "using one salt for the whole capture."
        )
    return lines


def _count(number: int, noun: str) -> str:
    """Return ``number`` and ``noun``, pluralized the ordinary way."""
    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"
