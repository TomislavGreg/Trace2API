"""Find the values a workflow learns from one response and sends in a later request.

A workflow is rarely a list of independent requests. One response hands out an
identifier, a cursor, or a token, and the next request carries it in its path, its query
string, a header, or its payload. Those links are what a direct client has to reproduce:
a client that replays the observed identifier works once, against the one order that
happened to be open while the recording was made, and a client that reads the identifier
out of the earlier response works every time.

This module reads a single capture and reports those links. It needs one recording
rather than two, because a value that came out of a response is evidence on its own: it
was observed in a response before it was ever sent.

Two rules recognize a link, and each one is recorded with the flow it produced:

``whole-value``
    A later request sent exactly what the response carried, such as an identifier that
    became a path segment.
``embedded-value``
    What the response carried appears inside a longer value the later request sent, such
    as a token inside an ``Authorization`` header or a cookie inside a ``Cookie`` header.
    Only a value that stands on its own counts, so a number is not found inside a longer
    number.

A value is only taken to come from a response when the workflow did not already have it.
A request that ran at or before the response sent the same value is proof that it did, so
such a value is scaffolding the workflow carried all along rather than something it was
handed. This is what keeps a response that echoes its own query string from reading as a
dependency.

Where a value came out of several responses, the earliest one is reported: that is where
the workflow learned it.

Ordering is by position in the capture, which is the order the requests began. A response
that arrived after a later request had already been sent is therefore still treated as
available to it, which can name a source that is one exchange too early. Both sides of
such a pair carry the value, so the link itself is real even when its source is.

Redaction runs first, as everywhere else. A credential keeps the same placeholder
wherever it appears in a capture, so a session cookie handed out by one response and sent
back by the next is recognized as one value and reported as ``(redacted)``: the
dependency is visible without the credential being shown.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Sequence
from datetime import datetime
from enum import StrEnum
from typing import Any, NamedTuple
from urllib.parse import parse_qsl

from pydantic import BaseModel, ConfigDict, Field

from trace2api.analyze.diff import display_value
from trace2api.analyze.relevance import DEFAULT_KEPT, Relevance, classify_capture
from trace2api.models import Body, Capture, CaptureSource, Entry, Headers, Request, Response
from trace2api.sanitize import redact_capture, split_secrets

__all__ = [
    "MINIMUM_EMBEDDED_LENGTH",
    "MINIMUM_LENGTH",
    "CaptureFlows",
    "FlowEndpoint",
    "FlowRule",
    "TracedRequest",
    "ValueFlow",
    "flow_reason",
    "render_flows",
    "standalone_index",
    "trace_flows",
]


class FlowRule(StrEnum):
    """How a value a request sent was recognized in an earlier response."""

    WHOLE_VALUE = "whole-value"
    """The request sent exactly what the response carried."""

    EMBEDDED_VALUE = "embedded-value"
    """What the response carried sits inside a longer value the request sent."""


_FLOW_REASONS: dict[FlowRule, str] = {
    FlowRule.WHOLE_VALUE: "the request sent exactly what the earlier response carried",
    FlowRule.EMBEDDED_VALUE: "what the earlier response carried sits inside the value sent",
}


def flow_reason(rule: FlowRule) -> str:
    """Return why ``rule`` takes a request value to have come from an earlier response."""
    return _FLOW_REASONS[rule]


class FlowEndpoint(BaseModel):
    """One end of a link: a request in the capture, and the value's place in it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    position: int = Field(ge=1)
    """Where the exchange sits in the capture, counting from one as ``inspect`` does."""

    method: str
    host: str
    path: str
    location: str
    """Where the value sits, spelled as redaction spells it."""


class TracedRequest(BaseModel):
    """One request the trace read, whether or not any value reached it or came from it.

    A link names the two requests it ties together, so a request that neither took a value
    from a response nor handed one out appears nowhere in the links. It was still read,
    and a stage that reasons about the workflow as a whole, such as the dependency graph,
    needs to know it was there.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    position: int = Field(ge=1)
    """Where the exchange sits in the capture, counting from one as ``inspect`` does."""

    method: str
    host: str
    path: str


class ValueFlow(BaseModel):
    """One value a response carried and a later request sent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: FlowEndpoint
    """The exchange whose response carried the value first."""

    target: FlowEndpoint
    rule: FlowRule
    value: str
    """The value as the response carried it, after redaction."""

    @property
    def reason(self) -> str:
        """Return a one line explanation of the link."""
        return flow_reason(self.rule)


class CaptureFlows(BaseModel):
    """Every value a capture was observed to carry from one response into a later request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: CaptureSource
    created_at: datetime
    total_requests: int = Field(default=0, ge=0)
    requests: list[TracedRequest] = Field(default_factory=list)
    """The entries that were read, the rest having been filtered as noise."""

    flows: list[ValueFlow] = Field(default_factory=list)
    redacted_values: int = Field(default=0, ge=0)
    """How many credentials were removed from the capture before it was read."""

    @property
    def traced_requests(self) -> int:
        """Return how many requests were read."""
        return len(self.requests)

    @property
    def dependent_requests(self) -> int:
        """Return how many requests carry at least one value from an earlier response."""
        return len({flow.target.position for flow in self.flows})

    def as_json(self) -> str:
        """Return the links as a JSON document."""
        return json.dumps(self.model_dump(mode="json"), indent=2)


def trace_flows(
    capture: Capture,
    *,
    keep: Iterable[Relevance] = DEFAULT_KEPT,
    salt: bytes | None = None,
) -> CaptureFlows:
    """Report the values ``capture`` carries from one response into a later request.

    Only the entries whose relevance is in ``keep`` are read, so a stylesheet that happens
    to quote an identifier is not offered as the source of one. Positions are still
    counted over the whole capture, so they match what ``inspect`` prints.

    A ``salt`` may be supplied to make the redaction reproducible. Whichever salt is used,
    it is one salt for the whole capture, which is what lets a credential handed out by
    one response be recognized in the next request.
    """
    sanitized = redact_capture(capture, salt=salt)
    kept = frozenset(keep)
    verdicts = {
        item.entry_id: item.relevance
        for item in classify_capture(sanitized.capture).classifications
    }
    traced = [
        _Positioned(position, entry)
        for position, entry in enumerate(sanitized.capture.entries, start=1)
        if verdicts[entry.id] in kept
    ]
    return CaptureFlows(
        source=sanitized.capture.metadata.source,
        created_at=sanitized.capture.metadata.created_at,
        total_requests=len(sanitized.capture),
        requests=[_traced_request(item) for item in traced],
        flows=_trace(traced),
        redacted_values=len(sanitized.report),
    )


def _traced_request(item: _Positioned) -> TracedRequest:
    """Record that an entry was read, and where it sat in the capture."""
    return TracedRequest(
        position=item.position,
        method=item.entry.request.method,
        host=item.entry.request.host,
        path=item.entry.request.path,
    )


class _Positioned(NamedTuple):
    """One entry together with where it sits in the capture it came from."""

    position: int
    entry: Entry


class _LocatedValue(NamedTuple):
    """One value of a request or a response, and where in it the value sits."""

    location: str
    value: str


class _Source(NamedTuple):
    """The first response observed to carry one value."""

    position: int
    request: Request
    location: str


MINIMUM_LENGTH = 4
"""Shortest value a link may be drawn from.

Anything shorter matches by coincidence more often than it matches for a reason: a status
word or a small number is sent by a workflow that never read it anywhere.
"""

MINIMUM_EMBEDDED_LENGTH = 8
"""Shortest value that may be recognized inside a longer one.

Finding a short value inside a longer one says very little, so the embedded rule asks for
more evidence than the whole value rule does.
"""


def _trace(entries: Sequence[_Positioned]) -> list[ValueFlow]:
    """Return the links between the given entries, in the order the requests were made."""
    sent = {position: _request_values(item.request) for position, item in entries}
    sources = _sources(entries, _first_sent(entries, sent))
    flows: list[ValueFlow] = []
    for position, entry in entries:
        for located in sent[position]:
            match = _match(located.value, sources, position)
            if match is not None:
                flows.append(_flow(match, position, entry.request, located.location))
    return flows


def _first_sent(
    entries: Sequence[_Positioned], sent: dict[int, list[_LocatedValue]]
) -> dict[str, int]:
    """Return, for each value a request carried, the first position that carried it."""
    first: dict[str, int] = {}
    for position, _ in entries:
        for located in sent[position]:
            first.setdefault(located.value, position)
    return first


def _sources(entries: Sequence[_Positioned], first_sent: dict[str, int]) -> dict[str, _Source]:
    """Return, for each value a response handed out, where the workflow first saw it.

    A value some request had already sent by then is not one the workflow was handed, so
    it is left out entirely rather than recorded against a later response.
    """
    sources: dict[str, _Source] = {}
    for position, entry in entries:
        if entry.response is None:
            continue
        for located in _response_values(entry.response):
            value = located.value
            if len(value) < MINIMUM_LENGTH or value in sources:
                continue
            already_sent = first_sent.get(value)
            if already_sent is not None and already_sent <= position:
                continue
            sources[value] = _Source(position, entry.request, located.location)
    return sources


class _Match(NamedTuple):
    """One request value recognized in an earlier response, and how."""

    rule: FlowRule
    value: str
    """The value as the response carried it, which for an embedded match is the part of
    the request value that came from there."""

    source: _Source


def _match(text: str, sources: dict[str, _Source], position: int) -> _Match | None:
    """Return where a request value came from, or ``None`` when no response carried it.

    The whole value rule runs first, so a value that came from a response outright is
    never reported as a fragment of itself found somewhere else.
    """
    source = sources.get(text)
    if source is not None and source.position < position:
        return _Match(FlowRule.WHOLE_VALUE, text, source)
    return _embedded_match(text, sources, position)


def _embedded_match(text: str, sources: dict[str, _Source], position: int) -> _Match | None:
    """Return the earliest response value that stands on its own inside ``text``.

    Sources are recorded in the order the responses arrived, so the first one found is the
    earliest one.
    """
    for value, source in sources.items():
        if (
            source.position < position
            and len(value) >= MINIMUM_EMBEDDED_LENGTH
            and _occurs_on_its_own(value, text)
        ):
            return _Match(FlowRule.EMBEDDED_VALUE, value, source)
    return None


_TOKEN_CHARACTER = re.compile(r"[A-Za-z0-9]")


def standalone_index(value: str, text: str) -> int:
    """Return where ``value`` first sits in ``text`` on its own, or ``-1`` when it never does.

    ``4711`` sits on its own in ``CNF-4711-88`` and inside ``24711`` it does not, which is
    the difference between a value carried along and a coincidence of digits. Generated code
    rewrites the same span this finds, so the rule that recognized a link and the rule that
    reproduces it stay one rule.
    """
    start = text.find(value)
    while start != -1:
        end = start + len(value)
        before = text[start - 1] if start else ""
        after = text[end] if end < len(text) else ""
        if not _TOKEN_CHARACTER.fullmatch(before) and not _TOKEN_CHARACTER.fullmatch(after):
            return start
        start = text.find(value, start + 1)
    return -1


def _occurs_on_its_own(value: str, text: str) -> bool:
    """Return whether ``value`` appears in ``text`` without running into its neighbours."""
    return standalone_index(value, text) != -1


def _flow(match: _Match, position: int, request: Request, location: str) -> ValueFlow:
    """Describe one link between a response and a request that came after it."""
    return ValueFlow(
        source=_endpoint(match.source.position, match.source.request, match.source.location),
        target=_endpoint(position, request, location),
        rule=match.rule,
        value=match.value,
    )


def _endpoint(position: int, request: Request, location: str) -> FlowEndpoint:
    """Describe one end of a link."""
    return FlowEndpoint(
        position=position,
        method=request.method,
        host=request.host,
        path=request.path,
        location=location,
    )


# Reading a request


_DERIVED_HEADERS = frozenset({"content-length"})
"""Request headers whose value follows from the request rather than from the workflow."""


def _request_values(request: Request) -> list[_LocatedValue]:
    """Return every value ``request`` sent, located where it sits."""
    values = [
        _LocatedValue(f"request.path[{index}]", segment)
        for index, segment in enumerate(_segments(request.path), start=1)
    ]
    values.extend(_named_values(_query_fields(request), "request.query"))
    values.extend(_header_values(request.headers, "request.headers", skip=_DERIVED_HEADERS))
    values.extend(_request_body_values(request.body))
    return [located for located in values if located.value]


def _segments(path: str) -> list[str]:
    """Return the non-empty segments of ``path``, in order."""
    return [segment for segment in path.split("/") if segment]


def _query_fields(request: Request) -> dict[str, tuple[str, ...]]:
    """Return the query values recorded under each name, first seen name first."""
    query = request.query
    return {name: query.get_all(name) for name in query.names()}


def _request_body_values(body: Body | None) -> list[_LocatedValue]:
    """Return the values a request payload carried.

    A payload that cannot be read as a structure is kept whole, so a token written into a
    text payload is still found inside it by the embedded rule.
    """
    location = "request.body"
    readable = _readable(body)
    if readable is None:
        return []
    structured = _structured_values(readable, location)
    if structured is not None:
        return structured
    return [_LocatedValue(location, readable.text or "")]


# Reading a response


_DERIVED_RESPONSE_HEADERS = frozenset(
    {
        "accept-ranges",
        "age",
        "cache-control",
        "connection",
        "content-encoding",
        "content-length",
        "content-type",
        "date",
        "expires",
        "keep-alive",
        "last-modified",
        "pragma",
        "server",
        "transfer-encoding",
        "vary",
    }
)
"""Response headers that describe the response itself rather than the workflow.

A request that asks for ``application/json`` and a response that declares it are not a
dependency, and neither is a clock reading a server put on its own reply.
"""


def _response_values(response: Response) -> list[_LocatedValue]:
    """Return every value ``response`` handed out, located where it sits."""
    values = _header_values(
        response.headers, "response.headers", skip=_DERIVED_RESPONSE_HEADERS, cookies=True
    )
    if response.redirect_url:
        values.append(_LocatedValue("response.redirect_url", response.redirect_url))
    values.extend(_response_body_values(response.body))
    return [located for located in values if located.value]


def _response_body_values(body: Body | None) -> list[_LocatedValue]:
    """Return the values a response payload handed out.

    A payload that reads as a structure is read field by field. One that does not is a
    page or a script, and the only values that can be located in it without parsing the
    language it is written in are the credential shaped ones redaction already found, so
    those are what is taken from it.
    """
    location = "response.body"
    readable = _readable(body)
    if readable is None:
        return []
    structured = _structured_values(readable, location)
    if structured is not None:
        return structured
    return [
        _LocatedValue(location, part.text)
        for part in split_secrets(readable.text or "")
        if part.is_secret
    ]


# Reading either


def _readable(body: Body | None) -> Body | None:
    """Return ``body`` when it carries text, and ``None`` when there is nothing to read.

    A binary payload is nothing to read: locating a value in one means decoding a format
    this project does not claim to understand, which is also why redaction leaves it as
    observed.
    """
    if body is None or body.is_empty or body.encoding is not None:
        return None
    return body


_FORM_MEDIA_TYPE = "application/x-www-form-urlencoded"


def _structured_values(body: Body, location: str) -> list[_LocatedValue] | None:
    """Return the fields of a payload, or ``None`` when it is not a structure."""
    if body.is_json:
        try:
            document = json.loads(body.text or "")
        except ValueError:
            return None
        return _json_values(document, location)
    if body.media_type == _FORM_MEDIA_TYPE:
        return _named_values(_form_fields(body), location)
    return None


def _form_fields(body: Body) -> dict[str, tuple[str, ...]]:
    """Return the values recorded under each field of a form encoded payload."""
    fields: dict[str, list[str]] = {}
    for name, value in parse_qsl(body.text or "", keep_blank_values=True):
        fields.setdefault(name, []).append(value)
    return {name: tuple(values) for name, values in fields.items()}


def _json_values(document: Any, location: str) -> list[_LocatedValue]:
    """Read a parsed payload leaf by leaf, keeping the path to each leaf.

    A leaf is read as the text it was sent as, so an identifier a response numbered and a
    later request spelled into a path are one value.
    """
    if isinstance(document, dict):
        return [
            located
            for key, item in document.items()
            for located in _json_values(item, f"{location}.{key}")
        ]
    if isinstance(document, list):
        return [
            located
            for index, item in enumerate(document)
            for located in _json_values(item, f"{location}[{index}]")
        ]
    if document is None or isinstance(document, bool):
        # A flag is not a value a workflow carries from one request to the next, and
        # ``true`` would otherwise link every payload that holds one to every other.
        return []
    text = document if isinstance(document, str) else json.dumps(document, ensure_ascii=False)
    return [_LocatedValue(location, text)]


def _named_values(fields: dict[str, tuple[str, ...]], location: str) -> list[_LocatedValue]:
    """Return named values, numbering the repeats of a name that was sent more than once."""
    values: list[_LocatedValue] = []
    for name, sent in fields.items():
        for index, value in enumerate(sent):
            where = f"{location}[{name}]"
            values.append(_LocatedValue(f"{where}[{index}]" if len(sent) > 1 else where, value))
    return values


def _header_values(
    headers: Headers,
    location: str,
    *,
    skip: frozenset[str],
    cookies: bool = False,
) -> list[_LocatedValue]:
    """Return header values, located by their lowercased names.

    ``Set-Cookie`` is read cookie by cookie when ``cookies`` asks for it, because what a
    later request sends back is one cookie value rather than the whole field with its
    attributes.
    """
    values: list[_LocatedValue] = []
    for name in dict.fromkeys(header.name.strip().lower() for header in headers):
        if name in skip:
            continue
        sent = headers.get_all(name)
        if cookies and name == "set-cookie":
            values.extend(_set_cookie_values(sent, location))
            continue
        for index, value in enumerate(sent):
            where = f"{location}.{name}"
            values.append(_LocatedValue(f"{where}[{index}]" if len(sent) > 1 else where, value))
    return values


def _set_cookie_values(sent: Iterable[str], location: str) -> list[_LocatedValue]:
    """Return the cookie a server set in each ``Set-Cookie`` field, without its attributes."""
    values: list[_LocatedValue] = []
    for field in sent:
        name, assignment, value = field.partition(";")[0].strip().partition("=")
        if assignment and value.strip():
            values.append(_LocatedValue(f"{location}.set-cookie[{name.strip()}]", value.strip()))
    return values


# Rendering


def render_flows(flows: CaptureFlows, *, explain: bool = False) -> str:
    """Render ``flows`` as the text ``trace2api flow`` writes.

    Links are grouped under the request that depends on them, which is the request a
    client cannot send until it has read the responses above it. ``explain`` adds the rule
    behind each link.
    """
    lines = _headline(flows)
    width = _columns(flows.flows)
    for position, group in _by_target(flows.flows):
        lines.append("")
        lines.extend(_target_lines(position, group, width, explain=explain))
    lines.append("")
    lines.extend(_summary(flows))
    return "\n".join(lines) + "\n"


class _Columns(NamedTuple):
    """How wide the two location columns are, so every link reads as one table."""

    target: int
    source: int


def _columns(flows: Sequence[ValueFlow]) -> _Columns:
    """Return the widths the listed links need, padding nothing when there are none."""
    return _Columns(
        target=max((len(flow.target.location) for flow in flows), default=0),
        source=max((len(flow.source.location) for flow in flows), default=0),
    )


def _by_target(flows: Sequence[ValueFlow]) -> list[tuple[int, list[ValueFlow]]]:
    """Group links under the request that depends on them, in the order they were made."""
    grouped: dict[int, list[ValueFlow]] = {}
    for flow in flows:
        grouped.setdefault(flow.target.position, []).append(flow)
    return sorted(grouped.items())


def _headline(flows: CaptureFlows) -> list[str]:
    """Return the lines describing the capture the links were read from."""
    return [
        f"Capture: {_count(flows.total_requests, 'request')} from {flows.source.value}, "
        f"recorded {flows.created_at.isoformat()}",
        f"Tracing {_count(flows.traced_requests, 'kept request')} for values that came "
        "from an earlier response.",
    ]


def _target_lines(
    position: int, flows: Sequence[ValueFlow], width: _Columns, *, explain: bool
) -> list[str]:
    """Return the heading and the links of one request that depends on earlier responses."""
    target = flows[0].target
    lines = [f"{position}  {target.method} {target.host}{target.path}"]
    for flow in flows:
        lines.append(
            f"  {flow.target.location.ljust(width.target)}  <- "
            f"{flow.source.position}  {flow.source.location.ljust(width.source)}  "
            f"{display_value(flow.value)}"
        )
        if explain:
            lines.append(f"      {flow.reason}")
    return lines


def _summary(flows: CaptureFlows) -> list[str]:
    """Return the lines accounting for the capture as a whole."""
    if not flows.flows:
        lines = ["No value a response carried was sent by a later request."]
    else:
        linked = len(flows.flows)
        moves = "flows" if linked == 1 else "flow"
        lines = [
            f"{_count(linked, 'value')} {moves} from a response into a later request.",
            f"{flows.dependent_requests} of {flows.traced_requests} kept requests depend "
            "on a response above them.",
        ]
    if flows.redacted_values:
        lines.append(
            f"Redacted {_count(flows.redacted_values, 'value')} before tracing, "
            "using one salt for the whole capture."
        )
    return lines


def _count(number: int, noun: str) -> str:
    """Return ``number`` and ``noun``, pluralized the ordinary way."""
    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"
