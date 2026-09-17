"""Decide which links of a traced capture a generated client can resolve at run time.

The trace reports a link as two places: a value sat here in one response, and the next
request sent it there. A client reproducing the workflow has one of two honest answers for
each such pair. Either it reads the value out of the response while it runs, which is what
makes it work against whatever the server hands it that day, or it cannot, and the
observed value stays in the code where a reader can see it for what it is.

This module decides which of the two a link gets, and says why whenever the answer is the
second one. It works on the locations the trace recorded rather than on any one language,
so what it produces is a place in a response and a place in a request: reading
``response.body.orders[0].id`` out of an httpx response and spelling it into a path
segment are the same instruction, written twice.

A link is resolved when all of these hold:

* The value is not a credential. Redaction replaced those with placeholders, so the
  capture no longer says which part of a response carried one, and a client is given them
  from the environment instead. Reading a token out of a response the capture cannot
  locate it in is not something this can offer.
* The response location addresses a header, a redirect target, or a field of a payload
  recorded as JSON.
* The request location addresses a path segment, a query parameter, a header, or a field
  of a JSON payload, and that place is still there in the capture.
* A value sitting inside a longer one lands in text rather than in a number, because
  splicing into a number would send a payload that is not the shape the server saw.

Every other link is reported unresolved with the reason behind it, and the client replays
the value as observed. That is a client that works once rather than one that works wrongly,
and the difference is written where it can be read.
"""

from __future__ import annotations

import builtins
import json
import keyword
import re
from collections.abc import Iterable, Sequence
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from trace2api.analyze.flow import CaptureFlows, FlowRule, ValueFlow
from trace2api.generate.headers import omission_rule
from trace2api.models import Body, Capture, Entry, Request, Response
from trace2api.sanitize import is_redacted

__all__ = [
    "AccessorKind",
    "DependencyResolution",
    "ResolvedDependency",
    "ResponseAccessor",
    "SiteKind",
    "SubstitutionSite",
    "UnresolvedDependency",
    "read_json_leaf",
    "resolve_dependencies",
    "write_json_leaf",
]


class AccessorKind(StrEnum):
    """What a client has to look at to read the value out of a response."""

    HEADER = "header"
    REDIRECT_URL = "redirect-url"
    JSON_FIELD = "json-field"


class SiteKind(StrEnum):
    """What a client has to rewrite to send the value on in a later request."""

    PATH_SEGMENT = "path-segment"
    QUERY_PARAMETER = "query-parameter"
    HEADER = "header"
    JSON_FIELD = "json-field"


class ResponseAccessor(BaseModel):
    """Where in a response the value is read from."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: AccessorKind
    name: str = ""
    """Header name, lowercased as the trace recorded it."""

    index: int | None = Field(default=None, ge=0)
    """Which of a repeated header carried it, when the response sent the name twice."""

    steps: list[str | int] = Field(default_factory=list)
    """Keys and array indices leading to a JSON field, outermost first."""


class SubstitutionSite(BaseModel):
    """Where in a later request the value is written."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: SiteKind
    name: str = ""
    """Header name, lowercased, or query parameter name as it was sent."""

    index: int | None = Field(default=None, ge=0)
    """Which of a repeated header or query parameter carried it."""

    segment: int | None = Field(default=None, ge=1)
    """Which path segment carried it, counting the non-empty ones from one."""

    steps: list[str | int] = Field(default_factory=list)
    """Keys and array indices leading to a JSON field, outermost first."""

    quoted: bool = True
    """Whether a JSON field held text. A number can hold nothing but the value itself."""


class ResolvedDependency(BaseModel):
    """One link a generated client reads at run time instead of replaying."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: int = Field(ge=1)
    target: int = Field(ge=1)
    source_location: str
    target_location: str
    rule: FlowRule
    value: str
    """The value as the capture observed it, which is what the site is rewritten around."""

    variable: str
    """The name the value is read into, shared by every request that sends it on."""

    accessor: ResponseAccessor
    site: SubstitutionSite


class UnresolvedDependency(BaseModel):
    """One link a generated client replays as observed, and why it cannot do better."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: int = Field(ge=1)
    target: int = Field(ge=1)
    source_location: str
    target_location: str
    reason: str


class DependencyResolution(BaseModel):
    """What a client can and cannot do about the links a capture holds."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    resolved: list[ResolvedDependency] = Field(default_factory=list)
    unresolved: list[UnresolvedDependency] = Field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        """Return whether the capture holds no links at all."""
        return not self.resolved and not self.unresolved

    @property
    def variables(self) -> int:
        """Return how many values the client reads out of a response."""
        return len({item.variable for item in self.resolved})

    @property
    def reads(self) -> list[ResolvedDependency]:
        """Return one entry per value read out of a response, in the order traced.

        A value two later requests send on is read once, so this is the list of variables
        a generated client binds.
        """
        seen: set[str] = set()
        reads: list[ResolvedDependency] = []
        for item in self.resolved:
            if item.variable not in seen:
                seen.add(item.variable)
                reads.append(item)
        return reads

    def read_after(self, position: int) -> list[ResolvedDependency]:
        """Return the values read once the response at ``position`` has arrived."""
        return [item for item in self.reads if item.source == position]

    def sent_by(self, position: int) -> list[ResolvedDependency]:
        """Return the links the request at ``position`` carries a read value into."""
        return [item for item in self.resolved if item.target == position]

    def replayed_by(self, position: int) -> list[UnresolvedDependency]:
        """Return the links the request at ``position`` sends as the capture observed them."""
        return [item for item in self.unresolved if item.target == position]

    def targets_of(self, variable: str) -> list[int]:
        """Return the positions that send ``variable`` on, earliest first."""
        return sorted({item.target for item in self.resolved if item.variable == variable})


CREDENTIAL_REASON = "the value is a credential the client is given from the environment instead"
"""Why a link carrying a secret is left alone. Stated once, because it is the common case."""

_UNREADABLE_RESPONSE = "the place in the response cannot be addressed field by field"
_UNPARSED_RESPONSE = "the payload it came from was not recorded as JSON"
_UNREADABLE_REQUEST = "the place in the request cannot be addressed field by field"
_UNPARSED_REQUEST = "the payload it is sent in was not recorded as JSON"
_DERIVED_HEADER = "the client sets that header itself rather than sending what was observed"
_INSIDE_A_NUMBER = "it sits inside a number, which cannot be rewritten without changing its type"
_NOT_IN_CAPTURE = "the exchange it was read from is not in the capture"


def resolve_dependencies(flows: CaptureFlows, capture: Capture) -> DependencyResolution:
    """Decide what a client can do about each link ``flows`` reports.

    ``capture`` must be the redacted capture the links were traced from. The decision
    depends on what the exchanges actually hold, such as whether a payload was recorded as
    JSON, so the two have to describe the same traffic.
    """
    entries = dict(enumerate(capture.entries, start=1))
    names = _Names()
    resolved: list[ResolvedDependency] = []
    unresolved: list[UnresolvedDependency] = []
    for flow in flows.flows:
        outcome = _resolve(flow, entries, names)
        if isinstance(outcome, ResolvedDependency):
            resolved.append(outcome)
        else:
            unresolved.append(_unresolved(flow, outcome))
    return DependencyResolution(resolved=resolved, unresolved=unresolved)


def _resolve(flow: ValueFlow, entries: dict[int, Entry], names: _Names) -> ResolvedDependency | str:
    """Return how ``flow`` is compiled, or the reason it cannot be."""
    if is_redacted(flow.value):
        return CREDENTIAL_REASON
    source = entries.get(flow.source.position)
    target = entries.get(flow.target.position)
    if source is None or target is None or source.response is None:
        return _NOT_IN_CAPTURE
    accessor = _accessor(flow.source.location, source.response)
    if isinstance(accessor, str):
        return accessor
    site = _site(flow.target.location, target.request)
    if isinstance(site, str):
        return site
    if not site.quoted and flow.rule is FlowRule.EMBEDDED_VALUE:
        return _INSIDE_A_NUMBER
    return ResolvedDependency(
        source=flow.source.position,
        target=flow.target.position,
        source_location=flow.source.location,
        target_location=flow.target.location,
        rule=flow.rule,
        value=flow.value,
        variable=names.assign(flow.source.position, flow.source.location, accessor),
        accessor=accessor,
        site=site,
    )


def _unresolved(flow: ValueFlow, reason: str) -> UnresolvedDependency:
    """Record that a link is replayed as observed."""
    return UnresolvedDependency(
        source=flow.source.position,
        target=flow.target.position,
        source_location=flow.source.location,
        target_location=flow.target.location,
        reason=reason,
    )


# Reading a location


_RESPONSE_REDIRECT = "response.redirect_url"
_RESPONSE_HEADERS = "response.headers."
_RESPONSE_BODY = "response.body"
_REQUEST_PATH = "request.path"
_REQUEST_QUERY = "request.query"
_REQUEST_HEADERS = "request.headers."
_REQUEST_BODY = "request.body"

_HEADER_LOCATION = re.compile(r"(?P<name>[^.\[\]]+)(?:\[(?P<index>\d+)\])?")
_NAMED_LOCATION = re.compile(r"\[(?P<name>.*?)\](?:\[(?P<index>\d+)\])?")
_SEGMENT_LOCATION = re.compile(r"\[(?P<index>\d+)\]")
_STEP = re.compile(r"\.(?P<key>[^.\[\]]+)|\[(?P<index>\d+)\]")


def _accessor(location: str, response: Response) -> ResponseAccessor | str:
    """Return how ``location`` is read out of ``response``, or why it cannot be."""
    if location == _RESPONSE_REDIRECT:
        return ResponseAccessor(kind=AccessorKind.REDIRECT_URL)
    rest = _after(location, _RESPONSE_HEADERS)
    if rest is not None:
        # A ``set-cookie`` location never arrives here: every cookie value is redacted, so
        # such a link is answered as a credential before the response is looked at.
        header = _HEADER_LOCATION.fullmatch(rest)
        if header is None:
            return _UNREADABLE_RESPONSE
        return ResponseAccessor(
            kind=AccessorKind.HEADER,
            name=header["name"],
            index=None if header["index"] is None else int(header["index"]),
        )
    rest = _after(location, _RESPONSE_BODY)
    if rest is None:
        return _UNREADABLE_RESPONSE
    body = response.body
    if body is None or not body.is_json:
        return _UNPARSED_RESPONSE
    steps = _steps(rest)
    if steps is None or _leaf_of(body, steps) is None:
        return _UNREADABLE_RESPONSE
    return ResponseAccessor(kind=AccessorKind.JSON_FIELD, steps=steps)


def _site(location: str, request: Request) -> SubstitutionSite | str:
    """Return how ``location`` is rewritten in ``request``, or why it cannot be."""
    rest = _after(location, _REQUEST_PATH)
    if rest is not None:
        return _path_site(rest, request)
    rest = _after(location, _REQUEST_QUERY)
    if rest is not None:
        return _query_site(rest, request)
    rest = _after(location, _REQUEST_HEADERS)
    if rest is not None:
        return _header_site(rest, request)
    rest = _after(location, _REQUEST_BODY)
    if rest is None:
        return _UNREADABLE_REQUEST
    return _body_site(rest, request.body)


def _path_site(rest: str, request: Request) -> SubstitutionSite | str:
    """Return the path segment ``rest`` names, when the request still has one there."""
    match = _SEGMENT_LOCATION.fullmatch(rest)
    if match is None:
        return _UNREADABLE_REQUEST
    segment = int(match["index"])
    if not 1 <= segment <= len(_path_segments(request.path)):
        return _UNREADABLE_REQUEST
    return SubstitutionSite(kind=SiteKind.PATH_SEGMENT, segment=segment)


def _query_site(rest: str, request: Request) -> SubstitutionSite | str:
    """Return the query parameter ``rest`` names, when the request still sends one."""
    named = _NAMED_LOCATION.fullmatch(rest)
    if named is None:
        return _UNREADABLE_REQUEST
    index = 0 if named["index"] is None else int(named["index"])
    if index >= len(request.query.get_all(named["name"])):
        return _UNREADABLE_REQUEST
    return SubstitutionSite(kind=SiteKind.QUERY_PARAMETER, name=named["name"], index=index)


def _header_site(rest: str, request: Request) -> SubstitutionSite | str:
    """Return the header ``rest`` names, when the request still sends one.

    A header a generated client derives for itself, such as ``Content-Length``, is not a
    place to write anything: nothing a client wrote there would be sent.
    """
    header = _HEADER_LOCATION.fullmatch(rest)
    if header is None:
        return _UNREADABLE_REQUEST
    index = 0 if header["index"] is None else int(header["index"])
    name = header["name"]
    sent = [item for item in request.headers if item.name.strip().lower() == name]
    if index >= len(sent):
        return _UNREADABLE_REQUEST
    if omission_rule(sent[index]) is not None:
        return _DERIVED_HEADER
    return SubstitutionSite(kind=SiteKind.HEADER, name=name, index=index)


def _body_site(rest: str, body: Body | None) -> SubstitutionSite | str:
    """Return the payload field ``rest`` names, when the payload was recorded as JSON."""
    if body is None or not body.is_json:
        return _UNPARSED_REQUEST
    steps = _steps(rest)
    if steps is None:
        return _UNREADABLE_REQUEST
    leaf = _leaf_of(body, steps)
    if leaf is None:
        return _UNREADABLE_REQUEST
    return SubstitutionSite(kind=SiteKind.JSON_FIELD, steps=steps, quoted=isinstance(leaf, str))


def _after(location: str, prefix: str) -> str | None:
    """Return what follows ``prefix`` in ``location``, or ``None`` when it starts elsewhere."""
    return location[len(prefix) :] if location.startswith(prefix) else None


def _steps(rest: str) -> list[str | int] | None:
    """Read ``.key`` and ``[index]`` steps, or return ``None`` when the location is not that.

    A key holding a dot or a bracket cannot be told from the syntax around it, so such a
    location is reported unreadable rather than guessed at.
    """
    steps: list[str | int] = []
    position = 0
    for match in _STEP.finditer(rest):
        if match.start() != position:
            return None
        key = match["key"]
        steps.append(key if key is not None else int(match["index"]))
        position = match.end()
    return steps if steps and position == len(rest) else None


def _path_segments(path: str) -> list[str]:
    """Return the non-empty segments of ``path``, the way a location numbers them."""
    return [segment for segment in path.split("/") if segment]


# Reading and writing a JSON payload


def read_json_leaf(document: Any, steps: Sequence[str | int]) -> str | int | float | None:
    """Return the scalar ``steps`` leads to, or ``None`` when they lead to anything else.

    A step onto a missing key, into a container, or onto a flag returns ``None``, because
    none of those is a value a workflow carries from one request to the next.
    """
    current = document
    for step in steps:
        if isinstance(step, int):
            if not isinstance(current, list) or not 0 <= step < len(current):
                return None
        elif not isinstance(current, dict) or step not in current:
            return None
        current = current[step]
    if isinstance(current, bool) or not isinstance(current, str | int | float):
        return None
    return current


def write_json_leaf(document: Any, steps: Sequence[str | int], value: str) -> None:
    """Replace the scalar ``steps`` leads to with ``value``.

    Only called for steps :func:`read_json_leaf` has already followed, so the walk cannot
    run off the document.
    """
    current = document
    for step in steps[:-1]:
        current = current[step]
    current[steps[-1]] = value


def _leaf_of(body: Body, steps: Sequence[str | int]) -> str | int | float | None:
    """Return the scalar ``steps`` leads to in a JSON payload, or ``None``."""
    try:
        document = json.loads(body.text or "")
    except ValueError:
        return None
    return read_json_leaf(document, steps)


# Naming what is read


_RESERVED = frozenset({"client", "httpx", "json", "main", "os", "response", "responses", "run"})
"""Names the generated module already uses for something else."""

_RESPONSE_VARIABLE = re.compile(r"response_\d+")
_FALLBACK_NAME = "value"


class _Names:
    """Hand one variable name to each value a response hands out."""

    def __init__(self) -> None:
        self._assigned: dict[tuple[int, str], str] = {}
        self._taken: set[str] = set()

    def assign(self, position: int, location: str, accessor: ResponseAccessor) -> str:
        """Return the name for the value at ``location``, the same one every time."""
        key = (position, location)
        name = self._assigned.get(key)
        if name is None:
            name = self._pick(_candidates(accessor))
            self._assigned[key] = name
            self._taken.add(name)
        return name

    def _pick(self, candidates: Iterable[str]) -> str:
        """Return the first candidate nothing else has claimed, numbering as a last resort."""
        options = [candidate for candidate in candidates if candidate]
        for option in options:
            if self._is_free(option):
                return option
        stem = options[0] if options else _FALLBACK_NAME
        suffix = 2
        while not self._is_free(f"{stem}_{suffix}"):
            suffix += 1
        return f"{stem}_{suffix}"

    def _is_free(self, name: str) -> bool:
        """Return whether ``name`` can be bound without shadowing something that matters."""
        return not (
            name in self._taken
            or name in _RESERVED
            or keyword.iskeyword(name)
            or hasattr(builtins, name)
            or _RESPONSE_VARIABLE.fullmatch(name)
        )


def _candidates(accessor: ResponseAccessor) -> list[str]:
    """Return the names the value could go by, the most specific reading first.

    A field is known by its own name where that is free, and by its parent's name and its
    own where it is not: ``id`` under ``orders`` reads as ``orders_id`` rather than as a
    number nobody can place. A name with no parent to fall back on says what it holds
    instead, which is how a top level ``id`` becomes ``id_value`` rather than shadowing a
    builtin.
    """
    if accessor.kind is AccessorKind.REDIRECT_URL:
        return _named_after("redirect_url")
    if accessor.kind is AccessorKind.HEADER:
        return _named_after(accessor.name)
    named = [str(step) for step in accessor.steps if isinstance(step, str)]
    if not named:
        return [_FALLBACK_NAME]
    return _named_after(named[-1], "_".join(named[-2:]), "_".join(named))


def _named_after(*parts: str) -> list[str]:
    """Return the readings of a name, each one tried before the value is numbered."""
    readings = [_identifier(part) for part in parts]
    return [*readings, f"{readings[0]}_{_FALLBACK_NAME}"]


def _identifier(text: str) -> str:
    """Return ``text`` as a lowercase Python identifier."""
    name = re.sub(r"[^0-9A-Za-z]+", "_", text).strip("_").lower()
    if not name or name[0].isdigit():
        return f"{_FALLBACK_NAME}_{name}" if name else _FALLBACK_NAME
    return name
