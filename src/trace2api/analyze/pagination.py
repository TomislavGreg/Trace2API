"""Detect the common shapes a workflow uses to page through a list of results.

A single recording cannot say how a workflow pages: the parameter that moves a listing
forward looks like any other value until it is seen to move. Two recordings of the same
workflow, fetched a page apart, are what say something, the same evidence ``diff`` and
``classify`` read. This module asks a narrower question of that evidence than either one:
not what a value is, but whether it says how far into a list a request reaches.

Three styles are recognized, each by the vocabulary an API commonly gives it:

``page-number``
    A page index a client increments by one to move forward, such as ``page`` or
    ``pageNumber``.
``offset``
    A count of results already seen, such as ``offset`` or ``skip``.
``cursor``
    An opaque continuation value one response hands out for the next request to send,
    such as ``cursor``, ``after``, or ``pageToken``. Relay style connections spell it
    ``after`` and ``before``, and a client keeps whatever the server handed out rather
    than computing it.

The rule for each style is a name, narrow and explainable on purpose: a parameter called
``page`` or ``offset`` is common enough to be worth recognizing, while a name that could
just as easily be something else, such as ``start`` or ``id``, is left alone rather than
guessed at. The page-number and offset styles are confirmed by shape as well, since a
value counting pages or results is always a whole number; a cursor is not required to be,
because a server is free to spell a continuation value however it likes.

Only a value that actually moved between the two recordings is reported, for the same
reason ``diff`` reports only what changed: a parameter that held still says nothing about
how the workflow paged this time, whatever its name.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from trace2api.analyze.diff import (
    AlignedRequest,
    AlignmentRule,
    ComparedCapture,
    ComparedValue,
    align_captures,
    alignment_reason,
    compare_requests,
    display_value,
    value_name,
)
from trace2api.analyze.relevance import DEFAULT_KEPT, Relevance
from trace2api.models import Capture

__all__ = [
    "PaginatedRequest",
    "PaginatedValue",
    "PaginationDetection",
    "PaginationRule",
    "PaginationStyle",
    "detect_pagination",
    "render_pagination",
]


class PaginationStyle(StrEnum):
    """The way a workflow pages through a list of results."""

    PAGE_NUMBER = "page-number"
    """A page index a client increments by one to move forward."""

    OFFSET = "offset"
    """A count of results already seen, advanced by however many a client just read."""

    CURSOR = "cursor"
    """An opaque continuation value one response hands out for the next request to send."""


class PaginationRule(StrEnum):
    """The rule that recognized one value as a pagination parameter."""

    PAGE_NUMBER_NAME = "page-number-name"
    OFFSET_NAME = "offset-name"
    CURSOR_NAME = "cursor-name"


_STYLE_BY_RULE: dict[PaginationRule, PaginationStyle] = {
    PaginationRule.PAGE_NUMBER_NAME: PaginationStyle.PAGE_NUMBER,
    PaginationRule.OFFSET_NAME: PaginationStyle.OFFSET,
    PaginationRule.CURSOR_NAME: PaginationStyle.CURSOR,
}

_RULE_REASONS: dict[PaginationRule, str] = {
    PaginationRule.PAGE_NUMBER_NAME: (
        "named after a page index, and every observed value is a whole number"
    ),
    PaginationRule.OFFSET_NAME: (
        "named after a count of results already seen, and every observed value is a whole number"
    ),
    PaginationRule.CURSOR_NAME: (
        "named after a continuation value an earlier response would have handed out"
    ),
}


class PaginatedValue(BaseModel):
    """One request value recognized as a pagination parameter, and why."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    location: str
    """Where the value sits, spelled as redaction and the comparison spell it."""

    style: PaginationStyle
    rule: PaginationRule
    name: str
    """The name the rule matched on, lowercased as it was sent."""

    left: str | None = None
    """What the first recording sent, or ``None`` where it sent nothing."""

    right: str | None = None

    @property
    def reason(self) -> str:
        """Return a one line explanation of why this value was recognized."""
        return _RULE_REASONS[self.rule]


class PaginatedRequest(BaseModel):
    """One request recognized in both recordings, with the pagination values it carries."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    left_position: int = Field(ge=1)
    """Where the request sits in the first capture, counting from one as ``inspect`` does."""

    right_position: int = Field(ge=1)
    method: str
    host: str
    path: str
    rule: AlignmentRule
    """How the two entries were recognized as the same request."""

    values: list[PaginatedValue] = Field(default_factory=list)

    @property
    def reason(self) -> str:
        """Return why the two entries were taken to be the same request."""
        return alignment_reason(self.rule)


class PaginationDetection(BaseModel):
    """The pagination values found across every request two recordings have in common."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    left: ComparedCapture
    right: ComparedCapture
    requests: list[PaginatedRequest] = Field(default_factory=list)
    redacted_values: int = Field(default=0, ge=0)

    @property
    def paginated(self) -> list[PaginatedRequest]:
        """Return the paired requests that carry at least one pagination value."""
        return [request for request in self.requests if request.values]

    def counts_by_style(self) -> dict[PaginationStyle, int]:
        """Return how many values reached each style, including the empty ones."""
        counts = dict.fromkeys(PaginationStyle, 0)
        for request in self.requests:
            for value in request.values:
                counts[value.style] += 1
        return counts

    def as_json(self) -> str:
        """Return the detection as a JSON document."""
        return json.dumps(self.model_dump(mode="json"), indent=2)


def detect_pagination(
    left: Capture,
    right: Capture,
    *,
    keep: Iterable[Relevance] = DEFAULT_KEPT,
    salt: bytes | None = None,
) -> PaginationDetection:
    """Detect page-number, offset, and cursor pagination across two recordings of a workflow.

    ``keep`` and ``salt`` mean what they mean for the comparison: only the entries whose
    relevance is kept take part, and one redaction salt is shared between the two
    recordings so a credential that happens to share a name with a pagination parameter
    still reads as one value.
    """
    aligned = align_captures(left, right, keep=keep, salt=salt)
    return PaginationDetection(
        left=aligned.left,
        right=aligned.right,
        requests=[_detect_request(request) for request in aligned.requests],
        redacted_values=aligned.redacted_values,
    )


def _detect_request(request: AlignedRequest) -> PaginatedRequest:
    """Return one paired request with the pagination values it carries, if any."""
    values = [
        detected
        for value in compare_requests(request.left, request.right)
        if value.is_changed
        for detected in (_match(value),)
        if detected is not None
    ]
    return PaginatedRequest(
        left_position=request.left_position,
        right_position=request.right_position,
        method=request.left.method,
        host=request.left.host,
        path=request.left.path,
        rule=request.rule,
        values=values,
    )


# Rules


def _match(value: ComparedValue) -> PaginatedValue | None:
    """Return the pagination verdict for ``value``, or ``None`` where no rule recognizes it.

    A name says what a value is for; the page-number and offset styles are confirmed by
    shape as well, since a page index or a count of results is always a whole number. A
    cursor carries no such constraint, because a server is free to spell one however it
    likes.
    """
    name = value_name(value.location)
    if name is None:
        return None
    rule = _rule_for(name, value.observed)
    if rule is None:
        return None
    return PaginatedValue(
        location=value.location,
        style=_STYLE_BY_RULE[rule],
        rule=rule,
        name=name,
        left=value.left,
        right=value.right,
    )


def _rule_for(name: str, observed: tuple[str, ...]) -> PaginationRule | None:
    """Return the rule ``name`` and ``observed`` satisfy, or ``None`` where none do."""
    if name in _CURSOR_NAMES:
        return PaginationRule.CURSOR_NAME
    if name in _PAGE_NUMBER_NAMES and _all_whole_numbers(observed):
        return PaginationRule.PAGE_NUMBER_NAME
    if name in _OFFSET_NAMES and _all_whole_numbers(observed):
        return PaginationRule.OFFSET_NAME
    return None


_PAGE_NUMBER_NAMES = frozenset({"page", "pagenumber", "pagenum", "pageindex", "pg"})
"""Names that say a value counts pages rather than results."""

_OFFSET_NAMES = frozenset({"offset", "skip", "startindex"})
"""Names that say a value counts results already seen."""

_CURSOR_NAMES = frozenset(
    {
        "after",
        "before",
        "continuation",
        "continuationtoken",
        "cursor",
        "endcursor",
        "endingbefore",
        "nextcursor",
        "nextpagetoken",
        "nexttoken",
        "pagetoken",
        "startcursor",
        "startingafter",
    }
)
"""Names that say a value is a continuation an earlier response would have handed out.

Deliberately narrow, and unlike the page-number and offset names, not confirmed by shape:
a page index or a count of results is always a whole number, but a cursor is whatever a
server chose to spell it as, opaque or not.
"""


def _all_whole_numbers(observed: tuple[str, ...]) -> bool:
    """Return whether every observed value is a non-negative whole number."""
    return bool(observed) and all(item.isdigit() for item in observed)


# Rendering


def render_pagination(detection: PaginationDetection, *, explain: bool = False) -> str:
    """Render ``detection`` as the text ``trace2api paginate`` writes.

    A request with no pagination value recognized is left out entirely, since most of a
    workflow is not paging through anything. ``explain`` adds the rule behind each value.
    """
    lines = _headline(detection)
    paginated = detection.paginated
    width = _location_width(paginated)
    for request in paginated:
        lines.append("")
        lines.extend(_request_lines(request, width, explain=explain))
    lines.append("")
    lines.extend(_summary(detection))
    return "\n".join(lines) + "\n"


def _headline(detection: PaginationDetection) -> list[str]:
    """Return the lines describing the two recordings being read."""
    return [
        f"Left:  {_side(detection.left)}",
        f"Right: {_side(detection.right)}",
        f"Reading {_count(len(detection.requests), 'paired request')} for pagination.",
    ]


def _side(capture: ComparedCapture) -> str:
    """Return one recording's provenance as it is shown above the detection."""
    return (
        f"{_count(capture.total_requests, 'request')} from {capture.source.value}, "
        f"recorded {capture.created_at.isoformat()}"
    )


def _location_width(requests: Iterable[PaginatedRequest]) -> int:
    """Return the width to pad locations to, so every value reads as one column."""
    locations = [len(value.location) for request in requests for value in request.values]
    return max(locations, default=0)


def _request_lines(request: PaginatedRequest, width: int, *, explain: bool) -> list[str]:
    """Return the heading and the pagination values of one paired request."""
    lines = [
        f"{request.left_position} -> {request.right_position}  "
        f"{request.method} {request.host}{request.path}"
    ]
    if request.rule is not AlignmentRule.IDENTICAL_PATH:
        lines.append(f"  paired on the {request.reason}")
    for value in request.values:
        lines.append(f"  {value.location.ljust(width)}  {value.style.value}  {_sides(value)}")
        if explain:
            lines.append(f"      {value.reason}")
    return lines


def _sides(value: PaginatedValue) -> str:
    """Return what a value shows of itself, never a credential."""
    if value.left is None:
        return f"{display_value(value.right or '')} (second recording only)"
    if value.right is None:
        return f"{display_value(value.left)} (first recording only)"
    return f"{display_value(value.left)} -> {display_value(value.right)}"


_STYLE_NOUNS: dict[PaginationStyle, str] = {
    PaginationStyle.PAGE_NUMBER: "page-number value",
    PaginationStyle.OFFSET: "offset value",
    PaginationStyle.CURSOR: "cursor value",
}


def _summary(detection: PaginationDetection) -> list[str]:
    """Return the lines accounting for the detection as a whole."""
    paginated = detection.paginated
    total = sum(len(request.values) for request in paginated)
    if not total:
        lines = ["No pagination was recognized between the two recordings."]
    else:
        counts = detection.counts_by_style()
        reached = ", ".join(
            _count(counts[style], _STYLE_NOUNS[style]) for style in PaginationStyle if counts[style]
        )
        lines = [
            f"Recognized {_count(total, 'pagination value')} in "
            f"{_count(len(paginated), 'request')}: {reached}."
        ]
    if detection.redacted_values:
        lines.append(
            f"Redacted {_count(detection.redacted_values, 'value')} before comparing, "
            "using one salt for both captures."
        )
    return lines


def _count(number: int, noun: str) -> str:
    """Return ``number`` and ``noun``, pluralized the ordinary way."""
    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"
