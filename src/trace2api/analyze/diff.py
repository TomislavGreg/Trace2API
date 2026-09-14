"""Compare two recordings of one workflow and report which request values changed.

Performing the same workflow twice is the cheapest experiment available: whatever differs
between the two recordings is where the workflow takes its values from, and whatever
holds still is scaffolding. This module runs that comparison and stops there. What a
changed value *is*, an input the operator supplied, an identifier the server minted, or a
constant that happens to differ, is the next stage's question.

The comparison has two steps.

Entries are paired first. Two recordings of one workflow rarely line up by position: a
bundle is fetched on the first run and served from cache on the second, a poll fires twice
instead of once, and a path carries an identifier that differs by definition. So pairing
is by what identifies a request rather than by where it sits, and the rule that paired two
entries is kept with the pair. An entry with no counterpart is reported as unpaired rather
than forced onto the nearest candidate, because a wrong pairing invents changes that were
never observed.

Each pair is then compared value by value: path segments, query parameters, headers, and
payload fields. Every change is located with the same names redaction uses, such as
``request.query[status]`` or ``request.body.payment_method``, so a difference can be
traced back to the exact place it was observed.

Both captures are redacted before anything is compared, and with one salt shared between
them. A credential that stayed the same across the two runs reads as the same placeholder
on both sides and reports as unchanged, while one that was reissued reports as changed
without either value being shown.
"""

from __future__ import annotations

import json
import re
import secrets
from collections import deque
from collections.abc import Callable, Iterable, Sequence
from datetime import datetime
from enum import StrEnum
from typing import Any, NamedTuple, Self
from urllib.parse import parse_qsl

from pydantic import BaseModel, ConfigDict, Field, model_validator

from trace2api.analyze.relevance import DEFAULT_KEPT, Relevance, classify_capture
from trace2api.models import Body, Capture, CaptureSource, Entry, QueryParams, Request
from trace2api.sanitize import is_redacted, redact_capture, split_secrets

__all__ = [
    "REDACTED_DISPLAY",
    "VALUE_DISPLAY_WIDTH",
    "AlignedCaptures",
    "AlignedRequest",
    "AlignmentRule",
    "CaptureDiff",
    "ChangeKind",
    "ComparedCapture",
    "ComparedValue",
    "PairedRequest",
    "UnpairedRequest",
    "ValueChange",
    "align_captures",
    "alignment_reason",
    "compare_requests",
    "diff_captures",
    "display_value",
    "render_diff",
]


class AlignmentRule(StrEnum):
    """How two entries were recognized as the same request of one workflow."""

    IDENTICAL_PATH = "identical-path"
    """Same method, host, and path. Repeats pair in the order they were observed."""

    PATH_SHAPE = "path-shape"
    """Same path once identifier shaped segments are set aside."""

    SINGLE_SEGMENT = "single-segment"
    """Same path but for one segment, with no other candidate it could have been."""


_ALIGNMENT_REASONS: dict[AlignmentRule, str] = {
    AlignmentRule.IDENTICAL_PATH: "same method, host, and path",
    AlignmentRule.PATH_SHAPE: "same path once identifier shaped segments are set aside",
    AlignmentRule.SINGLE_SEGMENT: "same path but for one segment, and nothing else it could be",
}


def alignment_reason(rule: AlignmentRule) -> str:
    """Return why ``rule`` takes two entries to be the same request of one workflow."""
    return _ALIGNMENT_REASONS[rule]


class ChangeKind(StrEnum):
    """What happened to one value between the two recordings."""

    CHANGED = "changed"
    ADDED = "added"
    """Present in the second recording only."""

    REMOVED = "removed"
    """Present in the first recording only."""


class ComparedValue(NamedTuple):
    """One request value as each recording sent it, located where it was observed.

    A side is ``None`` where that recording did not send the value at all, which is how a
    field one run added or dropped is told apart from one it sent empty.
    """

    location: str
    left: str | None
    right: str | None

    @property
    def is_changed(self) -> bool:
        """Return whether the two recordings sent different values."""
        return self.left != self.right

    @property
    def observed(self) -> tuple[str, ...]:
        """Return the values that were actually sent, one side or both."""
        return tuple(value for value in (self.left, self.right) if value is not None)


class ValueChange(BaseModel):
    """One request value that differs, and what it was on each side."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    location: str
    """Where the value sits, spelled as redaction spells it."""

    kind: ChangeKind
    left: str | None = None
    right: str | None = None

    @model_validator(mode="after")
    def _check_sides(self) -> Self:
        present = {ChangeKind.CHANGED: (True, True), ChangeKind.ADDED: (False, True)}.get(
            self.kind, (True, False)
        )
        if (self.left is not None, self.right is not None) != present:
            raise ValueError(f"a {self.kind.value} value does not carry both sides")
        return self


class PairedRequest(BaseModel):
    """One request recognized in both recordings, with the values that differ."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    left_position: int = Field(ge=1)
    """Where the request sits in the first capture, counting from one as ``inspect`` does."""

    right_position: int = Field(ge=1)
    method: str
    host: str
    path: str
    """The path as the first recording observed it. A path that differs says so in the changes."""

    rule: AlignmentRule
    changes: list[ValueChange] = Field(default_factory=list)

    @property
    def is_unchanged(self) -> bool:
        """Return whether every compared value was identical."""
        return not self.changes

    @property
    def reason(self) -> str:
        """Return why the two entries were taken to be the same request."""
        return alignment_reason(self.rule)


class UnpairedRequest(BaseModel):
    """One request that was observed in a single recording."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    position: int = Field(ge=1)
    method: str
    host: str
    path: str


class ComparedCapture(BaseModel):
    """One side of the comparison: where it came from and how much of it was compared."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: CaptureSource
    created_at: datetime
    total_requests: int = Field(default=0, ge=0)
    compared_requests: int = Field(default=0, ge=0)
    """How many entries were kept for comparison, the rest being filtered as noise."""


class CaptureDiff(BaseModel):
    """What two recordings of one workflow have in common and where they differ."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    left: ComparedCapture
    right: ComparedCapture
    pairs: list[PairedRequest] = Field(default_factory=list)
    unpaired_left: list[UnpairedRequest] = Field(default_factory=list)
    unpaired_right: list[UnpairedRequest] = Field(default_factory=list)
    redacted_values: int = Field(default=0, ge=0)
    """How many credentials were removed from the two captures before comparing them."""

    @property
    def changed_pairs(self) -> list[PairedRequest]:
        """Return the paired requests that carry at least one changed value."""
        return [pair for pair in self.pairs if not pair.is_unchanged]

    @property
    def total_changes(self) -> int:
        """Return how many values differ across every pair."""
        return sum(len(pair.changes) for pair in self.pairs)

    def as_json(self) -> str:
        """Return the comparison as a JSON document, unchanged pairs included."""
        return json.dumps(self.model_dump(mode="json"), indent=2)


class AlignedRequest(NamedTuple):
    """One request recognized in both recordings, as each of them sent it."""

    rule: AlignmentRule
    left_position: int
    right_position: int
    left: Request
    right: Request


class AlignedCaptures(NamedTuple):
    """Two redacted recordings and the requests recognized on both sides.

    This is what every stage that reads two recordings of one workflow starts from. The
    comparison in this module is one such stage, and classifying what the values mean is
    another, so the redaction, the relevance filtering, and the pairing happen once and in
    one place rather than once per stage.
    """

    left: ComparedCapture
    right: ComparedCapture
    requests: list[AlignedRequest]
    unpaired_left: list[UnpairedRequest]
    unpaired_right: list[UnpairedRequest]
    redacted_values: int


def align_captures(
    left: Capture,
    right: Capture,
    *,
    keep: Iterable[Relevance] = DEFAULT_KEPT,
    salt: bytes | None = None,
) -> AlignedCaptures:
    """Redact ``left`` and ``right``, then pair the requests they have in common.

    Only the entries whose relevance is in ``keep`` take part, so a comparison is not
    drowned by the beacons and bundle fetches that differ between any two page loads.
    Positions are still counted over the whole capture, so they match what ``inspect``
    prints.

    A ``salt`` may be supplied to make the redaction reproducible. Whether it is or not,
    one salt is used for both captures: reading values redacted under two different salts
    would report every credential as changed.
    """
    shared_salt = salt if salt is not None else secrets.token_bytes(32)
    sanitized_left = redact_capture(left, salt=shared_salt)
    sanitized_right = redact_capture(right, salt=shared_salt)
    kept = frozenset(keep)
    selected_left = _select(sanitized_left.capture, kept)
    selected_right = _select(sanitized_right.capture, kept)
    paired, unpaired_left, unpaired_right = _align(selected_left, selected_right)
    return AlignedCaptures(
        left=_compared(sanitized_left.capture, len(selected_left)),
        right=_compared(sanitized_right.capture, len(selected_right)),
        requests=[_aligned(pairing) for pairing in paired],
        unpaired_left=[_unpaired(item) for item in unpaired_left],
        unpaired_right=[_unpaired(item) for item in unpaired_right],
        redacted_values=len(sanitized_left.report) + len(sanitized_right.report),
    )


def diff_captures(
    left: Capture,
    right: Capture,
    *,
    keep: Iterable[Relevance] = DEFAULT_KEPT,
    salt: bytes | None = None,
) -> CaptureDiff:
    """Compare ``left`` and ``right`` as two recordings of the same workflow.

    ``keep`` and ``salt`` mean what they mean for :func:`align_captures`, which is where
    the two recordings are redacted and their requests paired.
    """
    aligned = align_captures(left, right, keep=keep, salt=salt)
    return CaptureDiff(
        left=aligned.left,
        right=aligned.right,
        pairs=[_pair(request) for request in aligned.requests],
        unpaired_left=aligned.unpaired_left,
        unpaired_right=aligned.unpaired_right,
        redacted_values=aligned.redacted_values,
    )


class _Positioned(NamedTuple):
    """One entry together with where it sits in the capture it came from."""

    position: int
    entry: Entry


class _Pairing(NamedTuple):
    """Two entries taken to be the same request, and the rule that paired them."""

    rule: AlignmentRule
    left: _Positioned
    right: _Positioned


def _select(capture: Capture, keep: frozenset[Relevance]) -> list[_Positioned]:
    """Return the entries to compare, each with its position in the whole capture."""
    verdicts = {item.entry_id: item.relevance for item in classify_capture(capture).classifications}
    return [
        _Positioned(position, entry)
        for position, entry in enumerate(capture.entries, start=1)
        if verdicts[entry.id] in keep
    ]


def _compared(capture: Capture, compared: int) -> ComparedCapture:
    """Describe one side of the comparison."""
    return ComparedCapture(
        source=capture.metadata.source,
        created_at=capture.metadata.created_at,
        total_requests=len(capture),
        compared_requests=compared,
    )


def _unpaired(item: _Positioned) -> UnpairedRequest:
    """Describe a request that was observed in one recording only."""
    return UnpairedRequest(
        position=item.position,
        method=item.entry.request.method,
        host=item.entry.request.host,
        path=item.entry.request.path,
    )


def _aligned(pairing: _Pairing) -> AlignedRequest:
    """Describe one request recognized in both recordings, keeping both sides of it."""
    return AlignedRequest(
        rule=pairing.rule,
        left_position=pairing.left.position,
        right_position=pairing.right.position,
        left=pairing.left.entry.request,
        right=pairing.right.entry.request,
    )


def _pair(request: AlignedRequest) -> PairedRequest:
    """Describe one paired request by the values that differ between the two recordings."""
    return PairedRequest(
        left_position=request.left_position,
        right_position=request.right_position,
        method=request.left.method,
        host=request.left.host,
        path=request.left.path,
        rule=request.rule,
        changes=[
            _as_change(value)
            for value in compare_requests(request.left, request.right)
            if value.is_changed
        ],
    )


# Pairing


def _align(
    left: Sequence[_Positioned], right: Sequence[_Positioned]
) -> tuple[list[_Pairing], list[_Positioned], list[_Positioned]]:
    """Pair the entries of two recordings, most exact rule first.

    Each rule runs over what the rules before it could not pair, so a request that matches
    exactly is never spent on a looser match elsewhere. The pairs come back in the order
    the first recording observed them.
    """
    paired: list[_Pairing] = []
    for rule, key in (
        (AlignmentRule.IDENTICAL_PATH, _exact_key),
        (AlignmentRule.PATH_SHAPE, _shape_key),
    ):
        matched, left, right = _pair_by_key(left, right, key)
        paired.extend(_Pairing(rule, one, other) for one, other in matched)
    matched, left, right = _pair_by_single_segment(left, right)
    paired.extend(_Pairing(AlignmentRule.SINGLE_SEGMENT, one, other) for one, other in matched)
    paired.sort(key=lambda pairing: pairing.left.position)
    return paired, list(left), list(right)


def _pair_by_key(
    left: Sequence[_Positioned],
    right: Sequence[_Positioned],
    key: Callable[[Entry], tuple[Any, ...]],
) -> tuple[list[tuple[_Positioned, _Positioned]], list[_Positioned], list[_Positioned]]:
    """Pair entries sharing a key, the nth on one side with the nth on the other."""
    available: dict[tuple[Any, ...], deque[_Positioned]] = {}
    for item in right:
        available.setdefault(key(item.entry), deque()).append(item)
    matched: list[tuple[_Positioned, _Positioned]] = []
    unmatched_left: list[_Positioned] = []
    for item in left:
        candidates = available.get(key(item.entry))
        if candidates:
            matched.append((item, candidates.popleft()))
        else:
            unmatched_left.append(item)
    taken = {other.position for _, other in matched}
    return matched, unmatched_left, [item for item in right if item.position not in taken]


def _pair_by_single_segment(
    left: Sequence[_Positioned], right: Sequence[_Positioned]
) -> tuple[list[tuple[_Positioned, _Positioned]], list[_Positioned], list[_Positioned]]:
    """Pair leftovers whose paths differ in exactly one segment, where that is unambiguous.

    This is what recognizes a value the workflow carries in the path but that no shape
    rule can spot, such as a search term. It pairs only when a single candidate remains,
    because ``/api/customers`` and ``/api/orders`` also differ in exactly one segment, and
    guessing between them would report changes that were never made.
    """
    matched: list[tuple[_Positioned, _Positioned]] = []
    unmatched_left: list[_Positioned] = []
    available = list(right)
    for item in left:
        candidates = [
            other for other in available if _differs_in_one_segment(item.entry, other.entry)
        ]
        if len(candidates) == 1:
            matched.append((item, candidates[0]))
            available.remove(candidates[0])
        else:
            unmatched_left.append(item)
    return matched, unmatched_left, available


def _exact_key(entry: Entry) -> tuple[str, str, str]:
    """Return what identifies a request when nothing about it varies."""
    request = entry.request
    return request.method, request.host, request.path


def _shape_key(entry: Entry) -> tuple[str, str, tuple[str, ...]]:
    """Return what identifies a request once its identifier shaped segments are set aside."""
    request = entry.request
    segments = tuple(
        _VARIABLE_SEGMENT if _is_identifier_shaped(segment) else segment
        for segment in _segments(request.path)
    )
    return request.method, request.host, segments


def _differs_in_one_segment(left: Entry, right: Entry) -> bool:
    """Return whether two requests address the same path but for a single segment."""
    if _exact_key(left)[:2] != _exact_key(right)[:2]:
        return False
    left_segments = _segments(left.request.path)
    right_segments = _segments(right.request.path)
    if len(left_segments) != len(right_segments):
        return False
    paired_segments = zip(left_segments, right_segments, strict=True)
    return sum(1 for one, other in paired_segments if one != other) == 1


_VARIABLE_SEGMENT = "{}"

_UUID_SEGMENT = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX_SEGMENT = re.compile(r"^[0-9a-f]{12,}$", re.I)


def _is_identifier_shaped(segment: str) -> bool:
    """Return whether a path segment looks like an identifier rather than a name.

    Deliberately narrow: a number, a UUID, or a long run of hex. A word that differs
    between two runs is left to the single segment rule, which refuses to guess when more
    than one request could have been meant.
    """
    return bool(segment.isdigit() or _UUID_SEGMENT.match(segment) or _HEX_SEGMENT.match(segment))


def _segments(path: str) -> list[str]:
    """Return the non-empty segments of ``path``, in order."""
    return [segment for segment in path.split("/") if segment]


# Comparing


def compare_requests(left: Request, right: Request) -> list[ComparedValue]:
    """Return every value the two requests carry, side by side, in the order they are read.

    Values that held still are reported alongside the ones that differ. A comparison shows
    only the differences, but a stage that has to say what a value *is* needs both: a value
    that was identical on two runs is evidence in its own right.
    """
    values = _path_values(left, right)
    values.extend(_named_values(_by_name(left.query), _by_name(right.query), "request.query"))
    values.extend(_header_values(left, right))
    values.extend(_body_values(left.body, right.body))
    return values


def _as_change(value: ComparedValue) -> ValueChange:
    """Return what happened to one value that differs between the two recordings."""
    if value.left is None:
        return _added(value.location, value.right or "")
    if value.right is None:
        return _removed(value.location, value.left)
    return ValueChange(
        location=value.location, kind=ChangeKind.CHANGED, left=value.left, right=value.right
    )


def _path_values(left: Request, right: Request) -> list[ComparedValue]:
    """Return the path segments of both requests, numbered from one as a reader counts them."""
    left_segments = _segments(left.path)
    right_segments = _segments(right.path)
    if len(left_segments) != len(right_segments):
        return [ComparedValue("request.path", left.path, right.path)]
    numbered = enumerate(zip(left_segments, right_segments, strict=True), start=1)
    return [ComparedValue(f"request.path[{position}]", *values) for position, values in numbered]


def _by_name(params: QueryParams) -> dict[str, tuple[str, ...]]:
    """Return the values recorded under each name, first seen name first."""
    return {name: params.get_all(name) for name in params.names()}


_DERIVED_HEADERS = frozenset({"content-length"})
"""Headers whose value follows from the request rather than from the workflow.

A ``Content-Length`` that changed is the payload change reported on its own line, said a
second time in bytes, which is why it is left out here.
"""


def _header_values(left: Request, right: Request) -> list[ComparedValue]:
    """Return the request headers of both sides, located by their lowercased names."""
    left_headers = _headers_by_name(left)
    right_headers = _headers_by_name(right)
    return _named_values(left_headers, right_headers, "request.headers", bracketed=False)


def _headers_by_name(request: Request) -> dict[str, tuple[str, ...]]:
    """Return the header values under each lowercased name, derived headers left out."""
    names = [
        name
        for name in dict.fromkeys(header.name.strip().lower() for header in request.headers)
        if name not in _DERIVED_HEADERS
    ]
    return {name: request.headers.get_all(name) for name in names}


def _named_values(
    left: dict[str, tuple[str, ...]],
    right: dict[str, tuple[str, ...]],
    location: str,
    *,
    bracketed: bool = True,
) -> list[ComparedValue]:
    """Read two sets of named values, matching repeats by the order they were observed."""
    values: list[ComparedValue] = []
    names = list(left) + [name for name in right if name not in left]
    for name in names:
        left_values = left.get(name, ())
        right_values = right.get(name, ())
        where = f"{location}[{name}]" if bracketed else f"{location}.{name}"
        repeated = max(len(left_values), len(right_values)) > 1
        for index in range(max(len(left_values), len(right_values))):
            values.append(
                ComparedValue(
                    f"{where}[{index}]" if repeated else where,
                    left_values[index] if index < len(left_values) else None,
                    right_values[index] if index < len(right_values) else None,
                )
            )
    return values


_FORM_MEDIA_TYPE = "application/x-www-form-urlencoded"
_BODY_LOCATION = "request.body"


def _body_values(left: Body | None, right: Body | None) -> list[ComparedValue]:
    """Return the payload values of both sides, field by field where the payload is a structure.

    A payload neither side can be read as a structure is read whole, because the way to
    describe a difference inside an opaque body is to show both of them.
    """
    left = _payload(left)
    right = _payload(right)
    if left is None and right is None:
        return []
    if left is None or right is None:
        return [
            ComparedValue(
                _BODY_LOCATION,
                _body_value(left) if left is not None else None,
                _body_value(right) if right is not None else None,
            )
        ]
    if left.is_json and right.is_json:
        documents = _both_parsed(left, right)
        if documents is not None:
            return _json_values(documents[0], documents[1], _BODY_LOCATION)
    if left.media_type == _FORM_MEDIA_TYPE and right.media_type == _FORM_MEDIA_TYPE:
        return _named_values(_form_fields(left), _form_fields(right), _BODY_LOCATION)
    return [ComparedValue(_BODY_LOCATION, _body_value(left), _body_value(right))]


def _payload(body: Body | None) -> Body | None:
    """Return ``body`` when it carries content, and ``None`` when it does not."""
    return None if body is None or body.is_empty else body


def _body_value(body: Body) -> str:
    """Return what stands for a whole payload in a comparison.

    A binary payload is described rather than quoted. Its bytes mean nothing to a reader,
    and redaction leaves them as observed precisely because it cannot read them.
    """
    if body.encoding == "base64":
        return f"<{len(body.as_bytes())} bytes of {body.media_type or 'binary data'}>"
    return body.text or ""


def _both_parsed(left: Body, right: Body) -> tuple[Any, Any] | None:
    """Return both payloads parsed as JSON, or ``None`` when either one does not parse."""
    try:
        return json.loads(left.text or ""), json.loads(right.text or "")
    except ValueError:
        return None


def _form_fields(body: Body) -> dict[str, tuple[str, ...]]:
    """Return the values recorded under each field of a form encoded payload."""
    fields: dict[str, list[str]] = {}
    for name, value in parse_qsl(body.text or "", keep_blank_values=True):
        fields.setdefault(name, []).append(value)
    return {name: tuple(values) for name, values in fields.items()}


def _json_values(left: Any, right: Any, location: str) -> list[ComparedValue]:
    """Read two parsed payloads leaf by leaf, keeping the path to each one.

    A leaf is read as the text it was sent as, so a field that carried the number ``1`` on
    one run and the string ``"1"`` on the other reads as one value. Reporting a change
    there would mean printing the same characters on both sides of an arrow.
    """
    if isinstance(left, dict) and isinstance(right, dict):
        values: list[ComparedValue] = []
        for key in list(left) + [key for key in right if key not in left]:
            where = f"{location}.{key}"
            if key not in right:
                values.append(ComparedValue(where, _json_text(left[key]), None))
            elif key not in left:
                values.append(ComparedValue(where, None, _json_text(right[key])))
            else:
                values.extend(_json_values(left[key], right[key], where))
        return values
    if isinstance(left, list) and isinstance(right, list):
        values = []
        for index in range(max(len(left), len(right))):
            where = f"{location}[{index}]"
            if index >= len(right):
                values.append(ComparedValue(where, _json_text(left[index]), None))
            elif index >= len(left):
                values.append(ComparedValue(where, None, _json_text(right[index])))
            else:
                values.extend(_json_values(left[index], right[index], where))
        return values
    return [ComparedValue(location, _json_text(left), _json_text(right))]


def _json_text(value: Any) -> str:
    """Return a JSON value as the text a comparison shows for it."""
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)


def _added(location: str, value: str) -> ValueChange:
    """Return a value the second recording sent and the first did not."""
    return ValueChange(location=location, kind=ChangeKind.ADDED, right=value)


def _removed(location: str, value: str) -> ValueChange:
    """Return a value the first recording sent and the second did not."""
    return ValueChange(location=location, kind=ChangeKind.REMOVED, left=value)


# Rendering

VALUE_DISPLAY_WIDTH = 40
"""Longest value rendered in full. A longer one keeps its start and is marked as cut."""

REDACTED_DISPLAY = "(redacted)"
"""How a value redaction replaced is shown, in place of the placeholder it left behind."""

_ELLIPSIS = "..."


def render_diff(diff: CaptureDiff, *, include_unchanged: bool = False) -> str:
    """Render ``diff`` as the text ``trace2api diff`` writes.

    Requests whose values all held still are counted rather than listed, unless
    ``include_unchanged`` asks for them: a comparison is read for what moved.
    """
    lines = _diff_headline(diff)
    shown = diff.pairs if include_unchanged else diff.changed_pairs
    width = _location_width(shown)
    for pair in shown:
        lines.append("")
        lines.extend(_pair_lines(pair, width))
    lines.append("")
    lines.extend(_diff_summary(diff))
    return "\n".join(lines) + "\n"


def _diff_headline(diff: CaptureDiff) -> list[str]:
    """Return the lines describing the two recordings being compared."""
    return [
        f"Left:  {_side(diff.left)}",
        f"Right: {_side(diff.right)}",
        f"Comparing {_count(diff.left.compared_requests, 'kept request')} on the left "
        f"with {diff.right.compared_requests} on the right.",
    ]


def _side(capture: ComparedCapture) -> str:
    """Return one recording's provenance as it is shown above the comparison."""
    return (
        f"{_count(capture.total_requests, 'request')} from {capture.source.value}, "
        f"recorded {capture.created_at.isoformat()}"
    )


def _pair_lines(pair: PairedRequest, width: int) -> list[str]:
    """Return the heading and the changed values of one paired request."""
    lines = [f"{pair.left_position} -> {pair.right_position}  {pair.method} {pair.host}{pair.path}"]
    if pair.rule is not AlignmentRule.IDENTICAL_PATH:
        lines.append(f"  paired on the {pair.reason}")
    if pair.is_unchanged:
        lines.append("  no request value changed")
    lines.extend(
        f"  {change.location.ljust(width)}  {change.kind.value.ljust(7)}  {_sides(change)}"
        for change in pair.changes
    )
    return lines


def _location_width(pairs: Iterable[PairedRequest]) -> int:
    """Return the width to pad locations to, so every change reads as one column."""
    locations = [len(change.location) for pair in pairs for change in pair.changes]
    return max(locations, default=0)


def _sides(change: ValueChange) -> str:
    """Return what a change shows of the values themselves."""
    if change.kind is ChangeKind.CHANGED:
        return f"{display_value(change.left or '')} -> {display_value(change.right or '')}"
    return display_value((change.right if change.kind is ChangeKind.ADDED else change.left) or "")


def display_value(value: str) -> str:
    """Return ``value`` as it is shown: quoted, shortened, and never a credential.

    A placeholder becomes the word ``(redacted)`` rather than the fingerprint it carries.
    The fingerprint is salted per run, so printing it would make the same comparison read
    differently every time while saying nothing a reader can act on.

    A value that is nothing but a placeholder is left unquoted, so a credential reissued
    between the two runs reads as ``(redacted) -> (redacted)`` rather than as a value that
    changed into itself.
    """
    if is_redacted(value):
        return REDACTED_DISPLAY
    shown = "".join(
        REDACTED_DISPLAY if part.is_secret else part.text for part in split_secrets(value)
    )
    if len(shown) > VALUE_DISPLAY_WIDTH:
        shown = shown[: VALUE_DISPLAY_WIDTH - len(_ELLIPSIS)] + _ELLIPSIS
    return f'"{shown}"'


def _diff_summary(diff: CaptureDiff) -> list[str]:
    """Return the lines accounting for the comparison as a whole."""
    paired = len(diff.pairs)
    changed = len(diff.changed_pairs)
    lines = [
        f"Paired {_count(paired, 'request')}: {changed} changed, {paired - changed} unchanged.",
    ]
    if diff.total_changes:
        differ = "differs" if diff.total_changes == 1 else "differ"
        lines.append(f"{_count(diff.total_changes, 'value')} {differ}.")
    lines.extend(_unpaired_lines(diff.unpaired_left, "left"))
    lines.extend(_unpaired_lines(diff.unpaired_right, "right"))
    if diff.redacted_values:
        lines.append(
            f"Redacted {_count(diff.redacted_values, 'value')} before comparing, "
            "using one salt for both captures."
        )
    return lines


def _unpaired_lines(requests: list[UnpairedRequest], side: str) -> list[str]:
    """Return the account of the requests that were observed on one side only."""
    if not requests:
        return []
    lines = [f"Unpaired on the {side}: {len(requests)}."]
    lines.extend(
        f"  {request.position}  {request.method} {request.host}{request.path}"
        for request in requests
    )
    return lines


def _count(number: int, noun: str) -> str:
    """Return ``number`` and ``noun``, pluralized the ordinary way."""
    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"
