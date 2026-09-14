"""Say what each value of a workflow is, given two recordings of it.

A comparison reports which request values differ. That is the evidence, not the answer.
The answer a client needs is what to *do* with each value: send it as observed, take it
as a parameter, mint a fresh one per run, or read it from the environment. This module
turns the evidence into that verdict.

Every value both recordings carry is read, not only the ones that moved, because a value
that held still across two runs is evidence in its own right: it is the case for sending
it as observed. The verdicts are:

``constant``
    Identical in both recordings. A client can send it as it was observed.
``input``
    Differed, and reads like something supplied to the workflow. A client takes it as a
    parameter.
``generated``
    Differed, and reads like something a machine minted: a UUID, a moment from the clock,
    a nonce, or a header the browser maintains for itself. A client has to produce a fresh
    one rather than replay the observed value.
``secret``
    Redaction removed it. A client reads it from the environment, whether or not it was
    reissued between the two runs.
``unknown``
    Differed, and no rule recognized it. Saying so is the point: a guess here becomes a
    client that fails for a reason nobody can see.

The rules are deterministic and narrow, and each verdict records the rule behind it and
what that rule matched on. Where a rule matches on a name, the name is recorded; the
values themselves are never what a rule reports, and a credential is shown as
``(redacted)`` wherever a value is shown at all.

Two recordings are the smallest experiment that says anything, and they say it only about
values that the second run actually varied. A value the operator happened to leave alone
reads as a constant here, which is why a workflow is worth recording twice with as much
changed as possible.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from enum import StrEnum
from typing import NamedTuple

from pydantic import BaseModel, ConfigDict, Field

from trace2api.analyze.diff import (
    AlignedRequest,
    AlignmentRule,
    ComparedCapture,
    ComparedValue,
    UnpairedRequest,
    align_captures,
    alignment_reason,
    compare_requests,
    display_value,
)
from trace2api.analyze.relevance import DEFAULT_KEPT, Relevance
from trace2api.models import Capture
from trace2api.sanitize import split_secrets

__all__ = [
    "ClassifiedRequest",
    "ClassifiedValue",
    "ValueClassification",
    "ValueRole",
    "ValueRule",
    "classify_values",
    "render_classification",
]


class ValueRole(StrEnum):
    """What one request value is to a client that has to reproduce the workflow."""

    INPUT = "input"
    """Supplied to the workflow. A client takes it as a parameter."""

    CONSTANT = "constant"
    """The same on both runs. A client sends it as observed."""

    GENERATED = "generated"
    """Minted per request. A client produces a fresh one rather than replaying it."""

    SECRET = "secret"
    """Redaction removed it. A client reads it from the environment."""

    UNKNOWN = "unknown"
    """No rule recognized it. Kept as a verdict of its own rather than guessed at."""


class ValueRule(StrEnum):
    """The rule that decided a value.

    Verdicts carry the rule so that one can be traced back to the reason for it.
    """

    CREDENTIAL = "credential"
    HELD_STILL = "held-still"
    GENERATED_NAME = "generated-name"
    UUID_SHAPE = "uuid-shape"
    TIMESTAMP_SHAPE = "timestamp-shape"
    OPAQUE_SHAPE = "opaque-shape"
    BROWSER_HEADER = "browser-header"
    OPAQUE_PAYLOAD = "opaque-payload"
    PLAIN_VALUE = "plain-value"
    NO_RULE_MATCHED = "no-rule-matched"


_RULE_ROLES: dict[ValueRule, ValueRole] = {
    ValueRule.CREDENTIAL: ValueRole.SECRET,
    ValueRule.HELD_STILL: ValueRole.CONSTANT,
    ValueRule.GENERATED_NAME: ValueRole.GENERATED,
    ValueRule.UUID_SHAPE: ValueRole.GENERATED,
    ValueRule.TIMESTAMP_SHAPE: ValueRole.GENERATED,
    ValueRule.OPAQUE_SHAPE: ValueRole.GENERATED,
    ValueRule.BROWSER_HEADER: ValueRole.GENERATED,
    ValueRule.OPAQUE_PAYLOAD: ValueRole.UNKNOWN,
    ValueRule.PLAIN_VALUE: ValueRole.INPUT,
    ValueRule.NO_RULE_MATCHED: ValueRole.UNKNOWN,
}

_RULE_REASONS: dict[ValueRule, str] = {
    ValueRule.CREDENTIAL: "redaction removed it, so a client reads it from the environment",
    ValueRule.HELD_STILL: "both recordings sent the same value",
    ValueRule.GENERATED_NAME: "named after a value that is minted per request",
    ValueRule.UUID_SHAPE: "every observed value is a UUID, which is minted rather than supplied",
    ValueRule.TIMESTAMP_SHAPE: "every observed value reads as a moment taken from the clock",
    ValueRule.OPAQUE_SHAPE: "every observed value is a long opaque string",
    ValueRule.BROWSER_HEADER: "the browser maintains this header from the page it was on",
    ValueRule.OPAQUE_PAYLOAD: "the payload could only be read whole, so what moved in it is"
    " not located",
    ValueRule.PLAIN_VALUE: "it differs, and every observed value is ordinary text",
    ValueRule.NO_RULE_MATCHED: "it differs, and no rule recognized it",
}


class ClassifiedValue(BaseModel):
    """One request value, what it is taken to be, and why."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    location: str
    """Where the value sits, spelled as redaction and the comparison spell it."""

    role: ValueRole
    rule: ValueRule
    detail: str | None = None
    """What the rule matched, such as a field or header name. Never a value."""

    left: str | None = None
    """What the first recording sent, or ``None`` where it sent nothing."""

    right: str | None = None

    @property
    def reason(self) -> str:
        """Return a one line explanation of the verdict."""
        text = _RULE_REASONS[self.rule]
        return text if self.detail is None else f"{text}: {self.detail}"

    @property
    def is_constant(self) -> bool:
        """Return whether the value held still across the two recordings."""
        return self.role is ValueRole.CONSTANT


class ClassifiedRequest(BaseModel):
    """One request recognized in both recordings, with a verdict for each of its values."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    left_position: int = Field(ge=1)
    """Where the request sits in the first capture, counting from one as ``inspect`` does."""

    right_position: int = Field(ge=1)
    method: str
    host: str
    path: str
    """The path as the first recording observed it. A path that differs says so in the values."""

    rule: AlignmentRule
    """How the two entries were recognized as the same request."""

    values: list[ClassifiedValue] = Field(default_factory=list)

    @property
    def varying(self) -> list[ClassifiedValue]:
        """Return the values that did not simply hold still, which is what is worth reading."""
        return [value for value in self.values if not value.is_constant]

    @property
    def reason(self) -> str:
        """Return why the two entries were taken to be the same request."""
        return alignment_reason(self.rule)


class ValueClassification(BaseModel):
    """What every value of a workflow is taken to be, across two recordings of it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    left: ComparedCapture
    right: ComparedCapture
    requests: list[ClassifiedRequest] = Field(default_factory=list)
    unpaired_left: list[UnpairedRequest] = Field(default_factory=list)
    """Requests observed in one recording only. Nothing is concluded about their values."""

    unpaired_right: list[UnpairedRequest] = Field(default_factory=list)
    redacted_values: int = Field(default=0, ge=0)

    @property
    def values(self) -> list[ClassifiedValue]:
        """Return every classified value, request by request."""
        return [value for request in self.requests for value in request.values]

    def counts_by_role(self) -> dict[ValueRole, int]:
        """Return how many values reached each verdict, including the empty ones."""
        counts = dict.fromkeys(ValueRole, 0)
        for value in self.values:
            counts[value.role] += 1
        return counts

    def as_json(self) -> str:
        """Return the classification as a JSON document, constants included."""
        return json.dumps(self.model_dump(mode="json"), indent=2)


def classify_values(
    left: Capture,
    right: Capture,
    *,
    keep: Iterable[Relevance] = DEFAULT_KEPT,
    salt: bytes | None = None,
) -> ValueClassification:
    """Classify the values of every request ``left`` and ``right`` have in common.

    ``keep`` and ``salt`` mean what they mean for the comparison: only the entries whose
    relevance is kept take part, and one redaction salt is shared between the two
    recordings so that a credential which held still reads as one value.
    """
    aligned = align_captures(left, right, keep=keep, salt=salt)
    return ValueClassification(
        left=aligned.left,
        right=aligned.right,
        requests=[_classify_request(request) for request in aligned.requests],
        unpaired_left=aligned.unpaired_left,
        unpaired_right=aligned.unpaired_right,
        redacted_values=aligned.redacted_values,
    )


def _classify_request(request: AlignedRequest) -> ClassifiedRequest:
    """Return one paired request with a verdict for each value it carries."""
    return ClassifiedRequest(
        left_position=request.left_position,
        right_position=request.right_position,
        method=request.left.method,
        host=request.left.host,
        path=request.left.path,
        rule=request.rule,
        values=[classify_value(value) for value in compare_requests(request.left, request.right)],
    )


# Rules


def classify_value(value: ComparedValue) -> ClassifiedValue:
    """Return the verdict for one value, with the rule that reached it.

    The rules run most specific first, and the first one that fires is the one recorded.
    Credentials come before everything else: a placeholder is not a value, so no rule about
    what a value looks like has anything to say about one.
    """
    rule, detail = _match(value)
    return ClassifiedValue(
        location=value.location,
        role=_RULE_ROLES[rule],
        rule=rule,
        detail=detail,
        left=value.left,
        right=value.right,
    )


def _match(value: ComparedValue) -> tuple[ValueRule, str | None]:
    """Return the first rule that recognizes ``value``, and what it matched on."""
    if any(_carries_a_secret(observed) for observed in value.observed):
        return ValueRule.CREDENTIAL, None
    if not value.is_changed:
        return ValueRule.HELD_STILL, None
    name = _value_name(value.location)
    if name is not None and _names_a_minted_value(name):
        return ValueRule.GENERATED_NAME, name
    if name is not None and _is_header(value.location) and name in _BROWSER_HEADERS:
        return ValueRule.BROWSER_HEADER, name
    if value.location == _WHOLE_BODY:
        return ValueRule.OPAQUE_PAYLOAD, None
    observed = value.observed
    if all(_UUID.fullmatch(item) for item in observed):
        return ValueRule.UUID_SHAPE, None
    if all(_is_timestamp(item) for item in observed):
        return ValueRule.TIMESTAMP_SHAPE, None
    if all(_is_opaque(item) for item in observed):
        return ValueRule.OPAQUE_SHAPE, None
    if all(_is_plain(item) for item in observed):
        return ValueRule.PLAIN_VALUE, None
    return ValueRule.NO_RULE_MATCHED, None


_WHOLE_BODY = "request.body"
"""The location a payload gets when neither side could be read as a structure."""

_UNNAMED_LOCATIONS = frozenset({"request.path", "request.query", "request.headers", _WHOLE_BODY})
"""Locations that stand for a whole part of a request rather than for a named value."""

_HEADER_LOCATION = "request.headers."

_INDEX_SUFFIX = re.compile(r"(\[\d+\])+$")

_GENERATED_NAMES = frozenset(
    {
        "_",
        "cachebust",
        "cachebuster",
        "cb",
        "correlationid",
        "epoch",
        "guid",
        "nonce",
        "rand",
        "random",
        "reqid",
        "requestid",
        "spanid",
        "timestamp",
        "traceid",
        "ts",
        "uuid",
        "xcorrelationid",
        "xrequestid",
        "xtraceid",
    }
)
"""Names that say outright that a value is minted per request.

Deliberately narrow. Names such as ``time``, ``date``, or ``id`` name a value a workflow
is just as likely to be given as to mint, and calling those generated would tell a client
to invent a value the operator meant to choose.
"""

_BROWSER_HEADERS = frozenset(
    {
        "origin",
        "referer",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-user",
    }
)
"""Request headers the browser maintains from the page a request was issued on.

One that differs between two recordings describes the browsing that led to the request
rather than anything the workflow supplied, so a client sets it from its own context.
"""

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)

_ISO_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?")

_EPOCH_SECONDS = range(1_000_000_000, 4_000_000_000)
"""Unix seconds from 2001 to 2096. Outside it, ten digits are as likely to be an account
number as a clock reading."""

_OPAQUE_LENGTH = 24
"""Shortest run of opaque characters taken as minted rather than supplied."""

_OPAQUE = re.compile(r"[A-Za-z0-9+/=_-]+")

_HEX = re.compile(r"[0-9a-f]{16,}", re.IGNORECASE)

_PLAIN_LENGTH = 64
"""Longest value taken as something a person could have supplied."""

_PLAIN = re.compile(r"[\w .,:@/+-]*", re.UNICODE)


def _carries_a_secret(value: str) -> bool:
    """Return whether any part of ``value`` is a placeholder redaction left behind."""
    return any(part.is_secret for part in split_secrets(value))


def _value_name(location: str) -> str | None:
    """Return the name a value was sent under, or ``None`` where it has none.

    A path segment has no name, and neither does a payload that could only be read whole.
    An index is not a name either, so ``request.query[tag][1]`` is named ``tag``.
    """
    trimmed = _INDEX_SUFFIX.sub("", location)
    if trimmed in _UNNAMED_LOCATIONS:
        return None
    if trimmed.endswith("]"):
        return trimmed[trimmed.rindex("[") + 1 : -1].lower()
    return trimmed.rsplit(".", 1)[-1].lower()


def _is_header(location: str) -> bool:
    """Return whether a location names a request header."""
    return location.startswith(_HEADER_LOCATION)


def _names_a_minted_value(name: str) -> bool:
    """Return whether a name says outright that its value is minted per request.

    ``X-Request-Id``, ``x_request_id``, and ``xRequestId`` all name the same thing, so the
    separators are removed before the name is looked up: a rule that recognized only one
    spelling would be a rule about spelling. The bare ``_`` that a cache buster is usually
    called survives nothing being removed, so it is matched as it was sent.
    """
    lowered = name.lower()
    return lowered in _GENERATED_NAMES or re.sub(r"[^a-z0-9]", "", lowered) in _GENERATED_NAMES


def _is_timestamp(value: str) -> bool:
    """Return whether a value reads as a moment in time rather than as a number.

    Epoch seconds and milliseconds are recognized only inside a plausible window, and a
    date on its own is not: a date is what a person picks out of a calendar.
    """
    if _ISO_TIMESTAMP.fullmatch(value):
        return True
    if not value.isdigit():
        return False
    if len(value) == 10:
        return int(value) in _EPOCH_SECONDS
    return len(value) == 13 and int(value) // 1000 in _EPOCH_SECONDS


def _is_opaque(value: str) -> bool:
    """Return whether a value is a long run of characters carrying no words.

    A long hexadecimal run counts whatever else it holds. Anything else has to mix letters
    and digits, so that a long sentence or a long path is not read as a minted token.
    """
    if _HEX.fullmatch(value):
        return True
    return (
        len(value) >= _OPAQUE_LENGTH
        and bool(_OPAQUE.fullmatch(value))
        and any(character.isdigit() for character in value)
        and any(character.isalpha() for character in value)
    )


def _is_plain(value: str) -> bool:
    """Return whether a value is short and ordinary enough to have been supplied."""
    return len(value) <= _PLAIN_LENGTH and bool(_PLAIN.fullmatch(value))


# Rendering

_ROLE_NOUNS: dict[ValueRole, str] = {
    ValueRole.INPUT: "input",
    ValueRole.GENERATED: "generated value",
    ValueRole.SECRET: "secret",
    ValueRole.UNKNOWN: "unknown value",
    ValueRole.CONSTANT: "constant",
}
"""How each verdict is counted, in the order a summary reads them. Constants come last
because they are the part of a workflow that needs no decision."""


def render_classification(
    classification: ValueClassification,
    *,
    include_constants: bool = False,
    explain: bool = False,
) -> str:
    """Render ``classification`` as the text ``trace2api classify`` writes.

    Constants are counted rather than listed unless ``include_constants`` asks for them:
    most of a request is scaffolding that held still, and what is read for is the handful
    of values a client has to decide about. ``explain`` adds the rule behind each verdict.
    """
    lines = _headline(classification)
    listed = [
        (request, request.values if include_constants else request.varying)
        for request in classification.requests
    ]
    width = _columns([value for _, values in listed for value in values])
    for request, values in listed:
        if not values:
            continue
        lines.append("")
        lines.extend(_request_lines(request, values, width, explain=explain))
    lines.append("")
    lines.extend(_summary(classification, include_constants=include_constants))
    return "\n".join(lines) + "\n"


class _Columns(NamedTuple):
    """How wide the location and verdict columns are, so every value reads as one table."""

    location: int
    role: int


def _columns(values: Iterable[ClassifiedValue]) -> _Columns:
    """Return the widths the listed values need, padding nothing when there are none."""
    listed = list(values)
    return _Columns(
        location=max((len(value.location) for value in listed), default=0),
        role=max((len(value.role.value) for value in listed), default=0),
    )


def _headline(classification: ValueClassification) -> list[str]:
    """Return the lines describing the two recordings the verdicts came from."""
    paired = len(classification.requests)
    return [
        f"Left:  {_side(classification.left)}",
        f"Right: {_side(classification.right)}",
        f"Classifying the values of {_count(paired, 'paired request')}.",
    ]


def _side(capture: ComparedCapture) -> str:
    """Return one recording's provenance as it is shown above the verdicts."""
    return (
        f"{_count(capture.total_requests, 'request')} from {capture.source.value}, "
        f"recorded {capture.created_at.isoformat()}"
    )


def _request_lines(
    request: ClassifiedRequest,
    values: list[ClassifiedValue],
    width: _Columns,
    *,
    explain: bool,
) -> list[str]:
    """Return the heading and the listed values of one paired request."""
    lines = [
        f"{request.left_position} -> {request.right_position}  "
        f"{request.method} {request.host}{request.path}"
    ]
    if request.rule is not AlignmentRule.IDENTICAL_PATH:
        lines.append(f"  paired on the {request.reason}")
    for value in values:
        lines.append(
            f"  {value.location.ljust(width.location)}  "
            f"{value.role.value.ljust(width.role)}  {_sides(value)}"
        )
        if explain:
            lines.append(f"      {value.reason}")
    return lines


def _sides(value: ClassifiedValue) -> str:
    """Return what a verdict shows of the value itself, credentials never among it."""
    if value.left is None:
        return f"{display_value(value.right or '')} (second recording only)"
    if value.right is None:
        return f"{display_value(value.left)} (first recording only)"
    if value.left == value.right:
        return display_value(value.left)
    return f"{display_value(value.left)} -> {display_value(value.right)}"


def _summary(classification: ValueClassification, *, include_constants: bool) -> list[str]:
    """Return the lines accounting for the classification as a whole."""
    counts = classification.counts_by_role()
    total = sum(counts.values())
    if not total:
        return ["No values were classified."]
    reached = ", ".join(
        _count(counts[role], _ROLE_NOUNS[role]) for role in _ROLE_NOUNS if counts[role]
    )
    lines = [f"Classified {_count(total, 'value')}: {reached}."]
    constants = counts[ValueRole.CONSTANT]
    if constants and not include_constants:
        decided = total - constants
        lines.append(
            f"Listing the {decided} a client has to decide about. "
            "Pass --constants to list the rest."
            if decided
            else "Every value held still across the two recordings. Pass --constants to list them."
        )
    lines.extend(_unpaired_lines(classification.unpaired_left, "left"))
    lines.extend(_unpaired_lines(classification.unpaired_right, "right"))
    if classification.redacted_values:
        lines.append(
            f"Redacted {_count(classification.redacted_values, 'value')} before classifying, "
            "using one salt for both captures."
        )
    return lines


def _unpaired_lines(requests: list[UnpairedRequest], side: str) -> list[str]:
    """Return the account of the requests nothing was concluded about."""
    if not requests:
        return []
    lines = [f"Unpaired on the {side}, so not classified: {len(requests)}."]
    lines.extend(
        f"  {request.position}  {request.method} {request.host}{request.path}"
        for request in requests
    )
    return lines


def _count(number: int, noun: str) -> str:
    """Return ``number`` and ``noun``, pluralized the ordinary way."""
    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"
