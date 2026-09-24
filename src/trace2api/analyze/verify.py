"""Compare a browser observed response with a replayed one, structurally.

A replay hits a live server, so the response it gets back is never going to be a byte for
byte copy of what the browser observed: a timestamp advances, an identifier is minted
fresh, a session token is reissued. Comparing the two for equality would report a mismatch
on every one of those and call it a failure, which is worse than not comparing at all.

What actually says a replay reproduced the workflow is the *shape* of what came back: the
same status, the same declared content type, and where the body is JSON, the same keys, the
same nesting, and the same array lengths, whatever the leaf values happen to read. A leaf
that is a string on both sides is not compared further even when the two strings differ,
because a rule that tried would have to guess which differences were the dynamic values a
live server is expected to hand out fresh and which were a real regression, and this project
does not ship a guess where a rule cannot back it.

One consequence of comparing shape rather than value is that a mismatch never needs to
carry the value that triggered it. What :class:`Mismatch` reports is a shape name such as
``"string"`` or ``"array of 3"``, never the text or the number itself, so a credential or
any other sensitive value flowing through a body under comparison is never at risk of
reaching a report built from this module.

:func:`verify_capture` runs the whole check end to end: it replays a capture's kept
requests and compares each response actually received against the one the capture
observed, using :func:`compare_responses` for the comparison itself. A request the
capture never observed a response for, such as one that failed while it was being
recorded, has nothing to compare against and is reported as such rather than skipped
silently. A response a replay receives is not redacted by the engine that sent it, so it
is redacted here, the same as any other response, before it is compared or reported.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Mapping
from datetime import datetime
from enum import StrEnum
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field

from trace2api.analyze.relevance import DEFAULT_KEPT, Relevance
from trace2api.models import Body, Capture, CaptureSource, Entry, Response
from trace2api.replay import ReplayedEntry, ReplayOutcome, replay_capture
from trace2api.sanitize import redact_capture

__all__ = [
    "CaptureVerification",
    "Mismatch",
    "MismatchKind",
    "ResponseComparison",
    "VerificationOutcome",
    "VerifiedRequest",
    "compare_responses",
    "render_verification",
    "verify_capture",
]

_BODY_LOCATION = "response.body"
_INVALID_JSON_SHAPE = "invalid-json"
_ABSENT_SHAPE = "absent"


class MismatchKind(StrEnum):
    """What kind of structural difference one mismatch reports."""

    STATUS = "status"
    """The two responses carry a different status code."""

    CONTENT_TYPE = "content-type"
    """The two responses declare a different content type, charset aside."""

    BODY_PRESENCE = "body-presence"
    """One response carries a body and the other does not."""

    BODY_SHAPE = "body-shape"
    """A JSON body differs in a way its shape can say: a key, a type, or a length."""


class Mismatch(BaseModel):
    """One structural difference between an observed response and a replayed one."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    location: str
    """Where the difference sits, spelled the way :mod:`trace2api.analyze.flow` spells it."""

    kind: MismatchKind
    observed: str
    """The shape observed carried at ``location``, never the value itself."""

    replayed: str
    """The shape replayed carried at ``location``, never the value itself."""


class ResponseComparison(BaseModel):
    """What comparing one observed response with its replay found."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    observed_status: int = Field(ge=100, le=599)
    replayed_status: int = Field(ge=100, le=599)
    mismatches: list[Mismatch] = Field(default_factory=list)

    @property
    def matches(self) -> bool:
        """Return whether the replay reproduced the observed response's shape."""
        return not self.mismatches

    def as_json(self) -> str:
        """Return the comparison as a JSON document."""
        return json.dumps(self.model_dump(mode="json"), indent=2)


def compare_responses(observed: Response, replayed: Response) -> ResponseComparison:
    """Compare ``observed`` with ``replayed`` and report every structural difference.

    The status and the declared content type are compared for equality. A JSON body is
    compared key by key, index by index, down to its leaves, but a leaf's value is never
    read: only whether both sides agree it is a string, a number, a boolean, ``null``, an
    object, or an array. A body that is not JSON on both sides is checked for presence only,
    because nothing about its structure can be located without a format this project does
    not claim to read.
    """
    mismatches: list[Mismatch] = []
    if observed.status != replayed.status:
        mismatches.append(
            Mismatch(
                location="response.status",
                kind=MismatchKind.STATUS,
                observed=str(observed.status),
                replayed=str(replayed.status),
            )
        )
    observed_type = _declared_media_type(observed)
    replayed_type = _declared_media_type(replayed)
    if observed_type != replayed_type:
        mismatches.append(
            Mismatch(
                location="response.headers.content-type",
                kind=MismatchKind.CONTENT_TYPE,
                observed=observed_type or "(none)",
                replayed=replayed_type or "(none)",
            )
        )
    mismatches.extend(_body_mismatches(observed.body, replayed.body))
    return ResponseComparison(
        observed_status=observed.status, replayed_status=replayed.status, mismatches=mismatches
    )


def _declared_media_type(response: Response) -> str | None:
    """Return the response's declared media type, charset and other parameters left off."""
    content_type = response.content_type
    if content_type is None:
        return None
    return content_type.split(";", 1)[0].strip().lower() or None


def _body_mismatches(observed: Body | None, replayed: Body | None) -> list[Mismatch]:
    """Return the structural mismatches between two response bodies."""
    observed_present = observed is not None and not observed.is_empty
    replayed_present = replayed is not None and not replayed.is_empty
    if not observed_present and not replayed_present:
        return []
    if observed_present != replayed_present:
        return [
            Mismatch(
                location=_BODY_LOCATION,
                kind=MismatchKind.BODY_PRESENCE,
                observed=_ABSENT_SHAPE if not observed_present else "present",
                replayed=_ABSENT_SHAPE if not replayed_present else "present",
            )
        ]
    assert observed is not None and replayed is not None  # both present, checked above
    if not (observed.is_json and replayed.is_json):
        return []
    return _shape_mismatches(_parsed(observed), _parsed(replayed), _BODY_LOCATION)


class _Invalid:
    """Marks a body that declared JSON but did not parse as it."""

    __slots__ = ()


_INVALID = _Invalid()


def _parsed(body: Body) -> Any:
    """Return ``body`` parsed as JSON, or :data:`_INVALID` where it does not parse."""
    try:
        return json.loads(body.text or "")
    except ValueError:
        return _INVALID


def _shape_mismatches(observed: Any, replayed: Any, location: str) -> list[Mismatch]:
    """Compare two parsed JSON values by shape alone, recursing into objects and arrays."""
    observed_shape = _json_shape(observed)
    replayed_shape = _json_shape(replayed)
    if observed_shape != replayed_shape:
        return [
            Mismatch(
                location=location,
                kind=MismatchKind.BODY_SHAPE,
                observed=observed_shape,
                replayed=replayed_shape,
            )
        ]
    if observed_shape == "object":
        return _object_mismatches(observed, replayed, location)
    if observed_shape == "array":
        return _array_mismatches(observed, replayed, location)
    return []


def _object_mismatches(observed: dict, replayed: dict, location: str) -> list[Mismatch]:
    """Compare two JSON objects key by key, most exact rule first."""
    mismatches: list[Mismatch] = []
    for key in list(observed) + [key for key in replayed if key not in observed]:
        where = f"{location}.{key}"
        if key not in replayed:
            mismatches.append(
                Mismatch(
                    location=where,
                    kind=MismatchKind.BODY_SHAPE,
                    observed=_json_shape(observed[key]),
                    replayed=_ABSENT_SHAPE,
                )
            )
        elif key not in observed:
            mismatches.append(
                Mismatch(
                    location=where,
                    kind=MismatchKind.BODY_SHAPE,
                    observed=_ABSENT_SHAPE,
                    replayed=_json_shape(replayed[key]),
                )
            )
        else:
            mismatches.extend(_shape_mismatches(observed[key], replayed[key], where))
    return mismatches


def _array_mismatches(observed: list, replayed: list, location: str) -> list[Mismatch]:
    """Compare two JSON arrays by length first, then element by element."""
    if len(observed) != len(replayed):
        return [
            Mismatch(
                location=location,
                kind=MismatchKind.BODY_SHAPE,
                observed=f"array of {len(observed)}",
                replayed=f"array of {len(replayed)}",
            )
        ]
    mismatches: list[Mismatch] = []
    for index, (observed_item, replayed_item) in enumerate(zip(observed, replayed, strict=True)):
        mismatches.extend(_shape_mismatches(observed_item, replayed_item, f"{location}[{index}]"))
    return mismatches


def _json_shape(value: Any) -> str:
    """Return the name of one JSON value's shape: its type, never its content."""
    if value is _INVALID:
        return _INVALID_JSON_SHAPE
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    raise TypeError(
        f"not a JSON value: {value!r}"
    )  # pragma: no cover - json.loads cannot yield this


# Replaying and verifying a whole capture


class VerificationOutcome(StrEnum):
    """What replaying one request and comparing its response concluded."""

    MATCHED = "matched"
    """The replay reproduced the observed response's shape."""

    MISMATCHED = "mismatched"
    """The replay responded, but not with the same shape the capture observed."""

    FAILED = "failed"
    """The request could not be sent, or produced no response."""

    NOT_OBSERVED = "not-observed"
    """The capture holds no response for this request, so there is nothing to compare."""


class VerifiedRequest(BaseModel):
    """What verifying one request of a capture found."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    position: int = Field(ge=1)
    """Where the exchange sits in the capture, counting from one as ``inspect`` does."""

    method: str
    host: str
    path: str
    outcome: VerificationOutcome
    comparison: ResponseComparison | None = None
    """Set when a replayed response was compared against what was observed."""

    error: str | None = None
    """Set when ``outcome`` is ``FAILED`` and the request produced no response at all."""


class CaptureVerification(BaseModel):
    """What replaying a capture and comparing every response it received found."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: CaptureSource
    created_at: datetime
    total_requests: int = Field(default=0, ge=0)
    requests: list[VerifiedRequest] = Field(default_factory=list)
    redacted_values: int = Field(default=0, ge=0)
    """How many credentials were removed from the capture and its replayed responses."""

    @property
    def passed(self) -> bool:
        """Return whether every replayed request matched what the capture observed.

        A capture with nothing to replay has not been verified, so this is ``False`` for
        one as well as for one carrying a mismatch, a failure, or a request the capture
        never observed a response for.
        """
        return bool(self.requests) and all(
            item.outcome is VerificationOutcome.MATCHED for item in self.requests
        )

    def as_json(self) -> str:
        """Return the verification as a JSON document."""
        return json.dumps(self.model_dump(mode="json"), indent=2)


def verify_capture(
    capture: Capture,
    secrets: Mapping[str, str],
    *,
    keep: Iterable[Relevance] = DEFAULT_KEPT,
    client: httpx.Client | None = None,
) -> CaptureVerification:
    """Replay the kept requests of ``capture`` and compare each response with what was observed.

    ``secrets`` supplies every credential a kept request needs, by the same variable name a
    generated client would read it under. :func:`~trace2api.replay.replay_capture` raises
    :class:`~trace2api.replay.MissingSecretError` before anything is sent when one is
    missing, rather than partway through the workflow.

    A ``client`` may be supplied for a caller that wants its own transport, timeouts, or
    proxy, the same as :func:`~trace2api.replay.replay_capture` accepts.
    """
    sanitized = redact_capture(capture)
    observed_by_id = {entry.id: entry for entry in sanitized.capture.entries}
    positions = {
        entry.id: position for position, entry in enumerate(sanitized.capture.entries, start=1)
    }
    replayed = replay_capture(capture, secrets, keep=keep, client=client)
    redacted_responses, response_redactions = _redact_responses(capture, replayed.entries)
    requests = [
        _verify_entry(
            item, observed_by_id[item.entry_id], positions[item.entry_id], redacted_responses
        )
        for item in replayed.entries
    ]
    return CaptureVerification(
        source=sanitized.capture.metadata.source,
        created_at=sanitized.capture.metadata.created_at,
        total_requests=len(sanitized.capture),
        requests=requests,
        redacted_values=len(sanitized.report) + response_redactions,
    )


def _redact_responses(
    capture: Capture, replayed: list[ReplayedEntry]
) -> tuple[dict[str, Response], int]:
    """Redact every response a replay actually received, the same as any other response.

    A replay does not redact what it observes, so this is where a session token or any
    other credential a live server hands back is removed before it reaches a comparison
    or a report, the same as it would be for a browser observed response.
    """
    responded = {item.entry_id: item.response for item in replayed if item.response is not None}
    if not responded:
        return {}, 0
    entries_by_id = {entry.id: entry for entry in capture.entries}
    wrapper = capture.model_copy(
        update={
            "entries": [
                entries_by_id[entry_id].model_copy(update={"response": response, "failure": None})
                for entry_id, response in responded.items()
            ]
        }
    )
    sanitized = redact_capture(wrapper)
    redacted = {entry.id: entry.response for entry in sanitized.capture.entries}
    return redacted, len(sanitized.report)


def _verify_entry(
    replayed: ReplayedEntry,
    entry: Entry,
    position: int,
    redacted_responses: Mapping[str, Response],
) -> VerifiedRequest:
    """Compare one replayed request with what the capture observed for it."""
    request = entry.request
    if replayed.outcome is ReplayOutcome.FAILED:
        return VerifiedRequest(
            position=position,
            method=request.method,
            host=request.host,
            path=request.path,
            outcome=VerificationOutcome.FAILED,
            error=replayed.error,
        )
    if entry.response is None:
        return VerifiedRequest(
            position=position,
            method=request.method,
            host=request.host,
            path=request.path,
            outcome=VerificationOutcome.NOT_OBSERVED,
        )
    comparison = compare_responses(entry.response, redacted_responses[entry.id])
    outcome = VerificationOutcome.MATCHED if comparison.matches else VerificationOutcome.MISMATCHED
    return VerifiedRequest(
        position=position,
        method=request.method,
        host=request.host,
        path=request.path,
        outcome=outcome,
        comparison=comparison,
    )


_OUTCOME_LABELS: dict[VerificationOutcome, str] = {
    VerificationOutcome.MATCHED: "matched",
    VerificationOutcome.MISMATCHED: "mismatched",
    VerificationOutcome.FAILED: "failed",
    VerificationOutcome.NOT_OBSERVED: "not observed",
}


def render_verification(verification: CaptureVerification) -> str:
    """Render ``verification`` as the text ``trace2api verify`` writes.

    Every replayed request gets one line naming what became of it, and a mismatch is
    followed by the differences :func:`compare_responses` found. ``--json`` writes the
    same account as a JSON document.
    """
    lines = _headline(verification)
    width = _method_width(verification.requests)
    for item in verification.requests:
        lines.append("")
        lines.extend(_request_lines(item, width))
    lines.append("")
    lines.extend(_verification_summary(verification))
    return "\n".join(lines) + "\n"


def _method_width(requests: list[VerifiedRequest]) -> int:
    """Return the width to pad methods to, so every request reads as one column."""
    return max((len(item.method) for item in requests), default=0)


def _headline(verification: CaptureVerification) -> list[str]:
    """Return the lines describing the capture the verification was read from."""
    return [
        f"Capture: {_count(verification.total_requests, 'request')} from "
        f"{verification.source.value}, recorded {verification.created_at.isoformat()}",
        f"Replayed {_count(len(verification.requests), 'kept request')} and compared each "
        "response with what was observed.",
    ]


def _request_lines(item: VerifiedRequest, width: int) -> list[str]:
    """Return the heading and, for a mismatch, the differences of one verified request."""
    lines = [
        f"{item.position}  {item.method.ljust(width)}  {item.host}{item.path}"
        f"  {_OUTCOME_LABELS[item.outcome]}"
    ]
    if item.error:
        lines.append(f"  {item.error}")
    if item.comparison is not None:
        location_width = max((len(m.location) for m in item.comparison.mismatches), default=0)
        for mismatch in item.comparison.mismatches:
            lines.append(
                f"  {mismatch.location.ljust(location_width)}  {mismatch.kind.value}  "
                f"{mismatch.observed} -> {mismatch.replayed}"
            )
    return lines


def _verification_summary(verification: CaptureVerification) -> list[str]:
    """Return the lines accounting for the capture as a whole."""
    total = len(verification.requests)
    if total == 0:
        lines = ["No kept request to replay."]
    else:
        counts = Counter(item.outcome for item in verification.requests)
        parts = ", ".join(
            f"{counts[outcome]} {label}"
            for outcome, label in _OUTCOME_LABELS.items()
            if counts[outcome]
        )
        lines = [f"{_count(total, 'request')} replayed: {parts}."]
    if verification.redacted_values:
        lines.append(
            f"Redacted {_count(verification.redacted_values, 'value')} before comparing, "
            "using one salt for the requests and another for the replayed responses."
        )
    return lines


def _count(number: int, noun: str) -> str:
    """Return ``number`` and ``noun``, pluralized the ordinary way."""
    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"
