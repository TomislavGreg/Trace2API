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
"""

from __future__ import annotations

import json
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from trace2api.models import Body, Response

__all__ = [
    "Mismatch",
    "MismatchKind",
    "ResponseComparison",
    "compare_responses",
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
