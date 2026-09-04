"""Turn a capture into the account of it that ``trace2api inspect`` prints.

Reading a recorded workflow by hand means scrolling a devtools panel or a HAR file
looking for the handful of exchanges that carry data. This module answers the same
question in one screen: what was requested, what came back, and whether the request
looks like part of the workflow or like page furniture.

Two properties matter more than the layout:

* A capture is redacted before anything about it is rendered, so inspecting a real
  recording does not put credentials on a terminal or into a shell history file.
* Every relevance verdict keeps the rule that produced it, so ``--explain`` can say why
  a request was set aside instead of asking the reader to trust the filter.

Only the path of a request is shown, never its query string. Query strings routinely
carry tokens and identifiers, and the path is enough to recognize an endpoint.
"""

from __future__ import annotations

import json
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from trace2api.analyze.relevance import Classification, FilterRule, Relevance, classify_entry
from trace2api.models import Capture, CaptureSource, Entry, ResourceType
from trace2api.sanitize import redact_capture

__all__ = [
    "InspectedEntry",
    "Inspection",
    "inspect_capture",
    "render_inspection",
]

PATH_DISPLAY_WIDTH = 48
"""Longest path rendered in full. Longer paths keep their end, which identifies them."""

_NO_RESPONSE = "-"
_FAILED = "failed"
_ELLIPSIS = "..."


class InspectedEntry(BaseModel):
    """One exchange reduced to what identifies it, plus the verdict reached for it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    position: int = Field(ge=1)
    """Where the exchange sits in the capture, counting from one."""

    method: str
    host: str
    path: str
    status: int | None = None
    failure: str | None = None
    resource_type: ResourceType
    classification: Classification

    @property
    def entry_id(self) -> str:
        """Return the id of the entry this describes."""
        return self.classification.entry_id

    @property
    def relevance(self) -> Relevance:
        """Return what the request looks like."""
        return self.classification.relevance

    @property
    def rule(self) -> FilterRule:
        """Return the rule behind the verdict."""
        return self.classification.rule

    @property
    def reason(self) -> str:
        """Return a one line explanation of the verdict."""
        return self.classification.reason

    @property
    def outcome(self) -> str:
        """Return the status code, or why there is none."""
        if self.status is not None:
            return str(self.status)
        return _FAILED if self.failure is not None else _NO_RESPONSE


class Inspection(BaseModel):
    """What a capture holds: where it came from, and every exchange in it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: CaptureSource
    created_at: datetime
    start_url: str | None = None
    hosts: list[str] = Field(default_factory=list)
    entries: list[InspectedEntry] = Field(default_factory=list)
    redacted_values: int = Field(default=0, ge=0)
    """How many credentials were removed before any of this was rendered."""

    def __len__(self) -> int:
        return len(self.entries)

    def visible(self, *, include_noise: bool) -> list[InspectedEntry]:
        """Return the entries to show, in the order they were observed."""
        if include_noise:
            return list(self.entries)
        return [entry for entry in self.entries if entry.relevance is not Relevance.NOISE]

    def counts_by_relevance(self) -> dict[Relevance, int]:
        """Return how many entries reached each verdict, including the empty ones."""
        counts = dict.fromkeys(Relevance, 0)
        for entry in self.entries:
            counts[entry.relevance] += 1
        return counts

    def noise_counts_by_rule(self) -> dict[FilterRule, int]:
        """Return which rules accounted for the noise, most frequent first."""
        counts: dict[FilterRule, int] = {}
        for entry in self.entries:
            if entry.relevance is Relevance.NOISE:
                counts[entry.rule] = counts.get(entry.rule, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))

    def as_json(self) -> str:
        """Return the inspection as a JSON document, with every entry included."""
        return json.dumps(self.model_dump(mode="json"), indent=2)


def inspect_capture(capture: Capture, *, salt: bytes | None = None) -> Inspection:
    """Redact ``capture``, classify what is left, and describe the result.

    Redaction runs first because the inspection is meant to be displayed. A ``salt`` may
    be supplied to make the redaction reproducible when two captures are inspected
    together.
    """
    sanitized = redact_capture(capture, salt=salt)
    entries = [
        _inspect_entry(entry, position)
        for position, entry in enumerate(sanitized.capture.entries, start=1)
    ]
    return Inspection(
        source=sanitized.capture.metadata.source,
        created_at=sanitized.capture.metadata.created_at,
        start_url=sanitized.capture.metadata.start_url,
        hosts=list(sanitized.capture.hosts),
        entries=entries,
        redacted_values=len(sanitized.report),
    )


def _inspect_entry(entry: Entry, position: int) -> InspectedEntry:
    """Describe one exchange."""
    return InspectedEntry(
        position=position,
        method=entry.request.method,
        host=entry.request.host,
        path=entry.request.path,
        status=entry.response.status if entry.response is not None else None,
        failure=entry.failure,
        resource_type=entry.resource_type,
        classification=classify_entry(entry),
    )


_COLUMNS = ("#", "METHOD", "HOST", "PATH", "STATUS", "TYPE", "RELEVANCE")
_WHY_COLUMN = "WHY"


def render_inspection(
    inspection: Inspection,
    *,
    include_noise: bool = False,
    explain: bool = False,
) -> str:
    """Render ``inspection`` as the text ``trace2api inspect`` writes.

    Columns are sized to their contents so short captures do not print a table padded
    for URLs that are not there.
    """
    shown = inspection.visible(include_noise=include_noise)
    lines = _headline(inspection)
    if shown:
        lines.append("")
        lines.extend(_table(shown, explain=explain))
    lines.append("")
    lines.extend(_summary(inspection, shown=len(shown), include_noise=include_noise))
    return "\n".join(lines) + "\n"


def _headline(inspection: Inspection) -> list[str]:
    """Return the provenance lines shown above the table."""
    recorded = inspection.created_at.isoformat()
    lines = [
        f"Capture: {_count(len(inspection), 'request')} from {inspection.source.value}, "
        f"recorded {recorded}"
    ]
    if inspection.start_url is not None:
        lines.append(f"Started at: {inspection.start_url}")
    if inspection.hosts:
        lines.append(f"Hosts: {', '.join(inspection.hosts)}")
    return lines


def _table(entries: list[InspectedEntry], *, explain: bool) -> list[str]:
    """Return the header row and one row per entry, padded to a common width."""
    rows = [list(_COLUMNS + ((_WHY_COLUMN,) if explain else ()))]
    for entry in entries:
        row = [
            str(entry.position),
            entry.method,
            entry.host,
            _shorten(entry.path, PATH_DISPLAY_WIDTH),
            entry.outcome,
            entry.resource_type.value,
            entry.relevance.value,
        ]
        if explain:
            row.append(entry.reason)
        rows.append(row)
    widths = [max(len(row[column]) for row in rows) for column in range(len(rows[0]))]
    return [
        "  ".join(cell.ljust(width) for cell, width in zip(row, widths, strict=True)).rstrip()
        for row in rows
    ]


def _summary(inspection: Inspection, *, shown: int, include_noise: bool) -> list[str]:
    """Return the lines accounting for everything the table did not show."""
    counts = inspection.counts_by_relevance()
    lines = [
        f"Showing {shown} of {_count(len(inspection), 'request')}: "
        f"{counts[Relevance.APPLICATION]} application, "
        f"{counts[Relevance.UNKNOWN]} unknown, {counts[Relevance.NOISE]} noise."
    ]
    noise = counts[Relevance.NOISE]
    if noise and not include_noise:
        by_rule = ", ".join(
            f"{count} {rule.value}" for rule, count in inspection.noise_counts_by_rule().items()
        )
        lines.append(f"Filtered as noise ({by_rule}). Pass --all to list them.")
    if inspection.redacted_values:
        lines.append(
            f"Redacted {_count(inspection.redacted_values, 'value')} before displaying this."
        )
    return lines


def _count(number: int, noun: str) -> str:
    """Return ``number`` and ``noun``, pluralized the ordinary way."""
    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"


def _shorten(text: str, width: int) -> str:
    """Return ``text`` trimmed from the left to ``width``, keeping the end that names it.

    The cut is moved to the next path separator so the first segment shown is a whole
    one, unless a single segment is itself longer than the room available.
    """
    if len(text) <= width:
        return text
    tail = text[-(width - len(_ELLIPSIS)) :]
    boundary = tail.find("/")
    return _ELLIPSIS + (tail[boundary:] if boundary > 0 else tail)
