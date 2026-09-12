"""Reduce a capture to the few numbers that say what is in it.

A recording of a real workflow runs to hundreds of exchanges, and the first question
asked of one is never about a particular request. It is whether the recording caught the
workflow at all: how much traffic there was, how much of it was page furniture, how many
requests look like the application, and whether what came back was data or markup. A
table answers that by making the reader count, which is what this module does instead.

The counts come from the same rules ``inspect`` shows per request, so a summary and a
listing of the same capture never disagree. Redaction runs first, for the same reason it
runs first everywhere else: a summary is meant to be displayed, including in a report of
a recording nobody wants to hand over whole.

Kept and filtered here mean what they mean everywhere else in the project: an entry is
kept when its verdict is in :data:`~trace2api.analyze.relevance.DEFAULT_KEPT`, which is
what ``inspect`` lists and what ``generate`` writes out.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from trace2api.analyze.relevance import (
    DEFAULT_KEPT,
    Classification,
    FilterRule,
    Relevance,
    classify_capture,
)
from trace2api.models import Capture, CaptureSource, Entry
from trace2api.sanitize import redact_capture

__all__ = [
    "UNDECLARED_CONTENT_TYPE",
    "CaptureSummary",
    "ContentTypeCount",
    "render_summary",
    "summarize_capture",
]

UNDECLARED_CONTENT_TYPE = "not declared"
"""How a response that named no content type is labelled."""


class ContentTypeCount(BaseModel):
    """How many of the kept responses came back as one media type."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    media_type: str | None = None
    """The media type without its parameters, or ``None`` when none was declared."""

    count: int = Field(ge=1)

    @property
    def label(self) -> str:
        """Return the media type as it is displayed."""
        return self.media_type if self.media_type is not None else UNDECLARED_CONTENT_TYPE


class CaptureSummary(BaseModel):
    """What a capture holds, counted rather than listed."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: CaptureSource
    created_at: datetime
    start_url: str | None = None
    hosts: list[str] = Field(default_factory=list)
    total_requests: int = Field(default=0, ge=0)
    counts_by_relevance: dict[Relevance, int] = Field(default_factory=dict)
    """How many requests reached each verdict, including the verdicts nothing reached."""

    noise_by_rule: dict[FilterRule, int] = Field(default_factory=dict)
    """Which rules accounted for the filtered requests, most frequent first."""

    kept_content_types: list[ContentTypeCount] = Field(default_factory=list)
    """What the kept requests answered with, most frequent first."""

    kept_without_response: int = Field(default=0, ge=0)
    """Kept requests that failed or were still in flight when recording stopped."""

    redacted_values: int = Field(default=0, ge=0)
    """How many credentials were removed before any of this was counted."""

    @property
    def kept(self) -> int:
        """Return how many requests are kept by default."""
        return sum(self.counts_by_relevance.get(relevance, 0) for relevance in DEFAULT_KEPT)

    @property
    def filtered(self) -> int:
        """Return how many requests were filtered as noise."""
        return self.counts_by_relevance.get(Relevance.NOISE, 0)

    def as_json(self) -> str:
        """Return the summary as a JSON document."""
        return json.dumps(self.model_dump(mode="json"), indent=2)


def summarize_capture(capture: Capture, *, salt: bytes | None = None) -> CaptureSummary:
    """Redact ``capture``, classify what is left, and count the result.

    A ``salt`` may be supplied to make the redaction reproducible when two captures are
    summarized together.
    """
    sanitized = redact_capture(capture, salt=salt)
    report = classify_capture(sanitized.capture)
    verdicts = {item.entry_id: item.relevance for item in report.classifications}
    kept = frozenset(DEFAULT_KEPT)
    kept_entries = [entry for entry in sanitized.capture.entries if verdicts[entry.id] in kept]
    return CaptureSummary(
        source=sanitized.capture.metadata.source,
        created_at=sanitized.capture.metadata.created_at,
        start_url=sanitized.capture.metadata.start_url,
        hosts=list(sanitized.capture.hosts),
        total_requests=len(sanitized.capture),
        counts_by_relevance=report.counts_by_relevance(),
        noise_by_rule=_noise_by_rule(report.classifications),
        kept_content_types=_content_types(kept_entries),
        kept_without_response=sum(1 for entry in kept_entries if entry.response is None),
        redacted_values=len(sanitized.report),
    )


def _noise_by_rule(classifications: Iterable[Classification]) -> dict[FilterRule, int]:
    """Return which rules filtered the noise, most frequent first."""
    counts = Counter(item.rule for item in classifications if item.relevance is Relevance.NOISE)
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0].value)))


def _content_types(entries: list[Entry]) -> list[ContentTypeCount]:
    """Return what ``entries`` answered with, most frequent first, then alphabetically.

    Requests that never received a response are left out and counted separately: a
    recording that ends mid flight has no content type to report for them, and folding
    them in with the answered ones would make a summary claim more than was observed.
    """
    counts = Counter(
        _media_type(entry.response.content_type) for entry in entries if entry.response is not None
    )
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0] is None, item[0] or ""))
    return [ContentTypeCount(media_type=media_type, count=count) for media_type, count in ordered]


def _media_type(content_type: str | None) -> str | None:
    """Return ``content_type`` without its parameters, lowercased."""
    if content_type is None:
        return None
    media_type = content_type.split(";", 1)[0].strip().lower()
    return media_type or None


def render_summary(summary: CaptureSummary) -> str:
    """Render ``summary`` as the text ``trace2api summary`` writes."""
    lines = _headline(summary)
    lines.append("")
    lines.extend(_counts(summary))
    return "\n".join(lines) + "\n"


def _headline(summary: CaptureSummary) -> list[str]:
    """Return the provenance lines shown above the counts."""
    lines = [
        f"Capture: {_count(summary.total_requests, 'request')} from {summary.source.value}, "
        f"recorded {summary.created_at.isoformat()}"
    ]
    if summary.start_url is not None:
        lines.append(f"Started at: {summary.start_url}")
    if summary.hosts:
        lines.append(f"Hosts: {', '.join(summary.hosts)}")
    return lines


def _counts(summary: CaptureSummary) -> list[str]:
    """Return the counted account of the capture.

    A count that is zero is left out rather than printed, so what is shown is what was
    observed. The totals line is the exception: a capture with nothing kept is exactly
    the case a reader needs told.
    """
    if not summary.total_requests:
        return ["No requests were recorded."]
    lines = [
        f"Requests: {summary.total_requests} total, {summary.kept} kept, "
        f"{summary.filtered} filtered as noise."
    ]
    kept_by_relevance = _by_name(
        (relevance.value, summary.counts_by_relevance.get(relevance, 0))
        for relevance in DEFAULT_KEPT
    )
    if kept_by_relevance:
        lines.append(f"Kept: {kept_by_relevance}.")
    noise_by_rule = _by_name((rule.value, count) for rule, count in summary.noise_by_rule.items())
    if noise_by_rule:
        lines.append(f"Noise: {noise_by_rule}.")
    content_types = _by_name((item.label, item.count) for item in summary.kept_content_types)
    if content_types:
        lines.append(f"Kept content types: {content_types}.")
    if summary.kept_without_response:
        lines.append(
            f"{_count(summary.kept_without_response, 'kept request')} never received a response."
        )
    if summary.redacted_values:
        lines.append(f"Redacted {_count(summary.redacted_values, 'value')} before counting this.")
    return lines


def _by_name(counted: Iterable[tuple[str, int]]) -> str:
    """Return ``count name`` parts joined for display, dropping the empty ones."""
    return ", ".join(f"{count} {name}" for name, count in counted if count)


def _count(number: int, noun: str) -> str:
    """Return ``number`` and ``noun``, pluralized the ordinary way."""
    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"
