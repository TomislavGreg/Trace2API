"""Working out what a capture means.

The stages in this package read a capture and say something about it: which requests
carry the workflow, which values are inputs, and how one request depends on another.
They are deterministic, and every verdict names the rule behind it, so the reasoning can
be inspected rather than trusted.
"""

from __future__ import annotations

from trace2api.analyze.diff import (
    REDACTED_DISPLAY,
    AlignmentRule,
    CaptureDiff,
    ChangeKind,
    ComparedCapture,
    PairedRequest,
    UnpairedRequest,
    ValueChange,
    diff_captures,
    render_diff,
)
from trace2api.analyze.relevance import (
    DEFAULT_KEPT,
    Classification,
    FilterReport,
    FilterResult,
    FilterRule,
    Relevance,
    classify_capture,
    classify_entry,
    filter_capture,
)
from trace2api.analyze.summary import (
    UNDECLARED_CONTENT_TYPE,
    CaptureSummary,
    ContentTypeCount,
    render_summary,
    summarize_capture,
)

__all__ = [
    "DEFAULT_KEPT",
    "REDACTED_DISPLAY",
    "UNDECLARED_CONTENT_TYPE",
    "AlignmentRule",
    "CaptureDiff",
    "CaptureSummary",
    "ChangeKind",
    "Classification",
    "ComparedCapture",
    "ContentTypeCount",
    "FilterReport",
    "FilterResult",
    "FilterRule",
    "PairedRequest",
    "Relevance",
    "UnpairedRequest",
    "ValueChange",
    "classify_capture",
    "classify_entry",
    "diff_captures",
    "filter_capture",
    "render_diff",
    "render_summary",
    "summarize_capture",
]
