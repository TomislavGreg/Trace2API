"""Working out what a capture means.

The stages in this package read a capture and say something about it: which requests
carry the workflow, which values are inputs, and how one request depends on another.
They are deterministic, and every verdict names the rule behind it, so the reasoning can
be inspected rather than trusted.
"""

from __future__ import annotations

from trace2api.analyze.classify import (
    ClassifiedRequest,
    ClassifiedValue,
    ValueClassification,
    ValueRole,
    ValueRule,
    classify_values,
    render_classification,
)
from trace2api.analyze.diff import (
    REDACTED_DISPLAY,
    AlignedCaptures,
    AlignedRequest,
    AlignmentRule,
    CaptureDiff,
    ChangeKind,
    ComparedCapture,
    ComparedValue,
    PairedRequest,
    UnpairedRequest,
    ValueChange,
    align_captures,
    compare_requests,
    diff_captures,
    render_diff,
)
from trace2api.analyze.flow import (
    CaptureFlows,
    FlowEndpoint,
    FlowRule,
    TracedRequest,
    ValueFlow,
    render_flows,
    trace_flows,
)
from trace2api.analyze.graph import (
    Dependency,
    DependencyLink,
    GraphNode,
    RequestGraph,
    build_graph,
    graph_capture,
    render_graph,
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
from trace2api.analyze.verify import (
    Mismatch,
    MismatchKind,
    ResponseComparison,
    compare_responses,
)

__all__ = [
    "DEFAULT_KEPT",
    "REDACTED_DISPLAY",
    "UNDECLARED_CONTENT_TYPE",
    "AlignedCaptures",
    "AlignedRequest",
    "AlignmentRule",
    "CaptureDiff",
    "CaptureFlows",
    "CaptureSummary",
    "ChangeKind",
    "Classification",
    "ClassifiedRequest",
    "ClassifiedValue",
    "ComparedCapture",
    "ComparedValue",
    "ContentTypeCount",
    "Dependency",
    "DependencyLink",
    "FilterReport",
    "FilterResult",
    "FilterRule",
    "FlowEndpoint",
    "FlowRule",
    "GraphNode",
    "Mismatch",
    "MismatchKind",
    "PairedRequest",
    "Relevance",
    "RequestGraph",
    "ResponseComparison",
    "TracedRequest",
    "UnpairedRequest",
    "ValueChange",
    "ValueClassification",
    "ValueFlow",
    "ValueRole",
    "ValueRule",
    "align_captures",
    "build_graph",
    "classify_capture",
    "classify_entry",
    "classify_values",
    "compare_requests",
    "compare_responses",
    "diff_captures",
    "filter_capture",
    "graph_capture",
    "render_classification",
    "render_diff",
    "render_flows",
    "render_graph",
    "render_summary",
    "summarize_capture",
    "trace_flows",
]
