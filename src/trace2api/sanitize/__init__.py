"""Removal of credentials from captured traffic.

Nothing outside this package should write a capture to disk, print one, or feed one to
a generator without passing it through :func:`redact_capture` first.
"""

from __future__ import annotations

from trace2api.sanitize.policy import (
    RedactionRule,
    is_jwt_shaped,
    is_sensitive_header,
    is_sensitive_name,
    is_sensitive_query_name,
)
from trace2api.sanitize.redact import (
    Redaction,
    RedactionReport,
    RedactionResult,
    is_redacted,
    redact_capture,
)

__all__ = [
    "Redaction",
    "RedactionReport",
    "RedactionResult",
    "RedactionRule",
    "is_jwt_shaped",
    "is_redacted",
    "is_sensitive_header",
    "is_sensitive_name",
    "is_sensitive_query_name",
    "redact_capture",
]
