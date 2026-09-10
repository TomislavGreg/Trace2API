"""Removal of credentials from captured traffic.

Nothing outside this package should write a capture to disk, print one, or feed one to
a generator without passing it through :func:`redact_capture` first.
"""

from __future__ import annotations

from trace2api.sanitize.policy import (
    EmbeddedSecret,
    RedactionRule,
    find_embedded_secrets,
    is_jwt_shaped,
    is_sensitive_header,
    is_sensitive_name,
    is_sensitive_query_name,
)
from trace2api.sanitize.redact import (
    Redaction,
    RedactionReport,
    RedactionResult,
    SecretSegment,
    is_redacted,
    redact_capture,
    split_secrets,
)

__all__ = [
    "EmbeddedSecret",
    "Redaction",
    "RedactionReport",
    "RedactionResult",
    "RedactionRule",
    "SecretSegment",
    "find_embedded_secrets",
    "is_jwt_shaped",
    "is_redacted",
    "is_sensitive_header",
    "is_sensitive_name",
    "is_sensitive_query_name",
    "redact_capture",
    "split_secrets",
]
