"""Rules deciding which captured values are treated as credentials.

The rules are name based and shape based rather than statistical, so every redaction
can be explained by pointing at the rule that fired. Entropy scoring is deliberately
avoided: it produces redactions nobody can account for and misses short secrets.
"""

from __future__ import annotations

import re
from enum import StrEnum

__all__ = [
    "COOKIE_HEADERS",
    "CREDENTIAL_SCHEME_HEADERS",
    "RedactionRule",
    "is_jwt_shaped",
    "is_sensitive_header",
    "is_sensitive_name",
    "is_sensitive_query_name",
    "normalize_name",
]


class RedactionRule(StrEnum):
    """Why a value was redacted.

    Reports carry the rule instead of the value, so a capture can be explained without
    quoting what was removed.
    """

    SENSITIVE_HEADER = "sensitive-header"
    CREDENTIAL_SCHEME = "credential-scheme"
    COOKIE_VALUE = "cookie-value"
    SENSITIVE_PARAMETER = "sensitive-parameter"
    JWT_SHAPED_VALUE = "jwt-shaped-value"
    URL_USERINFO = "url-userinfo"


CREDENTIAL_SCHEME_HEADERS = frozenset({"authorization", "proxy-authorization"})
"""Headers holding a scheme followed by a credential. The scheme itself is kept."""

COOKIE_HEADERS = frozenset({"cookie", "set-cookie"})
"""Headers holding cookies. Every cookie value is treated as a credential."""

_SENSITIVE_HEADERS = frozenset(
    {
        "authentication",
        "proxyauthenticate",
        "wwwauthenticate",
        "xamzsecuritytoken",
        "xauth",
        "xsessionid",
    }
)

_SENSITIVE_NAMES = frozenset(
    {
        "accesskey",
        "authentication",
        "authenticity",
        "authorization",
        "bearer",
        "cookie",
        "csrf",
        "jwt",
        "otp",
        "pass",
        "privatekey",
        "proxyauthorization",
        "pwd",
        "secretkey",
        "session",
        "sessionid",
        "sid",
        "totp",
        "xsrf",
    }
)

_SENSITIVE_NAME_SUFFIXES = (
    "apikey",
    "auth",
    "credential",
    "credentials",
    "password",
    "passwd",
    "secret",
    "signature",
    "token",
)

_SENSITIVE_QUERY_NAMES = frozenset({"code", "key", "sig"})
"""Names redacted in query strings only.

An OAuth ``code`` or an API ``key`` in a URL is a credential. The same words name
ordinary data in request bodies (a country code, a sort key), so applying these
outside a query string would redact values the later inference stages depend on.
"""

_JWT_PATTERN = re.compile(r"^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")


def normalize_name(name: str) -> str:
    """Return ``name`` with case, spacing, and separators removed for comparison.

    ``X-CSRF-Token``, ``x_csrf_token``, and ``csrfToken`` all reduce to a form the
    name rules can match.
    """
    return re.sub(r"[^a-z0-9]", "", name.strip().lower())


def is_sensitive_name(name: str) -> bool:
    """Return whether a header, parameter, or field name names a credential."""
    normalized = normalize_name(name)
    if not normalized:
        return False
    if normalized in _SENSITIVE_NAMES:
        return True
    return normalized.endswith(_SENSITIVE_NAME_SUFFIXES)


def is_sensitive_query_name(name: str) -> bool:
    """Return whether a query parameter name names a credential."""
    return is_sensitive_name(name) or normalize_name(name) in _SENSITIVE_QUERY_NAMES


def is_sensitive_header(name: str) -> bool:
    """Return whether a header carries a credential as its whole value.

    Credential scheme headers and cookie headers are excluded: their values are
    partially redacted elsewhere so the structure a reader needs stays visible.
    """
    normalized = normalize_name(name)
    if normalized in _SENSITIVE_HEADERS:
        return True
    lowered = name.strip().lower()
    if lowered in CREDENTIAL_SCHEME_HEADERS or lowered in COOKIE_HEADERS:
        return False
    return is_sensitive_name(name)


def is_jwt_shaped(value: str) -> bool:
    """Return whether ``value`` has the three part shape of a JSON Web Token.

    The first segment must start with ``eyJ``, the base64url encoding of a JSON object,
    which keeps ordinary dotted values from matching.
    """
    return bool(_JWT_PATTERN.match(value.strip()))
