"""Rules deciding which captured values are treated as credentials.

The rules are name based and shape based rather than statistical, so every redaction
can be explained by pointing at the rule that fired. Entropy scoring is deliberately
avoided: it produces redactions nobody can account for and misses short secrets.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from enum import StrEnum
from typing import NamedTuple

__all__ = [
    "COOKIE_HEADERS",
    "CREDENTIAL_SCHEME_HEADERS",
    "EmbeddedSecret",
    "RedactionRule",
    "find_embedded_secrets",
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
    EMBEDDED_ASSIGNMENT = "embedded-assignment"
    EMBEDDED_META_CONTENT = "embedded-meta-content"


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

_EMBEDDED_ASSIGNMENT = re.compile(
    r"""
    (?P<name_quote>["'])?
    (?P<name>[A-Za-z_][A-Za-z0-9_.\-]{0,62})
    (?(name_quote)(?P=name_quote))
    \s*[:=]\s*
    (?P<value_quote>["'])(?P<value>[^"'\\\r\n]+)(?P=value_quote)
    """,
    re.VERBOSE,
)
"""A named field assigned a quoted value, as written in a script or a markup attribute.

Only quoted values are recognized. An unquoted one cannot be told from the expression,
keyword, or media type that follows an equals sign in the same text, and replacing those
would cost the inference stages more than it protects.
"""

_EMBEDDED_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_.\-])eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*(?![A-Za-z0-9_-])"
)
"""A JSON Web Token written into surrounding text, recognized by shape alone."""

_HTML_META_TAG = re.compile(r"""<meta\b(?:"[^"]*"|'[^']*'|[^<>"'])*>""", re.IGNORECASE)
"""A ``meta`` element. Quoted attributes are read whole, since a value can hold ``>``."""

_HTML_ATTRIBUTE = re.compile(
    r"""(?P<name>[A-Za-z_:][A-Za-z0-9_:.\-]*)\s*=\s*(?P<quote>["'])(?P<value>[^"']*)(?P=quote)"""
)

_META_NAMING_ATTRIBUTES = frozenset({"id", "itemprop", "name", "property"})
"""Attributes that say what a ``meta`` element carries. Its value is in ``content``."""

_PLAIN_NAME = re.compile(r"[A-Za-z0-9_:.\-]{1,64}")
"""What a reported field name may look like.

A name taken out of a page is written into a redaction report, and from there into the
comment a generated client carries. Anything but a plain name is not treated as one, so
nothing a page chooses to call itself can break out of the line it is printed on.
"""


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


class EmbeddedSecret(NamedTuple):
    """Where a credential shaped value sits inside text that is kept as observed.

    ``start`` and ``end`` bound the value itself rather than what surrounds it, so the
    text it was written into survives the replacement. ``name`` is the field the value
    was assigned to, when a name is what gave it away.
    """

    start: int
    end: int
    rule: RedactionRule
    name: str | None = None


def find_embedded_secrets(text: str) -> tuple[EmbeddedSecret, ...]:
    """Return the credential shaped values written into ``text``, in the order they sit.

    Structured payloads are read as the structures they are elsewhere. This covers what
    is left: a page, a script, a stylesheet, an unparsable payload, or a string inside a
    structure, all of which are kept as observed because the inference stages read them,
    and any of which can carry a token that appears nowhere else in a capture.

    The findings never overlap, so a caller can replace them in one pass. Where two rules
    reach the same text, the wider finding stands, and a name outranks a shape over the
    same span: a token assigned to a named field is reported as the field it was given to.
    """
    candidates = sorted(
        (*_find_assignments(text), *_find_meta_content(text), *_find_tokens(text)),
        key=lambda item: (item.start, -item.end),
    )
    found: list[EmbeddedSecret] = []
    for candidate in candidates:
        if found and candidate.start < found[-1].end:
            continue
        found.append(candidate)
    return tuple(found)


def _find_assignments(text: str) -> Iterator[EmbeddedSecret]:
    """Yield the quoted values assigned to credential named fields."""
    position = 0
    while (match := _EMBEDDED_ASSIGNMENT.search(text, position)) is not None:
        if _names_a_credential(match.group("name")):
            yield EmbeddedSecret(
                match.start("value"),
                match.end("value"),
                RedactionRule.EMBEDDED_ASSIGNMENT,
                match.group("name"),
            )
            position = match.end("value")
            continue
        # Resume inside the value rather than after it: a value that is not itself a
        # credential can still have one written inside it, as a page script does.
        position = match.end("name")


def _find_meta_content(text: str) -> Iterator[EmbeddedSecret]:
    """Yield the ``content`` of every ``meta`` element that names a credential.

    A page hands a token to its own scripts this way, and the name saying what the value
    is sits in a different attribute from the value itself.
    """
    for tag in _HTML_META_TAG.finditer(text):
        attributes = list(_HTML_ATTRIBUTE.finditer(tag.group()))
        named = next(
            (
                attribute.group("value")
                for attribute in attributes
                if attribute.group("name").lower() in _META_NAMING_ATTRIBUTES
                and _PLAIN_NAME.fullmatch(attribute.group("value"))
                and is_sensitive_name(attribute.group("value"))
            ),
            None,
        )
        if named is None:
            continue
        for attribute in attributes:
            if attribute.group("name").lower() == "content" and attribute.group("value"):
                yield EmbeddedSecret(
                    tag.start() + attribute.start("value"),
                    tag.start() + attribute.end("value"),
                    RedactionRule.EMBEDDED_META_CONTENT,
                    named,
                )


def _find_tokens(text: str) -> Iterator[EmbeddedSecret]:
    """Yield the token shaped values written into ``text``."""
    for match in _EMBEDDED_TOKEN.finditer(text):
        yield EmbeddedSecret(match.start(), match.end(), RedactionRule.JWT_SHAPED_VALUE)


def _names_a_credential(name: str) -> bool:
    """Return whether an assigned field names a credential.

    A dotted path is judged by its last segment as well as whole, so ``document.cookie``
    is recognized by the property being written rather than by the object holding it.
    """
    if is_sensitive_name(name):
        return True
    segment = name.rsplit(".", 1)[-1]
    return segment != name and is_sensitive_name(segment)
