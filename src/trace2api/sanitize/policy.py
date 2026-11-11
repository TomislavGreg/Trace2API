"""Rules deciding which captured values are treated as credentials.

The rules are name based and shape based rather than statistical, so every redaction
can be explained by pointing at the rule that fired. Entropy scoring is deliberately
avoided: it produces redactions nobody can account for and misses short secrets.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from enum import StrEnum
from typing import NamedTuple
from urllib.parse import unquote, urlsplit

__all__ = [
    "COOKIE_HEADERS",
    "CREDENTIAL_SCHEME_HEADERS",
    "EmbeddedSecret",
    "RedactionRule",
    "find_embedded_secrets",
    "find_path_secrets",
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
    EMBEDDED_FORM_FIELD_VALUE = "embedded-form-field-value"


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

_URL_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>]+", re.IGNORECASE)
"""A URL written into text, such as a pagination link or a callback address.

The scheme is read as broadly as RFC 3986 allows rather than limited to ``http`` and
``https``, since a mobile app's OAuth callback is a custom scheme such as
``com.example.app://`` or ``myapp://`` just as often as it is an ordinary web address,
and either one can carry the same credential shaped query or fragment value."""

_PROTOCOL_RELATIVE_URL_PATTERN = re.compile(
    r"(?<![\w:./])//(?:[^\s\"'<>@/]+@)?(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}"
    r"(?::\d+)?(?:[/?#][^\s\"'<>]*)?"
)
"""A protocol-relative URL written into text, such as ``//cdn.example.com/asset``.

A page or a script commonly links a resource this way so it is fetched over whichever
scheme the page itself was, and the same credential shaped query, fragment, or userinfo
``_URL_PATTERN`` already reads on an absolute link can sit on one of these just as well.
The host is required to carry a dotted label and a letter led top level domain, which
is what keeps an ordinary comment opener or a bare ``//`` inside a path from matching."""

_URL_QUERY_PAIR = re.compile(r"(?P<name>[^&=]*)=(?P<value>[^&]*)")

_HTML_META_TAG = re.compile(r"""<meta\b(?:"[^"]*"|'[^']*'|[^<>"'])*>""", re.IGNORECASE)
"""A ``meta`` element. Quoted attributes are read whole, since a value can hold ``>``."""

_HTML_INPUT_TAG = re.compile(r"""<input\b(?:"[^"]*"|'[^']*'|[^<>"'])*>""", re.IGNORECASE)
"""An ``input`` element, read the same way a ``meta`` element already is."""

_HTML_ATTRIBUTE = re.compile(
    r"""(?P<name>[A-Za-z_:][A-Za-z0-9_:.\-]*)\s*=\s*(?P<quote>["'])(?P<value>[^"']*)(?P=quote)"""
)

_META_NAMING_ATTRIBUTES = frozenset({"id", "itemprop", "name", "property"})
"""Attributes that say what a ``meta`` element carries. Its value is in ``content``."""

_INPUT_NAMING_ATTRIBUTES = frozenset({"name"})
"""The attribute that says what an ``input`` element carries. Its value is in ``value``."""

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
    """Return whether a header, parameter, or field name names a credential.

    A plain trailing ``s`` is stripped before the name and suffix rules are tried again,
    so ``tokens``, ``api_keys``, and ``passwords`` are recognized the same way their
    singular forms are: an API describing a batch of credentials does not stop naming
    them credentials for it.
    """
    normalized = normalize_name(name)
    if not normalized:
        return False
    if _matches_sensitive_name(normalized):
        return True
    return normalized.endswith("s") and _matches_sensitive_name(normalized[:-1])


def _matches_sensitive_name(normalized: str) -> bool:
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
    return _without_overlaps(
        (
            *_find_assignments(text),
            *_find_meta_content(text),
            *_find_input_values(text),
            *_find_url_secrets(text),
            *_find_tokens(text),
        )
    )


def find_path_secrets(path: str) -> tuple[EmbeddedSecret, ...]:
    """Return the credentials carried by a URL's own path.

    A bare credential shaped value, such as a JWT carried as a password reset or magic
    link token, is found the same way free standing text already is. A redirect or
    callback URL nested inside a path segment, percent encoded the way a link shortener
    or tracking redirect actually carries one, is read for a credential of its own the
    same way one nested in a query or fragment value already is.
    """
    return _without_overlaps((*find_embedded_secrets(path), *_find_in_decoded(path, 0)))


def _without_overlaps(candidates: Iterable[EmbeddedSecret]) -> tuple[EmbeddedSecret, ...]:
    """Return ``candidates`` in order, dropping one that starts inside an earlier one.

    Where two findings reach the same span, the wider one stands, and a name outranks a
    shape over the same span: a token assigned to a named field is reported as the field
    it was given to.
    """
    found: list[EmbeddedSecret] = []
    for candidate in sorted(candidates, key=lambda item: (item.start, -item.end)):
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
    yield from _find_tag_attribute_secrets(
        text,
        _HTML_META_TAG,
        _META_NAMING_ATTRIBUTES,
        "content",
        RedactionRule.EMBEDDED_META_CONTENT,
    )


def _find_input_values(text: str) -> Iterator[EmbeddedSecret]:
    """Yield the ``value`` of every ``input`` element whose ``name`` names a credential.

    A server renders a CSRF token, or a session or form token, straight into a hidden
    field, such as ``<input type="hidden" name="csrf_token" value="...">``, the same way
    a page hands one to its own scripts through a ``meta`` element. The name saying what
    the value is sits in its own ``name`` attribute rather than in the attribute carrying
    the value, so neither a named assignment nor a bare shape finds it on its own.
    """
    yield from _find_tag_attribute_secrets(
        text,
        _HTML_INPUT_TAG,
        _INPUT_NAMING_ATTRIBUTES,
        "value",
        RedactionRule.EMBEDDED_FORM_FIELD_VALUE,
    )


def _find_tag_attribute_secrets(
    text: str,
    tag_pattern: re.Pattern[str],
    naming_attributes: frozenset[str],
    value_attribute: str,
    rule: RedactionRule,
) -> Iterator[EmbeddedSecret]:
    """Yield ``value_attribute`` of every match of ``tag_pattern`` named by a credential.

    One attribute says what the element carries, by name, and a different attribute
    holds the value itself; this is shared between a ``meta`` element's ``content`` and
    an ``input`` element's ``value``.
    """
    for tag in tag_pattern.finditer(text):
        attributes = list(_HTML_ATTRIBUTE.finditer(tag.group()))
        named = next(
            (
                attribute.group("value")
                for attribute in attributes
                if attribute.group("name").lower() in naming_attributes
                and _PLAIN_NAME.fullmatch(attribute.group("value"))
                and is_sensitive_name(attribute.group("value"))
            ),
            None,
        )
        if named is None:
            continue
        for attribute in attributes:
            if attribute.group("name").lower() == value_attribute and attribute.group("value"):
                yield EmbeddedSecret(
                    tag.start() + attribute.start("value"),
                    tag.start() + attribute.end("value"),
                    rule,
                    named,
                )


def _find_url_secrets(text: str) -> Iterator[EmbeddedSecret]:
    """Yield the credential shaped parts of a URL written into text.

    A link embedded in a page, a script, or a JSON value, such as a pagination or
    callback URL, a mobile app's custom scheme OAuth callback such as
    ``myapp://oauth/callback``, or a protocol-relative link such as
    ``//cdn.example.com/asset`` left to be fetched over whichever scheme the page
    itself was, can carry the same credentials a request's own URL does: a username
    and password in its userinfo, a sensitive parameter in its query string, or, for
    an OAuth implicit grant returning its token that way instead, in its fragment. A
    query or fragment value that is itself a redirect or callback link is read the same
    way again, so a credential nested inside the destination the first link points to
    is found as well, and so is one nested inside the link's own path, the way a link
    shortener or tracking redirect carries its destination as a path segment rather
    than a query value. Only the credential itself is reported, so the rest of the
    link, and whatever is not a credential, stays as observed.
    """
    matches = sorted(
        (*_URL_PATTERN.finditer(text), *_PROTOCOL_RELATIVE_URL_PATTERN.finditer(text)),
        key=lambda match: match.start(),
    )
    for url_match in matches:
        yield from _find_matched_url_secrets(url_match)


def _find_matched_url_secrets(url_match: re.Match[str]) -> Iterator[EmbeddedSecret]:
    """Yield the credential shaped parts of one URL already matched in text.

    The netloc always starts right after the first ``//``, whether that pair of
    slashes was introduced by a scheme, as in ``https://``, or opens the link on its
    own, as a protocol-relative one does, so locating it this way reads either kind of
    link the same way without caring which it was.
    """
    url = url_match.group()
    parts = urlsplit(url)
    netloc_start = url_match.start() + url.index("//") + 2
    if parts.username is not None or parts.password is not None:
        userinfo = parts.netloc.rpartition("@")[0]
        yield EmbeddedSecret(
            netloc_start,
            netloc_start + len(userinfo),
            RedactionRule.URL_USERINFO,
            "userinfo",
        )
    if parts.path:
        path_start = netloc_start + len(parts.netloc)
        yield from _find_in_decoded(parts.path, path_start)
    if parts.query:
        query_start = url_match.start() + url.index("?") + 1
        yield from _find_pair_secrets(parts.query, query_start)
    if parts.fragment:
        fragment_start = url_match.start() + url.index("#") + 1
        yield from _find_pair_secrets(parts.fragment, fragment_start)


def _find_pair_secrets(pairs_text: str, offset: int) -> Iterator[EmbeddedSecret]:
    """Yield the credential shaped values among ``name=value`` pairs found at ``offset``."""
    for pair in _URL_QUERY_PAIR.finditer(pairs_text):
        value = pair.group("value")
        if not value:
            continue
        name = unquote(pair.group("name"))
        if is_sensitive_query_name(name):
            yield EmbeddedSecret(
                offset + pair.start("value"),
                offset + pair.end("value"),
                RedactionRule.SENSITIVE_PARAMETER,
                name,
            )
            continue
        if is_jwt_shaped(unquote(value)):
            yield EmbeddedSecret(
                offset + pair.start("value"),
                offset + pair.end("value"),
                RedactionRule.JWT_SHAPED_VALUE,
                name,
            )
            continue
        # The value is not itself a credential, but it may be a redirect or callback
        # address carrying one of its own, the same as a link found directly in the
        # surrounding text already is. Each finding is qualified with the name it sat
        # under here, so a credential two links deep is still reported by the full path
        # that reaches it.
        value_start = offset + pair.start("value")
        for nested in _find_in_decoded(value, value_start):
            qualified = name if nested.name is None else f"{name}.{nested.name}"
            yield EmbeddedSecret(nested.start, nested.end, nested.rule, qualified)


def _find_in_decoded(encoded: str, offset: int) -> Iterator[EmbeddedSecret]:
    """Yield the credentials of a value nested inside ``encoded``, decoding it first.

    A redirect or callback link carried as a query value, a fragment value, or a path
    segment is written there percent encoded, since its own `:`, `?`, and `/` are not
    valid unescaped in any of those. ``encoded`` is decoded before being searched. A
    credential's own characters are rarely ones percent encoding touches, so the text a
    finding names is looked up again in the still encoded value to recover the span to
    redact there; a finding whose text cannot be found this way, because encoding did
    change it, is left for the decoded value's own redaction to catch when it is read
    on its own.
    """
    decoded = unquote(encoded)
    search_from = 0
    for nested in find_embedded_secrets(decoded):
        secret_text = decoded[nested.start : nested.end]
        match_index = encoded.find(secret_text, search_from)
        if match_index == -1:
            continue
        search_from = match_index + len(secret_text)
        yield EmbeddedSecret(
            offset + match_index,
            offset + match_index + len(secret_text),
            nested.rule,
            nested.name,
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
