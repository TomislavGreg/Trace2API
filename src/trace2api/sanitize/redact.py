"""Replace credentials in a capture with placeholders before it is stored or shown.

Redaction runs before a capture is written to disk, printed, logged, or turned into
generated code, so the rest of the project only ever handles sanitized traffic.

Secrets are replaced rather than dropped. Each placeholder carries a short fingerprint
of the value it replaced, computed with a per run salt, so a token reused across several
requests still looks like one value to later stages while the value itself is gone. The
salt lives only in memory for the duration of a run and is never written into a capture,
which keeps the fingerprints from being reversible by anyone reading the output.

Redacting an already sanitized capture is how a capture read back from disk enters a
later stage, so it is not treated as a special case: the placeholders stay as they are,
and the report still accounts for each one. The report, not the capture, is what says
where a secret belonged, and a stage such as code generation needs that to name the
variable a value comes back under.

A body redaction cannot read as a structure is still read as text. A page, a script, or
an unparsable payload keeps everything about it that the inference stages read, and the
credential shaped values written into it are replaced where they sit. Binary payloads
are the exception: nothing in them can be located without decoding a format redaction
does not claim to understand, so they are left as observed and are caught only where the
same value also appears in a header, a query string, or a structured field.

Nor does a credential named field hide its whole subtree: an object under such a name is
walked into on its own terms, so its leaves are judged by their own names and shapes.

A redirect's `Location` header is redacted the same way its `redirect_url` field already
is, and a request's `Referer` header is redacted the same way: each carries a URL a
browser sent along on its own, and a credential in a query parameter is a credential
whichever name it is read back under.

A header that is not one of the above, such as a `Link` naming one or more pages of
results alongside other text, or a `Refresh` naming a delay and a destination, is read
the same way a page's own text already is: only the credential shaped values embedded
in it move, whatever the header is called. This is what catches a custom pagination or
callback header a server happens to send, without needing its name listed here first.

A query parameter or a form field whose own value is a redirect or callback address is
read for the same credential shaped query values that address would carry on a request
of its own, the same as one embedded in a JSON string or a page's own text already is.
A multipart form field is read the same way once its own name is ruled out as a
credential.

A URL's fragment is read for credential shaped values the same way its query string
already is, wherever that URL is redacted: a request's own `url`, a `redirect_url`, a
`Location` or `Referer` header, or one embedded in text. An OAuth implicit grant
returns its access token there instead of in the query so a browser never sends it to
a server, and the fragment was otherwise carried through untouched.

A URL's path is read for a credential shaped value the same way free standing text
already is, wherever that URL is redacted. A password reset or magic link token is
often carried as a path segment rather than a query parameter, and it had passed
through untouched because nothing read the path at all. A segment with no shape a
rule recognizes, such as an ordinary identifier, is left as observed: a path segment
names nothing of its own, so only a value a shape rule catches, such as a JWT, is
found this way.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from collections.abc import Iterable
from typing import Any, NamedTuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field

from trace2api.models import Body, Capture, Entry, Header, Headers, Request, Response
from trace2api.sanitize.policy import (
    COOKIE_HEADERS,
    CREDENTIAL_SCHEME_HEADERS,
    RedactionRule,
    find_embedded_secrets,
    is_jwt_shaped,
    is_sensitive_header,
    is_sensitive_name,
    is_sensitive_query_name,
)

__all__ = [
    "Redaction",
    "RedactionReport",
    "RedactionResult",
    "SecretSegment",
    "is_redacted",
    "redact_capture",
    "split_secrets",
]

_FINGERPRINT_LENGTH = 8
_PLACEHOLDER_PATTERN = re.compile(rf"<redacted:([0-9a-f]{{{_FINGERPRINT_LENGTH}}})>")

_FORM_MEDIA_TYPE = "application/x-www-form-urlencoded"
_MULTIPART_MEDIA_TYPE = "multipart/form-data"

_MULTIPART_LEADING_NEWLINE = re.compile(r"\A(\r\n|\n)")
_MULTIPART_BLANK_LINE = re.compile(r"(\r\n\r\n|\n\n)")
_MULTIPART_TRAILING_NEWLINE = re.compile(r"(\r\n|\n)\Z")
_MULTIPART_DISPOSITION = re.compile(
    r"(?im)^Content-Disposition\s*:\s*form-data(?P<params>[^\r\n]*)$"
)
_MULTIPART_NAME = re.compile(r'name\s*=\s*"((?:[^"\\]|\\.)*)"', re.IGNORECASE)
_MULTIPART_FILENAME = re.compile(r'filename\s*=\s*"', re.IGNORECASE)

_URL_VALUED_HEADERS = frozenset({"location", "referer"})
"""Headers whose whole value is a URL, read the same way a request's own ``url`` is."""


def is_redacted(value: str) -> bool:
    """Return whether ``value`` is a placeholder left behind by redaction."""
    return _placeholder_fingerprint(value) is not None


def _placeholder_fingerprint(value: str) -> str | None:
    """Return the fingerprint ``value`` carries, when it is a placeholder and nothing else."""
    match = _PLACEHOLDER_PATTERN.fullmatch(value.strip())
    return match.group(1) if match else None


class SecretSegment(NamedTuple):
    """One run of a value: either literal text, or where a secret used to be."""

    text: str
    fingerprint: str | None = None

    @property
    def is_secret(self) -> bool:
        """Return whether this run stands in for a value redaction removed."""
        return self.fingerprint is not None


def split_secrets(text: str) -> tuple[SecretSegment, ...]:
    """Split ``text`` into its literal runs and the placeholders redaction left in it.

    A generator needs both halves separately: literal runs are quoted for the language
    being written, while each placeholder becomes a reference to wherever the value is
    supplied at run time. Splitting here keeps the placeholder format in the one module
    that defines it.
    """
    segments: list[SecretSegment] = []
    position = 0
    for match in _PLACEHOLDER_PATTERN.finditer(text):
        if match.start() > position:
            segments.append(SecretSegment(text[position : match.start()]))
        segments.append(SecretSegment(match.group(0), match.group(1)))
        position = match.end()
    if position < len(text):
        segments.append(SecretSegment(text[position:]))
    return tuple(segments)


def _holds_a_value(value: Any) -> bool:
    """Return whether a JSON value could itself be a credential.

    A numeric secret such as a one time code is redacted like a string one, which turns
    the field into text. Booleans and nulls are flags rather than secrets, and objects
    and arrays are walked into instead.
    """
    if value is None or isinstance(value, bool):
        return False
    return isinstance(value, str | int | float) and str(value) != ""


class Redaction(BaseModel):
    """One secret a capture held, described without quoting it.

    A value an earlier run already replaced is reported here too, since the report is
    what tells a later stage where a placeholder belongs.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    entry_id: str
    location: str
    rule: RedactionRule
    fingerprint: str


class RedactionReport(BaseModel):
    """Every secret redaction accounted for in a capture, by location and rule."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    redactions: list[Redaction] = Field(default_factory=list)

    def __len__(self) -> int:
        return len(self.redactions)

    @property
    def is_empty(self) -> bool:
        """Return whether nothing was redacted."""
        return not self.redactions

    def counts_by_rule(self) -> dict[RedactionRule, int]:
        """Return how many values each rule accounted for, most frequent first."""
        counts: dict[RedactionRule, int] = {}
        for redaction in self.redactions:
            counts[redaction.rule] = counts.get(redaction.rule, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))

    def for_entry(self, entry_id: str) -> tuple[Redaction, ...]:
        """Return the redactions recorded against ``entry_id``."""
        return tuple(item for item in self.redactions if item.entry_id == entry_id)


class RedactionResult(BaseModel):
    """A sanitized capture and the account of what was taken out of it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capture: Capture
    report: RedactionReport


def redact_capture(capture: Capture, *, salt: bytes | None = None) -> RedactionResult:
    """Return ``capture`` with its credentials replaced by placeholders.

    A ``salt`` may be supplied to make fingerprints reproducible, which lets two
    captures of the same workflow be redacted consistently so they stay comparable. It
    must be kept out of anything that is persisted alongside the redacted capture.
    """
    redactor = _Redactor(salt if salt is not None else secrets.token_bytes(32))
    entries = [redactor.redact_entry(entry) for entry in capture.entries]
    return RedactionResult(
        capture=capture.model_copy(update={"entries": entries}),
        report=RedactionReport(redactions=redactor.redactions),
    )


class _Redactor:
    """Carries the salt and the growing report while one capture is rewritten."""

    def __init__(self, salt: bytes) -> None:
        self._salt = salt
        self.redactions: list[Redaction] = []
        self._entry_id = ""

    # Recording

    def _replace(self, value: str, location: str, rule: RedactionRule) -> str:
        """Record a redaction and return the placeholder that takes the value's place.

        A value an earlier run already replaced keeps the placeholder it has, so
        redacting a capture twice produces the same capture. It is still reported, so
        that redacting twice also produces the same report: a capture read back from
        disk is already sanitized, and a stage that needs to know where its secrets
        belong has only the report to tell it.
        """
        existing = _placeholder_fingerprint(value)
        fingerprint = existing if existing is not None else self._fingerprint(value)
        self.redactions.append(
            Redaction(
                entry_id=self._entry_id,
                location=location,
                rule=rule,
                fingerprint=fingerprint,
            )
        )
        return value if existing is not None else f"<redacted:{fingerprint}>"

    def _fingerprint(self, value: str) -> str:
        """Return the salted fingerprint standing in for ``value``."""
        digest = hmac.new(self._salt, value.encode("utf-8"), hashlib.sha256).hexdigest()
        return digest[:_FINGERPRINT_LENGTH]

    # Entries

    def redact_entry(self, entry: Entry) -> Entry:
        self._entry_id = entry.id
        updates: dict[str, Any] = {"request": self._redact_request(entry.request)}
        if entry.response is not None:
            updates["response"] = self._redact_response(entry.response)
        return entry.model_copy(update=updates)

    def _redact_request(self, request: Request) -> Request:
        return request.model_copy(
            update={
                "url": self._redact_url(request.url, "request.url"),
                "headers": self._redact_headers(request.headers, "request.headers"),
                "body": self._redact_body(request.body, "request.body"),
            }
        )

    def _redact_response(self, response: Response) -> Response:
        updates: dict[str, Any] = {
            "headers": self._redact_headers(response.headers, "response.headers"),
            "body": self._redact_body(response.body, "response.body"),
        }
        if response.redirect_url:
            updates["redirect_url"] = self._redact_url(
                response.redirect_url, "response.redirect_url"
            )
        return response.model_copy(update=updates)

    # URLs

    def _redact_url(self, url: str, location: str) -> str:
        parts = urlsplit(url)
        netloc = parts.netloc
        if parts.username is not None or parts.password is not None:
            userinfo, _, host = netloc.rpartition("@")
            placeholder = self._replace(
                userinfo, f"{location}.userinfo", RedactionRule.URL_USERINFO
            )
            netloc = f"{placeholder}@{host}"

        path = parts.path
        if path:
            # A password reset or magic link token is often a path segment rather
            # than a query parameter, such as /reset-password/<jwt>. It carries no
            # name of its own to judge, so only a value recognized by shape, such as
            # a JWT, is caught here; an opaque identifier that is not is left alone.
            path = self._redact_text(path, f"{location}.path")

        query = parts.query
        if query:
            pairs = parse_qsl(query, keep_blank_values=True)
            redacted = self._redact_pairs(pairs, location=f"{location}.query", query=True)
            if redacted is not None:
                query = urlencode(redacted)

        fragment = parts.fragment
        if fragment:
            fragment = self._redact_fragment(fragment, f"{location}.fragment")

        if (
            netloc == parts.netloc
            and path == parts.path
            and query == parts.query
            and fragment == parts.fragment
        ):
            return url
        return urlunsplit((parts.scheme, netloc, path, query, fragment))

    def _redact_fragment(self, fragment: str, location: str) -> str:
        """Redact a URL fragment the same way its query string already is.

        An OAuth implicit grant returns its token this way instead of in the query, so
        a browser's own address bar never sends it to a server:
        ``#access_token=abc123&token_type=Bearer&state=xyz``. A plain anchor such as
        ``#section-2`` parses as one pair with no value and is left alone.
        """
        pairs = parse_qsl(fragment, keep_blank_values=True)
        redacted = self._redact_pairs(pairs, location=location, query=True)
        return urlencode(redacted) if redacted is not None else fragment

    def _redact_pairs(
        self,
        pairs: Iterable[tuple[str, str]],
        *,
        location: str,
        query: bool,
    ) -> list[tuple[str, str]] | None:
        """Redact name and value pairs, returning ``None`` when nothing changed."""
        is_sensitive = is_sensitive_query_name if query else is_sensitive_name
        result: list[tuple[str, str]] = []
        changed = False
        for name, value in pairs:
            if not value:
                result.append((name, value))
                continue
            where = f"{location}[{name}]"
            if is_sensitive(name):
                replaced = self._replace(value, where, RedactionRule.SENSITIVE_PARAMETER)
            elif is_jwt_shaped(value):
                replaced = self._replace(value, where, RedactionRule.JWT_SHAPED_VALUE)
            else:
                # The value itself may be a redirect or callback address carrying a
                # credential shaped query parameter of its own, the same as one written
                # into a JSON string or a page's own text already is.
                replaced = self._redact_text(value, where)
            result.append((name, replaced))
            changed = changed or replaced != value
        return result if changed else None

    # Headers

    def _redact_headers(self, headers: Headers, location: str) -> Headers:
        return Headers([self._redact_header(header, location) for header in headers])

    def _redact_header(self, header: Header, location: str) -> Header:
        name = header.name.strip().lower()
        value = header.value
        if not value:
            return header
        where = f"{location}.{name}"

        if name in CREDENTIAL_SCHEME_HEADERS:
            return header.model_copy(update={"value": self._redact_credential(value, where)})
        if name in COOKIE_HEADERS:
            redacted = (
                self._redact_cookie_pairs(value, where)
                if name == "cookie"
                else self._redact_set_cookie(value, where)
            )
            return header.model_copy(update={"value": redacted})
        if name in _URL_VALUED_HEADERS:
            # A redirect response's `Location` header carries the same URL its own
            # `redirect_url` field already redacts, and a request's `Referer` header
            # carries the address of whatever page sent the request, query string and
            # all; either can hold the same sensitive parameter a request's own URL
            # does and gets the same treatment.
            return header.model_copy(update={"value": self._redact_url(value, where)})
        if is_sensitive_header(name):
            return header.model_copy(
                update={"value": self._replace(value, where, RedactionRule.SENSITIVE_HEADER)}
            )
        if is_jwt_shaped(value):
            return header.model_copy(
                update={"value": self._replace(value, where, RedactionRule.JWT_SHAPED_VALUE)}
            )
        # Whatever this header is called, it may still carry a credential shaped value
        # alongside other text the same way a page's own markup does: a `Link` naming a
        # page of results, a `Refresh` naming a delay and a destination, or a header
        # this project has never seen before doing much the same thing.
        return header.model_copy(update={"value": self._redact_text(value, where)})

    def _redact_credential(self, value: str, location: str) -> str:
        """Redact an ``Authorization`` style value, keeping the scheme it announces."""
        scheme, separator, credential = value.partition(" ")
        if not separator or not credential.strip():
            return self._replace(value, location, RedactionRule.CREDENTIAL_SCHEME)
        placeholder = self._replace(credential.strip(), location, RedactionRule.CREDENTIAL_SCHEME)
        return f"{scheme} {placeholder}"

    def _redact_cookie_pairs(self, value: str, location: str) -> str:
        """Redact every value in a ``Cookie`` header, keeping the cookie names."""
        parts = []
        for pair in value.split(";"):
            name, separator, cookie_value = pair.strip().partition("=")
            if not separator or not cookie_value:
                parts.append(pair.strip())
                continue
            placeholder = self._replace(
                cookie_value, f"{location}[{name}]", RedactionRule.COOKIE_VALUE
            )
            parts.append(f"{name}={placeholder}")
        return "; ".join(part for part in parts if part)

    def _redact_set_cookie(self, value: str, location: str) -> str:
        """Redact a ``Set-Cookie`` value, keeping the cookie name and its attributes."""
        first, separator, attributes = value.partition(";")
        name, assignment, cookie_value = first.strip().partition("=")
        if not assignment or not cookie_value:
            return value
        placeholder = self._replace(
            cookie_value.strip(), f"{location}[{name}]", RedactionRule.COOKIE_VALUE
        )
        redacted = f"{name}={placeholder}"
        return f"{redacted};{attributes}" if separator else redacted

    # Bodies

    def _redact_body(self, body: Body | None, location: str) -> Body | None:
        if body is None or body.text is None or body.encoding is not None:
            return body
        if body.is_json:
            return self._redact_json_body(body, location)
        if body.media_type == _FORM_MEDIA_TYPE:
            return self._redact_form_body(body, location)
        if body.media_type == _MULTIPART_MEDIA_TYPE:
            return self._redact_multipart_body(body, location)
        return self._redact_text_body(body, location)

    def _redact_json_body(self, body: Body, location: str) -> Body:
        try:
            document = json.loads(body.text or "")
        except ValueError:
            # A body that does not parse is read as text instead. The importer reports
            # malformed payloads; redaction is not the stage that judges them, and a
            # credential in one is still a credential.
            return self._redact_text_body(body, location)
        redacted, changed = self._redact_json_value(document, location)
        if not changed:
            return body
        return body.model_copy(update={"text": json.dumps(redacted, ensure_ascii=False)})

    def _redact_json_value(self, value: Any, location: str) -> tuple[Any, bool]:
        if isinstance(value, dict):
            result: dict[str, Any] = {}
            changed = False
            for key, item in value.items():
                where = f"{location}.{key}"
                if is_sensitive_name(key):
                    if _holds_a_value(item):
                        replaced = self._replace(
                            str(item), where, RedactionRule.SENSITIVE_PARAMETER
                        )
                        result[key] = replaced
                        changed = changed or replaced != item
                        continue
                    if isinstance(item, list):
                        items = [
                            self._redact_sensitive_list_item(entry, f"{where}[{index}]")
                            for index, entry in enumerate(item)
                        ]
                        result[key] = [entry for entry, _ in items]
                        changed = changed or any(item_changed for _, item_changed in items)
                        continue
                result[key], item_changed = self._redact_json_value(item, where)
                changed = changed or item_changed
            return result, changed
        if isinstance(value, list):
            items = [
                self._redact_json_value(item, f"{location}[{index}]")
                for index, item in enumerate(value)
            ]
            return [item for item, _ in items], any(item_changed for _, item_changed in items)
        if isinstance(value, str):
            if is_jwt_shaped(value):
                return self._replace(value, location, RedactionRule.JWT_SHAPED_VALUE), True
            # A string leaf can hold a page or a script of its own, so it is read as
            # text as well as judged by the name it sits under.
            redacted = self._redact_text(value, location)
            return redacted, redacted != value
        return value, False

    def _redact_sensitive_list_item(self, item: Any, location: str) -> tuple[Any, bool]:
        """Redact one element of a list sitting directly under a credential named field.

        A string or number in the list is itself a credential the field name already
        named, the same as a scalar directly under that name would be, so it is
        replaced whole rather than only matched by shape. A further list nested inside
        carries no name of its own either, so the same treatment applies to its own
        elements, however many levels deep the nesting goes. An object does carry names
        of its own, so it is walked into on its own terms instead, the same as an object
        directly under the name is.
        """
        if _holds_a_value(item):
            replaced = self._replace(str(item), location, RedactionRule.SENSITIVE_PARAMETER)
            return replaced, replaced != item
        if isinstance(item, list):
            items = [
                self._redact_sensitive_list_item(entry, f"{location}[{index}]")
                for index, entry in enumerate(item)
            ]
            return [entry for entry, _ in items], any(entry_changed for _, entry_changed in items)
        return self._redact_json_value(item, location)

    def _redact_text_body(self, body: Body, location: str) -> Body:
        """Replace the credentials written into a body that is otherwise kept as observed."""
        text = body.text or ""
        redacted = self._redact_text(text, location)
        if redacted == text:
            return body
        return body.model_copy(update={"text": redacted})

    def _redact_text(self, text: str, location: str) -> str:
        """Replace the credential shaped values in ``text``, leaving the rest of it alone.

        Only the values move. What surrounds them is what tells a later stage where the
        request came from, and a page with its scripts blanked would explain nothing.
        """
        found = find_embedded_secrets(text)
        if not found:
            return text
        pieces: list[str] = []
        position = 0
        for secret in found:
            where = location if secret.name is None else f"{location}.{secret.name}"
            pieces.append(text[position : secret.start])
            pieces.append(self._replace(text[secret.start : secret.end], where, secret.rule))
            position = secret.end
        pieces.append(text[position:])
        return "".join(pieces)

    def _redact_form_body(self, body: Body, location: str) -> Body:
        pairs = parse_qsl(body.text or "", keep_blank_values=True)
        redacted = self._redact_pairs(pairs, location=location, query=False)
        if redacted is None:
            return body
        return body.model_copy(update={"text": urlencode(redacted)})

    def _redact_multipart_body(self, body: Body, location: str) -> Body:
        """Redact the fields of a multipart form, keeping everything else byte for byte.

        A field is split from the rest of the payload by its boundary, which is read
        from the declared media type rather than guessed, so a value is never mistaken
        for a delimiter. A part this cannot make sense of, including the whole body when
        no boundary was declared, is read as text instead rather than left untouched.
        """
        boundary = _multipart_boundary(body.mime_type or "")
        if boundary is None:
            return self._redact_text_body(body, location)
        delimiter = f"--{boundary}"
        segments = (body.text or "").split(delimiter)
        if len(segments) < 3:
            return self._redact_text_body(body, location)
        changed = False
        for index in range(1, len(segments) - 1):
            redacted_segment, segment_changed = self._redact_multipart_part(
                segments[index], location
            )
            if segment_changed:
                segments[index] = redacted_segment
                changed = True
        if not changed:
            return body
        return body.model_copy(update={"text": delimiter.join(segments)})

    def _redact_multipart_part(self, part: str, location: str) -> tuple[str, bool]:
        """Redact one field of a multipart form, or return it unchanged."""
        leading = _MULTIPART_LEADING_NEWLINE.match(part)
        if leading is None:
            return part, False
        rest = part[leading.end() :]
        blank = _MULTIPART_BLANK_LINE.search(rest)
        if blank is None:
            return part, False
        headers_text = rest[: blank.start()]
        content = rest[blank.end() :]
        trailing = _MULTIPART_TRAILING_NEWLINE.search(content)
        value = content[: trailing.start()] if trailing else content
        if not value:
            return part, False
        disposition = _MULTIPART_DISPOSITION.search(headers_text)
        if disposition is None or _MULTIPART_FILENAME.search(disposition["params"]):
            # An unnamed part or a file carries no field name to judge, and a file's
            # content is not read as text here either: the structure, not the bytes
            # inside a part this project does not otherwise claim to understand.
            return part, False
        name_match = _MULTIPART_NAME.search(disposition["params"])
        if name_match is None:
            return part, False
        name = name_match.group(1).replace('\\"', '"')
        where = f"{location}[{name}]"
        if is_sensitive_name(name):
            replaced = self._replace(value, where, RedactionRule.SENSITIVE_PARAMETER)
        elif is_jwt_shaped(value):
            replaced = self._replace(value, where, RedactionRule.JWT_SHAPED_VALUE)
        else:
            # The field is not itself a credential, but its value may be a redirect or
            # callback address carrying one of its own, the same as a JSON string, a
            # form field, or a page's own text already is read for.
            replaced = self._redact_text(value, where)
        if replaced == value:
            return part, False
        rebuilt = leading.group(0) + headers_text + blank.group(1) + replaced
        rebuilt += content[trailing.start() :] if trailing else ""
        return rebuilt, True


def _multipart_boundary(mime_type: str) -> str | None:
    """Return the boundary a multipart media type declared, or ``None`` without one."""
    for parameter in mime_type.split(";")[1:]:
        name, separator, value = parameter.partition("=")
        if not separator or name.strip().lower() != "boundary":
            continue
        value = value.strip()
        if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        return value or None
    return None
