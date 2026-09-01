"""Replace credentials in a capture with placeholders before it is stored or shown.

Redaction runs before a capture is written to disk, printed, logged, or turned into
generated code, so the rest of the project only ever handles sanitized traffic.

Secrets are replaced rather than dropped. Each placeholder carries a short fingerprint
of the value it replaced, computed with a per run salt, so a token reused across several
requests still looks like one value to later stages while the value itself is gone. The
salt lives only in memory for the duration of a run and is never written into a capture,
which keeps the fingerprints from being reversible by anyone reading the output.

What redaction does not do: bodies it cannot parse (binary payloads, unknown text
formats) are left untouched, because blanking them would destroy the evidence the
inference stages read. Sensitive material in such a body is caught only if it also
appears in a header, a query string, or a structured field. Nor does a credential named
field hide its whole subtree: an object under such a name is walked into on its own
terms, so its leaves are judged by their own names and shapes.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from collections.abc import Iterable
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field

from trace2api.models import Body, Capture, Entry, Header, Headers, Request, Response
from trace2api.sanitize.policy import (
    COOKIE_HEADERS,
    CREDENTIAL_SCHEME_HEADERS,
    RedactionRule,
    is_jwt_shaped,
    is_sensitive_header,
    is_sensitive_name,
    is_sensitive_query_name,
)

__all__ = [
    "Redaction",
    "RedactionReport",
    "RedactionResult",
    "is_redacted",
    "redact_capture",
]

_FINGERPRINT_LENGTH = 8
_PLACEHOLDER_PATTERN = re.compile(rf"^<redacted:[0-9a-f]{{{_FINGERPRINT_LENGTH}}}>$")

_FORM_MEDIA_TYPE = "application/x-www-form-urlencoded"


def is_redacted(value: str) -> bool:
    """Return whether ``value`` is a placeholder left behind by redaction."""
    return bool(_PLACEHOLDER_PATTERN.match(value.strip()))


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
    """One value that was removed, described without quoting it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entry_id: str
    location: str
    rule: RedactionRule
    fingerprint: str


class RedactionReport(BaseModel):
    """Everything redaction removed from a capture."""

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

        A value that is already a placeholder is returned untouched, so redacting a
        capture twice produces the same capture and the same report.
        """
        if is_redacted(value):
            return value
        digest = hmac.new(self._salt, value.encode("utf-8"), hashlib.sha256).hexdigest()
        fingerprint = digest[:_FINGERPRINT_LENGTH]
        self.redactions.append(
            Redaction(
                entry_id=self._entry_id,
                location=location,
                rule=rule,
                fingerprint=fingerprint,
            )
        )
        return f"<redacted:{fingerprint}>"

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

        query = parts.query
        if query:
            pairs = parse_qsl(query, keep_blank_values=True)
            redacted = self._redact_pairs(pairs, location=f"{location}.query", query=True)
            if redacted is not None:
                query = urlencode(redacted)

        if netloc == parts.netloc and query == parts.query:
            return url
        return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))

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
            if is_sensitive(name):
                rule = RedactionRule.SENSITIVE_PARAMETER
            elif is_jwt_shaped(value):
                rule = RedactionRule.JWT_SHAPED_VALUE
            else:
                result.append((name, value))
                continue
            replaced = self._replace(value, f"{location}[{name}]", rule)
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
        if is_sensitive_header(name):
            return header.model_copy(
                update={"value": self._replace(value, where, RedactionRule.SENSITIVE_HEADER)}
            )
        if is_jwt_shaped(value):
            return header.model_copy(
                update={"value": self._replace(value, where, RedactionRule.JWT_SHAPED_VALUE)}
            )
        return header

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
        return body

    def _redact_json_body(self, body: Body, location: str) -> Body:
        try:
            document = json.loads(body.text or "")
        except ValueError:
            # A body that does not parse is left as observed. The importer reports
            # malformed payloads; redaction is not the stage that judges them.
            return body
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
                if is_sensitive_name(key) and _holds_a_value(item):
                    replaced = self._replace(str(item), where, RedactionRule.SENSITIVE_PARAMETER)
                    result[key] = replaced
                    changed = changed or replaced != item
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
        if isinstance(value, str) and is_jwt_shaped(value):
            return self._replace(value, location, RedactionRule.JWT_SHAPED_VALUE), True
        return value, False

    def _redact_form_body(self, body: Body, location: str) -> Body:
        pairs = parse_qsl(body.text or "", keep_blank_values=True)
        redacted = self._redact_pairs(pairs, location=location, query=False)
        if redacted is None:
            return body
        return body.model_copy(update={"text": urlencode(redacted)})
