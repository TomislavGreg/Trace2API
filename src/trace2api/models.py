"""Core models for captured HTTP traffic.

Every later stage (import, filtering, inference, generation, replay) reads and writes
these types, so they describe what was observed on the wire rather than what any one
source format happens to store.

Two choices keep a capture from describing itself two different ways:

* Cookies are not modelled separately. Request cookies live in the ``Cookie`` header and
  response cookies in ``Set-Cookie``, which keeps headers the single place credential
  material can hide.
* Query parameters are derived from the request URL instead of being stored beside it,
  so a request cannot carry a query string that disagrees with its own URL.
"""

from __future__ import annotations

import base64
import binascii
import codecs
from collections.abc import Iterable, Iterator
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal, Self
from urllib.parse import parse_qsl, urlsplit

from pydantic import BaseModel, ConfigDict, Field, RootModel, field_validator, model_validator

from trace2api import __version__

__all__ = [
    "Body",
    "Capture",
    "CaptureMetadata",
    "CaptureSource",
    "Entry",
    "Header",
    "Headers",
    "HttpMessage",
    "QueryParam",
    "QueryParams",
    "Request",
    "ResourceType",
    "Response",
    "Timings",
]


class TrafficModel(BaseModel):
    """Base configuration for the traffic models.

    Captured traffic is evidence, so the models are frozen: a stage that needs to change
    something (redaction, filtering, rewriting) produces a new object instead of editing
    the record of what was observed.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)


class NameValue(TrafficModel):
    """A name and value pair as it was observed."""

    name: str
    value: str


class Header(NameValue):
    """One HTTP header field, with the name spelled as it was observed."""


class QueryParam(NameValue):
    """One decoded query string parameter."""


class _NameValueSequence:
    """Lookup helpers shared by the header and query parameter containers.

    Mixed into ``RootModel`` subclasses, which supply ``root``.
    """

    @staticmethod
    def _key(name: str) -> str:
        """Return the form of ``name`` used to compare two entries."""
        return name

    def __iter__(self) -> Iterator[NameValue]:
        return iter(self.root)

    def __len__(self) -> int:
        return len(self.root)

    def __contains__(self, name: str) -> bool:
        key = self._key(name)
        return any(self._key(item.name) == key for item in self.root)

    def names(self) -> tuple[str, ...]:
        """Return the names in the order they were observed, including repeats."""
        return tuple(item.name for item in self.root)

    def get_all(self, name: str) -> tuple[str, ...]:
        """Return every value recorded under ``name``, in the order observed."""
        key = self._key(name)
        return tuple(item.value for item in self.root if self._key(item.name) == key)

    def get(self, name: str, default: str | None = None) -> str | None:
        """Return the first value recorded under ``name``, or ``default``."""
        values = self.get_all(name)
        return values[0] if values else default


class Headers(_NameValueSequence, RootModel[list[Header]]):
    """Header fields in observed order. Names repeat and are matched case insensitively."""

    model_config = ConfigDict(frozen=True)

    root: list[Header] = Field(default_factory=list)

    @staticmethod
    def _key(name: str) -> str:
        return name.strip().lower()

    @classmethod
    def from_pairs(cls, pairs: Iterable[tuple[str, str]]) -> Headers:
        """Build headers from ``(name, value)`` pairs."""
        return cls([Header(name=name, value=value) for name, value in pairs])


class QueryParams(_NameValueSequence, RootModel[list[QueryParam]]):
    """Query string parameters in observed order. Names repeat and are case sensitive."""

    model_config = ConfigDict(frozen=True)

    root: list[QueryParam] = Field(default_factory=list)

    @classmethod
    def from_pairs(cls, pairs: Iterable[tuple[str, str]]) -> QueryParams:
        """Build query parameters from ``(name, value)`` pairs."""
        return cls([QueryParam(name=name, value=value) for name, value in pairs])


class Body(TrafficModel):
    """A request or response payload as captured.

    Text payloads are held in ``text`` as characters. Binary payloads are held in
    ``text`` as base64 with ``encoding`` set to ``"base64"``, matching how HAR and the
    browser devtools protocol report them.
    """

    mime_type: str | None = None
    text: str | None = None
    encoding: Literal["base64"] | None = None
    size: int | None = Field(default=None, ge=0)
    truncated: bool = False

    @model_validator(mode="after")
    def _check_encoded_text(self) -> Self:
        if self.encoding is None:
            return self
        if self.text is None:
            raise ValueError("body encoding is set but no body text was captured")
        try:
            base64.b64decode(self.text, validate=True)
        except (binascii.Error, ValueError) as error:
            raise ValueError(f"body text is not valid base64: {error}") from error
        return self

    @property
    def media_type(self) -> str | None:
        """Return the media type without parameters, lowercased."""
        if self.mime_type is None:
            return None
        media_type = self.mime_type.split(";", 1)[0].strip().lower()
        return media_type or None

    @property
    def charset(self) -> str | None:
        """Return the charset parameter of the media type, lowercased."""
        if self.mime_type is None:
            return None
        for parameter in self.mime_type.split(";")[1:]:
            name, separator, value = parameter.partition("=")
            if separator and name.strip().lower() == "charset":
                return value.strip().strip('"').lower() or None
        return None

    @property
    def is_empty(self) -> bool:
        """Return whether the payload carries no content."""
        return not self.text

    @property
    def is_json(self) -> bool:
        """Return whether the media type describes JSON."""
        media_type = self.media_type
        return media_type is not None and (
            media_type == "application/json" or media_type.endswith("+json")
        )

    def as_bytes(self) -> bytes:
        """Return the payload as bytes, decoding base64 when that is how it was stored."""
        if self.text is None:
            return b""
        if self.encoding == "base64":
            return base64.b64decode(self.text, validate=True)
        return self.text.encode(self._text_codec(), errors="replace")

    def _text_codec(self) -> str:
        """Return the charset to encode text with, falling back to UTF-8."""
        charset = self.charset
        if charset is None:
            return "utf-8"
        try:
            codecs.lookup(charset)
        except LookupError:
            return "utf-8"
        return charset


Milliseconds = Annotated[float | None, Field(default=None, ge=0)]


class Timings(TrafficModel):
    """Observed durations in milliseconds. Phases the source did not report are ``None``."""

    blocked_ms: Milliseconds
    dns_ms: Milliseconds
    connect_ms: Milliseconds
    ssl_ms: Milliseconds
    send_ms: Milliseconds
    wait_ms: Milliseconds
    receive_ms: Milliseconds
    total_ms: Milliseconds


class ResourceType(StrEnum):
    """What a browser considered a request to be."""

    DOCUMENT = "document"
    STYLESHEET = "stylesheet"
    IMAGE = "image"
    MEDIA = "media"
    FONT = "font"
    SCRIPT = "script"
    XHR = "xhr"
    FETCH = "fetch"
    WEBSOCKET = "websocket"
    EVENTSOURCE = "eventsource"
    MANIFEST = "manifest"
    OTHER = "other"

    @classmethod
    def from_label(cls, label: str | None) -> ResourceType:
        """Map a label reported by a capture source onto a known type.

        Sources spell these differently (``XHR``, ``xmlhttprequest``, ``text-track``),
        and unknown labels are recorded as ``OTHER`` rather than rejected.
        """
        if label is None:
            return cls.OTHER
        normalized = label.strip().lower().replace("-", "").replace("_", "")
        aliases = {
            "xmlhttprequest": cls.XHR,
            "css": cls.STYLESHEET,
            "img": cls.IMAGE,
            "texttrack": cls.MEDIA,
            "audio": cls.MEDIA,
            "video": cls.MEDIA,
            "ws": cls.WEBSOCKET,
            "websockets": cls.WEBSOCKET,
            "eventstream": cls.EVENTSOURCE,
        }
        if normalized in aliases:
            return aliases[normalized]
        try:
            return cls(normalized)
        except ValueError:
            return cls.OTHER


class HttpMessage(TrafficModel):
    """Fields shared by a request and a response."""

    http_version: str | None = None
    headers: Headers = Field(default_factory=Headers)
    body: Body | None = None

    @property
    def content_type(self) -> str | None:
        """Return the declared content type, preferring the header over the payload."""
        header = self.headers.get("content-type")
        if header is not None:
            return header
        return self.body.mime_type if self.body is not None else None


_SUPPORTED_URL_SCHEMES = ("http", "https")
_DEFAULT_PORTS = {"http": 80, "https": 443}


class Request(HttpMessage):
    """An observed HTTP request."""

    method: str
    url: str

    @field_validator("method")
    @classmethod
    def _normalize_method(cls, value: str) -> str:
        method = value.strip().upper()
        if not method or method.split() != [method]:
            raise ValueError(f"HTTP method must be a single token, got {value!r}")
        return method

    @field_validator("url")
    @classmethod
    def _check_url(cls, value: str) -> str:
        url = value.strip()
        parts = urlsplit(url)
        # Validation messages quote the URL without its query string, because query
        # strings routinely carry tokens and identifiers. Pydantic still records the
        # rejected value on the error itself, so code that reports a validation failure
        # should render the message rather than the raw input.
        quotable = url.split("?", 1)[0]
        if parts.scheme.lower() not in _SUPPORTED_URL_SCHEMES:
            raise ValueError(f"request URL must use http or https, got {quotable!r}")
        if not parts.netloc:
            raise ValueError(f"request URL must include a host, got {quotable!r}")
        return url

    @property
    def scheme(self) -> str:
        """Return the URL scheme, lowercased."""
        return urlsplit(self.url).scheme.lower()

    @property
    def host(self) -> str:
        """Return the host, lowercased and without any port."""
        return (urlsplit(self.url).hostname or "").lower()

    @property
    def port(self) -> int:
        """Return the port, falling back to the default for the scheme."""
        parts = urlsplit(self.url)
        return parts.port or _DEFAULT_PORTS[self.scheme]

    @property
    def path(self) -> str:
        """Return the path, which is ``/`` when the URL omits one."""
        return urlsplit(self.url).path or "/"

    @property
    def query_string(self) -> str:
        """Return the raw query string, without the leading question mark."""
        return urlsplit(self.url).query

    @property
    def query(self) -> QueryParams:
        """Return the decoded query parameters, in the order they appear in the URL."""
        pairs = parse_qsl(self.query_string, keep_blank_values=True)
        return QueryParams.from_pairs(pairs)

    @property
    def url_without_query(self) -> str:
        """Return the URL with the query string and fragment removed."""
        parts = urlsplit(self.url)
        return f"{parts.scheme.lower()}://{parts.netloc}{self.path}"


class Response(HttpMessage):
    """An observed HTTP response."""

    status: int = Field(ge=100, le=599)
    status_text: str | None = None
    redirect_url: str | None = None

    @property
    def is_success(self) -> bool:
        """Return whether the status is in the 2xx range."""
        return 200 <= self.status < 300

    @property
    def is_redirect(self) -> bool:
        """Return whether the status is in the 3xx range."""
        return 300 <= self.status < 400

    @property
    def is_error(self) -> bool:
        """Return whether the status is in the 4xx or 5xx range."""
        return self.status >= 400


class Entry(TrafficModel):
    """One observed request together with its response, if one arrived."""

    id: str
    started_at: datetime
    request: Request
    response: Response | None = None
    timings: Timings | None = None
    resource_type: ResourceType = ResourceType.OTHER
    failure: str | None = None

    @field_validator("id")
    @classmethod
    def _check_id(cls, value: str) -> str:
        entry_id = value.strip()
        if not entry_id:
            raise ValueError("entry id must not be blank")
        return entry_id

    @model_validator(mode="after")
    def _check_outcome(self) -> Self:
        if self.response is not None and self.failure is not None:
            raise ValueError(f"entry {self.id!r} records both a response and a failure reason")
        return self

    @property
    def succeeded(self) -> bool:
        """Return whether the request produced a response at all."""
        return self.response is not None


class CaptureSource(StrEnum):
    """Where a capture came from."""

    HAR = "har"
    BROWSER = "browser"


class CaptureMetadata(TrafficModel):
    """Provenance of a capture."""

    source: CaptureSource
    created_at: datetime
    creator_name: str | None = None
    creator_version: str | None = None
    browser_name: str | None = None
    browser_version: str | None = None
    start_url: str | None = None
    trace2api_version: str = __version__


class Capture(TrafficModel):
    """A recorded workflow: its provenance and the exchanges observed during it."""

    metadata: CaptureMetadata
    entries: list[Entry] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_entry_ids(self) -> Self:
        seen: set[str] = set()
        for entry in self.entries:
            if entry.id in seen:
                raise ValueError(f"capture contains more than one entry with id {entry.id!r}")
            seen.add(entry.id)
        return self

    def __iter__(self) -> Iterator[Entry]:  # type: ignore[override]
        return iter(self.entries)

    def __len__(self) -> int:
        return len(self.entries)

    def entry(self, entry_id: str) -> Entry | None:
        """Return the entry with ``entry_id``, or ``None`` when the capture has no such entry."""
        for entry in self.entries:
            if entry.id == entry_id:
                return entry
        return None

    @property
    def hosts(self) -> tuple[str, ...]:
        """Return the distinct hosts the capture touched, sorted."""
        return tuple(sorted({entry.request.host for entry in self.entries}))
