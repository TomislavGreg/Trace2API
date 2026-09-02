"""Read HAR 1.2 archives into the capture models.

A HAR file is the most common way an observed workflow leaves a browser, so it is the
first source Trace2API reads. The importer keeps what the archive actually recorded and
resolves the places where HAR says the same thing twice:

* Query parameters are taken from the request URL rather than from ``queryString``, so a
  request cannot describe a query string that disagrees with its own URL.
* Request cookies live in the ``Cookie`` header. The ``cookies`` array is used only to
  rebuild that header when an exporter listed the cookies but omitted the header.
* HTTP/2 pseudo headers (``:method``, ``:authority``) restate the request line rather
  than carry header fields, so they are dropped.

Entries whose URL never crossed the network (``data:``, ``blob:``, extension URLs) are
not imported, because there is no request there to reproduce. Everything else that the
archive gets wrong is an error rather than a silent omission.

Errors are raised as :class:`HarImportError` and name the position in the document that
caused them. They never quote a captured value: any field in an archive can hold a
credential, so a message describes the shape of the problem instead of its content.
Import does not redact. A capture returned from here still holds whatever the archive
held, and must pass through :func:`~trace2api.sanitize.redact_capture` before it is
stored or shown.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit

from pydantic import ValidationError

from trace2api.models import (
    Body,
    Capture,
    CaptureMetadata,
    CaptureSource,
    Entry,
    Header,
    Headers,
    Request,
    ResourceType,
    Response,
    Timings,
)

__all__ = ["HarImportError", "load_har", "parse_har"]

_SUPPORTED_MAJOR_VERSION = "1"
_REPLAYABLE_SCHEMES = frozenset({"http", "https"})
_UNKNOWN_HTTP_VERSIONS = frozenset({"unknown", "http/unknown"})
_NO_RESPONSE_RECORDED = "the archive records no response for this request"


class HarImportError(ValueError):
    """A HAR document could not be read into the capture models.

    ``location`` names the position in the document that failed, such as
    ``log.entries[3].request.url``, so a report can point at the field rather than at the
    file. ``reason`` is the message without that prefix.
    """

    def __init__(self, reason: str, *, location: str | None = None) -> None:
        self.reason = reason
        self.location = location
        super().__init__(f"{location}: {reason}" if location else reason)


def load_har(path: str | Path) -> Capture:
    """Read the HAR file at ``path`` into a capture."""
    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8-sig")
    except OSError as error:
        detail = error.strerror or type(error).__name__
        raise HarImportError(f"HAR file could not be read: {detail}") from None
    except UnicodeDecodeError:
        raise HarImportError("HAR file is not valid UTF-8 text") from None
    try:
        document = json.loads(text)
    except json.JSONDecodeError as error:
        raise HarImportError(
            f"HAR file is not valid JSON: {error.msg} at line {error.lineno} column {error.colno}"
        ) from None
    return parse_har(document)


def parse_har(document: Any) -> Capture:
    """Read an already parsed HAR document into a capture."""
    if not isinstance(document, dict):
        raise HarImportError(f"HAR document must be an object, found {_type_name(document)}")
    log = _object(_require(document, "log", ""), "log")
    _check_version(log)
    entries = []
    for index, raw_entry in enumerate(_array(log.get("entries", []), "log.entries")):
        entry = _import_entry(raw_entry, index)
        if entry is not None:
            entries.append(entry)
    return Capture(metadata=_import_metadata(log, entries), entries=entries)


# Document structure


def _check_version(log: dict[str, Any]) -> None:
    """Reject archives written to a HAR version this importer does not understand.

    An archive that omits the version is read as 1.2, which is what exporters that leave
    it out are writing.
    """
    raw_version = log.get("version")
    if raw_version is None:
        return
    version = _text(raw_version, "log.version")
    if version.split(".", 1)[0].strip() != _SUPPORTED_MAJOR_VERSION:
        raise HarImportError(
            f"unsupported HAR version {version!r}, expected 1.x", location="log.version"
        )


def _import_metadata(log: dict[str, Any], entries: list[Entry]) -> CaptureMetadata:
    """Describe where the capture came from.

    Provenance holds only what an archive cannot hide a credential in, so the recorded
    page URL is not copied here: redaction rewrites entries, not metadata.
    """
    creator_name, creator_version = _import_agent(log.get("creator"), "log.creator")
    browser_name, browser_version = _import_agent(log.get("browser"), "log.browser")
    return CaptureMetadata(
        source=CaptureSource.HAR,
        created_at=_capture_start(log, entries),
        creator_name=creator_name,
        creator_version=creator_version,
        browser_name=browser_name,
        browser_version=browser_version,
    )


def _import_agent(value: Any, location: str) -> tuple[str | None, str | None]:
    """Return the name and version of a HAR creator or browser record."""
    if value is None:
        return None, None
    agent = _object(value, location)
    return (
        _optional_text(agent.get("name"), _at(location, "name")),
        _optional_text(agent.get("version"), _at(location, "version")),
    )


def _capture_start(log: dict[str, Any], entries: list[Entry]) -> datetime:
    """Return when recording began: the first page, else the first entry, else now."""
    pages = _array(log.get("pages", []), "log.pages")
    if pages:
        location = "log.pages[0]"
        started = _object(pages[0], location).get("startedDateTime")
        if started is not None:
            return _timestamp(started, _at(location, "startedDateTime"))
    if entries:
        return min(entry.started_at for entry in entries)
    return datetime.now(UTC)


# Entries


def _import_entry(raw_entry: Any, index: int) -> Entry | None:
    """Import one archived exchange, or return ``None`` when it never hit the network."""
    location = f"log.entries[{index}]"
    entry = _object(raw_entry, location)
    request_location = _at(location, "request")
    raw_request = _object(_require(entry, "request", location), request_location)
    url = _text(_require(raw_request, "url", request_location), _at(request_location, "url"))
    if urlsplit(url.strip()).scheme.lower() not in _REPLAYABLE_SCHEMES:
        return None
    response, failure = _import_response(entry, location)
    return _build(
        Entry,
        location,
        # Ids number the slot the entry occupied in the archive, so an imported entry can
        # still be traced back to the document it came from.
        id=f"e{index + 1:04d}",
        started_at=_timestamp(
            _require(entry, "startedDateTime", location), _at(location, "startedDateTime")
        ),
        request=_import_request(raw_request, url, request_location),
        response=response,
        failure=failure,
        timings=_import_timings(entry, location),
        resource_type=ResourceType.from_label(_label(entry.get("_resourceType"))),
    )


def _import_request(raw_request: dict[str, Any], url: str, location: str) -> Request:
    """Import the request half of an exchange."""
    headers = _import_headers(raw_request.get("headers"), _at(location, "headers"))
    return _build(
        Request,
        location,
        method=_text(_require(raw_request, "method", location), _at(location, "method")),
        url=url,
        http_version=_http_version(raw_request.get("httpVersion"), _at(location, "httpVersion")),
        headers=_with_cookie_header(headers, raw_request.get("cookies"), _at(location, "cookies")),
        body=_import_request_body(raw_request, location),
    )


def _import_response(
    entry: dict[str, Any], entry_location: str
) -> tuple[Response | None, str | None]:
    """Import the response half of an exchange, or explain why there is none.

    A request that never completed is archived with status ``0``, which is not a status
    at all. Such an entry is imported as a failure so that later stages see that the
    request was observed without treating the missing response as data.
    """
    raw_response = entry.get("response")
    location = _at(entry_location, "response")
    if raw_response is None:
        return None, _failure_reason(entry)
    response = _object(raw_response, location)
    status = _integer(_require(response, "status", location), _at(location, "status"))
    if status == 0:
        return None, _failure_reason(entry)
    return (
        _build(
            Response,
            location,
            status=status,
            status_text=_optional_text(response.get("statusText"), _at(location, "statusText")),
            redirect_url=_optional_text(response.get("redirectURL"), _at(location, "redirectURL")),
            http_version=_http_version(response.get("httpVersion"), _at(location, "httpVersion")),
            headers=_import_headers(response.get("headers"), _at(location, "headers")),
            body=_import_response_body(response, location),
        ),
        None,
    )


def _failure_reason(entry: dict[str, Any]) -> str:
    """Return why an exchange has no response, preferring what the archive recorded."""
    recorded = _label(entry.get("_error"))
    return recorded.strip() if recorded and recorded.strip() else _NO_RESPONSE_RECORDED


def _import_headers(value: Any, location: str) -> Headers:
    """Import header fields, dropping the pseudo headers HTTP/2 archives carry."""
    if value is None:
        return Headers()
    headers = []
    for index, item in enumerate(_array(value, location)):
        item_location = f"{location}[{index}]"
        field = _object(item, item_location)
        name = _text(_require(field, "name", item_location), _at(item_location, "name"))
        if name.startswith(":"):
            continue
        headers.append(
            Header(
                name=name,
                value=_text(_require(field, "value", item_location), _at(item_location, "value")),
            )
        )
    return Headers(headers)


def _with_cookie_header(headers: Headers, value: Any, location: str) -> Headers:
    """Rebuild the ``Cookie`` header from the cookie array when the export omitted it.

    Only request cookies are rebuilt. A request cookie is exactly a name and a value, so
    reconstructing the header loses nothing, while a response cookie carries attributes
    the array does not fully restate.
    """
    if value is None or "cookie" in headers:
        return headers
    pairs = []
    for index, item in enumerate(_array(value, location)):
        item_location = f"{location}[{index}]"
        cookie = _object(item, item_location)
        name = _text(_require(cookie, "name", item_location), _at(item_location, "name"))
        pairs.append(
            f"{name}={_optional_text(cookie.get('value'), _at(item_location, 'value')) or ''}"
        )
    if not pairs:
        return headers
    return Headers([*headers, Header(name="Cookie", value="; ".join(pairs))])


# Bodies


def _import_request_body(raw_request: dict[str, Any], location: str) -> Body | None:
    """Import a sent payload from ``postData``.

    HAR stores a form payload either as text or as decoded parameters. When only the
    parameters were recorded the payload is re-encoded, so a request that carries a form
    keeps a body the later stages can read.
    """
    raw_post_data = raw_request.get("postData")
    if raw_post_data is None:
        return None
    size = _byte_count(raw_request.get("bodySize"), _at(location, "bodySize"))
    post_location = _at(location, "postData")
    post_data = _object(raw_post_data, post_location)
    text = _optional_text(post_data.get("text"), _at(post_location, "text"))
    if text is None and post_data.get("params") is not None:
        text = _encode_form_params(post_data["params"], _at(post_location, "params"))
    mime_type = _optional_text(post_data.get("mimeType"), _at(post_location, "mimeType"))
    if text is None and mime_type is None:
        return None
    return _build(Body, post_location, mime_type=mime_type, text=text, size=size)


def _encode_form_params(value: Any, location: str) -> str:
    """Re-encode decoded form parameters into the payload the request sent."""
    pairs = []
    for index, item in enumerate(_array(value, location)):
        item_location = f"{location}[{index}]"
        param = _object(item, item_location)
        name = _text(_require(param, "name", item_location), _at(item_location, "name"))
        pairs.append((name, _optional_text(param.get("value"), _at(item_location, "value")) or ""))
    return urlencode(pairs)


def _import_response_body(response: dict[str, Any], location: str) -> Body | None:
    """Import a received payload from ``content``.

    ``content.size`` is the length of the body the browser saw. When it exceeds what the
    archive actually stored, the payload was recorded only in part (or not at all), and
    the body is marked truncated so later stages do not read it as the whole answer.
    """
    raw_content = response.get("content")
    if raw_content is None:
        return None
    location = _at(location, "content")
    content = _object(raw_content, location)
    encoding = _optional_text(content.get("encoding"), _at(location, "encoding"))
    if encoding is not None and encoding.lower() != "base64":
        raise HarImportError(
            f"unsupported content encoding {encoding!r}, expected 'base64'",
            location=_at(location, "encoding"),
        )
    text = _optional_text(content.get("text"), _at(location, "text"))
    mime_type = _optional_text(content.get("mimeType"), _at(location, "mimeType"))
    size = _byte_count(content.get("size"), _at(location, "size"))
    if text is None and mime_type is None and size is None:
        return None
    body = _build(
        Body,
        location,
        mime_type=mime_type,
        text=text,
        encoding="base64" if encoding is not None and text is not None else None,
        size=size,
    )
    if size is not None and size > len(body.as_bytes()):
        return body.model_copy(update={"truncated": True})
    return body


# Timings


def _import_timings(entry: dict[str, Any], location: str) -> Timings | None:
    """Import observed durations, reading HAR's ``-1`` as a phase that was not measured."""
    total_ms = _duration(entry.get("time"), _at(location, "time"))
    raw_timings = entry.get("timings")
    if raw_timings is None:
        return None if total_ms is None else Timings(total_ms=total_ms)
    location = _at(location, "timings")
    timings = _object(raw_timings, location)
    return _build(
        Timings,
        location,
        blocked_ms=_duration(timings.get("blocked"), _at(location, "blocked")),
        dns_ms=_duration(timings.get("dns"), _at(location, "dns")),
        connect_ms=_duration(timings.get("connect"), _at(location, "connect")),
        ssl_ms=_duration(timings.get("ssl"), _at(location, "ssl")),
        send_ms=_duration(timings.get("send"), _at(location, "send")),
        wait_ms=_duration(timings.get("wait"), _at(location, "wait")),
        receive_ms=_duration(timings.get("receive"), _at(location, "receive")),
        total_ms=total_ms,
    )


# Field readers


def _at(parent: str, key: str) -> str:
    """Return the location of ``key`` inside ``parent``."""
    return f"{parent}.{key}" if parent else key


def _type_name(value: Any) -> str:
    """Name a JSON value's type the way the document spells it."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "a boolean"
    if isinstance(value, (int, float)):
        return "a number"
    if isinstance(value, str):
        return "a string"
    if isinstance(value, list):
        return "an array"
    if isinstance(value, dict):
        return "an object"
    return type(value).__name__


def _require(container: dict[str, Any], key: str, location: str) -> Any:
    """Return a field that must be present and not null."""
    value = container.get(key)
    if value is None:
        raise HarImportError("required field is missing", location=_at(location, key))
    return value


def _object(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise HarImportError(f"expected an object, found {_type_name(value)}", location=location)
    return value


def _array(value: Any, location: str) -> list[Any]:
    if not isinstance(value, list):
        raise HarImportError(f"expected an array, found {_type_name(value)}", location=location)
    return value


def _text(value: Any, location: str) -> str:
    if not isinstance(value, str):
        raise HarImportError(f"expected a string, found {_type_name(value)}", location=location)
    return value


def _optional_text(value: Any, location: str) -> str | None:
    """Read a string field, reading absent and empty alike as nothing recorded."""
    if value is None:
        return None
    text = _text(value, location)
    return text or None


def _label(value: Any) -> str | None:
    """Read a vendor extension that should be a string, ignoring it when it is not."""
    return value if isinstance(value, str) else None


def _http_version(value: Any, location: str) -> str | None:
    """Read a protocol version, reading the placeholders exporters use as unrecorded."""
    version = _optional_text(value, location)
    if version is None or version.strip().lower() in _UNKNOWN_HTTP_VERSIONS:
        return None
    return version


def _timestamp(value: Any, location: str) -> datetime:
    """Read an ISO 8601 instant.

    HAR requires an offset, and an instant without one cannot be lined up with the rest
    of a workflow, so a naive timestamp is refused rather than assumed to be UTC.
    """
    text = _text(value, location)
    try:
        moment = datetime.fromisoformat(text.strip())
    except ValueError:
        raise HarImportError("expected an ISO 8601 timestamp", location=location) from None
    if moment.tzinfo is None:
        raise HarImportError("timestamp must include a UTC offset", location=location)
    return moment


def _number(value: Any, location: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise HarImportError(f"expected a number, found {_type_name(value)}", location=location)
    return float(value)


def _integer(value: Any, location: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise HarImportError(f"expected an integer, found {_type_name(value)}", location=location)
    return value


def _duration(value: Any, location: str) -> float | None:
    """Read a duration in milliseconds. HAR reports an unmeasured phase as a negative."""
    if value is None:
        return None
    milliseconds = _number(value, location)
    return None if milliseconds < 0 else milliseconds


def _byte_count(value: Any, location: str) -> int | None:
    """Read a size in bytes. HAR reports a size it does not know as a negative."""
    if value is None:
        return None
    size = _integer(value, location)
    return None if size < 0 else size


def _build[ModelT](model: type[ModelT], location: str, **fields: Any) -> ModelT:
    """Build a capture model, reporting what it rejected without quoting the input.

    Only the failing field and the reason are kept. A validation error carries the value
    it rejected, and any value in an archive can be a credential, so the original error is
    not chained onto the failure either.
    """
    try:
        return model(**fields)
    except ValidationError as error:
        raise HarImportError(_describe(error), location=location) from None


def _describe(error: ValidationError) -> str:
    """Summarize a validation failure as the fields that failed and why."""
    reasons = []
    for detail in error.errors():
        field = ".".join(str(part) for part in detail["loc"])
        reasons.append(f"{field}: {detail['msg']}" if field else detail["msg"])
    return "; ".join(reasons)
