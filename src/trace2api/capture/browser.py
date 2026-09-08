"""Record the traffic a live browser session performs into the capture models.

A HAR export is a workflow someone already finished; this module watches one as it
happens. It listens to the request events a Playwright browser context emits and turns
each exchange into an :class:`~trace2api.models.Entry`, so a recorded session reads the
same way as an imported archive and every later stage works on it unchanged.

Three decisions shape what a recording holds:

* Every http and https exchange is recorded, assets and analytics included. Deciding what
  is noise is the analysis stage's job, and a recording that dropped requests could not
  report what it left out.
* Response payloads are kept only for the exchanges the analysis reads. A page asset
  keeps its media type and size, which is what a summary needs, without carrying an image
  around in memory. A payload past :data:`DEFAULT_MAX_BODY_BYTES` is recorded as truncated
  for the same reason.
* Recording uses a throwaway browser profile, so a session leaves no cookie jar, history,
  or cache behind on disk.

Like the HAR importer, recording does not redact. A capture returned from here still
holds whatever the session sent, and must pass through
:func:`~trace2api.sanitize.redact_capture` before it is stored or shown.
"""

from __future__ import annotations

import base64
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import ModuleType
from typing import Any, Protocol
from urllib.parse import urlsplit, urlunsplit

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

__all__ = [
    "DEFAULT_MAX_BODY_BYTES",
    "BrowserCaptureError",
    "BrowserRecorder",
    "record_session",
    "recording",
]

DEFAULT_MAX_BODY_BYTES = 512 * 1024
"""Largest payload kept in full. A longer one is recorded as truncated instead."""

_RECORDABLE_SCHEMES = frozenset({"http", "https"})

_BODY_CARRYING_TYPES = frozenset(
    {
        ResourceType.DOCUMENT,
        ResourceType.XHR,
        ResourceType.FETCH,
        ResourceType.EVENTSOURCE,
        ResourceType.OTHER,
    }
)
"""Resource types whose response payload is kept. The rest are page furniture."""

_TEXT_MEDIA_TYPES = frozenset(
    {
        "application/javascript",
        "application/x-javascript",
        "application/x-www-form-urlencoded",
        "application/xml",
        "application/graphql",
        "image/svg+xml",
    }
)

_UNSETTLED = "the recording ended before the response arrived"
_UNREPORTED_FAILURE = "the browser reported no reason for the failure"
_UNREAD = "the response arrived but the browser closed before it could be read"

_STARTED, _FINISHED, _FAILED = "started", "finished", "failed"

DRAIN_INTERVAL_MS = 250
"""How often a running session is drained. Long enough to be cheap, short enough that a
browser has not yet discarded the payloads waiting to be read."""


class BrowserCaptureError(RuntimeError):
    """A browser session could not be recorded.

    Messages never quote a query string: a URL an operator hands to the recorder can
    carry a token as readily as one the session sends.
    """


class PlaywrightResponse(Protocol):
    """The part of a Playwright response the recorder reads."""

    @property
    def status(self) -> int: ...

    @property
    def status_text(self) -> str: ...

    def headers_array(self) -> Sequence[Mapping[str, str]]: ...

    def body(self) -> bytes: ...


class PlaywrightRequest(Protocol):
    """The part of a Playwright request the recorder reads."""

    @property
    def url(self) -> str: ...

    @property
    def method(self) -> str: ...

    @property
    def resource_type(self) -> str: ...

    @property
    def post_data_buffer(self) -> bytes | None: ...

    @property
    def failure(self) -> str | None: ...

    @property
    def timing(self) -> Mapping[str, float]: ...

    def headers_array(self) -> Sequence[Mapping[str, str]]: ...

    def response(self) -> PlaywrightResponse | None: ...


class PlaywrightContext(Protocol):
    """The part of a Playwright browser context the recorder attaches to."""

    def on(self, event: str, handler: Callable[[Any], None]) -> None: ...

    def remove_listener(self, event: str, handler: Callable[[Any], None]) -> None: ...


@dataclass
class _Exchange:
    """One request being recorded, and whatever has arrived for it so far."""

    request: Request
    started_at: datetime
    resource_type: ResourceType
    response: Response | None = None
    timings: Timings | None = None
    failure: str | None = None
    settled: bool = False


@dataclass
class BrowserRecorder:
    """Collect the exchanges a browser context performs.

    The recorder is driven by events rather than driving the browser itself, so the same
    object serves an operator clicking through a workflow and a test feeding it recorded
    events. Exchanges are held in the order their requests started, whatever order the
    responses arrive in.

    Noting an event and reading what it refers to are separate steps. Playwright answers
    a question about a request by asking the browser, and an event handler is the one
    place its synchronous API cannot do that, so ``note_*`` only records that something
    happened and :meth:`drain` performs the reads from the thread driving the session.
    Draining while the session runs keeps payloads readable, because a browser discards
    them as it goes.
    """

    start_url: str | None = None
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    now: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if self.max_body_bytes < 0:
            raise ValueError("max_body_bytes must not be negative")
        self._noted: list[tuple[str, PlaywrightRequest]] = []
        self._exchanges: dict[int, _Exchange] = {}
        # Playwright reports the same request object to every handler, so the object is
        # kept alive here to stop a later request reusing its id.
        self._seen: dict[int, PlaywrightRequest] = {}
        self._started_at = self.now()

    def note_request(self, request: PlaywrightRequest) -> None:
        """Note that a request left the browser."""
        self._noted.append((_STARTED, request))

    def note_finished(self, request: PlaywrightRequest) -> None:
        """Note that a response completed a request."""
        self._noted.append((_FINISHED, request))

    def note_failed(self, request: PlaywrightRequest) -> None:
        """Note that a request will not produce a response."""
        self._noted.append((_FAILED, request))

    def drain(self) -> None:
        """Read what the events noted so far refer to.

        Safe to call as often as the session allows. Anything already read is not read
        again, so draining is how a long recording keeps payloads the browser is about to
        discard.
        """
        noted, self._noted = self._noted, []
        for event, request in noted:
            if event is _STARTED:
                self._start(request)
            elif event is _FINISHED:
                self._finish(request)
            else:
                self._fail(request)

    def _start(self, request: PlaywrightRequest) -> None:
        """Record a request the browser sent."""
        url = request.url.strip()
        if urlsplit(url).scheme.lower() not in _RECORDABLE_SCHEMES:
            # data:, blob:, and extension URLs never crossed the network, so there is no
            # request there to reproduce.
            return
        key = id(request)
        if key in self._exchanges:
            return
        self._seen[key] = request
        self._exchanges[key] = _Exchange(
            request=Request(
                method=request.method,
                url=url,
                headers=_headers(request.headers_array()),
                body=_request_body(request),
            ),
            started_at=_start_time(request) or self.now(),
            resource_type=ResourceType.from_label(request.resource_type),
        )

    def _finish(self, request: PlaywrightRequest) -> None:
        """Record the response that completed a request."""
        exchange = self._exchanges.get(id(request))
        if exchange is None or exchange.settled:
            return
        response = _call(request.response)
        if response is None:
            exchange.failure = _UNREPORTED_FAILURE
        else:
            # Reading a response is a question for the browser, which may have closed or
            # moved on since the event arrived. A response half read is not recorded as a
            # response, so nothing later mistakes it for what came back.
            recorded = _call(lambda: self._read(response, exchange.resource_type))
            if recorded is None:
                exchange.failure = _UNREAD
            else:
                exchange.response = recorded
        exchange.timings = _timings(request)
        exchange.settled = True

    def _fail(self, request: PlaywrightRequest) -> None:
        """Record that a request never produced a response."""
        exchange = self._exchanges.get(id(request))
        if exchange is None or exchange.settled:
            return
        exchange.failure = _text_or_none(_call(lambda: request.failure)) or _UNREPORTED_FAILURE
        exchange.timings = _timings(request)
        exchange.settled = True

    def capture(
        self, *, browser_name: str | None = None, browser_version: str | None = None
    ) -> Capture:
        """Return what has been recorded so far.

        Anything noted but not yet read is drained first, so a caller that never drains
        still gets the whole session, at the cost of reading it all at the end.

        An exchange still in flight is recorded as a failure rather than dropped: the
        request was observed, and a workflow that stops halfway is worth seeing.
        """
        self.drain()
        entries = [
            Entry(
                # Ids number the order requests started, so an entry can be traced back
                # to its place in the session.
                id=f"b{position:04d}",
                started_at=exchange.started_at,
                request=exchange.request,
                response=exchange.response,
                failure=None if exchange.response is not None else exchange.failure or _UNSETTLED,
                timings=exchange.timings,
                resource_type=exchange.resource_type,
            )
            for position, exchange in enumerate(self._exchanges.values(), start=1)
        ]
        return Capture(
            metadata=CaptureMetadata(
                source=CaptureSource.BROWSER,
                created_at=self._started_at,
                browser_name=browser_name,
                browser_version=browser_version,
                # Provenance is not redacted later, so the start URL is kept without its
                # query string, which is where a shared link hides its token.
                start_url=_without_query(self.start_url) if self.start_url else None,
            ),
            entries=entries,
        )

    def _read(self, response: PlaywrightResponse, resource_type: ResourceType) -> Response:
        """Return what came back, asking the browser for the parts it still holds."""
        fields = response.headers_array()
        return Response(
            status=response.status,
            status_text=_text_or_none(response.status_text),
            headers=_headers(fields),
            body=self._payload(response, fields, resource_type),
            redirect_url=_redirect_url(response.status, fields),
        )

    def _payload(
        self,
        response: PlaywrightResponse,
        fields: Sequence[Mapping[str, str]],
        resource_type: ResourceType,
    ) -> Body:
        """Return the received payload, or what is known about one that was not kept."""
        mime_type = _header_value(fields, "content-type")
        if resource_type not in _BODY_CARRYING_TYPES:
            return Body(mime_type=mime_type, size=_declared_size(fields), truncated=True)
        raw = _call(response.body)
        if raw is None:
            # A redirect, a 304, or a response the browser has already discarded has no
            # payload to read. What it declared is still worth recording.
            return Body(mime_type=mime_type)
        if len(raw) > self.max_body_bytes:
            return Body(mime_type=mime_type, size=len(raw), truncated=True)
        return _body(mime_type, raw)


@contextmanager
def recording(
    context: PlaywrightContext,
    *,
    start_url: str | None = None,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> Iterator[BrowserRecorder]:
    """Record every exchange ``context`` performs for the duration of the block.

    The recorder is yielded rather than the capture, so a caller can read what has been
    recorded while the session is still open. Listeners are removed on the way out, which
    leaves the context usable afterwards.

    A caller driving the browser for more than a moment should call
    :meth:`BrowserRecorder.drain` as it goes, so payloads are read while the browser still
    holds them.
    """
    recorder = BrowserRecorder(start_url=start_url, max_body_bytes=max_body_bytes)
    handlers = {
        "request": recorder.note_request,
        "requestfinished": recorder.note_finished,
        "requestfailed": recorder.note_failed,
    }
    for event, handler in handlers.items():
        context.on(event, handler)
    try:
        yield recorder
    finally:
        for event, handler in handlers.items():
            # A context that closed with the browser has nothing left to detach from.
            with suppress(Exception):
                context.remove_listener(event, handler)


def record_session(
    start_url: str,
    *,
    headless: bool = False,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    timeout_s: float | None = None,
) -> Capture:
    """Open a browser at ``start_url`` and record it until the session ends.

    The call returns when the operator closes the browser, or when ``timeout_s`` elapses,
    whichever comes first. Recording runs in a throwaway profile, so the workflow starts
    signed out and nothing from the session is left on disk.
    """
    scheme = urlsplit(start_url.strip()).scheme.lower()
    if scheme not in _RECORDABLE_SCHEMES:
        raise BrowserCaptureError(
            f"start URL must use http or https, got {_without_query(start_url)!r}"
        )
    playwright_api = _playwright_api()
    with playwright_api.sync_playwright() as playwright:
        browser = _launch(playwright, headless=headless)
        try:
            context = browser.new_context()
            with recording(context, start_url=start_url, max_body_bytes=max_body_bytes) as recorder:
                page = context.new_page()
                try:
                    page.goto(start_url, wait_until="domcontentloaded")
                except playwright_api.Error as error:
                    raise BrowserCaptureError(
                        f"{_without_query(start_url)} could not be opened: {_reason(error)}"
                    ) from None
                _record_until_closed(context, recorder, playwright_api, timeout_s)
                return recorder.capture(
                    browser_name=browser.browser_type.name, browser_version=browser.version
                )
        finally:
            with suppress(Exception):
                browser.close()


def _playwright_api() -> ModuleType:
    """Return the Playwright sync API, explaining the install when it is absent.

    Playwright is an optional dependency. Reading a HAR archive, generating a client, and
    everything else Trace2API does works without a browser, so only live recording pays
    for one.
    """
    try:
        from playwright import sync_api as playwright_api
    except ImportError:
        raise BrowserCaptureError(
            "live recording needs Playwright, which is not installed. "
            'Install it with: pip install "trace2api[browser]" && playwright install chromium'
        ) from None
    return playwright_api


def _launch(playwright: Any, *, headless: bool) -> Any:
    """Start Chromium, explaining a missing browser build rather than raising through."""
    try:
        return playwright.chromium.launch(headless=headless)
    except Exception as error:
        raise BrowserCaptureError(f"a browser could not be started: {_reason(error)}") from None


def _record_until_closed(
    context: Any,
    recorder: BrowserRecorder,
    playwright_api: ModuleType,
    timeout_s: float | None,
) -> None:
    """Wait out the session in short spells, draining what it reports between them.

    Waiting is what lets Playwright deliver its events at all, and the spells are short so
    that the recorder reads each payload while the browser still holds it.
    """
    remaining_ms = None if timeout_s is None else max(timeout_s * 1000, 0.0)
    while remaining_ms is None or remaining_ms > 0:
        spell = DRAIN_INTERVAL_MS if remaining_ms is None else min(DRAIN_INTERVAL_MS, remaining_ms)
        try:
            context.wait_for_event("close", timeout=spell)
        except playwright_api.TimeoutError:
            recorder.drain()
        except playwright_api.Error:
            # The browser is gone, which ends the session as surely as closing the window.
            return
        else:
            return
        if remaining_ms is not None:
            remaining_ms -= spell


# Fields


def _headers(fields: Sequence[Mapping[str, str]]) -> Headers:
    """Build headers from Playwright's name and value array.

    HTTP/2 pseudo headers restate the request line rather than carry header fields, so
    they are dropped, as they are on import.
    """
    return Headers(
        [
            Header(name=item["name"], value=item.get("value", ""))
            for item in fields
            if not item.get("name", "").startswith(":")
        ]
    )


def _header_value(fields: Sequence[Mapping[str, str]], name: str) -> str | None:
    """Return the first value recorded under ``name``, matched case insensitively."""
    for item in fields:
        if item.get("name", "").strip().lower() == name:
            return _text_or_none(item.get("value"))
    return None


def _request_body(request: PlaywrightRequest) -> Body | None:
    """Return the sent payload, if the request carried one."""
    raw = _call(lambda: request.post_data_buffer)
    if not raw:
        return None
    return _body(_header_value(request.headers_array(), "content-type"), raw)


def _body(mime_type: str | None, raw: bytes) -> Body:
    """Hold a payload as text where it is text, and as base64 where it is not."""
    if _is_textual(mime_type):
        try:
            return Body(mime_type=mime_type, text=raw.decode("utf-8"), size=len(raw))
        except UnicodeDecodeError:
            # The declared type says text but the bytes are not, so what was sent is kept
            # rather than a lossy reading of it.
            pass
    return Body(
        mime_type=mime_type,
        text=base64.b64encode(raw).decode("ascii"),
        encoding="base64",
        size=len(raw),
    )


def _is_textual(mime_type: str | None) -> bool:
    """Return whether a media type describes something to hold as characters."""
    if mime_type is None:
        return False
    media_type = mime_type.split(";", 1)[0].strip().lower()
    return (
        media_type.startswith("text/")
        or media_type.endswith(("+json", "+xml"))
        or media_type == "application/json"
        or media_type in _TEXT_MEDIA_TYPES
    )


def _declared_size(fields: Sequence[Mapping[str, str]]) -> int | None:
    """Return the payload length the response declared, when it declared a usable one."""
    declared = _header_value(fields, "content-length")
    if declared is None or not declared.isdigit():
        return None
    return int(declared)


def _redirect_url(status: int, fields: Sequence[Mapping[str, str]]) -> str | None:
    """Return where a redirect pointed, which is what its ``Location`` header names."""
    if not 300 <= status < 400:
        return None
    return _header_value(fields, "location")


def _start_time(request: PlaywrightRequest) -> datetime | None:
    """Return when the browser started the request, as an instant."""
    timing = _call(lambda: request.timing)
    if not timing:
        return None
    start_ms = timing.get("startTime")
    if not isinstance(start_ms, (int, float)) or start_ms <= 0:
        return None
    return datetime.fromtimestamp(start_ms / 1000, tz=UTC)


def _timings(request: PlaywrightRequest) -> Timings | None:
    """Map Playwright's request timeline onto the observed durations.

    Playwright reports each mark as milliseconds since the request started, and a phase it
    did not measure as a negative number, so a duration is recorded only when both of its
    marks were measured.
    """
    timing = _call(lambda: request.timing)
    if not timing:
        return None
    marks = {
        name: value
        for name, value in timing.items()
        if isinstance(value, (int, float)) and value >= 0
    }
    timings = Timings(
        blocked_ms=_mark(marks, "domainLookupStart"),
        dns_ms=_span(marks, "domainLookupStart", "domainLookupEnd"),
        connect_ms=_span(marks, "connectStart", "connectEnd"),
        ssl_ms=_span(marks, "secureConnectionStart", "connectEnd"),
        # Playwright marks when the request went out but not how long sending took, so
        # send_ms stays unmeasured.
        wait_ms=_span(marks, "requestStart", "responseStart"),
        receive_ms=_span(marks, "responseStart", "responseEnd"),
        total_ms=_mark(marks, "responseEnd"),
    )
    return timings if any(value is not None for value in timings.model_dump().values()) else None


def _mark(marks: Mapping[str, float], name: str) -> float | None:
    """Return how long after the request started ``name`` happened."""
    return marks.get(name)


def _span(marks: Mapping[str, float], start: str, end: str) -> float | None:
    """Return the duration between two marks, if both were measured."""
    if start not in marks or end not in marks:
        return None
    return max(marks[end] - marks[start], 0.0)


def _call[T](reader: Callable[[], T]) -> T | None:
    """Read a value from the browser, treating what it can no longer answer as unknown.

    Playwright raises when a payload has been discarded, a page has navigated away, or the
    browser has closed. None of that makes the exchange less worth recording, so the field
    is left unknown instead of ending the recording.
    """
    try:
        return reader()
    except Exception:
        return None


def _text_or_none(value: str | None) -> str | None:
    """Read a string the browser reported, treating blank as nothing reported."""
    if value is None:
        return None
    text = value.strip()
    return text or None


def _without_query(url: str) -> str:
    """Return ``url`` with its query string and fragment removed."""
    parts = urlsplit(url.strip())
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _reason(error: Exception) -> str:
    """Summarize a browser failure as its first line, which names the problem."""
    message = str(error).strip().splitlines()
    return message[0].strip() if message else type(error).__name__
