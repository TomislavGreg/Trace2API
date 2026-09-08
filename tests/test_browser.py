"""Tests for recording a live browser session.

Most of these drive the recorder with stand-in request and response objects shaped like
the ones Playwright reports, which keeps the rules about headers, payloads, and timings
under test without a browser. The tests at the end record a real Chromium session against
a local HTTP server; they are skipped where Playwright or a browser build is missing.

Every value here is synthetic. The credential shaped strings are literals written for
these tests and are not valid anywhere.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

import pytest

from trace2api.capture import (
    BrowserCaptureError,
    BrowserRecorder,
    browser,
    record_session,
    recording,
)
from trace2api.capture.browser import DEFAULT_MAX_BODY_BYTES
from trace2api.models import CaptureSource, ResourceType
from trace2api.sanitize import is_redacted, redact_capture

STARTED_AT = datetime(2026, 9, 8, 9, 15, tzinfo=UTC)
START_TIME_MS = STARTED_AT.timestamp() * 1000


class Unavailable(Exception):
    """Stands in for what Playwright raises when it can no longer answer."""


class FakeResponse:
    """A response shaped like the one Playwright reports."""

    def __init__(
        self,
        *,
        status: int = 200,
        status_text: str = "OK",
        headers: list[tuple[str, str]] | None = None,
        body: bytes | None = b'{"orders": [1, 2]}',
    ) -> None:
        self.status = status
        self.status_text = status_text
        self._headers = headers if headers is not None else [("content-type", "application/json")]
        self._body = body

    def headers_array(self) -> list[dict[str, str]]:
        return [{"name": name, "value": value} for name, value in self._headers]

    def body(self) -> bytes:
        if self._body is None:
            raise Unavailable("response body is unavailable")
        return self._body


class FakeRequest:
    """A request shaped like the one Playwright reports."""

    def __init__(
        self,
        *,
        url: str = "https://shop.example.test/api/v1/orders",
        method: str = "GET",
        resource_type: str = "xhr",
        headers: list[tuple[str, str]] | None = None,
        post_data: bytes | None = None,
        response: FakeResponse | None = None,
        failure: str | None = None,
        timing: dict[str, float] | None = None,
    ) -> None:
        self.url = url
        self.method = method
        self.resource_type = resource_type
        self.post_data_buffer = post_data
        self.failure = failure
        self.timing = timing if timing is not None else {"startTime": START_TIME_MS}
        self._headers = headers if headers is not None else [("Accept", "application/json")]
        self._response = response if response is not None else FakeResponse()

    def headers_array(self) -> list[dict[str, str]]:
        return [{"name": name, "value": value} for name, value in self._headers]

    def response(self) -> FakeResponse:
        return self._response


class FakeContext:
    """A browser context that only remembers what was attached to it."""

    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {}

    def on(self, event: str, handler: Any) -> None:
        self.handlers[event] = handler

    def remove_listener(self, event: str, handler: Any) -> None:
        if self.handlers.get(event) is handler:
            del self.handlers[event]


def record(*requests: FakeRequest, **options: Any) -> Any:
    """Run a completed exchange for each request through a recorder."""
    recorder = BrowserRecorder(**options)
    for request in requests:
        recorder.note_request(request)
    for request in requests:
        if request.failure is not None:
            recorder.note_failed(request)
        else:
            recorder.note_finished(request)
    return recorder.capture()


# What a recording holds


def test_records_a_completed_exchange() -> None:
    capture = record(
        FakeRequest(
            headers=[("Accept", "application/json"), ("Authorization", "Bearer t-abc")],
        )
    )

    assert capture.metadata.source is CaptureSource.BROWSER
    assert len(capture.entries) == 1
    entry = capture.entries[0]
    assert entry.request.method == "GET"
    assert entry.request.url == "https://shop.example.test/api/v1/orders"
    assert entry.request.headers.get("authorization") == "Bearer t-abc"
    assert entry.resource_type is ResourceType.XHR
    assert entry.started_at == STARTED_AT
    assert entry.response is not None
    assert entry.response.status == 200
    assert entry.response.status_text == "OK"
    assert entry.response.body is not None
    assert entry.response.body.text == '{"orders": [1, 2]}'
    assert entry.failure is None


def test_keeps_requests_in_the_order_they_started() -> None:
    first = FakeRequest(url="https://shop.example.test/orders", resource_type="document")
    second = FakeRequest(url="https://shop.example.test/api/v1/orders")
    recorder = BrowserRecorder()

    recorder.note_request(first)
    recorder.note_request(second)
    # The second request is answered first, which is ordinary for parallel traffic.
    recorder.note_finished(second)
    recorder.note_finished(first)
    capture = recorder.capture()

    assert [entry.request.path for entry in capture.entries] == [
        "/orders",
        "/api/v1/orders",
    ]
    assert [entry.id for entry in capture.entries] == ["b0001", "b0002"]


def test_skips_requests_that_never_crossed_the_network() -> None:
    capture = record(
        FakeRequest(url="data:image/png;base64,iVBORw0KGgo="),
        FakeRequest(url="https://shop.example.test/api/v1/orders"),
    )

    assert [entry.request.host for entry in capture.entries] == ["shop.example.test"]


def test_ignores_a_request_reported_twice() -> None:
    request = FakeRequest()
    recorder = BrowserRecorder()

    recorder.note_request(request)
    recorder.note_request(request)
    recorder.note_finished(request)

    assert len(recorder.capture().entries) == 1


def test_ignores_events_for_a_request_that_was_never_recorded() -> None:
    recorder = BrowserRecorder()

    recorder.note_finished(FakeRequest())
    recorder.note_failed(FakeRequest())

    assert recorder.capture().entries == []


def test_drops_http2_pseudo_headers() -> None:
    capture = record(
        FakeRequest(
            headers=[(":method", "GET"), (":authority", "shop.example.test"), ("Accept", "*/*")]
        )
    )

    assert capture.entries[0].request.headers.names() == ("Accept",)


def test_records_a_sent_payload_as_text() -> None:
    capture = record(
        FakeRequest(
            method="POST",
            headers=[("Content-Type", "application/json")],
            post_data=b'{"payment_method":"invoice"}',
        )
    )

    body = capture.entries[0].request.body
    assert body is not None
    assert body.text == '{"payment_method":"invoice"}'
    assert body.encoding is None
    assert body.size == 28


def test_records_a_binary_payload_as_base64() -> None:
    raw = bytes(range(32))
    capture = record(
        FakeRequest(
            method="POST",
            headers=[("Content-Type", "application/octet-stream")],
            post_data=raw,
        )
    )

    body = capture.entries[0].request.body
    assert body is not None
    assert body.encoding == "base64"
    assert body.as_bytes() == raw


def test_records_text_that_is_not_valid_utf8_as_base64() -> None:
    raw = b"\xff\xfe not text after all"
    capture = record(
        FakeRequest(method="POST", headers=[("Content-Type", "text/plain")], post_data=raw)
    )

    body = capture.entries[0].request.body
    assert body is not None
    assert body.encoding == "base64"
    assert body.as_bytes() == raw


def test_records_no_payload_when_none_was_sent() -> None:
    capture = record(FakeRequest(method="POST", post_data=b""))

    assert capture.entries[0].request.body is None


def test_records_where_a_redirect_pointed() -> None:
    capture = record(
        FakeRequest(
            response=FakeResponse(
                status=302,
                status_text="Found",
                headers=[("Location", "https://shop.example.test/orders")],
                body=None,
            )
        )
    )

    response = capture.entries[0].response
    assert response is not None
    assert response.redirect_url == "https://shop.example.test/orders"
    assert response.body is not None
    assert response.body.text is None


# Payload policy


def test_keeps_the_type_and_size_of_an_asset_without_its_payload() -> None:
    capture = record(
        FakeRequest(
            url="https://cdn.example.test/img/logo.png",
            resource_type="image",
            response=FakeResponse(
                headers=[("Content-Type", "image/png"), ("Content-Length", "8192")],
                body=b"\x89PNG" * 2048,
            ),
        )
    )

    body = capture.entries[0].response.body
    assert body is not None
    assert body.mime_type == "image/png"
    assert body.size == 8192
    assert body.text is None
    assert body.truncated is True


def test_records_a_payload_past_the_limit_as_truncated() -> None:
    capture = record(FakeRequest(response=FakeResponse(body=b"x" * 200)), max_body_bytes=100)

    body = capture.entries[0].response.body
    assert body is not None
    assert body.size == 200
    assert body.text is None
    assert body.truncated is True


def test_records_a_payload_the_browser_cannot_hand_back() -> None:
    capture = record(FakeRequest(response=FakeResponse(body=None)))

    body = capture.entries[0].response.body
    assert body is not None
    assert body.mime_type == "application/json"
    assert body.text is None
    assert body.truncated is False


def test_rejects_a_negative_payload_limit() -> None:
    with pytest.raises(ValueError, match="max_body_bytes"):
        BrowserRecorder(max_body_bytes=-1)


def test_default_payload_limit_is_stated_in_bytes() -> None:
    assert DEFAULT_MAX_BODY_BYTES == 512 * 1024


# Exchanges that did not complete


def test_records_a_failed_request_with_the_reason_the_browser_gave() -> None:
    capture = record(FakeRequest(failure="net::ERR_CONNECTION_REFUSED"))

    entry = capture.entries[0]
    assert entry.response is None
    assert entry.failure == "net::ERR_CONNECTION_REFUSED"


def test_records_a_failure_the_browser_did_not_explain() -> None:
    capture = record(FakeRequest(failure="   "))

    assert capture.entries[0].failure == "the browser reported no reason for the failure"


def test_records_a_response_the_browser_closed_before_it_could_be_read() -> None:
    class Gone(FakeResponse):
        def headers_array(self) -> list[dict[str, str]]:
            raise Unavailable("target page, context or browser has been closed")

    capture = record(FakeRequest(response=Gone()))

    entry = capture.entries[0]
    assert entry.response is None
    assert entry.failure == "the response arrived but the browser closed before it could be read"


def test_records_a_request_still_in_flight_when_recording_ended() -> None:
    recorder = BrowserRecorder()
    recorder.note_request(FakeRequest())

    entry = recorder.capture().entries[0]
    assert entry.response is None
    assert entry.failure == "the recording ended before the response arrived"


def test_keeps_the_first_outcome_reported_for_an_exchange() -> None:
    request = FakeRequest()
    recorder = BrowserRecorder()

    recorder.note_request(request)
    recorder.note_finished(request)
    request.failure = "net::ERR_ABORTED"
    recorder.note_failed(request)

    assert recorder.capture().entries[0].response is not None


# Timings


def test_maps_the_request_timeline_onto_observed_durations() -> None:
    capture = record(
        FakeRequest(
            timing={
                "startTime": START_TIME_MS,
                "domainLookupStart": 2.0,
                "domainLookupEnd": 5.0,
                "connectStart": 5.0,
                "secureConnectionStart": 8.0,
                "connectEnd": 12.0,
                "requestStart": 12.0,
                "responseStart": 40.0,
                "responseEnd": 45.0,
            }
        )
    )

    timings = capture.entries[0].timings
    assert timings is not None
    assert timings.blocked_ms == 2.0
    assert timings.dns_ms == 3.0
    assert timings.connect_ms == 7.0
    assert timings.ssl_ms == 4.0
    assert timings.wait_ms == 28.0
    assert timings.receive_ms == 5.0
    assert timings.total_ms == 45.0


def test_leaves_out_phases_the_browser_did_not_measure() -> None:
    capture = record(
        FakeRequest(
            timing={
                "startTime": START_TIME_MS,
                "domainLookupStart": -1,
                "domainLookupEnd": -1,
                "connectStart": -1,
                "secureConnectionStart": -1,
                "connectEnd": -1,
                "requestStart": 1.0,
                "responseStart": 20.0,
                "responseEnd": 25.0,
            }
        )
    )

    timings = capture.entries[0].timings
    assert timings is not None
    assert timings.dns_ms is None
    assert timings.connect_ms is None
    assert timings.send_ms is None
    assert timings.wait_ms == 19.0


def test_records_no_timings_when_the_browser_measured_nothing() -> None:
    capture = record(FakeRequest(timing={}))

    assert capture.entries[0].timings is None


def test_falls_back_to_the_recorder_clock_without_a_start_time() -> None:
    moment = datetime(2026, 9, 8, 11, 30, tzinfo=UTC)
    recorder = BrowserRecorder(now=lambda: moment)
    recorder.note_request(FakeRequest(timing={}))

    assert recorder.capture().entries[0].started_at == moment


# Provenance


def test_records_which_browser_the_session_ran_in() -> None:
    recorder = BrowserRecorder(start_url="https://shop.example.test/orders")

    metadata = recorder.capture(browser_name="chromium", browser_version="141.0").metadata
    assert metadata.source is CaptureSource.BROWSER
    assert metadata.browser_name == "chromium"
    assert metadata.browser_version == "141.0"


def test_keeps_the_start_url_without_its_query_string() -> None:
    # Provenance is not rewritten by redaction, so a token in a shared link must not
    # reach it in the first place.
    recorder = BrowserRecorder(start_url="https://shop.example.test/orders?token=t-abc#top")

    assert recorder.capture().metadata.start_url == "https://shop.example.test/orders"


def test_a_recording_can_be_redacted_like_any_other_capture() -> None:
    capture = record(
        FakeRequest(
            headers=[("Authorization", "Bearer t-abc"), ("Cookie", "session=s-def")],
        )
    )

    sanitized = redact_capture(capture)
    headers = sanitized.capture.entries[0].request.headers
    assert is_redacted(headers.get("authorization", "").removeprefix("Bearer "))
    assert is_redacted(headers.get("cookie", "").removeprefix("session="))
    assert sanitized.report.redactions


# Attaching to a context


def test_attaches_and_detaches_the_events_it_listens_to() -> None:
    context = FakeContext()

    with recording(context) as recorder:
        assert set(context.handlers) == {"request", "requestfinished", "requestfailed"}
        request = FakeRequest()
        context.handlers["request"](request)
        context.handlers["requestfinished"](request)
        assert len(recorder.capture().entries) == 1

    assert context.handlers == {}


def test_reads_nothing_from_the_browser_while_handling_an_event() -> None:
    # Playwright answers a question about a request by asking the browser, which its
    # synchronous API cannot do from inside an event handler, so noting an event must not
    # read anything. Draining is where the reads belong.
    class Silent(FakeRequest):
        readable = False

        def headers_array(self) -> list[dict[str, str]]:
            if not self.readable:
                raise Unavailable("the browser cannot be asked from inside a handler")
            return super().headers_array()

    request = Silent()
    recorder = BrowserRecorder()

    recorder.note_request(request)
    recorder.note_finished(request)
    request.readable = True
    capture = recorder.capture()

    assert capture.entries[0].response is not None


def test_drains_each_exchange_once() -> None:
    request = FakeRequest()
    recorder = BrowserRecorder()

    recorder.note_request(request)
    recorder.drain()
    recorder.note_finished(request)
    recorder.drain()
    recorder.drain()

    assert len(recorder.capture().entries) == 1
    assert recorder.capture().entries[0].response is not None


def test_a_context_that_closed_with_the_browser_needs_no_detaching() -> None:
    class ClosedContext(FakeContext):
        def remove_listener(self, event: str, handler: Any) -> None:
            raise Unavailable("target page, context or browser has been closed")

    with recording(ClosedContext()):
        pass


# Opening a session


def test_refuses_a_start_url_that_is_not_http() -> None:
    with pytest.raises(BrowserCaptureError, match="must use http or https"):
        record_session("file:///tmp/orders.html")


def test_a_rejected_start_url_is_reported_without_its_query_string() -> None:
    with pytest.raises(BrowserCaptureError) as failure:
        record_session("ftp://shop.example.test/orders?token=t-abc")

    assert "t-abc" not in str(failure.value)


def test_explains_how_to_install_playwright_when_it_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import builtins

    real_import = builtins.__import__

    def without_playwright(name: str, *args: Any, **kwargs: Any) -> Any:
        if name.startswith("playwright"):
            raise ImportError("No module named 'playwright'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_playwright)

    with pytest.raises(BrowserCaptureError, match="needs Playwright"):
        record_session("https://shop.example.test/orders")


# A real browser session


PAGE = """<!doctype html>
<html><body><h1>Orders</h1>
<script type="module">
  const listed = await fetch("/api/v1/orders?status=open", {
    headers: { "Accept": "application/json", "X-Requested-With": "trace2api-test" },
  });
  const orders = await listed.json();
  await fetch("/api/v1/orders/" + orders.orders[0].id + "/confirm", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ payment_method: "invoice" }),
  });
  document.body.insertAdjacentHTML("beforeend", '<p id="done">done</p>');
</script>
</body></html>
"""

ORDERS = {"orders": [{"id": 4711, "total": "18.00"}]}


class DemoHandler(BaseHTTPRequestHandler):
    """Serves the smallest page that performs a two request workflow."""

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path.startswith("/api/v1/orders"):
            self._send(200, "application/json", json.dumps(ORDERS).encode())
        elif path == "/":
            self._send(200, "text/html; charset=utf-8", PAGE.encode())
        else:
            self._send(404, "text/plain", b"not found")

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length") or 0)
        self.rfile.read(length)
        self._send(201, "application/json", b'{"confirmed": true}')

    def _send(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        """Keep the server quiet so test output stays readable."""


@pytest.fixture
def demo_server() -> Iterator[str]:
    """Serve the demo page on a local port for the length of a test."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), DemoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


CHROMIUM_EXECUTABLE = os.environ.get("TRACE2API_TEST_CHROMIUM")
"""A Chromium binary to record with, for a machine without Playwright's own download."""


def chromium(playwright: Any) -> Any:
    """Launch Chromium, skipping the test where no browser build is installed."""
    options = {"executable_path": CHROMIUM_EXECUTABLE} if CHROMIUM_EXECUTABLE else {}
    try:
        return playwright.chromium.launch(headless=True, **options)
    except Exception as error:  # pragma: no cover - depends on what is installed
        pytest.skip(f"chromium is not available: {str(error).splitlines()[0]}")


@pytest.fixture
def playwright() -> Iterator[Any]:
    """Start Playwright, skipping the test where it is not installed."""
    sync_playwright = pytest.importorskip("playwright.sync_api").sync_playwright
    with sync_playwright() as started:
        yield started


def settle(recorder: Any, page: Any, attempts: int = 20) -> None:
    """Wait until every recorded exchange has an outcome, for a bounded number of tries.

    An event arrives shortly after the exchange it describes, so a page that has finished
    its work is not yet a recording that has finished reading it.
    """
    for _ in range(attempts):
        if all(entry.succeeded for entry in recorder.capture().entries):
            return
        page.wait_for_timeout(100)


def test_records_a_real_workflow_from_a_browser(playwright: Any, demo_server: str) -> None:
    browser = chromium(playwright)
    try:
        context = browser.new_context()
        with recording(context, start_url=demo_server) as recorder:
            page = context.new_page()
            page.goto(demo_server, wait_until="domcontentloaded")
            page.wait_for_selector("#done", timeout=10_000)
            settle(recorder, page)
            capture = recorder.capture(
                browser_name=browser.browser_type.name, browser_version=browser.version
            )
    finally:
        browser.close()

    assert capture.metadata.source is CaptureSource.BROWSER
    assert capture.metadata.browser_name == "chromium"
    paths = [entry.request.path for entry in capture.entries]
    assert paths[0] == "/"
    assert "/api/v1/orders" in paths
    assert "/api/v1/orders/4711/confirm" in paths

    listed = next(entry for entry in capture.entries if entry.request.path == "/api/v1/orders")
    assert listed.resource_type is ResourceType.FETCH
    assert listed.request.query.get("status") == "open"
    assert listed.request.headers.get("x-requested-with") == "trace2api-test"
    assert listed.response is not None
    assert json.loads(listed.response.body.text) == ORDERS
    assert listed.timings is not None

    confirmed = next(entry for entry in capture.entries if entry.request.path.endswith("/confirm"))
    assert confirmed.request.method == "POST"
    assert confirmed.request.body is not None
    assert json.loads(confirmed.request.body.text) == {"payment_method": "invoice"}
    assert confirmed.response is not None
    assert confirmed.response.status == 201


def test_record_session_records_until_the_session_ends(
    demo_server: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # record_session opens Playwright itself, so this test must not hold one open too.
    pytest.importorskip("playwright.sync_api")
    if CHROMIUM_EXECUTABLE:
        # A machine using a Chromium build of its own points the launch at it here.
        monkeypatch.setattr(
            browser,
            "_launch",
            lambda started, *, headless: started.chromium.launch(
                headless=headless, executable_path=CHROMIUM_EXECUTABLE
            ),
        )

    try:
        capture = record_session(f"{demo_server}?token=t-abc", headless=True, timeout_s=2)
    except BrowserCaptureError as error:  # pragma: no cover - depends on what is installed
        pytest.skip(str(error))

    assert capture.metadata.start_url == demo_server
    assert capture.metadata.browser_name == "chromium"
    assert capture.entries[0].request.path == "/"
    listed = next(entry for entry in capture.entries if entry.request.path == "/api/v1/orders")
    assert listed.response is not None
    assert json.loads(listed.response.body.text) == ORDERS
