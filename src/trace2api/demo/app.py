"""A small storefront-shaped app for the demo workflow to run against.

The orders, the access token, and the CSRF token are all fixed: nothing here is random
or clock dependent, so recording the same workflow against a freshly started app twice
with the same inputs produces the same traffic both times. What does change between two
instances is their ``seed``, which stands in for two different signed-in sessions: each
issues its own CSRF token and its own confirmation reference, the way a real storefront
would.

The app itself is deliberately thin. It exists to be recorded and replayed, not to be a
realistic storefront implementation, and it keeps to the standard library so running it
needs nothing beyond what the project already depends on.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

__all__ = ["AUTH_TOKEN", "ORDERS", "PAGE_SIZE", "DemoAppState", "serve_demo_app"]

AUTH_TOKEN = "demo-access-token-not-a-real-credential"
"""The bearer token every instance of the app accepts. Synthetic, and never redacted away
in README examples drawn from it, the same as the token in the storefront HAR fixtures."""

PAGE_SIZE = 1
"""Orders returned per page, small enough that the fixture's two runs land on different
orders without a large dataset to page through."""

ORDERS: tuple[dict[str, Any], ...] = (
    {"id": 4711, "status": "open", "total": "18.00"},
    {"id": 4733, "status": "open", "total": "42.50"},
    {"id": 5822, "status": "shipped", "total": "9.99"},
)

_ORDERS_PAGE_HTML = '<!doctype html><title>Orders</title><div id="app"></div>'

_UNAUTHORIZED = {"error": "unauthorized"}
_FORBIDDEN = {"error": "forbidden"}
_NOT_FOUND = {"error": "not found"}


@dataclass(frozen=True)
class DemoAppState:
    """What one running instance of the app hands out.

    A fresh ``seed`` reissues the CSRF token and changes the confirmation reference a
    confirmed order gets, the way a new signed-in session would, without either value
    being random.
    """

    seed: int = 0

    @property
    def csrf_token(self) -> str:
        """Return the CSRF token this instance issues from the orders page."""
        return f"demo-csrf-not-a-real-secret-{self.seed:04d}"

    def confirmation_ref(self, order_id: int) -> str:
        """Return the confirmation reference this instance hands out for ``order_id``."""
        return f"CNF-{order_id}-{self.seed:04d}"


class _DemoServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], state: DemoAppState) -> None:
        super().__init__(address, _DemoHandler)
        self.state = state


class _DemoHandler(BaseHTTPRequestHandler):
    server: _DemoServer

    def do_GET(self) -> None:  # noqa: N802 - http.server's naming convention
        path = urlsplit(self.path).path
        if path == "/orders":
            self._send_orders_page()
        elif path == "/api/v1/orders":
            self._list_orders(urlsplit(self.path).query)
        elif path.startswith("/api/v1/orders/"):
            self._order_detail(path.removeprefix("/api/v1/orders/"))
        else:
            self._send_json(404, _NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802 - http.server's naming convention
        path = urlsplit(self.path).path
        if path.startswith("/api/v1/orders/") and path.endswith("/confirm"):
            segment = path.removeprefix("/api/v1/orders/").removesuffix("/confirm")
            self._confirm_order(segment)
        else:
            self._send_json(404, _NOT_FOUND)

    def _send_orders_page(self) -> None:
        body = _ORDERS_PAGE_HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", f"csrf={self.server.state.csrf_token}; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def _list_orders(self, query: str) -> None:
        if not self._authorized():
            self._send_json(401, _UNAUTHORIZED)
            return
        params = parse_qs(query)
        status = (params.get("status") or [None])[0]
        try:
            page = int((params.get("page") or ["1"])[0])
        except ValueError:
            self._send_json(400, {"error": "page must be a whole number"})
            return
        if page < 1:
            self._send_json(400, {"error": "page must be at least 1"})
            return
        matching = [order for order in ORDERS if status is None or order["status"] == status]
        start = (page - 1) * PAGE_SIZE
        self._send_json(200, {"orders": matching[start : start + PAGE_SIZE]})

    def _order_detail(self, segment: str) -> None:
        if not self._authorized():
            self._send_json(401, _UNAUTHORIZED)
            return
        order = self._find_order(segment)
        if order is None:
            self._send_json(404, {"error": "order not found"})
            return
        self._send_json(200, dict(order))

    def _confirm_order(self, segment: str) -> None:
        if not self._authorized():
            self._send_json(401, _UNAUTHORIZED)
            return
        if self.headers.get("X-CSRF-Token") != self.server.state.csrf_token:
            self._send_json(403, _FORBIDDEN)
            return
        order = self._find_order(segment)
        if order is None:
            self._send_json(404, {"error": "order not found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._send_json(400, {"error": "body must be JSON"})
            return
        response = {
            "confirmed": True,
            "confirmation_ref": self.server.state.confirmation_ref(order["id"]),
            "payment_method": payload.get("payment_method"),
        }
        if payload.get("gift_wrap"):
            response["gift_wrap"] = True
        self._send_json(201, response)

    def _authorized(self) -> bool:
        return self.headers.get("Authorization") == f"Bearer {AUTH_TOKEN}"

    @staticmethod
    def _find_order(segment: str) -> dict[str, Any] | None:
        try:
            order_id = int(segment)
        except ValueError:
            return None
        return next((order for order in ORDERS if order["id"] == order_id), None)

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        """Keep the server quiet; a caller that wants an account reads the capture."""


@contextmanager
def serve_demo_app(*, seed: int = 0, host: str = "127.0.0.1", port: int = 0) -> Iterator[str]:
    """Serve the demo app for the life of the context, and yield its base URL.

    ``port`` defaults to an ephemeral one chosen by the operating system, so more than
    one instance can run at a time without a caller having to pick ports itself.
    """
    server = _DemoServer((host, port), DemoAppState(seed=seed))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{host}:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
