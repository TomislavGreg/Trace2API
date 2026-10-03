"""Record a run of the demo app's order workflow as a HAR document.

A hand-authored HAR archive, which is what every other example under ``examples/``
is, describes a workflow without anything backing it: there is no server at
``shop.example.com`` to check it against. This module drives a running
:func:`~trace2api.demo.app.serve_demo_app` instance with real requests and writes down
what it actually answered, so the fixtures built from it can be regenerated and checked
rather than taken on faith.

The workflow is the same one the storefront examples describe: load the orders page,
list orders for a status, read one order's detail, confirm it. :class:`DemoWorkflowInputs`
is what one recording supplies; two recordings with different inputs are what the diff,
classify, and paginate commands compare, the same as the storefront fixtures.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from trace2api.demo.app import AUTH_TOKEN

__all__ = ["DemoWorkflowInputs", "perform_demo_workflow"]

_BASE_TIME = datetime(2026, 9, 1, 9, 0, tzinfo=UTC)
_STEP = timedelta(seconds=1)
_AUTH_HEADERS = {"Authorization": f"Bearer {AUTH_TOKEN}"}

# Headers httpx or the demo app add on their own and that describe the connection
# rather than the workflow, left out so a diff of two recordings compares what the
# workflow actually sent.
_OMITTED_REQUEST_HEADERS = frozenset({"host", "accept-encoding", "connection"})
_OMITTED_RESPONSE_HEADERS = frozenset({"date", "server"})


@dataclass(frozen=True)
class DemoWorkflowInputs:
    """What one recording of the demo workflow supplies."""

    status: str = "open"
    page: int | None = None
    payment_method: str = "invoice"
    gift_wrap: bool = False


_DEFAULT_INPUTS = DemoWorkflowInputs()


def perform_demo_workflow(
    base_url: str, inputs: DemoWorkflowInputs = _DEFAULT_INPUTS
) -> dict[str, Any]:
    """Run the list, detail, and confirm workflow against a running demo app.

    Returns a HAR 1.2 document built from what the app actually answered, in the shape
    :func:`trace2api.capture.parse_har` reads.
    """
    entries: list[dict[str, Any]] = []
    started = _BASE_TIME

    with httpx.Client(base_url=base_url) as client:
        page_response = client.get("/orders")
        entries.append(_entry(started, "document", page_response))
        started += _STEP

        query = {"status": inputs.status}
        if inputs.page is not None:
            query["page"] = str(inputs.page)
        list_response = client.get("/api/v1/orders", params=query, headers=_AUTH_HEADERS)
        entries.append(_entry(started, "xhr", list_response))
        started += _STEP
        list_response.raise_for_status()
        order_id = list_response.json()["orders"][0]["id"]

        detail_response = client.get(f"/api/v1/orders/{order_id}", headers=_AUTH_HEADERS)
        entries.append(_entry(started, "xhr", detail_response))
        started += _STEP

        confirm_body: dict[str, Any] = {"payment_method": inputs.payment_method}
        if inputs.gift_wrap:
            confirm_body["gift_wrap"] = True
        confirm_headers = {**_AUTH_HEADERS, "X-CSRF-Token": client.cookies.get("csrf") or ""}
        confirm_response = client.post(
            f"/api/v1/orders/{order_id}/confirm", json=confirm_body, headers=confirm_headers
        )
        entries.append(_entry(started, "fetch", confirm_response))

    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "trace2api demo", "version": "1.0"},
            "pages": [
                {
                    "id": "page_1",
                    "startedDateTime": _BASE_TIME.isoformat(),
                    "title": f"{base_url}/orders",
                }
            ],
            "entries": entries,
        }
    }


def _entry(started: datetime, resource_type: str, response: httpx.Response) -> dict[str, Any]:
    request = response.request
    return {
        "pageref": "page_1",
        "startedDateTime": started.isoformat(),
        "_resourceType": resource_type,
        "request": {
            "method": request.method,
            "url": str(request.url),
            "headers": _header_pairs(request.headers.items(), _OMITTED_REQUEST_HEADERS),
            "postData": _post_data(request),
        },
        "response": {
            "status": response.status_code,
            "statusText": response.reason_phrase,
            "headers": _header_pairs(response.headers.items(), _OMITTED_RESPONSE_HEADERS),
            "content": {
                "mimeType": response.headers.get("content-type", ""),
                "text": response.text,
                "size": len(response.content),
            },
        },
    }


def _header_pairs(items: Any, omit: frozenset[str]) -> list[dict[str, str]]:
    return [{"name": name, "value": value} for name, value in items if name.lower() not in omit]


def _post_data(request: httpx.Request) -> dict[str, str] | None:
    content = request.content
    if not content:
        return None
    return {
        "mimeType": request.headers.get("content-type", ""),
        "text": content.decode("utf-8"),
    }
