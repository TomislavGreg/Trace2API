"""Tests for recording the demo workflow as a HAR document."""

from __future__ import annotations

import json

from trace2api.capture import parse_har
from trace2api.demo.app import AUTH_TOKEN, serve_demo_app
from trace2api.demo.fixture import DemoWorkflowInputs, perform_demo_workflow
from trace2api.models import ResourceType


def test_perform_demo_workflow_is_deterministic_for_the_same_inputs() -> None:
    with serve_demo_app(seed=0) as base_url:
        first = perform_demo_workflow(base_url)
        second = perform_demo_workflow(base_url)
    assert first == second


def test_perform_demo_workflow_records_the_full_order_workflow() -> None:
    with serve_demo_app(seed=0) as base_url:
        document = perform_demo_workflow(
            base_url, DemoWorkflowInputs(payment_method="card", gift_wrap=True)
        )
    capture = parse_har(document)
    assert len(capture) == 4

    page, listed, detail, confirmed = capture.entries
    assert page.request.path == "/orders"
    assert page.resource_type is ResourceType.DOCUMENT

    assert listed.request.path == "/api/v1/orders"
    assert listed.request.query.get("status") == "open"
    assert listed.request.headers.get("authorization") == f"Bearer {AUTH_TOKEN}"
    assert listed.response is not None
    assert json.loads(listed.response.body.text)["orders"][0]["id"] == 4711

    assert detail.request.path == "/api/v1/orders/4711"

    assert confirmed.request.method == "POST"
    assert confirmed.request.path == "/api/v1/orders/4711/confirm"
    assert confirmed.request.headers.get("x-csrf-token")
    confirm_body = json.loads(confirmed.request.body.text)
    assert confirm_body == {"payment_method": "card", "gift_wrap": True}
    assert confirmed.response is not None
    response_body = json.loads(confirmed.response.body.text)
    assert response_body["confirmed"] is True
    assert response_body["confirmation_ref"] == "CNF-4711-0000"


def test_a_page_argument_is_reflected_in_the_recorded_query_string() -> None:
    with serve_demo_app(seed=0) as base_url:
        document = perform_demo_workflow(base_url, DemoWorkflowInputs(page=2))
    capture = parse_har(document)
    listed = capture.entries[1]
    assert listed.request.query.get("page") == "2"
    assert json.loads(listed.response.body.text)["orders"][0]["id"] == 4733


def test_two_sessions_reissue_the_csrf_token_and_confirmation_reference() -> None:
    with serve_demo_app(seed=0) as base_url:
        first = parse_har(perform_demo_workflow(base_url))
    with serve_demo_app(seed=1) as base_url:
        second = parse_har(perform_demo_workflow(base_url))

    first_confirm = json.loads(first.entries[-1].response.body.text)
    second_confirm = json.loads(second.entries[-1].response.body.text)
    assert first_confirm["confirmation_ref"] != second_confirm["confirmation_ref"]

    first_token = first.entries[-1].request.headers.get("x-csrf-token")
    second_token = second.entries[-1].request.headers.get("x-csrf-token")
    assert first_token != second_token
