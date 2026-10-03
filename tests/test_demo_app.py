"""Tests for the local demo storefront.

Every value exercised here is synthetic: the bearer token and CSRF token are literals
the app itself issues for this purpose and are not valid anywhere else.
"""

from __future__ import annotations

import httpx
import pytest

from trace2api.demo.app import AUTH_TOKEN, ORDERS, DemoAppState, serve_demo_app

AUTH_HEADERS = {"Authorization": f"Bearer {AUTH_TOKEN}"}


def test_state_issues_a_token_and_reference_per_seed() -> None:
    first = DemoAppState(seed=0)
    second = DemoAppState(seed=1)
    assert first.csrf_token != second.csrf_token
    assert first.confirmation_ref(4711) != second.confirmation_ref(4711)
    # The same seed always hands out the same values, so two recordings taken from the
    # same instance are comparable.
    assert DemoAppState(seed=0).csrf_token == first.csrf_token
    assert DemoAppState(seed=0).confirmation_ref(4711) == first.confirmation_ref(4711)


def test_orders_page_is_served_and_sets_a_csrf_cookie() -> None:
    with serve_demo_app(seed=7) as base_url:
        response = httpx.get(f"{base_url}/orders")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert response.cookies["csrf"] == DemoAppState(seed=7).csrf_token


def test_listing_orders_requires_authorization() -> None:
    with serve_demo_app() as base_url:
        unauthorized = httpx.get(f"{base_url}/api/v1/orders")
        authorized = httpx.get(f"{base_url}/api/v1/orders", headers=AUTH_HEADERS)
    assert unauthorized.status_code == 401
    assert authorized.status_code == 200


def test_listing_orders_filters_by_status_and_pages() -> None:
    with serve_demo_app() as base_url:
        first_page = httpx.get(
            f"{base_url}/api/v1/orders", params={"status": "open"}, headers=AUTH_HEADERS
        )
        second_page = httpx.get(
            f"{base_url}/api/v1/orders",
            params={"status": "open", "page": "2"},
            headers=AUTH_HEADERS,
        )
        shipped = httpx.get(
            f"{base_url}/api/v1/orders", params={"status": "shipped"}, headers=AUTH_HEADERS
        )
    open_orders = [order for order in ORDERS if order["status"] == "open"]
    assert first_page.json() == {"orders": [open_orders[0]]}
    assert second_page.json() == {"orders": [open_orders[1]]}
    assert shipped.json() == {"orders": [order for order in ORDERS if order["status"] == "shipped"]}


def test_listing_orders_rejects_a_page_that_is_not_a_positive_number() -> None:
    with serve_demo_app() as base_url:
        not_a_number = httpx.get(
            f"{base_url}/api/v1/orders", params={"page": "x"}, headers=AUTH_HEADERS
        )
        zero = httpx.get(f"{base_url}/api/v1/orders", params={"page": "0"}, headers=AUTH_HEADERS)
    assert not_a_number.status_code == 400
    assert zero.status_code == 400


def test_order_detail_is_served_by_id() -> None:
    with serve_demo_app() as base_url:
        found = httpx.get(f"{base_url}/api/v1/orders/4711", headers=AUTH_HEADERS)
        missing = httpx.get(f"{base_url}/api/v1/orders/9999", headers=AUTH_HEADERS)
    assert found.status_code == 200
    assert found.json() == ORDERS[0]
    assert missing.status_code == 404


@pytest.mark.parametrize("seed", [0, 3])
def test_confirming_an_order_requires_the_matching_csrf_token(seed: int) -> None:
    with serve_demo_app(seed=seed) as base_url:
        page = httpx.get(f"{base_url}/orders")
        csrf_token = page.cookies["csrf"]

        missing_token = httpx.post(
            f"{base_url}/api/v1/orders/4711/confirm",
            json={"payment_method": "invoice"},
            headers=AUTH_HEADERS,
        )
        wrong_token = httpx.post(
            f"{base_url}/api/v1/orders/4711/confirm",
            json={"payment_method": "invoice"},
            headers={**AUTH_HEADERS, "X-CSRF-Token": "not-it"},
        )
        confirmed = httpx.post(
            f"{base_url}/api/v1/orders/4711/confirm",
            json={"payment_method": "card", "gift_wrap": True},
            headers={**AUTH_HEADERS, "X-CSRF-Token": csrf_token},
        )

    assert missing_token.status_code == 403
    assert wrong_token.status_code == 403
    assert confirmed.status_code == 201
    assert confirmed.json() == {
        "confirmed": True,
        "confirmation_ref": DemoAppState(seed=seed).confirmation_ref(4711),
        "payment_method": "card",
        "gift_wrap": True,
    }


def test_confirming_an_unknown_order_is_reported_as_not_found() -> None:
    with serve_demo_app() as base_url:
        csrf_token = httpx.get(f"{base_url}/orders").cookies["csrf"]
        response = httpx.post(
            f"{base_url}/api/v1/orders/9999/confirm",
            json={"payment_method": "invoice"},
            headers={**AUTH_HEADERS, "X-CSRF-Token": csrf_token},
        )
    assert response.status_code == 404


def test_an_unknown_path_is_reported_as_not_found() -> None:
    with serve_demo_app() as base_url:
        response = httpx.get(f"{base_url}/nothing-here")
    assert response.status_code == 404
