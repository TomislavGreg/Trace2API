"""Tests for comparing two recordings of one workflow."""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from trace2api.analyze import (
    DEFAULT_KEPT,
    AlignmentRule,
    CaptureDiff,
    ChangeKind,
    Relevance,
    ValueChange,
    diff_captures,
    render_diff,
)
from trace2api.capture import load_har
from trace2api.models import (
    Body,
    Capture,
    CaptureMetadata,
    CaptureSource,
    Entry,
    Headers,
    Request,
    ResourceType,
    Response,
)

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
FIRST_RUN = EXAMPLES / "storefront-orders.har"
SECOND_RUN = EXAMPLES / "storefront-orders-second-run.har"

STARTED_AT = datetime(2026, 9, 4, 9, 15, tzinfo=UTC)
SALT = b"test-salt"


def entry(
    entry_id: str,
    url: str,
    *,
    method: str = "GET",
    headers: Headers | None = None,
    body: Body | None = None,
    resource_type: ResourceType = ResourceType.XHR,
) -> Entry:
    """Build one observed exchange, kept by the relevance rules unless said otherwise."""
    return Entry(
        id=entry_id,
        started_at=STARTED_AT,
        request=Request(method=method, url=url, headers=headers or Headers(), body=body),
        response=Response(status=200, headers=Headers.from_pairs([("Content-Type", "text/plain")])),
        resource_type=resource_type,
    )


def asset(entry_id: str, url: str) -> Entry:
    """Build one page asset, which the rules filter as noise."""
    return entry(entry_id, url, resource_type=ResourceType.IMAGE)


def json_body(payload: object) -> Body:
    """Build a JSON request payload."""
    return Body(mime_type="application/json", text=json.dumps(payload))


def capture(*entries: Entry) -> Capture:
    """Build a capture holding ``entries``."""
    return Capture(
        metadata=CaptureMetadata(source=CaptureSource.HAR, created_at=STARTED_AT),
        entries=list(entries),
    )


def diff_of(
    left: tuple[Entry, ...],
    right: tuple[Entry, ...],
    *,
    keep: Iterable[Relevance] = DEFAULT_KEPT,
) -> CaptureDiff:
    """Compare two captures built from entries, with a fixed redaction salt."""
    return diff_captures(capture(*left), capture(*right), keep=keep, salt=SALT)


def changes_of(left: Entry, right: Entry) -> list[ValueChange]:
    """Return the values that differ between two single request captures."""
    diff = diff_of((left,), (right,))
    assert len(diff.pairs) == 1, "the two requests were expected to pair"
    return diff.pairs[0].changes


def located(changes: list[ValueChange]) -> dict[str, tuple[ChangeKind, str | None, str | None]]:
    """Return the changes by location, for asserting on one of them at a time."""
    return {change.location: (change.kind, change.left, change.right) for change in changes}


class TestPairing:
    def test_pairs_requests_with_the_same_method_host_and_path(self) -> None:
        diff = diff_of(
            (entry("a", "https://shop.example.com/api/v1/orders"),),
            (entry("b", "https://shop.example.com/api/v1/orders"),),
        )
        assert [(pair.left_position, pair.right_position) for pair in diff.pairs] == [(1, 1)]
        assert diff.pairs[0].rule is AlignmentRule.IDENTICAL_PATH

    def test_repeats_pair_in_the_order_they_were_observed(self) -> None:
        diff = diff_of(
            (
                entry("a", "https://shop.example.com/api/v1/poll?seq=1"),
                entry("b", "https://shop.example.com/api/v1/poll?seq=2"),
            ),
            (
                entry("c", "https://shop.example.com/api/v1/poll?seq=7"),
                entry("d", "https://shop.example.com/api/v1/poll?seq=8"),
            ),
        )
        assert [(pair.left_position, pair.right_position) for pair in diff.pairs] == [
            (1, 1),
            (2, 2),
        ]
        assert located(diff.pairs[0].changes)["request.query[seq]"] == (
            ChangeKind.CHANGED,
            "1",
            "7",
        )

    def test_pairs_paths_that_differ_only_in_a_numeric_identifier(self) -> None:
        diff = diff_of(
            (entry("a", "https://shop.example.com/api/v1/orders/4711/confirm"),),
            (entry("b", "https://shop.example.com/api/v1/orders/5822/confirm"),),
        )
        assert diff.pairs[0].rule is AlignmentRule.PATH_SHAPE

    def test_pairs_paths_that_differ_only_in_a_uuid(self) -> None:
        diff = diff_of(
            (
                entry(
                    "a",
                    "https://shop.example.com/api/v1/carts/1b4e28ba-2fa1-11d2-883f-b9a761bde3fb",
                ),
            ),
            (
                entry(
                    "b",
                    "https://shop.example.com/api/v1/carts/3f2504e0-4f89-11d3-9a0c-0305e82c3301",
                ),
            ),
        )
        assert diff.pairs[0].rule is AlignmentRule.PATH_SHAPE

    def test_pairs_paths_that_differ_only_in_a_long_hex_identifier(self) -> None:
        diff = diff_of(
            (entry("a", "https://shop.example.com/api/v1/sessions/a1b2c3d4e5f6a7b8"),),
            (entry("b", "https://shop.example.com/api/v1/sessions/f1e2d3c4b5a69788"),),
        )
        assert diff.pairs[0].rule is AlignmentRule.PATH_SHAPE

    def test_a_short_word_is_not_taken_for_an_identifier(self) -> None:
        diff = diff_of(
            (entry("a", "https://shop.example.com/api/v1/orders"),),
            (entry("b", "https://shop.example.com/api/v1/baskets"),),
        )
        assert diff.pairs[0].rule is AlignmentRule.SINGLE_SEGMENT

    def test_pairs_a_single_differing_segment_when_nothing_else_could_be_meant(self) -> None:
        diff = diff_of(
            (entry("a", "https://shop.example.com/api/v1/search/shoes"),),
            (entry("b", "https://shop.example.com/api/v1/search/hats"),),
        )
        assert diff.pairs[0].rule is AlignmentRule.SINGLE_SEGMENT
        assert located(diff.pairs[0].changes)["request.path[4]"] == (
            ChangeKind.CHANGED,
            "shoes",
            "hats",
        )

    def test_refuses_to_guess_between_two_candidates(self) -> None:
        diff = diff_of(
            (entry("a", "https://shop.example.com/api/v1/orders"),),
            (
                entry("b", "https://shop.example.com/api/v1/baskets"),
                entry("c", "https://shop.example.com/api/v1/invoices"),
            ),
        )
        assert diff.pairs == []
        assert [request.position for request in diff.unpaired_left] == [1]
        assert [request.position for request in diff.unpaired_right] == [1, 2]

    def test_an_exact_match_is_not_spent_on_a_looser_one(self) -> None:
        diff = diff_of(
            (
                entry("a", "https://shop.example.com/api/v1/orders/4711"),
                entry("b", "https://shop.example.com/api/v1/orders/5822"),
            ),
            (entry("c", "https://shop.example.com/api/v1/orders/5822"),),
        )
        assert [(pair.left_position, pair.right_position) for pair in diff.pairs] == [(2, 1)]
        assert diff.pairs[0].rule is AlignmentRule.IDENTICAL_PATH
        assert [request.position for request in diff.unpaired_left] == [1]

    def test_paths_of_different_depth_are_never_paired(self) -> None:
        diff = diff_of(
            (entry("a", "https://shop.example.com/api/v1/orders"),),
            (entry("b", "https://shop.example.com/api/v1/orders/4711/lines"),),
        )
        assert diff.pairs == []

    def test_a_different_method_is_never_paired(self) -> None:
        diff = diff_of(
            (entry("a", "https://shop.example.com/api/v1/orders"),),
            (entry("b", "https://shop.example.com/api/v1/orders", method="POST"),),
        )
        assert diff.pairs == []

    def test_a_different_host_is_never_paired(self) -> None:
        diff = diff_of(
            (entry("a", "https://shop.example.com/api/v1/orders"),),
            (entry("b", "https://other.example.com/api/v1/orders"),),
        )
        assert diff.pairs == []

    def test_pairs_are_reported_in_the_order_the_first_recording_observed_them(self) -> None:
        diff = diff_of(
            (
                entry("a", "https://shop.example.com/api/v1/orders/4711"),
                entry("b", "https://shop.example.com/api/v1/orders"),
            ),
            (
                entry("c", "https://shop.example.com/api/v1/orders"),
                entry("d", "https://shop.example.com/api/v1/orders/5822"),
            ),
        )
        assert [pair.left_position for pair in diff.pairs] == [1, 2]

    def test_noise_is_left_out_of_the_comparison(self) -> None:
        diff = diff_of(
            (
                asset("a", "https://cdn.example.com/img/logo.png"),
                entry("b", "https://shop.example.com/api/v1/orders"),
            ),
            (
                asset("c", "https://cdn.example.com/img/hero.png"),
                entry("d", "https://shop.example.com/api/v1/orders"),
            ),
        )
        assert diff.left.total_requests == 2
        assert diff.left.compared_requests == 1
        assert [pair.left_position for pair in diff.pairs] == [2]
        assert diff.unpaired_left == []

    def test_all_relevances_can_be_compared(self) -> None:
        diff = diff_of(
            (asset("a", "https://cdn.example.com/img/logo.png"),),
            (asset("b", "https://cdn.example.com/img/logo.png"),),
            keep=tuple(Relevance),
        )
        assert diff.left.compared_requests == 1
        assert [pair.left_position for pair in diff.pairs] == [1]

    def test_positions_count_over_the_whole_capture(self) -> None:
        diff = diff_of(
            (
                asset("a", "https://cdn.example.com/img/logo.png"),
                asset("b", "https://cdn.example.com/static/app.png"),
                entry("c", "https://shop.example.com/api/v1/orders"),
            ),
            (entry("d", "https://shop.example.com/api/v1/orders"),),
        )
        assert [(pair.left_position, pair.right_position) for pair in diff.pairs] == [(3, 1)]


class TestChangedValues:
    def test_an_identical_request_carries_no_changes(self) -> None:
        paired = diff_of(
            (
                entry(
                    "a",
                    "https://shop.example.com/api/v1/orders?status=open",
                    headers=Headers.from_pairs([("Accept", "application/json")]),
                ),
            ),
            (
                entry(
                    "b",
                    "https://shop.example.com/api/v1/orders?status=open",
                    headers=Headers.from_pairs([("Accept", "application/json")]),
                ),
            ),
        ).pairs[0]
        assert paired.is_unchanged

    def test_reports_a_changed_query_parameter(self) -> None:
        changes = changes_of(
            entry("a", "https://shop.example.com/api/v1/orders?status=open"),
            entry("b", "https://shop.example.com/api/v1/orders?status=shipped"),
        )
        assert located(changes) == {
            "request.query[status]": (ChangeKind.CHANGED, "open", "shipped")
        }

    def test_reports_an_added_and_a_removed_query_parameter(self) -> None:
        changes = changes_of(
            entry("a", "https://shop.example.com/api/v1/orders?limit=20"),
            entry("b", "https://shop.example.com/api/v1/orders?page=2"),
        )
        assert located(changes) == {
            "request.query[limit]": (ChangeKind.REMOVED, "20", None),
            "request.query[page]": (ChangeKind.ADDED, None, "2"),
        }

    def test_a_repeated_query_parameter_is_compared_by_position(self) -> None:
        changes = changes_of(
            entry("a", "https://shop.example.com/api/v1/orders?tag=new&tag=paid"),
            entry("b", "https://shop.example.com/api/v1/orders?tag=new&tag=void"),
        )
        assert located(changes) == {"request.query[tag][1]": (ChangeKind.CHANGED, "paid", "void")}

    def test_reports_a_changed_path_segment_numbered_from_one(self) -> None:
        changes = changes_of(
            entry("a", "https://shop.example.com/api/v1/orders/4711"),
            entry("b", "https://shop.example.com/api/v1/orders/5822"),
        )
        assert located(changes) == {"request.path[4]": (ChangeKind.CHANGED, "4711", "5822")}

    def test_reports_a_changed_header_under_its_lowercased_name(self) -> None:
        changes = changes_of(
            entry(
                "a",
                "https://shop.example.com/api/v1/orders",
                headers=Headers.from_pairs([("X-Locale", "en-GB")]),
            ),
            entry(
                "b",
                "https://shop.example.com/api/v1/orders",
                headers=Headers.from_pairs([("X-Locale", "de-DE")]),
            ),
        )
        assert located(changes) == {
            "request.headers.x-locale": (ChangeKind.CHANGED, "en-GB", "de-DE")
        }

    def test_reports_a_header_only_one_run_sent(self) -> None:
        changes = changes_of(
            entry("a", "https://shop.example.com/api/v1/orders"),
            entry(
                "b",
                "https://shop.example.com/api/v1/orders",
                headers=Headers.from_pairs([("X-Retry", "1")]),
            ),
        )
        assert located(changes) == {"request.headers.x-retry": (ChangeKind.ADDED, None, "1")}

    def test_a_header_the_wire_derives_is_not_reported(self) -> None:
        changes = changes_of(
            entry(
                "a",
                "https://shop.example.com/api/v1/orders",
                method="POST",
                headers=Headers.from_pairs([("Content-Length", "12")]),
                body=json_body({"q": "shoes"}),
            ),
            entry(
                "b",
                "https://shop.example.com/api/v1/orders",
                method="POST",
                headers=Headers.from_pairs([("Content-Length", "900")]),
                body=json_body({"q": "shoes"}),
            ),
        )
        assert changes == []

    def test_reports_a_changed_payload_field(self) -> None:
        changes = changes_of(
            entry(
                "a",
                "https://s.example.com/api/o",
                method="POST",
                body=json_body({"pay": "invoice"}),
            ),
            entry(
                "b", "https://s.example.com/api/o", method="POST", body=json_body({"pay": "card"})
            ),
        )
        assert located(changes) == {"request.body.pay": (ChangeKind.CHANGED, "invoice", "card")}

    def test_reports_a_payload_field_only_one_run_sent(self) -> None:
        changes = changes_of(
            entry(
                "a", "https://s.example.com/api/o", method="POST", body=json_body({"pay": "card"})
            ),
            entry(
                "b",
                "https://s.example.com/api/o",
                method="POST",
                body=json_body({"pay": "card", "gift": True}),
            ),
        )
        assert located(changes) == {"request.body.gift": (ChangeKind.ADDED, None, "true")}

    def test_reports_a_changed_field_inside_a_nested_payload(self) -> None:
        changes = changes_of(
            entry(
                "a",
                "https://s.example.com/api/o",
                method="POST",
                body=json_body({"address": {"city": "Zagreb", "zip": "10000"}}),
            ),
            entry(
                "b",
                "https://s.example.com/api/o",
                method="POST",
                body=json_body({"address": {"city": "Split", "zip": "10000"}}),
            ),
        )
        assert located(changes) == {
            "request.body.address.city": (ChangeKind.CHANGED, "Zagreb", "Split")
        }

    def test_reports_a_changed_element_of_a_payload_list(self) -> None:
        changes = changes_of(
            entry(
                "a",
                "https://s.example.com/api/o",
                method="POST",
                body=json_body({"lines": [{"sku": "A1"}, {"sku": "B2"}]}),
            ),
            entry(
                "b",
                "https://s.example.com/api/o",
                method="POST",
                body=json_body({"lines": [{"sku": "A1"}]}),
            ),
        )
        assert located(changes) == {
            "request.body.lines[1]": (ChangeKind.REMOVED, '{"sku": "B2"}', None)
        }

    def test_a_payload_field_that_became_a_structure_is_reported_as_changed(self) -> None:
        changes = changes_of(
            entry("a", "https://s.example.com/api/o", method="POST", body=json_body({"to": "me"})),
            entry(
                "b",
                "https://s.example.com/api/o",
                method="POST",
                body=json_body({"to": {"name": "me"}}),
            ),
        )
        assert located(changes) == {"request.body.to": (ChangeKind.CHANGED, "me", '{"name": "me"}')}

    def test_a_form_payload_is_compared_field_by_field(self) -> None:
        changes = changes_of(
            entry(
                "a",
                "https://s.example.com/api/o",
                method="POST",
                body=Body(mime_type="application/x-www-form-urlencoded", text="q=shoes&page=1"),
            ),
            entry(
                "b",
                "https://s.example.com/api/o",
                method="POST",
                body=Body(mime_type="application/x-www-form-urlencoded", text="q=hats&page=1"),
            ),
        )
        assert located(changes) == {"request.body[q]": (ChangeKind.CHANGED, "shoes", "hats")}

    def test_a_payload_that_is_not_a_structure_is_compared_whole(self) -> None:
        changes = changes_of(
            entry(
                "a",
                "https://s.example.com/api/o",
                method="POST",
                body=Body(mime_type="text/plain", text="first"),
            ),
            entry(
                "b",
                "https://s.example.com/api/o",
                method="POST",
                body=Body(mime_type="text/plain", text="second"),
            ),
        )
        assert located(changes) == {"request.body": (ChangeKind.CHANGED, "first", "second")}

    def test_a_payload_that_does_not_parse_is_compared_whole(self) -> None:
        changes = changes_of(
            entry(
                "a",
                "https://s.example.com/api/o",
                method="POST",
                body=Body(mime_type="application/json", text="{not json"),
            ),
            entry(
                "b",
                "https://s.example.com/api/o",
                method="POST",
                body=Body(mime_type="application/json", text="{still not json"),
            ),
        )
        assert located(changes)["request.body"][0] is ChangeKind.CHANGED

    def test_a_binary_payload_is_described_rather_than_quoted(self) -> None:
        changes = changes_of(
            entry(
                "a",
                "https://s.example.com/api/o",
                method="POST",
                body=Body(mime_type="image/png", text="aGVsbG8=", encoding="base64"),
            ),
            entry(
                "b",
                "https://s.example.com/api/o",
                method="POST",
                body=Body(mime_type="image/png", text="Z29vZGJ5ZQ==", encoding="base64"),
            ),
        )
        assert located(changes) == {
            "request.body": (
                ChangeKind.CHANGED,
                "<5 bytes of image/png>",
                "<7 bytes of image/png>",
            )
        }

    def test_a_payload_only_one_run_sent_is_reported(self) -> None:
        changes = changes_of(
            entry("a", "https://s.example.com/api/o", method="POST"),
            entry("b", "https://s.example.com/api/o", method="POST", body=json_body({"q": "hats"})),
        )
        assert located(changes) == {"request.body": (ChangeKind.ADDED, None, '{"q": "hats"}')}

    def test_an_empty_payload_counts_as_none(self) -> None:
        changes = changes_of(
            entry(
                "a",
                "https://s.example.com/api/o",
                method="POST",
                body=Body(mime_type="application/json", text=""),
            ),
            entry("b", "https://s.example.com/api/o", method="POST"),
        )
        assert changes == []


class TestRedaction:
    def test_a_credential_that_held_still_reports_as_unchanged(self) -> None:
        token = Headers.from_pairs([("Authorization", "Bearer example-token")])
        paired = diff_of(
            (entry("a", "https://shop.example.com/api/v1/orders", headers=token),),
            (entry("b", "https://shop.example.com/api/v1/orders", headers=token),),
        ).pairs[0]
        assert paired.is_unchanged

    def test_a_reissued_credential_reports_as_changed_without_either_value(self) -> None:
        diff = diff_of(
            (
                entry(
                    "a",
                    "https://shop.example.com/api/v1/orders",
                    headers=Headers.from_pairs([("Authorization", "Bearer first-token")]),
                ),
            ),
            (
                entry(
                    "b",
                    "https://shop.example.com/api/v1/orders",
                    headers=Headers.from_pairs([("Authorization", "Bearer second-token")]),
                ),
            ),
        )
        change = located(diff.pairs[0].changes)["request.headers.authorization"]
        assert change[0] is ChangeKind.CHANGED
        rendered = render_diff(diff)
        assert "first-token" not in rendered
        assert "second-token" not in rendered
        assert '"Bearer (redacted)" -> "Bearer (redacted)"' in rendered

    def test_a_reissued_token_is_shown_as_redacted_on_both_sides(self) -> None:
        diff = diff_of(
            (
                entry(
                    "a",
                    "https://shop.example.com/api/v1/orders",
                    headers=Headers.from_pairs([("X-Csrf-Token", "first-value")]),
                ),
            ),
            (
                entry(
                    "b",
                    "https://shop.example.com/api/v1/orders",
                    headers=Headers.from_pairs([("X-Csrf-Token", "second-value")]),
                ),
            ),
        )
        assert "(redacted) -> (redacted)" in render_diff(diff)

    def test_a_credential_in_a_query_string_is_never_shown(self) -> None:
        diff = diff_of(
            (entry("a", "https://shop.example.com/api/v1/orders?access_token=first-secret"),),
            (entry("b", "https://shop.example.com/api/v1/orders?access_token=second-secret"),),
        )
        assert "secret" not in render_diff(diff)
        assert "secret" not in diff.as_json()

    def test_counts_the_credentials_removed_from_both_captures(self) -> None:
        diff = diff_of(
            (
                entry(
                    "a",
                    "https://shop.example.com/api/v1/orders",
                    headers=Headers.from_pairs([("Authorization", "Bearer example-token")]),
                ),
            ),
            (
                entry(
                    "b",
                    "https://shop.example.com/api/v1/orders",
                    headers=Headers.from_pairs([("Authorization", "Bearer example-token")]),
                ),
            ),
        )
        assert diff.redacted_values == 2


class TestRenderDiff:
    def test_reports_the_two_recordings_and_what_changed(self) -> None:
        rendered = render_diff(
            diff_of(
                (entry("a", "https://shop.example.com/api/v1/orders?status=open"),),
                (entry("b", "https://shop.example.com/api/v1/orders?status=shipped"),),
            )
        )
        assert rendered == (
            "Left:  1 request from har, recorded 2026-09-04T09:15:00+00:00\n"
            "Right: 1 request from har, recorded 2026-09-04T09:15:00+00:00\n"
            "Comparing 1 kept request on the left with 1 on the right.\n"
            "\n"
            "1 -> 1  GET shop.example.com/api/v1/orders\n"
            '  request.query[status]  changed  "open" -> "shipped"\n'
            "\n"
            "Paired 1 request: 1 changed, 0 unchanged.\n"
            "1 value differs.\n"
        )

    def test_an_unchanged_request_is_counted_rather_than_listed(self) -> None:
        rendered = render_diff(
            diff_of(
                (entry("a", "https://shop.example.com/api/v1/orders"),),
                (entry("b", "https://shop.example.com/api/v1/orders"),),
            )
        )
        assert "Paired 1 request: 0 changed, 1 unchanged." in rendered
        assert "/api/v1/orders" not in rendered

    def test_unchanged_requests_can_be_listed(self) -> None:
        rendered = render_diff(
            diff_of(
                (entry("a", "https://shop.example.com/api/v1/orders"),),
                (entry("b", "https://shop.example.com/api/v1/orders"),),
            ),
            include_unchanged=True,
        )
        assert "1 -> 1  GET shop.example.com/api/v1/orders" in rendered
        assert "  no request value changed" in rendered

    def test_names_the_rule_behind_a_pairing_that_was_not_exact(self) -> None:
        rendered = render_diff(
            diff_of(
                (entry("a", "https://shop.example.com/api/v1/orders/4711"),),
                (entry("b", "https://shop.example.com/api/v1/orders/5822"),),
            )
        )
        assert "paired on the same path once identifier shaped segments are set aside" in rendered

    def test_lists_the_requests_that_were_observed_once(self) -> None:
        rendered = render_diff(
            diff_of(
                (entry("a", "https://shop.example.com/api/v1/orders"),),
                (
                    entry("b", "https://shop.example.com/api/v1/orders"),
                    entry("c", "https://shop.example.com/api/v1/banners"),
                ),
            )
        )
        assert "Unpaired on the right: 1." in rendered
        assert "  2  GET shop.example.com/api/v1/banners" in rendered
        assert "Unpaired on the left" not in rendered

    def test_a_long_value_is_shortened(self) -> None:
        rendered = render_diff(
            diff_of(
                (entry("a", "https://shop.example.com/api/v1/orders?note=" + "x" * 80),),
                (entry("b", "https://shop.example.com/api/v1/orders?note=short"),),
            )
        )
        assert '"' + "x" * 37 + '..."' in rendered

    def test_a_comparison_of_two_empty_captures_says_so(self) -> None:
        rendered = render_diff(diff_of((), ()))
        assert rendered == (
            "Left:  0 requests from har, recorded 2026-09-04T09:15:00+00:00\n"
            "Right: 0 requests from har, recorded 2026-09-04T09:15:00+00:00\n"
            "Comparing 0 kept requests on the left with 0 on the right.\n"
            "\n"
            "Paired 0 requests: 0 changed, 0 unchanged.\n"
        )


class TestAsJson:
    def test_reports_the_comparison_under_readable_names(self) -> None:
        payload = json.loads(
            diff_of(
                (entry("a", "https://shop.example.com/api/v1/orders?status=open"),),
                (entry("b", "https://shop.example.com/api/v1/orders?status=shipped"),),
            ).as_json()
        )
        assert payload["left"]["compared_requests"] == 1
        assert payload["pairs"][0]["rule"] == "identical-path"
        assert payload["pairs"][0]["changes"] == [
            {
                "location": "request.query[status]",
                "kind": "changed",
                "left": "open",
                "right": "shipped",
            }
        ]


class TestShippedExamples:
    def test_compares_the_two_example_archives(self) -> None:
        rendered = render_diff(diff_captures(load_har(FIRST_RUN), load_har(SECOND_RUN)))
        assert rendered == (
            "Left:  8 requests from har, recorded 2026-09-04T09:15:00+00:00\n"
            "Right: 7 requests from har, recorded 2026-09-04T09:41:00+00:00\n"
            "Comparing 4 kept requests on the left with 4 on the right.\n"
            "\n"
            "4 -> 3  GET shop.example.com/api/v1/orders\n"
            '  request.query[status]          changed  "open" -> "shipped"\n'
            '  request.query[page]            added    "2"\n'
            "\n"
            "6 -> 5  GET shop.example.com/api/v1/orders/4711\n"
            "  paired on the same path once identifier shaped segments are set aside\n"
            '  request.path[4]                changed  "4711" -> "5822"\n'
            "\n"
            "7 -> 6  POST shop.example.com/api/v1/orders/4711/confirm\n"
            "  paired on the same path once identifier shaped segments are set aside\n"
            '  request.path[4]                changed  "4711" -> "5822"\n'
            "  request.headers.x-csrf-token   changed  (redacted) -> (redacted)\n"
            '  request.body.payment_method    changed  "invoice" -> "card"\n'
            '  request.body.confirmation_ref  changed  "CNF-4711-88" -> "CNF-5822-40"\n'
            '  request.body.gift_wrap         added    "true"\n'
            "\n"
            "Paired 4 requests: 3 changed, 1 unchanged.\n"
            "8 values differ.\n"
            "Redacted 12 values before comparing, using one salt for both captures.\n"
        )

    def test_the_two_archives_record_the_same_workflow(self) -> None:
        diff = diff_captures(load_har(FIRST_RUN), load_har(SECOND_RUN))
        assert diff.unpaired_left == []
        assert diff.unpaired_right == []
