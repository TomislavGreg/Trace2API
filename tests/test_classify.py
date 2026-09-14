"""Tests for saying what each value of a workflow is."""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

import pytest

from trace2api.analyze import (
    DEFAULT_KEPT,
    ComparedValue,
    Relevance,
    ValueClassification,
    ValueRole,
    ValueRule,
    classify_values,
    render_classification,
)
from trace2api.analyze.classify import classify_value
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


def json_body(payload: object) -> Body:
    """Build a JSON request payload."""
    return Body(mime_type="application/json", text=json.dumps(payload))


def capture(*entries: Entry) -> Capture:
    """Build a capture holding ``entries``."""
    return Capture(
        metadata=CaptureMetadata(source=CaptureSource.HAR, created_at=STARTED_AT),
        entries=list(entries),
    )


def classification_of(
    left: tuple[Entry, ...],
    right: tuple[Entry, ...],
    *,
    keep: Iterable[Relevance] = DEFAULT_KEPT,
) -> ValueClassification:
    """Classify two captures built from entries, with a fixed redaction salt."""
    return classify_values(capture(*left), capture(*right), keep=keep, salt=SALT)


def roles_of(left: Entry, right: Entry) -> dict[str, ValueRole]:
    """Return the verdict reached for each value of two single request captures."""
    classified = classification_of((left,), (right,))
    return {value.location: value.role for value in classified.requests[0].values}


def rule_for(location: str, left: str | None, right: str | None) -> ValueRule:
    """Return the rule that decides one value, without building a capture for it."""
    return classify_value(ComparedValue(location, left, right)).rule


class TestConstants:
    def test_a_value_sent_twice_is_a_constant(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders?status=open")
        right = entry("b", "https://shop.example.com/api/orders?status=open")
        assert roles_of(left, right)["request.query[status]"] is ValueRole.CONSTANT

    def test_a_path_segment_that_held_still_is_a_constant(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders")
        right = entry("b", "https://shop.example.com/api/orders")
        assert roles_of(left, right)["request.path[1]"] is ValueRole.CONSTANT

    def test_the_reason_says_both_recordings_agreed(self) -> None:
        value = classify_value(ComparedValue("request.query[limit]", "20", "20"))
        assert value.rule is ValueRule.HELD_STILL
        assert value.reason == "both recordings sent the same value"


class TestInputs:
    def test_a_changed_word_is_an_input(self) -> None:
        assert rule_for("request.query[status]", "open", "shipped") is ValueRule.PLAIN_VALUE

    def test_a_changed_identifier_in_a_path_is_an_input(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders/4711")
        right = entry("b", "https://shop.example.com/api/orders/5822")
        assert roles_of(left, right)["request.path[3]"] is ValueRole.INPUT

    def test_a_field_only_the_second_run_sent_is_an_input(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders", body=json_body({"paid": True}))
        right = entry(
            "b",
            "https://shop.example.com/api/orders",
            body=json_body({"paid": True, "gift_wrap": "yes"}),
        )
        roles = roles_of(left, right)
        assert roles["request.body.gift_wrap"] is ValueRole.INPUT
        assert roles["request.body.paid"] is ValueRole.CONSTANT

    def test_an_input_carries_both_observed_values(self) -> None:
        value = classify_value(ComparedValue("request.query[q]", "boots", "sandals"))
        assert (value.left, value.right) == ("boots", "sandals")

    def test_a_value_too_long_to_have_been_typed_is_not_an_input(self) -> None:
        assert rule_for("request.query[q]", "z" * 65, "y" * 65) is ValueRule.NO_RULE_MATCHED


class TestGeneratedValues:
    @pytest.mark.parametrize(
        "name",
        ["_", "nonce", "ts", "timestamp", "requestId", "X-Request-Id", "x_trace_id", "cb"],
    )
    def test_a_name_that_says_it_is_minted_decides_the_value(self, name: str) -> None:
        value = classify_value(ComparedValue(f"request.query[{name}]", "11", "12"))
        assert value.role is ValueRole.GENERATED
        assert value.detail == name.lower()

    def test_the_name_rule_reports_the_name_rather_than_the_value(self) -> None:
        value = classify_value(ComparedValue("request.query[nonce]", "abc", "def"))
        assert value.reason.endswith("nonce")
        assert "abc" not in value.reason

    def test_a_changed_uuid_is_generated(self) -> None:
        value = classify_value(
            ComparedValue(
                "request.body.client_key",
                "3f1d9a0c-2b4e-4a71-9f0d-1c2b3a4d5e6f",
                "9a8b7c6d-5e4f-4a3b-8c9d-0e1f2a3b4c5d",
            )
        )
        assert value.rule is ValueRule.UUID_SHAPE

    def test_a_changed_epoch_millisecond_reading_is_generated(self) -> None:
        assert rule_for("request.query[at]", "1757066100000", "1757069700000") is (
            ValueRule.TIMESTAMP_SHAPE
        )

    def test_a_changed_iso_timestamp_is_generated(self) -> None:
        assert (
            rule_for("request.body.sent_at", "2026-09-04T09:15:00", "2026-09-04T09:41:00")
            is ValueRule.TIMESTAMP_SHAPE
        )

    def test_a_number_outside_the_epoch_window_is_not_a_timestamp(self) -> None:
        assert rule_for("request.query[account]", "9900112233", "9900112244") is (
            ValueRule.PLAIN_VALUE
        )

    def test_a_date_on_its_own_is_something_a_person_picks(self) -> None:
        assert rule_for("request.query[from]", "2026-09-04", "2026-09-11") is ValueRule.PLAIN_VALUE

    def test_a_long_opaque_string_is_generated(self) -> None:
        assert (
            rule_for(
                "request.body.state", "Xh7fQ2mP9vLk3Rt8Ws5Zb1Nc4Dy6", "Qa2Ws3Ed4Rf5Tg6Yh7Uj8Ik9Ol0"
            )
            is ValueRule.OPAQUE_SHAPE
        )

    def test_a_long_hexadecimal_run_is_generated(self) -> None:
        assert rule_for("request.query[etag]", "a1b2c3d4e5f60718", "0718f6e5d4c3b2a1") is (
            ValueRule.OPAQUE_SHAPE
        )

    def test_a_long_sentence_is_not_an_opaque_token(self) -> None:
        assert (
            rule_for("request.body.note", "please deliver after six", "please deliver before ten")
            is ValueRule.PLAIN_VALUE
        )

    def test_a_header_the_browser_maintains_is_generated(self) -> None:
        value = classify_value(
            ComparedValue(
                "request.headers.referer",
                "https://shop.example.com/orders/4711",
                "https://shop.example.com/orders/5822",
            )
        )
        assert value.role is ValueRole.GENERATED
        assert value.rule is ValueRule.BROWSER_HEADER

    def test_a_body_field_named_like_a_browser_header_is_not_one(self) -> None:
        assert rule_for("request.body.referer", "one", "two") is ValueRule.PLAIN_VALUE


class TestSecrets:
    def test_a_credential_that_held_still_is_a_secret_rather_than_a_constant(self) -> None:
        headers = Headers.from_pairs([("Authorization", "Bearer s3cret-token-value")])
        left = entry("a", "https://shop.example.com/api/orders", headers=headers)
        right = entry("b", "https://shop.example.com/api/orders", headers=headers)
        assert roles_of(left, right)["request.headers.authorization"] is ValueRole.SECRET

    def test_a_reissued_credential_is_a_secret(self) -> None:
        left = entry(
            "a",
            "https://shop.example.com/api/orders",
            headers=Headers.from_pairs([("X-CSRF-Token", "first-csrf-value")]),
        )
        right = entry(
            "b",
            "https://shop.example.com/api/orders",
            headers=Headers.from_pairs([("X-CSRF-Token", "second-csrf-value")]),
        )
        assert roles_of(left, right)["request.headers.x-csrf-token"] is ValueRole.SECRET

    def test_no_credential_reaches_the_rendered_verdicts(self) -> None:
        headers = Headers.from_pairs([("Authorization", "Bearer s3cret-token-value")])
        left = entry("a", "https://shop.example.com/api/orders", headers=headers)
        right = entry("b", "https://shop.example.com/api/orders", headers=headers)
        rendered = render_classification(classification_of((left,), (right,)))
        assert "s3cret-token-value" not in rendered
        assert "(redacted)" in rendered


class TestUnreadablePayloads:
    def test_a_payload_that_could_only_be_read_whole_is_unknown(self) -> None:
        left = entry(
            "a",
            "https://shop.example.com/api/orders",
            method="POST",
            body=Body(mime_type="application/octet-stream", text="first"),
        )
        right = entry(
            "b",
            "https://shop.example.com/api/orders",
            method="POST",
            body=Body(mime_type="application/octet-stream", text="second"),
        )
        value = classification_of((left,), (right,)).requests[0].values[-1]
        assert value.location == "request.body"
        assert value.role is ValueRole.UNKNOWN
        assert value.rule is ValueRule.OPAQUE_PAYLOAD


class TestWholeCaptures:
    def test_only_the_kept_requests_are_classified(self) -> None:
        application = entry("a", "https://shop.example.com/api/orders")
        noise = entry("b", "https://cdn.example.com/logo.png", resource_type=ResourceType.IMAGE)
        classified = classification_of((application, noise), (application, noise))
        assert [request.path for request in classified.requests] == ["/api/orders"]
        with_noise = classification_of(
            (application, noise), (application, noise), keep=tuple(Relevance)
        )
        assert len(with_noise.requests) == 2

    def test_a_request_with_no_counterpart_is_not_classified(self) -> None:
        shared = entry("a", "https://shop.example.com/api/orders")
        alone = entry("b", "https://shop.example.com/api/customers")
        classified = classification_of((shared, alone), (shared,))
        assert [request.path for request in classified.requests] == ["/api/orders"]
        assert [request.path for request in classified.unpaired_left] == ["/api/customers"]
        assert classified.unpaired_right == []

    def test_positions_match_the_whole_capture(self) -> None:
        noise = entry("n", "https://cdn.example.com/logo.png", resource_type=ResourceType.IMAGE)
        application = entry("a", "https://shop.example.com/api/orders")
        classified = classification_of((noise, application), (noise, application))
        assert (classified.requests[0].left_position, classified.requests[0].right_position) == (
            2,
            2,
        )

    def test_counts_account_for_every_value(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders?status=open&limit=20")
        right = entry("b", "https://shop.example.com/api/orders?status=shipped&limit=20")
        classified = classification_of((left,), (right,))
        counts = classified.counts_by_role()
        assert sum(counts.values()) == len(classified.values)
        assert counts[ValueRole.INPUT] == 1

    def test_the_redaction_count_is_reported(self) -> None:
        headers = Headers.from_pairs([("Authorization", "Bearer s3cret-token-value")])
        left = entry("a", "https://shop.example.com/api/orders", headers=headers)
        right = entry("b", "https://shop.example.com/api/orders", headers=headers)
        assert classification_of((left,), (right,)).redacted_values == 2


class TestRenderClassification:
    def test_constants_are_counted_rather_than_listed(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders?status=open&limit=20")
        right = entry("b", "https://shop.example.com/api/orders?status=shipped&limit=20")
        rendered = render_classification(classification_of((left,), (right,)))
        assert 'request.query[status]  input  "open" -> "shipped"' in rendered
        assert "request.query[limit]" not in rendered
        assert "Pass --constants to list the rest." in rendered

    def test_constants_can_be_listed(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders?status=open&limit=20")
        right = entry("b", "https://shop.example.com/api/orders?status=shipped&limit=20")
        rendered = render_classification(
            classification_of((left,), (right,)), include_constants=True
        )
        assert 'request.query[limit]   constant  "20"' in rendered
        assert "Pass --constants" not in rendered

    def test_explain_names_the_rule_behind_a_verdict(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders?status=open")
        right = entry("b", "https://shop.example.com/api/orders?status=shipped")
        rendered = render_classification(classification_of((left,), (right,)), explain=True)
        assert "it differs, and every observed value is ordinary text" in rendered

    def test_a_value_only_one_recording_sent_says_which(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders")
        right = entry("b", "https://shop.example.com/api/orders?page=2")
        rendered = render_classification(classification_of((left,), (right,)))
        assert '"2" (second recording only)' in rendered

    def test_the_summary_counts_every_verdict(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders?status=open&limit=20")
        right = entry("b", "https://shop.example.com/api/orders?status=shipped&limit=20")
        rendered = render_classification(classification_of((left,), (right,)))
        assert "Classified 4 values: 1 input, 3 constants." in rendered

    def test_an_unpaired_request_is_reported_as_unclassified(self) -> None:
        shared = entry("a", "https://shop.example.com/api/orders")
        alone = entry("b", "https://shop.example.com/api/customers")
        rendered = render_classification(classification_of((shared, alone), (shared,)))
        assert "Unpaired on the left, so not classified: 1." in rendered
        assert "2  GET shop.example.com/api/customers" in rendered

    def test_two_captures_with_nothing_in_common_render(self) -> None:
        rendered = render_classification(classification_of((), ()))
        assert "Classifying the values of 0 paired requests." in rendered
        assert "No values were classified." in rendered


class TestAsJson:
    def test_the_document_holds_every_value_with_its_verdict(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders?status=open&limit=20")
        right = entry("b", "https://shop.example.com/api/orders?status=shipped&limit=20")
        payload = json.loads(classification_of((left,), (right,)).as_json())
        values = {item["location"]: item for item in payload["requests"][0]["values"]}
        assert values["request.query[status]"] == {
            "location": "request.query[status]",
            "role": "input",
            "rule": "plain-value",
            "detail": None,
            "left": "open",
            "right": "shipped",
        }
        assert values["request.query[limit]"]["role"] == "constant"

    def test_the_document_reads_back_as_a_classification(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders?status=open")
        right = entry("b", "https://shop.example.com/api/orders?status=shipped")
        classified = classification_of((left,), (right,))
        assert ValueClassification.model_validate_json(classified.as_json()) == classified


class TestShippedExamples:
    def test_the_two_archives_classify(self) -> None:
        classified = classify_values(load_har(FIRST_RUN), load_har(SECOND_RUN), salt=SALT)
        assert len(classified.requests) == 4
        counts = classified.counts_by_role()
        assert counts[ValueRole.INPUT] == 7
        assert counts[ValueRole.SECRET] == 5
        assert counts[ValueRole.UNKNOWN] == 0

    def test_the_order_a_workflow_selected_reads_as_an_input(self) -> None:
        classified = classify_values(load_har(FIRST_RUN), load_har(SECOND_RUN), salt=SALT)
        confirm = classified.requests[-1]
        located = {value.location: value for value in confirm.values}
        assert located["request.path[4]"].role is ValueRole.INPUT
        assert located["request.body.payment_method"].role is ValueRole.INPUT
        assert located["request.headers.x-csrf-token"].role is ValueRole.SECRET

    def test_no_credential_appears_in_the_rendered_output(self) -> None:
        classified = classify_values(load_har(FIRST_RUN), load_har(SECOND_RUN), salt=SALT)
        rendered = render_classification(classified, include_constants=True, explain=True)
        archived = FIRST_RUN.read_text(encoding="utf-8")
        assert "s3cr3t" not in rendered
        for secret in ("Bearer ", "session="):
            assert secret in archived
        assert "(redacted)" in rendered
