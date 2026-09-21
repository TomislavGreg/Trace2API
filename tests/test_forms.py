"""Tests for reading a form encoded payload the way a generated client has to send it."""

from __future__ import annotations

from datetime import UTC, datetime

from trace2api.generate import form_field_places, form_fields, form_secrets
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
from trace2api.sanitize import redact_capture

STARTED_AT = datetime(2026, 9, 4, 9, 15, tzinfo=UTC)

FORM = "application/x-www-form-urlencoded"
ACCESS_TOKEN = "example-access-token-not-a-real-credential"


def sent(text: str, *, mime_type: str = FORM) -> Body:
    """Return the payload as redaction would store it after the request was captured."""
    capture = Capture(
        metadata=CaptureMetadata(source=CaptureSource.HAR, created_at=STARTED_AT),
        entries=[
            Entry(
                id="a",
                started_at=STARTED_AT,
                request=Request(
                    method="POST",
                    url="https://shop.example.com/api/orders",
                    headers=Headers.from_pairs([("Content-Type", mime_type)]),
                    body=Body(mime_type=mime_type, text=text),
                ),
                response=Response(status=200, headers=Headers.from_pairs([])),
                resource_type=ResourceType.XHR,
            )
        ],
    )
    body = redact_capture(capture, salt=b"fixed-salt").capture.entries[0].request.body
    assert body is not None
    return body


def test_a_payload_that_held_no_credential_reports_none() -> None:
    fields = form_fields(sent("q=shoes&page=1"))
    assert fields is not None
    assert form_secrets(fields) == ()


def test_a_credential_is_found_although_redaction_encoded_the_placeholder() -> None:
    body = sent(f"ref=CNF-998172&csrf_token={ACCESS_TOKEN}")
    # The placeholder itself does not survive re-encoding, which is the reason a payload
    # is read field by field rather than searched as text.
    assert "<redacted:" not in (body.text or "")
    fields = form_fields(body)
    assert fields is not None
    assert len(form_secrets(fields)) == 1
    assert [field.name for field in fields] == ["ref", "csrf_token"]
    assert [field.is_secret for field in fields] == [False, True]


def test_a_field_redaction_left_alone_keeps_the_spelling_it_was_sent_with() -> None:
    fields = form_fields(sent(f"note=hello+world%21&csrf_token={ACCESS_TOKEN}"))
    assert fields is not None
    assert fields[0].spelled == "note=hello+world%21"


def test_two_credentials_are_reported_in_the_order_they_were_sent() -> None:
    fields = form_fields(sent(f"csrf_token={ACCESS_TOKEN}&q=shoes&api_key=live-key-value"))
    assert fields is not None
    first, second = form_secrets(fields)
    assert first != second


def test_a_repeated_field_name_is_read_as_the_two_fields_it_was_sent_as() -> None:
    fields = form_fields(sent("tag=new&tag=sale"))
    assert fields is not None
    assert [field.spelled for field in fields] == ["tag=new", "tag=sale"]


def test_a_field_sent_without_a_value_is_read_as_the_payload_spelled_it() -> None:
    fields = form_fields(Body(mime_type=FORM, text="draft&q=shoes"))
    assert fields is not None
    assert [field.spelled for field in fields] == ["draft", "q=shoes"]
    assert form_secrets(fields) == ()


def test_a_value_is_read_back_the_way_the_server_read_it() -> None:
    fields = form_fields(Body(mime_type=FORM, text="note=hello+world%21"))
    assert fields is not None
    assert fields[0].decoded == "hello world!"


def test_a_field_is_placed_under_the_name_the_server_read() -> None:
    fields = form_fields(Body(mime_type=FORM, text="order+ref=CNF-998172&qty=2"))
    assert fields is not None
    assert form_field_places(fields) == {("order ref", 0): 0, ("qty", 0): 1}


def test_a_repeated_name_places_each_field_under_the_value_it_carried() -> None:
    fields = form_fields(Body(mime_type=FORM, text="tag=new&q=shoes&tag=sale"))
    assert fields is not None
    assert form_field_places(fields) == {("tag", 0): 0, ("q", 0): 1, ("tag", 1): 2}


def test_an_empty_pair_is_passed_over_rather_than_counted_as_a_field() -> None:
    fields = form_fields(Body(mime_type=FORM, text="a=1&&b=2"))
    assert fields is not None
    assert form_field_places(fields) == {("a", 0): 0, ("b", 0): 2}


def test_a_payload_that_is_not_a_form_reports_nothing_to_read() -> None:
    assert form_fields(sent('{"ref":"CNF-998172"}', mime_type="application/json")) is None


def test_a_payload_with_nothing_in_it_reports_nothing_to_read() -> None:
    assert form_fields(Body(mime_type=FORM, text="")) is None
    assert form_fields(None) is None


def test_a_binary_payload_is_left_as_observed() -> None:
    assert form_fields(Body(mime_type=FORM, text="cT1zaG9lcw==", encoding="base64")) is None
