"""Tests for the core traffic models."""

from __future__ import annotations

import base64
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from trace2api.models import (
    Body,
    Capture,
    CaptureMetadata,
    CaptureSource,
    Entry,
    Header,
    Headers,
    QueryParams,
    Request,
    ResourceType,
    Response,
    Timings,
)

STARTED_AT = datetime(2026, 8, 31, 12, 0, 0, tzinfo=UTC)


def make_request(url: str = "https://api.example.test/v1/orders", **overrides: object) -> Request:
    fields: dict[str, object] = {"method": "GET", "url": url}
    fields.update(overrides)
    return Request(**fields)  # type: ignore[arg-type]


def make_entry(entry_id: str = "e0001", **overrides: object) -> Entry:
    fields: dict[str, object] = {
        "id": entry_id,
        "started_at": STARTED_AT,
        "request": make_request(),
        "response": Response(status=200),
    }
    fields.update(overrides)
    return Entry(**fields)  # type: ignore[arg-type]


def make_capture(*entries: Entry) -> Capture:
    metadata = CaptureMetadata(source=CaptureSource.HAR, created_at=STARTED_AT)
    return Capture(metadata=metadata, entries=list(entries))


class TestHeaders:
    def test_lookup_ignores_case(self) -> None:
        headers = Headers.from_pairs([("Content-Type", "application/json")])
        assert headers.get("content-type") == "application/json"
        assert headers.get("CONTENT-TYPE") == "application/json"
        assert "Content-type" in headers

    def test_repeated_names_are_all_kept(self) -> None:
        headers = Headers.from_pairs([("Set-Cookie", "a=1"), ("set-cookie", "b=2")])
        assert headers.get_all("Set-Cookie") == ("a=1", "b=2")
        assert headers.get("Set-Cookie") == "a=1"
        assert len(headers) == 2

    def test_missing_header_returns_default(self) -> None:
        headers = Headers()
        assert headers.get("Authorization") is None
        assert headers.get("Authorization", "") == ""
        assert headers.get_all("Authorization") == ()
        assert "Authorization" not in headers

    def test_observed_spelling_and_order_are_preserved(self) -> None:
        headers = Headers.from_pairs([("X-Request-Id", "1"), ("accept", "*/*")])
        assert headers.names() == ("X-Request-Id", "accept")
        assert [header.name for header in headers] == ["X-Request-Id", "accept"]

    def test_headers_accept_plain_pairs_from_serialized_data(self) -> None:
        headers = Headers.model_validate([{"name": "Accept", "value": "*/*"}])
        assert headers.get("accept") == "*/*"

    def test_headers_are_frozen(self) -> None:
        header = Header(name="Accept", value="*/*")
        with pytest.raises(ValidationError):
            header.value = "text/html"  # type: ignore[misc]


class TestQueryParams:
    def test_names_are_case_sensitive(self) -> None:
        params = QueryParams.from_pairs([("Page", "2")])
        assert params.get("Page") == "2"
        assert params.get("page") is None

    def test_repeated_names_are_all_kept(self) -> None:
        params = QueryParams.from_pairs([("tag", "a"), ("tag", "b")])
        assert params.get_all("tag") == ("a", "b")


class TestBody:
    def test_media_type_and_charset_are_parsed(self) -> None:
        body = Body(mime_type="Application/JSON; charset=UTF-8", text="{}")
        assert body.media_type == "application/json"
        assert body.charset == "utf-8"
        assert body.is_json

    def test_vendor_json_media_types_are_recognized(self) -> None:
        assert Body(mime_type="application/vnd.example+json").is_json
        assert not Body(mime_type="text/html").is_json

    def test_missing_mime_type_has_no_media_type(self) -> None:
        body = Body(text="{}")
        assert body.media_type is None
        assert body.charset is None
        assert not body.is_json

    def test_text_body_encodes_as_utf8(self) -> None:
        assert Body(text="café").as_bytes() == "café".encode()

    def test_text_body_uses_the_declared_charset(self) -> None:
        body = Body(mime_type="text/plain; charset=latin-1", text="café")
        assert body.as_bytes() == b"caf\xe9"

    def test_unknown_charset_falls_back_to_utf8(self) -> None:
        body = Body(mime_type="text/plain; charset=not-a-codec", text="café")
        assert body.as_bytes() == "café".encode()

    def test_base64_body_decodes_to_the_original_bytes(self) -> None:
        payload = b"\x89PNG\r\n\x1a\n"
        body = Body(
            mime_type="image/png",
            text=base64.b64encode(payload).decode(),
            encoding="base64",
            size=len(payload),
        )
        assert body.as_bytes() == payload

    def test_invalid_base64_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="not valid base64"):
            Body(text="not base64 !!", encoding="base64")

    def test_encoding_without_text_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="no body text was captured"):
            Body(encoding="base64")

    def test_negative_size_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Body(text="{}", size=-1)

    def test_empty_body_reports_no_content(self) -> None:
        assert Body().is_empty
        assert Body(text="").is_empty
        assert Body().as_bytes() == b""
        assert not Body(text="{}").is_empty


class TestTimings:
    def test_unreported_phases_are_none(self) -> None:
        timings = Timings(wait_ms=12.5, total_ms=30.0)
        assert timings.wait_ms == 12.5
        assert timings.dns_ms is None

    def test_negative_durations_are_rejected(self) -> None:
        # HAR uses -1 for phases that do not apply; importers map that to None.
        with pytest.raises(ValidationError):
            Timings(dns_ms=-1)


class TestResourceType:
    @pytest.mark.parametrize(
        ("label", "expected"),
        [
            ("XHR", ResourceType.XHR),
            ("xmlhttprequest", ResourceType.XHR),
            ("Fetch", ResourceType.FETCH),
            ("text-track", ResourceType.MEDIA),
            ("css", ResourceType.STYLESHEET),
            ("EventSource", ResourceType.EVENTSOURCE),
        ],
    )
    def test_known_labels_are_mapped(self, label: str, expected: ResourceType) -> None:
        assert ResourceType.from_label(label) == expected

    @pytest.mark.parametrize("label", [None, "", "signed-exchange", "cspviolationreport"])
    def test_unknown_labels_become_other(self, label: str | None) -> None:
        assert ResourceType.from_label(label) is ResourceType.OTHER


class TestRequest:
    def test_method_is_normalized(self) -> None:
        assert make_request(method=" get ").method == "GET"

    @pytest.mark.parametrize("method", ["", "   ", "GET POST"])
    def test_unusable_methods_are_rejected(self, method: str) -> None:
        with pytest.raises(ValidationError, match="single token"):
            make_request(method=method)

    def test_url_parts_are_derived(self) -> None:
        request = make_request("https://API.Example.test:8443/v1/orders?page=2&tag=a&tag=b#top")
        assert request.scheme == "https"
        assert request.host == "api.example.test"
        assert request.port == 8443
        assert request.path == "/v1/orders"
        assert request.query_string == "page=2&tag=a&tag=b"
        assert request.query.get("page") == "2"
        assert request.query.get_all("tag") == ("a", "b")
        assert request.url_without_query == "https://API.Example.test:8443/v1/orders"

    def test_port_defaults_to_the_scheme_default(self) -> None:
        assert make_request("https://api.example.test/v1").port == 443
        assert make_request("http://api.example.test/v1").port == 80

    def test_root_path_is_used_when_the_url_omits_one(self) -> None:
        request = make_request("https://api.example.test")
        assert request.path == "/"
        assert request.query_string == ""
        assert len(request.query) == 0

    def test_blank_query_values_are_kept(self) -> None:
        request = make_request("https://api.example.test/v1?cursor=")
        assert request.query.get("cursor") == ""

    @pytest.mark.parametrize(
        "url",
        ["/v1/orders", "api.example.test/v1", "ftp://api.example.test/v1", "https:///v1"],
    )
    def test_non_http_urls_are_rejected(self, url: str) -> None:
        with pytest.raises(ValidationError):
            make_request(url)

    def test_url_validation_messages_do_not_echo_the_query_string(self) -> None:
        with pytest.raises(ValidationError) as caught:
            make_request("ftp://api.example.test/v1?token=super-secret-value")
        message = caught.value.errors()[0]["msg"]
        assert "api.example.test/v1" in message
        assert "super-secret-value" not in message

    def test_content_type_prefers_the_header(self) -> None:
        request = make_request(
            headers=Headers.from_pairs([("Content-Type", "application/json")]),
            body=Body(mime_type="text/plain", text="{}"),
        )
        assert request.content_type == "application/json"

    def test_content_type_falls_back_to_the_body(self) -> None:
        request = make_request(body=Body(mime_type="text/plain", text="hello"))
        assert request.content_type == "text/plain"

    def test_content_type_is_none_when_nothing_declares_one(self) -> None:
        assert make_request().content_type is None

    def test_unknown_fields_are_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Request(method="GET", url="https://api.example.test/v1", cookies=[])  # type: ignore[call-arg]


class TestResponse:
    @pytest.mark.parametrize(
        ("status", "success", "redirect", "error"),
        [(200, True, False, False), (302, False, True, False), (404, False, False, True)],
    )
    def test_status_classes(self, status: int, success: bool, redirect: bool, error: bool) -> None:
        response = Response(status=status)
        assert response.is_success is success
        assert response.is_redirect is redirect
        assert response.is_error is error

    @pytest.mark.parametrize("status", [0, 99, 600])
    def test_impossible_statuses_are_rejected(self, status: int) -> None:
        with pytest.raises(ValidationError):
            Response(status=status)


class TestEntry:
    def test_blank_ids_are_rejected(self) -> None:
        with pytest.raises(ValidationError, match="must not be blank"):
            make_entry("   ")

    def test_a_failed_request_has_no_response(self) -> None:
        entry = make_entry(response=None, failure="net::ERR_CONNECTION_REFUSED")
        assert not entry.succeeded
        assert entry.response is None

    def test_an_entry_cannot_both_succeed_and_fail(self) -> None:
        with pytest.raises(ValidationError, match="both a response and a failure"):
            make_entry(failure="net::ERR_CONNECTION_REFUSED")

    def test_resource_type_defaults_to_other(self) -> None:
        assert make_entry().resource_type is ResourceType.OTHER


class TestCapture:
    def test_entries_are_iterable_and_countable(self) -> None:
        capture = make_capture(make_entry("e0001"), make_entry("e0002"))
        assert len(capture) == 2
        assert [entry.id for entry in capture] == ["e0001", "e0002"]

    def test_entries_are_looked_up_by_id(self) -> None:
        entry = make_entry("e0002")
        capture = make_capture(make_entry("e0001"), entry)
        assert capture.entry("e0002") is entry
        assert capture.entry("missing") is None

    def test_duplicate_entry_ids_are_rejected(self) -> None:
        with pytest.raises(ValidationError, match="more than one entry"):
            make_capture(make_entry("e0001"), make_entry("e0001"))

    def test_hosts_are_distinct_and_sorted(self) -> None:
        capture = make_capture(
            make_entry("e0001", request=make_request("https://b.example.test/one")),
            make_entry("e0002", request=make_request("https://a.example.test/two")),
            make_entry("e0003", request=make_request("https://b.example.test/three")),
        )
        assert capture.hosts == ("a.example.test", "b.example.test")

    def test_an_empty_capture_is_valid(self) -> None:
        capture = make_capture()
        assert len(capture) == 0
        assert capture.hosts == ()

    def test_metadata_records_the_generating_version(self) -> None:
        from trace2api import __version__

        assert make_capture().metadata.trace2api_version == __version__

    def test_capture_round_trips_through_json(self) -> None:
        capture = make_capture(
            make_entry(
                "e0001",
                request=make_request(
                    method="POST",
                    url="https://api.example.test/v1/orders?page=2",
                    headers=Headers.from_pairs([("Content-Type", "application/json")]),
                    body=Body(mime_type="application/json", text='{"sku":"A1"}', size=12),
                ),
                response=Response(
                    status=201,
                    status_text="Created",
                    headers=Headers.from_pairs([("Content-Type", "application/json")]),
                    body=Body(mime_type="application/json", text='{"id":7}', size=8),
                ),
                timings=Timings(wait_ms=18.0, total_ms=24.0),
                resource_type=ResourceType.XHR,
            )
        )
        restored = Capture.model_validate_json(capture.model_dump_json())
        assert restored == capture
        assert restored.entries[0].request.query.get("page") == "2"
        assert restored.entries[0].resource_type is ResourceType.XHR
