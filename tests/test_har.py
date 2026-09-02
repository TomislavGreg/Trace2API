"""Tests for the HAR importer.

Every archive here is synthetic. The credential shaped values are literals written for
these tests and are not valid anywhere.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from typing import Any

import pytest

from trace2api.capture import HarImportError, load_har, parse_har
from trace2api.models import CaptureSource, ResourceType
from trace2api.sanitize import is_redacted, redact_capture

STARTED_AT = "2026-09-02T09:15:00.000Z"


def har_request(**overrides: Any) -> dict[str, Any]:
    request: dict[str, Any] = {
        "method": "GET",
        "url": "https://api.example.test/v1/orders?page=2&page=3",
        "httpVersion": "http/2.0",
        "headers": [{"name": "Accept", "value": "application/json"}],
        "queryString": [{"name": "page", "value": "2"}],
        "cookies": [],
        "headersSize": -1,
        "bodySize": 0,
    }
    request.update(overrides)
    return request


def har_response(**overrides: Any) -> dict[str, Any]:
    response: dict[str, Any] = {
        "status": 200,
        "statusText": "OK",
        "httpVersion": "http/2.0",
        "headers": [{"name": "Content-Type", "value": "application/json"}],
        "cookies": [],
        "content": {"size": 18, "mimeType": "application/json", "text": '{"orders": [1, 2]}'},
        "redirectURL": "",
        "headersSize": -1,
        "bodySize": 18,
    }
    response.update(overrides)
    return response


def har_entry(**overrides: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "startedDateTime": STARTED_AT,
        "time": 42.5,
        "request": har_request(),
        "response": har_response(),
        "cache": {},
        "timings": {
            "blocked": 1.0,
            "dns": -1,
            "connect": -1,
            "send": 0.5,
            "wait": 40.0,
            "receive": 1.0,
        },
        "_resourceType": "xhr",
    }
    entry.update(overrides)
    return entry


def har_document(*entries: dict[str, Any], **log_overrides: Any) -> dict[str, Any]:
    log: dict[str, Any] = {
        "version": "1.2",
        "creator": {"name": "WebInspector", "version": "537.36"},
        "entries": list(entries) or [har_entry()],
    }
    log.update(log_overrides)
    return {"log": log}


class TestDocument:
    def test_imports_provenance(self) -> None:
        document = har_document(
            browser={"name": "Chrome", "version": "128.0"},
            pages=[{"id": "page_1", "startedDateTime": "2026-09-02T09:14:59+00:00", "title": "x"}],
        )
        capture = parse_har(document)

        assert capture.metadata.source is CaptureSource.HAR
        assert capture.metadata.creator_name == "WebInspector"
        assert capture.metadata.creator_version == "537.36"
        assert capture.metadata.browser_name == "Chrome"
        assert capture.metadata.browser_version == "128.0"
        assert capture.metadata.created_at == datetime(2026, 9, 2, 9, 14, 59, tzinfo=UTC)

    def test_capture_starts_at_the_first_entry_when_no_page_was_recorded(self) -> None:
        capture = parse_har(har_document())
        assert capture.metadata.created_at == datetime(2026, 9, 2, 9, 15, tzinfo=UTC)

    def test_page_url_is_not_copied_into_provenance(self) -> None:
        document = har_document(
            pages=[
                {
                    "id": "page_1",
                    "startedDateTime": STARTED_AT,
                    "title": "https://app.example.test/orders?invite=not-a-real-invite",
                }
            ]
        )
        capture = parse_har(document)
        assert capture.metadata.start_url is None

    def test_empty_archive_imports_as_an_empty_capture(self) -> None:
        capture = parse_har({"log": {"version": "1.2", "entries": []}})
        assert len(capture) == 0
        assert capture.metadata.source is CaptureSource.HAR

    def test_missing_version_is_read_as_har_1_2(self) -> None:
        capture = parse_har({"log": {"entries": [har_entry()]}})
        assert len(capture) == 1

    def test_har_1_1_is_accepted(self) -> None:
        capture = parse_har(har_document(version="1.1"))
        assert len(capture) == 1


class TestEntries:
    def test_imports_the_request(self) -> None:
        request = parse_har(har_document()).entries[0].request

        assert request.method == "GET"
        assert request.host == "api.example.test"
        assert request.path == "/v1/orders"
        assert request.http_version == "http/2.0"
        assert request.headers.get("accept") == "application/json"

    def test_query_parameters_come_from_the_url(self) -> None:
        document = har_document(
            har_entry(
                request=har_request(
                    url="https://api.example.test/v1/orders?page=2&page=3",
                    queryString=[{"name": "page", "value": "9"}],
                )
            )
        )
        request = parse_har(document).entries[0].request
        assert request.query.get_all("page") == ("2", "3")

    def test_imports_the_response(self) -> None:
        entry = parse_har(har_document()).entries[0]

        assert entry.response is not None
        assert entry.response.status == 200
        assert entry.response.status_text == "OK"
        assert entry.response.redirect_url is None
        assert entry.response.body is not None
        assert entry.response.body.is_json
        assert entry.response.body.truncated is False
        assert entry.failure is None

    def test_entry_ids_number_the_slot_in_the_archive(self) -> None:
        document = har_document(
            har_entry(request=har_request(url="data:image/png;base64,AAAA")),
            har_entry(),
        )
        capture = parse_har(document)

        assert [entry.id for entry in capture] == ["e0002"]

    def test_resource_type_comes_from_the_archive(self) -> None:
        capture = parse_har(har_document(har_entry(_resourceType="XHR")))
        assert capture.entries[0].resource_type is ResourceType.XHR

    def test_missing_resource_type_is_recorded_as_other(self) -> None:
        entry = har_entry()
        del entry["_resourceType"]
        assert parse_har(har_document(entry)).entries[0].resource_type is ResourceType.OTHER

    def test_timings_read_negative_phases_as_unmeasured(self) -> None:
        timings = parse_har(har_document()).entries[0].timings

        assert timings is not None
        assert timings.total_ms == 42.5
        assert timings.wait_ms == 40.0
        assert timings.dns_ms is None
        assert timings.ssl_ms is None

    def test_timings_are_absent_when_the_archive_recorded_none(self) -> None:
        entry = har_entry(time=-1)
        del entry["timings"]
        assert parse_har(har_document(entry)).entries[0].timings is None

    def test_unknown_http_version_is_not_recorded(self) -> None:
        document = har_document(har_entry(request=har_request(httpVersion="unknown")))
        assert parse_har(document).entries[0].request.http_version is None

    def test_pseudo_headers_are_dropped(self) -> None:
        document = har_document(
            har_entry(
                request=har_request(
                    headers=[
                        {"name": ":authority", "value": "api.example.test"},
                        {"name": ":method", "value": "GET"},
                        {"name": "Accept", "value": "*/*"},
                    ]
                )
            )
        )
        headers = parse_har(document).entries[0].request.headers

        assert headers.names() == ("Accept",)

    def test_entries_that_never_hit_the_network_are_not_imported(self) -> None:
        document = har_document(
            har_entry(request=har_request(url="data:text/plain,hello")),
            har_entry(request=har_request(url="blob:https://app.example.test/1234")),
            har_entry(request=har_request(url="chrome-extension://abcd/background.js")),
        )
        assert len(parse_har(document)) == 0

    def test_source_order_is_kept(self) -> None:
        document = har_document(
            har_entry(startedDateTime="2026-09-02T09:15:02Z"),
            har_entry(startedDateTime="2026-09-02T09:15:01Z"),
        )
        capture = parse_har(document)

        assert [entry.started_at.second for entry in capture] == [2, 1]


class TestFailedExchanges:
    def test_status_zero_is_imported_as_a_failure(self) -> None:
        document = har_document(
            har_entry(response=har_response(status=0, statusText=""), _error="net::ERR_ABORTED")
        )
        entry = parse_har(document).entries[0]

        assert entry.response is None
        assert entry.failure == "net::ERR_ABORTED"
        assert entry.succeeded is False

    def test_missing_response_is_imported_as_a_failure(self) -> None:
        entry = har_entry()
        del entry["response"]
        imported = parse_har(har_document(entry)).entries[0]

        assert imported.response is None
        assert imported.failure == "the archive records no response for this request"


class TestBodies:
    def test_imports_a_sent_payload(self) -> None:
        document = har_document(
            har_entry(
                request=har_request(
                    method="POST",
                    postData={"mimeType": "application/json", "text": '{"quantity": 2}'},
                    bodySize=15,
                )
            )
        )
        body = parse_har(document).entries[0].request.body

        assert body is not None
        assert body.text == '{"quantity": 2}'
        assert body.media_type == "application/json"
        assert body.size == 15

    def test_an_unrecorded_payload_size_is_not_invented(self) -> None:
        document = har_document(
            har_entry(
                request=har_request(
                    method="POST",
                    postData={"mimeType": "application/json", "text": "{}"},
                    bodySize=-1,
                )
            )
        )
        body = parse_har(document).entries[0].request.body

        assert body is not None
        assert body.size is None

    def test_form_parameters_are_re_encoded_when_no_text_was_recorded(self) -> None:
        document = har_document(
            har_entry(
                request=har_request(
                    method="POST",
                    postData={
                        "mimeType": "application/x-www-form-urlencoded",
                        "params": [
                            {"name": "sku", "value": "ABC 1"},
                            {"name": "quantity", "value": "2"},
                            {"name": "gift"},
                        ],
                    },
                )
            )
        )
        body = parse_har(document).entries[0].request.body

        assert body is not None
        assert body.text == "sku=ABC+1&quantity=2&gift="

    def test_no_payload_means_no_body(self) -> None:
        assert parse_har(har_document()).entries[0].request.body is None

    def test_binary_payloads_keep_their_encoding(self) -> None:
        encoded = base64.b64encode(b"\x89PNG\r\n\x1a\n").decode("ascii")
        document = har_document(
            har_entry(
                response=har_response(
                    content={
                        "size": 8,
                        "mimeType": "image/png",
                        "text": encoded,
                        "encoding": "base64",
                    }
                )
            )
        )
        body = parse_har(document).entries[0].response.body

        assert body is not None
        assert body.encoding == "base64"
        assert body.as_bytes() == b"\x89PNG\r\n\x1a\n"
        assert body.truncated is False

    def test_a_payload_larger_than_what_was_stored_is_marked_truncated(self) -> None:
        document = har_document(
            har_entry(response=har_response(content={"size": 4096, "mimeType": "application/json"}))
        )
        body = parse_har(document).entries[0].response.body

        assert body is not None
        assert body.truncated is True
        assert body.is_empty

    def test_unsupported_content_encoding_is_rejected(self) -> None:
        document = har_document(
            har_entry(response=har_response(content={"size": 2, "text": "aa", "encoding": "gzip"}))
        )
        with pytest.raises(HarImportError) as failure:
            parse_har(document)

        assert failure.value.location == "log.entries[0].response.content.encoding"
        assert "expected 'base64'" in failure.value.reason


class TestCookies:
    def test_the_cookie_header_is_rebuilt_when_the_export_omitted_it(self) -> None:
        document = har_document(
            har_entry(
                request=har_request(
                    headers=[{"name": "Accept", "value": "*/*"}],
                    cookies=[
                        {"name": "session", "value": "synthetic-session-value"},
                        {"name": "locale", "value": "en"},
                    ],
                )
            )
        )
        headers = parse_har(document).entries[0].request.headers

        assert headers.get("cookie") == "session=synthetic-session-value; locale=en"

    def test_an_observed_cookie_header_is_not_duplicated(self) -> None:
        document = har_document(
            har_entry(
                request=har_request(
                    headers=[{"name": "Cookie", "value": "session=observed"}],
                    cookies=[{"name": "session", "value": "synthetic-session-value"}],
                )
            )
        )
        headers = parse_har(document).entries[0].request.headers

        assert headers.get_all("cookie") == ("session=observed",)


class TestValidationErrors:
    def test_document_must_be_an_object(self) -> None:
        with pytest.raises(HarImportError, match="HAR document must be an object, found an array"):
            parse_har([])

    def test_log_is_required(self) -> None:
        with pytest.raises(HarImportError) as failure:
            parse_har({"entries": []})

        assert failure.value.location == "log"
        assert failure.value.reason == "required field is missing"

    def test_unsupported_version_is_rejected(self) -> None:
        with pytest.raises(HarImportError) as failure:
            parse_har(har_document(version="2.0"))

        assert failure.value.location == "log.version"
        assert "unsupported HAR version '2.0'" in failure.value.reason

    def test_entries_must_be_an_array(self) -> None:
        with pytest.raises(HarImportError) as failure:
            parse_har({"log": {"version": "1.2", "entries": {}}})

        assert failure.value.location == "log.entries"
        assert failure.value.reason == "expected an array, found an object"

    def test_missing_request_field_names_its_location(self) -> None:
        entry = har_entry()
        del entry["request"]["method"]
        with pytest.raises(HarImportError) as failure:
            parse_har(har_document(entry))

        assert failure.value.location == "log.entries[0].request.method"
        assert failure.value.reason == "required field is missing"

    def test_a_timestamp_without_an_offset_is_rejected(self) -> None:
        with pytest.raises(HarImportError) as failure:
            parse_har(har_document(har_entry(startedDateTime="2026-09-02T09:15:00")))

        assert failure.value.location == "log.entries[0].startedDateTime"
        assert failure.value.reason == "timestamp must include a UTC offset"

    def test_a_malformed_timestamp_is_rejected(self) -> None:
        with pytest.raises(HarImportError) as failure:
            parse_har(har_document(har_entry(startedDateTime="yesterday")))

        assert failure.value.reason == "expected an ISO 8601 timestamp"

    def test_a_wrongly_typed_field_names_the_type_it_found(self) -> None:
        with pytest.raises(HarImportError) as failure:
            parse_har(har_document(har_entry(response=har_response(status="200"))))

        assert failure.value.location == "log.entries[0].response.status"
        assert failure.value.reason == "expected an integer, found a string"

    def test_a_rejected_model_field_is_reported_without_the_value(self) -> None:
        with pytest.raises(HarImportError) as failure:
            parse_har(har_document(har_entry(response=har_response(status=999))))

        assert failure.value.location == "log.entries[0].response"
        assert "status" in failure.value.reason

    def test_an_invalid_url_is_reported_without_its_query_string(self) -> None:
        document = har_document(
            har_entry(request=har_request(url="http:///orders?token=synthetic-token-value"))
        )
        with pytest.raises(HarImportError) as failure:
            parse_har(document)

        assert failure.value.location == "log.entries[0].request"
        assert "synthetic-token-value" not in str(failure.value)


class TestLoadHar:
    def test_reads_a_file(self, tmp_path: Any) -> None:
        path = tmp_path / "capture.har"
        path.write_text(json.dumps(har_document()), encoding="utf-8")

        capture = load_har(path)

        assert len(capture) == 1
        assert capture.hosts == ("api.example.test",)

    def test_reads_a_file_with_a_byte_order_mark(self, tmp_path: Any) -> None:
        path = tmp_path / "capture.har"
        path.write_text(json.dumps(har_document()), encoding="utf-8-sig")

        assert len(load_har(path)) == 1

    def test_a_missing_file_is_reported(self, tmp_path: Any) -> None:
        with pytest.raises(HarImportError, match="HAR file could not be read"):
            load_har(tmp_path / "absent.har")

    def test_invalid_json_is_reported_with_its_position(self, tmp_path: Any) -> None:
        path = tmp_path / "capture.har"
        path.write_text('{"log": ', encoding="utf-8")

        with pytest.raises(HarImportError, match="HAR file is not valid JSON") as failure:
            load_har(path)

        assert "line 1" in failure.value.reason


def test_an_imported_capture_can_be_redacted() -> None:
    document = har_document(
        har_entry(
            request=har_request(
                headers=[
                    {"name": "Authorization", "value": "Bearer synthetic-token-value"},
                    {"name": "Accept", "value": "application/json"},
                ],
                cookies=[{"name": "session", "value": "synthetic-session-value"}],
            )
        )
    )
    result = redact_capture(parse_har(document))
    headers = result.capture.entries[0].request.headers

    assert headers.get("authorization") is not None
    assert is_redacted(headers.get("authorization", "").removeprefix("Bearer "))
    assert "synthetic-token-value" not in json.dumps(result.capture.model_dump(mode="json"))
    assert "synthetic-session-value" not in json.dumps(result.capture.model_dump(mode="json"))
    assert headers.get("accept") == "application/json"
