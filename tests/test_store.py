"""Tests for saving a capture to a local file and reading one back."""

from __future__ import annotations

import json
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from trace2api.capture import HarImportError
from trace2api.capture.store import (
    CAPTURE_FILE_FORMAT,
    CAPTURE_FILE_VERSION,
    CaptureFileError,
    load_capture_file,
    read_capture,
    save_capture,
)
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
    Timings,
)

RECORDED_AT = datetime(2026, 9, 4, 9, 15, tzinfo=UTC)


def capture_with(*entries: Entry, **metadata: Any) -> Capture:
    """Build a browser capture holding ``entries``."""
    fields: dict[str, Any] = {
        "source": CaptureSource.BROWSER,
        "created_at": RECORDED_AT,
        **metadata,
    }
    return Capture(metadata=CaptureMetadata(**fields), entries=list(entries))


def entry(
    entry_id: str = "b0001",
    *,
    url: str = "https://shop.example.com/api/v1/orders",
    headers: list[tuple[str, str]] | None = None,
    response: Response | None = None,
    failure: str | None = None,
    resource_type: ResourceType = ResourceType.XHR,
) -> Entry:
    """Build one recorded exchange."""
    return Entry(
        id=entry_id,
        started_at=RECORDED_AT,
        request=Request(
            method="GET",
            url=url,
            headers=Headers.from_pairs(headers or []),
        ),
        response=response,
        failure=failure,
        resource_type=resource_type,
    )


def stored(path: Path) -> dict[str, Any]:
    """Return the document a saved capture file holds."""
    return json.loads(path.read_text(encoding="utf-8"))


# Saving


def test_saved_capture_reads_back_unchanged(tmp_path: Path) -> None:
    original = capture_with(
        entry(
            response=Response(
                status=200,
                status_text="OK",
                headers=Headers.from_pairs([("Content-Type", "application/json")]),
                body=Body(mime_type="application/json", text='{"orders":[]}', size=13),
            ),
        ),
        browser_name="chromium",
        browser_version="127.0.0.0",
        start_url="https://shop.example.com/orders",
    )

    saved = save_capture(original, tmp_path / "capture.json")

    assert read_capture(tmp_path / "capture.json") == saved.capture


def test_saved_capture_keeps_what_a_har_entry_cannot_hold(tmp_path: Path) -> None:
    original = capture_with(
        entry(failure="the recording ended before the response arrived"),
        entry("b0002", resource_type=ResourceType.EVENTSOURCE),
        browser_name="chromium",
        start_url="https://shop.example.com/orders",
    )

    save_capture(original, tmp_path / "capture.json")
    reread = load_capture_file(tmp_path / "capture.json")

    assert reread.entries[0].failure == "the recording ended before the response arrived"
    assert reread.entries[1].resource_type is ResourceType.EVENTSOURCE
    assert reread.metadata.browser_name == "chromium"
    assert reread.metadata.start_url == "https://shop.example.com/orders"
    assert reread.metadata.source is CaptureSource.BROWSER


def test_saving_keeps_observed_timings(tmp_path: Path) -> None:
    recorded = Entry(
        id="b0001",
        started_at=RECORDED_AT,
        request=Request(method="GET", url="https://shop.example.com/api/v1/orders"),
        response=Response(status=200),
        timings=Timings(wait_ms=12.5, receive_ms=3.0, total_ms=20.0),
    )

    save_capture(capture_with(recorded), tmp_path / "capture.json")
    reread = load_capture_file(tmp_path / "capture.json")

    assert reread.entries[0].timings is not None
    assert reread.entries[0].timings.wait_ms == 12.5
    assert reread.entries[0].timings.dns_ms is None


def test_saving_records_the_format_and_version(tmp_path: Path) -> None:
    save_capture(capture_with(entry()), tmp_path / "capture.json")

    document = stored(tmp_path / "capture.json")

    assert document["format"] == CAPTURE_FILE_FORMAT
    assert document["format_version"] == CAPTURE_FILE_VERSION


def test_saving_returns_the_path_it_wrote(tmp_path: Path) -> None:
    destination = tmp_path / "nested" / "capture.json"
    destination.parent.mkdir()

    saved = save_capture(capture_with(entry()), destination)

    assert saved.path == destination
    assert destination.exists()


def test_saving_replaces_an_existing_file(tmp_path: Path) -> None:
    destination = tmp_path / "capture.json"
    save_capture(capture_with(entry(), entry("b0002")), destination)

    save_capture(capture_with(entry()), destination)

    assert len(load_capture_file(destination)) == 1


def test_saving_reports_a_destination_that_cannot_be_written(tmp_path: Path) -> None:
    with pytest.raises(CaptureFileError, match="could not be written"):
        save_capture(capture_with(entry()), tmp_path / "missing" / "capture.json")


# Redaction


def test_saving_redacts_credentials_before_they_reach_the_disk(tmp_path: Path) -> None:
    original = capture_with(
        entry(
            headers=[
                ("Authorization", "Bearer sk-live-4f2b91d7c8"),
                ("Cookie", "session=8ac31f0e2b"),
            ],
            url="https://shop.example.com/api/v1/orders?api_key=6d0c99ab7f",
        )
    )

    saved = save_capture(original, tmp_path / "capture.json")

    text = (tmp_path / "capture.json").read_text(encoding="utf-8")
    assert "sk-live-4f2b91d7c8" not in text
    assert "8ac31f0e2b" not in text
    assert "6d0c99ab7f" not in text
    assert saved.redacted_values >= 3


def test_saving_reports_what_it_redacted_without_quoting_it(tmp_path: Path) -> None:
    original = capture_with(
        entry(headers=[("Authorization", "Bearer sk-live-4f2b91d7c8")], entry_id="b0007")
    )

    saved = save_capture(original, tmp_path / "capture.json")

    assert saved.redacted_values == 1
    redaction = saved.report.redactions[0]
    assert redaction.entry_id == "b0007"
    assert "sk-live-4f2b91d7c8" not in redaction.model_dump_json()


def test_saved_capture_is_the_redacted_one(tmp_path: Path) -> None:
    original = capture_with(entry(headers=[("Authorization", "Bearer sk-live-4f2b91d7c8")]))

    saved = save_capture(original, tmp_path / "capture.json")

    assert saved.capture == load_capture_file(tmp_path / "capture.json")
    assert "sk-live" not in saved.capture.model_dump_json()


def test_saving_twice_leaves_the_same_capture(tmp_path: Path) -> None:
    """A saved capture is already redacted, so saving it again must not change it."""
    original = capture_with(entry(headers=[("Authorization", "Bearer sk-live-4f2b91d7c8")]))
    salt = b"a fixed salt keeps the placeholders comparable"

    once = save_capture(original, tmp_path / "first.json", salt=salt)
    twice = save_capture(once.capture, tmp_path / "second.json", salt=salt)

    assert twice.capture == once.capture
    assert twice.report == once.report


def test_saving_does_not_write_the_salt(tmp_path: Path) -> None:
    salt = b"secret-salt-value"

    save_capture(
        capture_with(entry(headers=[("Authorization", "Bearer t")])), tmp_path / "c.json", salt=salt
    )

    assert "secret-salt-value" not in (tmp_path / "c.json").read_text(encoding="utf-8")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file permissions")
def test_saved_capture_is_readable_only_by_its_owner(tmp_path: Path) -> None:
    destination = tmp_path / "capture.json"

    save_capture(capture_with(entry()), destination)

    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file permissions")
def test_saving_over_a_readable_file_tightens_its_permissions(tmp_path: Path) -> None:
    destination = tmp_path / "capture.json"
    destination.write_text("{}", encoding="utf-8")
    destination.chmod(0o644)

    save_capture(capture_with(entry()), destination)

    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


# Reading


def test_read_capture_accepts_a_har_archive(tmp_path: Path) -> None:
    archive = tmp_path / "session.har"
    archive.write_text(
        json.dumps(
            {
                "log": {
                    "version": "1.2",
                    "entries": [
                        {
                            "startedDateTime": "2026-09-04T09:15:00Z",
                            "request": {
                                "method": "GET",
                                "url": "https://shop.example.com/api/v1/orders",
                                "headers": [],
                            },
                            "response": {"status": 200, "headers": []},
                        }
                    ],
                }
            }
        ),
        encoding="utf-8",
    )

    recorded = read_capture(archive)

    assert recorded.metadata.source is CaptureSource.HAR
    assert len(recorded) == 1


def test_read_capture_chooses_the_format_by_content_not_by_name(tmp_path: Path) -> None:
    misnamed = tmp_path / "session.har"

    save_capture(capture_with(entry()), misnamed)

    assert read_capture(misnamed).metadata.source is CaptureSource.BROWSER


def test_load_capture_file_rejects_a_har_archive(tmp_path: Path) -> None:
    archive = tmp_path / "session.har"
    archive.write_text(json.dumps({"log": {"version": "1.2", "entries": []}}), encoding="utf-8")

    with pytest.raises(CaptureFileError, match="neither a Trace2API capture nor a HAR archive"):
        load_capture_file(archive)


def test_reading_a_missing_file_names_the_problem(tmp_path: Path) -> None:
    with pytest.raises(CaptureFileError, match="could not be read"):
        read_capture(tmp_path / "absent.json")


def test_reading_invalid_json_names_the_position(tmp_path: Path) -> None:
    broken = tmp_path / "capture.json"
    broken.write_text("{not json", encoding="utf-8")

    with pytest.raises(CaptureFileError, match="line 1 column"):
        read_capture(broken)


def test_reading_a_non_utf8_file_says_so(tmp_path: Path) -> None:
    broken = tmp_path / "capture.json"
    broken.write_bytes(b'{"format": "\xff\xfe"}')

    with pytest.raises(CaptureFileError, match="not valid UTF-8"):
        read_capture(broken)


def test_reading_a_document_that_is_not_an_object(tmp_path: Path) -> None:
    listed = tmp_path / "capture.json"
    listed.write_text("[]", encoding="utf-8")

    with pytest.raises(CaptureFileError, match="must hold an object, found an array"):
        read_capture(listed)


def test_reading_a_file_of_neither_format(tmp_path: Path) -> None:
    other = tmp_path / "capture.json"
    other.write_text(json.dumps({"requests": []}), encoding="utf-8")

    with pytest.raises(CaptureFileError, match="neither a Trace2API capture nor a HAR archive"):
        read_capture(other)


def test_reading_an_unsupported_version(tmp_path: Path) -> None:
    future = tmp_path / "capture.json"
    future.write_text(
        json.dumps({"format": CAPTURE_FILE_FORMAT, "format_version": 99, "capture": {}}),
        encoding="utf-8",
    )

    with pytest.raises(CaptureFileError, match="unsupported capture file version 99"):
        read_capture(future)


def test_reading_a_file_with_no_capture(tmp_path: Path) -> None:
    empty = tmp_path / "capture.json"
    empty.write_text(
        json.dumps({"format": CAPTURE_FILE_FORMAT, "format_version": CAPTURE_FILE_VERSION}),
        encoding="utf-8",
    )

    with pytest.raises(CaptureFileError, match="records no capture"):
        read_capture(empty)


def test_reading_a_malformed_capture_names_the_field(tmp_path: Path) -> None:
    malformed = tmp_path / "capture.json"
    document = {
        "format": CAPTURE_FILE_FORMAT,
        "format_version": CAPTURE_FILE_VERSION,
        "capture": {
            "metadata": {"source": "browser", "created_at": "2026-09-04T09:15:00Z"},
            "entries": [
                {
                    "id": "b0001",
                    "started_at": "2026-09-04T09:15:00Z",
                    "request": {"method": "GET", "url": "ftp://shop.example.com/orders"},
                }
            ],
        },
    }
    malformed.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(CaptureFileError, match="entries.0.request.url") as raised:
        read_capture(malformed)
    assert "must use http or https" in str(raised.value)


def test_a_malformed_har_still_names_the_archive_position(tmp_path: Path) -> None:
    archive = tmp_path / "session.har"
    archive.write_text(json.dumps({"log": {"version": "2.0", "entries": []}}), encoding="utf-8")

    with pytest.raises(HarImportError, match="log.version"):
        read_capture(archive)
