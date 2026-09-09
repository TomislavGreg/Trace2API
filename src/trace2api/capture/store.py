"""Save a recorded workflow to a local file, and read one back.

A HAR archive is what a browser exports, not what Trace2API records. A live recording
holds things a HAR entry has no field for: which exchanges never settled, the browser
that performed them, the URL the session started at, and the fact that the capture has
already been through redaction. This module stores a capture as itself instead, so
nothing observed is lost on the way to disk and nothing has to be reconstructed on the
way back.

Two properties matter more than the file layout:

* Saving redacts. :func:`save_capture` is the only way this package writes a capture out,
  and it runs :func:`~trace2api.sanitize.redact_capture` first, so an unsanitized
  recording cannot reach the filesystem through it.
* A saved capture is a private file. It is written with owner only permissions, because
  even a redacted recording describes hosts, paths, and response payloads that the
  operator was not necessarily meant to share.

:func:`read_capture` accepts either format, so a command takes a saved recording and a
HAR archive on the same argument and the operator does not have to say which is which.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError

from trace2api.capture.har import parse_har
from trace2api.models import Capture
from trace2api.sanitize import RedactionReport, redact_capture

__all__ = [
    "CAPTURE_FILE_FORMAT",
    "CAPTURE_FILE_VERSION",
    "CaptureFileError",
    "SavedCapture",
    "load_capture_file",
    "read_capture",
    "save_capture",
]

CAPTURE_FILE_FORMAT = "trace2api-capture"
"""Marker naming the file format, so a reader can tell one from a HAR archive."""

CAPTURE_FILE_VERSION = 1
"""Version of the file layout. A reader rejects a version it does not understand."""

CAPTURE_FILE_MODE = 0o600
"""Permissions a saved capture is written with: readable and writable by its owner only."""


class CaptureFileError(ValueError):
    """A capture file could not be written or read.

    Messages describe the shape of the problem rather than quoting a stored value, since
    any field in a capture can hold something that was not meant to be repeated.
    """


class SavedCapture(BaseModel):
    """What was written, and the account of what redaction took out on the way."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: Path
    capture: Capture
    """The sanitized capture, which is what the file holds."""

    report: RedactionReport

    @property
    def redacted_values(self) -> int:
        """Return how many credentials were removed before the file was written."""
        return len(self.report)


def save_capture(capture: Capture, path: str | Path, *, salt: bytes | None = None) -> SavedCapture:
    """Redact ``capture`` and write it to ``path``.

    Redaction runs here rather than at the call site so that no caller can write a
    recording to disk with its credentials still in it. A ``salt`` may be supplied to
    make the placeholders reproducible; it is never written to the file.
    """
    file_path = Path(path)
    sanitized = redact_capture(capture, salt=salt)
    document = {
        "format": CAPTURE_FILE_FORMAT,
        "format_version": CAPTURE_FILE_VERSION,
        "capture": sanitized.capture.model_dump(mode="json"),
    }
    _write_private(file_path, json.dumps(document, indent=2) + "\n")
    return SavedCapture(path=file_path, capture=sanitized.capture, report=sanitized.report)


def load_capture_file(path: str | Path) -> Capture:
    """Read a capture file written by :func:`save_capture`.

    A HAR archive is rejected here rather than read, because a caller asking for this
    format is asking about a saved recording. :func:`read_capture` takes either.
    """
    return _parse_capture_file(_read_document(Path(path)))


def read_capture(path: str | Path) -> Capture:
    """Read a saved capture or a HAR archive, whichever ``path`` holds.

    The format is decided by what the document contains rather than by the file name, so
    a capture saved under any extension still reads. A file that fails as a saved capture
    raises :class:`CaptureFileError`, and one that fails as an archive raises
    :class:`~trace2api.capture.har.HarImportError`, which names the position in the
    archive that caused it.
    """
    file_path = Path(path)
    document = _read_document(file_path)
    if isinstance(document, dict) and "log" in document:
        return parse_har(document)
    return _parse_capture_file(document)


def _read_document(path: Path) -> Any:
    """Read ``path`` as a JSON document, reporting what stopped it from being one.

    The wording stays away from either format, because reading is what decides which one
    the file holds and these failures happen before that.
    """
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as error:
        detail = error.strerror or type(error).__name__
        raise CaptureFileError(f"capture could not be read: {detail}") from None
    except UnicodeDecodeError:
        raise CaptureFileError("capture is not valid UTF-8 text") from None
    try:
        return json.loads(text)
    except json.JSONDecodeError as error:
        raise CaptureFileError(
            f"capture is not valid JSON: {error.msg} at line {error.lineno} column {error.colno}"
        ) from None


def _parse_capture_file(document: Any) -> Capture:
    """Read an already parsed document as a saved capture."""
    if not isinstance(document, dict):
        raise CaptureFileError(
            f"capture file must hold an object, found {_type_name(document)}",
        )
    marker = document.get("format")
    if marker != CAPTURE_FILE_FORMAT:
        raise CaptureFileError(
            "file is neither a Trace2API capture nor a HAR archive: expected a "
            f"{CAPTURE_FILE_FORMAT!r} format marker or a HAR log"
        )
    version = document.get("format_version")
    if version != CAPTURE_FILE_VERSION:
        raise CaptureFileError(
            f"unsupported capture file version {version!r}, expected {CAPTURE_FILE_VERSION}"
        )
    if "capture" not in document:
        raise CaptureFileError("capture file records no capture")
    try:
        return Capture.model_validate(document["capture"])
    except ValidationError as error:
        raise CaptureFileError(f"capture file is malformed: {_first_problem(error)}") from None


def _write_private(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` so that only its owner can read it back.

    The mode is passed to the open so a new file is never briefly world readable, and set
    again afterwards for the case where the file already existed, since the open mode
    applies only on creation.
    """
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, CAPTURE_FILE_MODE)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(path, CAPTURE_FILE_MODE)
    except OSError as error:
        detail = error.strerror or type(error).__name__
        raise CaptureFileError(f"capture file could not be written: {detail}") from None


def _first_problem(error: ValidationError) -> str:
    """Summarize a validation failure as its first problem and where in the file it is.

    Only the location and the message are repeated. Pydantic also carries the rejected
    input, which in a capture can be a header value or a payload.
    """
    problems = error.errors()
    if not problems:
        return "the stored capture does not match the capture models"
    first = problems[0]
    location = ".".join(str(part) for part in first.get("loc", ())) or "capture"
    return f"{location}: {first.get('msg', 'invalid value')}"


def _type_name(value: Any) -> str:
    """Name a JSON value's type the way the document format spells it."""
    names = {
        dict: "an object",
        list: "an array",
        str: "a string",
        bool: "a boolean",
        int: "a number",
        float: "a number",
    }
    if value is None:
        return "null"
    return names.get(type(value), type(value).__name__)
