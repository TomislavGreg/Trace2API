"""Ways of getting observed traffic into the capture models.

Each source in this package turns a recording of a workflow into a
:class:`~trace2api.models.Capture`. ``har`` reads an archive a browser already exported,
``browser`` watches a live session as it happens. Import is deliberately faithful: it
reports what the source recorded and leaves judgement about relevance to the analysis
stages. A capture that comes out of a source still holds whatever credentials were
observed, so anything that persists, prints, or generates code from it passes it through
:func:`~trace2api.sanitize.redact_capture` first.

``store`` is where a capture is kept between runs. :func:`~trace2api.capture.save_capture`
redacts before it writes, so a recording cannot reach the filesystem through this package
with its credentials still in it, and :func:`~trace2api.capture.read_capture` takes a
saved capture or a HAR archive so a command does not have to be told which it was given.

The browser recorder needs Playwright, which is an optional dependency. Importing this
package does not import it: only a live recording needs a browser.
"""

from __future__ import annotations

from trace2api.capture.browser import (
    DEFAULT_MAX_BODY_BYTES,
    BrowserCaptureError,
    BrowserRecorder,
    record_session,
    recording,
)
from trace2api.capture.har import HarImportError, load_har, parse_har
from trace2api.capture.store import (
    CAPTURE_FILE_FORMAT,
    CAPTURE_FILE_VERSION,
    CaptureFileError,
    SavedCapture,
    load_capture_file,
    read_capture,
    save_capture,
)

__all__ = [
    "CAPTURE_FILE_FORMAT",
    "CAPTURE_FILE_VERSION",
    "DEFAULT_MAX_BODY_BYTES",
    "BrowserCaptureError",
    "BrowserRecorder",
    "CaptureFileError",
    "HarImportError",
    "SavedCapture",
    "load_capture_file",
    "load_har",
    "parse_har",
    "read_capture",
    "record_session",
    "recording",
    "save_capture",
]
