"""Ways of getting observed traffic into the capture models.

Each source in this package turns a recording of a workflow into a
:class:`~trace2api.models.Capture`. ``har`` reads an archive a browser already exported,
``browser`` watches a live session as it happens. Import is deliberately faithful: it
reports what the source recorded and leaves judgement about relevance to the analysis
stages. A capture that comes out of here still holds whatever credentials were observed,
so anything that persists, prints, or generates code from it passes it through
:func:`~trace2api.sanitize.redact_capture` first.

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

__all__ = [
    "DEFAULT_MAX_BODY_BYTES",
    "BrowserCaptureError",
    "BrowserRecorder",
    "HarImportError",
    "load_har",
    "parse_har",
    "record_session",
    "recording",
]
