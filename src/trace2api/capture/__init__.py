"""Ways of getting observed traffic into the capture models.

Each source in this package turns a recording of a workflow into a
:class:`~trace2api.models.Capture`. Import is deliberately faithful: it reports what the
source recorded and leaves judgement about relevance to the analysis stages. A capture
that comes out of here still holds whatever credentials were observed, so anything that
persists, prints, or generates code from it passes it through
:func:`~trace2api.sanitize.redact_capture` first.
"""

from __future__ import annotations

from trace2api.capture.har import HarImportError, load_har, parse_har

__all__ = ["HarImportError", "load_har", "parse_har"]
