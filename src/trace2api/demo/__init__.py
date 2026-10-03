"""A deterministic local app standing in for a real storefront, for development and demos.

Every analysis and generation stage in this project has so far been exercised against
hand-authored HAR archives: realistic to read, but nothing a capture can actually be
recorded from or a generated client replayed against. This package is a small HTTP app
that performs the same order workflow those archives describe, so the full loop, record,
inspect, generate, replay, verify, has something local and reproducible to run against
end to end.

``app`` serves the workflow. ``fixture`` drives it once with a given set of inputs and
returns what it saw as a HAR document, the same shape :func:`trace2api.capture.parse_har`
reads, so a fixture committed under ``examples/`` can be regenerated rather than taken on
trust.
"""

from __future__ import annotations

from trace2api.demo.app import AUTH_TOKEN, ORDERS, DemoAppState, serve_demo_app
from trace2api.demo.fixture import DemoWorkflowInputs, perform_demo_workflow

__all__ = [
    "AUTH_TOKEN",
    "ORDERS",
    "DemoAppState",
    "DemoWorkflowInputs",
    "perform_demo_workflow",
    "serve_demo_app",
]
