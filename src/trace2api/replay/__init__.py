"""Sending the requests a sanitized capture holds, with secrets supplied explicitly.

Nothing outside this package should send a captured request over the network, and this
package never reads a credential from the process environment: :func:`replay_capture`
takes every secret a workflow needs as an argument, by the same variable name a generated
client would read it under, so a caller always knows exactly what a replay will send.
"""

from __future__ import annotations

from trace2api.replay.replay import (
    REPLAY_OMISSION_REASONS,
    MissingSecretError,
    ReplayedEntry,
    ReplayOutcome,
    ReplayResult,
    replay_capture,
)

__all__ = [
    "REPLAY_OMISSION_REASONS",
    "MissingSecretError",
    "ReplayOutcome",
    "ReplayResult",
    "ReplayedEntry",
    "replay_capture",
]
