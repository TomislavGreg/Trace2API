"""Write a capture out as a Pytest regression test rather than a client.

A generated client answers "how do I send this workflow again". This module answers a
narrower question that only matters afterward: "does the workflow still work". The test
it writes rereads the capture from the path it was given, replays the kept requests with
:func:`~trace2api.analyze.verify_capture`, and asserts that every response still has the
shape the browser observed. That is the same check ``trace2api verify`` runs, wrapped so
it can sit in a test suite and be rerun by hand or by continuous integration rather than
typed out one capture at a time.

The test rereads the capture rather than embedding it, so the file stays small and never
carries a copy of the recording: a change to the capture on disk is picked up the next
time the test runs without regenerating anything. What is embedded is the path, the
variable names the workflow's credentials are read under, and nothing else, so the test
reads the same way a hand written one would.

A missing credential skips the test rather than failing it, since a stopped test and a
broken workflow are not the same finding and only one of them belongs in a report.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable
from pathlib import PurePath

from pydantic import BaseModel, ConfigDict, Field

from trace2api.analyze.relevance import DEFAULT_KEPT, Relevance, classify_capture
from trace2api.generate.secrets import SecretBindings, bind_secrets
from trace2api.models import Capture
from trace2api.sanitize import redact_capture

__all__ = ["PytestModule", "generate_pytest_test"]


class PytestModule(BaseModel):
    """A Pytest regression test for a capture, and what it took to write it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str
    secrets: SecretBindings = Field(default_factory=SecretBindings)
    captured: int = Field(default=0, ge=0)
    kept: int = Field(default=0, ge=0)
    """How many of the captured requests the test replays."""


def generate_pytest_test(
    capture: Capture,
    source: str | os.PathLike[str],
    *,
    keep: Iterable[Relevance] = DEFAULT_KEPT,
    salt: bytes | None = None,
) -> PytestModule:
    """Write a Pytest module that replays ``capture`` and checks it still verifies.

    ``source`` is the path the capture was read from. It is written into the test as the
    path to reread at test time, so the test always checks the capture as it currently
    is on disk rather than a copy taken when the test was generated. ``keep`` and
    ``salt`` mean what they do for :func:`~trace2api.generate.python.generate_python`.
    """
    sanitized = redact_capture(capture, salt=salt)
    bindings = bind_secrets(sanitized.report)
    kept_set = frozenset(keep)
    classifications = classify_capture(sanitized.capture).classifications
    verdicts = {item.entry_id: item.relevance for item in classifications}
    kept = sum(1 for entry in sanitized.capture.entries if verdicts[entry.id] in kept_set)
    module = PytestModule(code="", secrets=bindings, captured=len(sanitized.capture), kept=kept)
    code = _render_module(module, sanitized.capture, source, kept_set)
    return module.model_copy(update={"code": code})


def _render_module(
    module: PytestModule,
    capture: Capture,
    source: str | os.PathLike[str],
    keep: frozenset[Relevance],
) -> str:
    """Return the whole test file: what it checks, what it needs, and the test itself."""
    lines = [_docstring(_summary(module, capture, source))]
    lines.extend(
        [
            "",
            "from __future__ import annotations",
            "",
            "import os",
            "from pathlib import Path",
            "",
            "import pytest",
            "",
            "from trace2api.analyze import Relevance, render_verification, verify_capture",
            "from trace2api.capture import read_capture",
            "",
            f"CAPTURE = Path({_string(str(source))})",
            f"KEEP = {_keep_expression(keep)}",
            *_secrets_lines(module.secrets),
            "",
            "",
            *_test_function(),
        ]
    )
    return "\n".join(lines) + "\n"


def _keep_expression(keep: frozenset[Relevance]) -> str:
    """Return ``keep`` as a Python tuple literal, in the enum's own declared order."""
    names = [relevance.name for relevance in Relevance if relevance in keep]
    joined = ", ".join(f"Relevance.{name}" for name in names)
    return f"({joined},)" if len(names) == 1 else f"({joined})"


def _secrets_lines(secrets: SecretBindings) -> list[str]:
    """Return the ``REQUIRED_SECRETS`` assignment, one variable name per line."""
    names = [binding.variable for binding in secrets]
    if not names:
        return ["REQUIRED_SECRETS: tuple[str, ...] = ()"]
    lines = ["REQUIRED_SECRETS = ("]
    lines.extend(f"    {_string(name)}," for name in names)
    lines.append(")")
    return lines


def _test_function() -> list[str]:
    """Return the test itself: skip on a missing credential, then replay and compare."""
    return [
        "def test_workflow_still_verifies() -> None:",
        '    """Replay CAPTURE and check every kept response still matches what was observed."""',
        "    missing = [name for name in REQUIRED_SECRETS if name not in os.environ]",
        "    if missing:",
        '        pytest.skip("missing credentials: " + ", ".join(missing))',
        "    capture = read_capture(CAPTURE)",
        "    verification = verify_capture(capture, os.environ, keep=KEEP)",
        "    if not verification.requests:",
        '        pytest.skip("no kept request to replay")',
        "    assert verification.passed, render_verification(verification)",
    ]


def _summary(module: PytestModule, capture: Capture, source: str | os.PathLike[str]) -> list[str]:
    """Return the module docstring: what the test checks, and what it needs to run."""
    metadata = capture.metadata
    lines = [
        f"Regression test for the workflow recorded {metadata.created_at.isoformat()} "
        f"(source: {metadata.source.value}).",
        "",
        f"Generated by `trace2api test {PurePath(source).as_posix()}`. Rereads that capture "
        f"and replays {_count(module.kept, 'kept request')} of "
        f"{_count(module.captured, 'captured request')}.",
        "",
        "Checks that every response still has the shape the browser observed: the same "
        "status, the same declared content type, and, where the body is JSON, the same "
        "keys, nesting, and array lengths. A leaf value is never compared, so a live server "
        "handing out a fresh session token or timestamp on this run is not reported as a "
        "failure.",
    ]
    if module.secrets.is_empty:
        lines.append("")
        lines.append("The capture held no credentials, so nothing has to be exported.")
        return lines
    lines.append("")
    lines.append("Credentials were removed from the capture. Export them before running:")
    width = max(len(binding.variable) for binding in module.secrets)
    lines.extend(
        f"  {binding.variable.ljust(width)}  {binding.location}" for binding in module.secrets
    )
    lines.append("")
    lines.append("A credential that is not set skips the test rather than failing it.")
    return lines


def _docstring(lines: list[str]) -> str:
    """Return ``lines`` as a module docstring, escaped the same way generated clients are."""
    body = "\n".join(lines).replace("\\", "\\\\").replace('"', '\\"')
    return f'"""{body}\n"""'


def _string(text: str) -> str:
    """Return ``text`` as a Python string literal."""
    return json.dumps(text)


def _count(number: int, noun: str) -> str:
    """Return ``number`` and ``noun``, pluralized the ordinary way."""
    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"
