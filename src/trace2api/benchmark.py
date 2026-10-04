"""Compare the demo workflow performed as a browser would with a compiled direct client.

Every other command in this project reads a capture that was recorded ahead of time.
This module runs the workflow itself, twice, against one freshly started instance of
:func:`trace2api.demo.serve_demo_app`: once the way :func:`trace2api.demo.perform_demo_workflow`
performs it, standing in for the browser, and once as the Python client
:func:`trace2api.generate.compile_python` writes from what that run recorded. Running both
against the same local instance is what keeps the comparison reproducible: nothing about
it depends on a third-party site, a network, or a clock.

The comparison that matters is correctness, not speed. The compiled client is written from
the same requests the browser flow just sent, in the same order, so a difference in how
many requests either one sends, or in what either one gets back, is a defect worth
reporting rather than a figure worth publishing. Elapsed time is measured and reported
alongside that because a reader will ask, but both flows send the same requests to the
same process on the same machine, so the number says more about this one run than about
either approach, and :func:`render_benchmark` says so rather than letting it read as a
claim.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field

from trace2api.capture import parse_har
from trace2api.demo.app import AUTH_TOKEN, DemoAppState, serve_demo_app
from trace2api.demo.fixture import DemoWorkflowInputs, perform_demo_workflow
from trace2api.generate.python import compile_python
from trace2api.generate.secrets import SecretBindings

__all__ = ["BenchmarkReport", "BenchmarkRun", "render_benchmark", "run_benchmark"]

_AUTHORIZATION_LOCATION = "request.headers.authorization"
_COOKIE_LOCATION_PREFIX = "request.headers.cookie["


class BenchmarkRun(BaseModel):
    """What one way of performing the demo workflow did."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    label: str
    requests_sent: int = Field(ge=0)
    elapsed_seconds: float = Field(ge=0)


class BenchmarkReport(BaseModel):
    """What running the demo workflow as a browser flow and as a direct client found."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    seed: int
    browser: BenchmarkRun
    direct: BenchmarkRun
    critical_path: int = Field(ge=0)
    """How many of the requests the dependency graph says cannot be sent at once."""

    responses_match: bool
    """Whether every response the direct client received matched the browser flow's."""

    @property
    def requests_match(self) -> bool:
        """Return whether the two flows sent the same number of requests."""
        return self.browser.requests_sent == self.direct.requests_sent

    def as_json(self) -> str:
        """Return the report as a JSON document."""
        return json.dumps(self.model_dump(mode="json"), indent=2)


def run_benchmark(*, seed: int = 0, inputs: DemoWorkflowInputs | None = None) -> BenchmarkReport:
    """Run the demo workflow as a browser flow and as a compiled direct client, and compare them.

    Both runs start from a freshly served instance of the demo app seeded with ``seed``, so
    the comparison needs nothing recorded in advance. The browser flow runs first and is
    what the direct client is compiled from, the same way ``record`` followed by ``compile``
    would work against a real site.
    """
    workflow_inputs = inputs if inputs is not None else DemoWorkflowInputs()
    with serve_demo_app(seed=seed) as base_url:
        started = time.perf_counter()
        document = perform_demo_workflow(base_url, workflow_inputs)
        browser_elapsed = time.perf_counter() - started

        capture = parse_har(document)
        compiled = compile_python(capture)
        state = DemoAppState(seed=seed)
        direct_responses, direct_elapsed = _run_direct_client(
            compiled.code, compiled.secrets, state
        )

    browser_entries = document["log"]["entries"]
    critical_path = (
        len(compiled.graph.longest_chain) if compiled.graph is not None else len(browser_entries)
    )
    return BenchmarkReport(
        seed=seed,
        browser=BenchmarkRun(
            label="browser flow",
            requests_sent=len(browser_entries),
            elapsed_seconds=browser_elapsed,
        ),
        direct=BenchmarkRun(
            label="direct client",
            requests_sent=len(direct_responses),
            elapsed_seconds=direct_elapsed,
        ),
        critical_path=critical_path,
        responses_match=_responses_match(browser_entries, direct_responses),
    )


def _run_direct_client(
    code: str, secrets: SecretBindings, state: DemoAppState
) -> tuple[list[httpx.Response], float]:
    """Exec the compiled module and run it, returning its responses and how long that took.

    The credentials the module reads at import time are the demo app's own fixed token and
    the CSRF token its ``seed`` hands out, which is why this needs the app's state rather
    than a secret supplied by an operator.
    """
    namespace: dict[str, Any] = {"__name__": "trace2api_demo_direct_client"}
    with _patched_environ(_demo_secret_values(secrets, state)):
        exec(code, namespace)  # noqa: S102 - running code this project just compiled
    run = namespace["run"]
    started = time.perf_counter()
    with httpx.Client() as client:
        responses = run(client)
    return responses, time.perf_counter() - started


def _demo_secret_values(secrets: SecretBindings, state: DemoAppState) -> dict[str, str]:
    """Return the demo app's own credential values, keyed by the variable each one reads.

    Neither value is a real secret: the bearer token is the app's single fixed constant,
    and the CSRF token is the one its ``seed`` was always going to hand out.
    """
    values: dict[str, str] = {}
    for binding in secrets:
        if binding.location == _AUTHORIZATION_LOCATION:
            values[binding.variable] = AUTH_TOKEN
        elif binding.location.startswith(_COOKIE_LOCATION_PREFIX):
            values[binding.variable] = state.csrf_token
    return values


@contextmanager
def _patched_environ(values: Mapping[str, str]) -> Iterator[None]:
    """Set ``values`` in the environment for the life of the context, then restore it."""
    previous = {key: os.environ.get(key) for key in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for key, old in previous.items():
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old


def _responses_match(entries: list[dict[str, Any]], responses: list[httpx.Response]) -> bool:
    """Return whether the direct client's responses match the browser flow's, in order."""
    if len(entries) != len(responses):
        return False
    return all(
        entry["response"]["status"] == response.status_code
        and entry["response"]["content"].get("text", "") == response.text
        for entry, response in zip(entries, responses, strict=True)
    )


def render_benchmark(report: BenchmarkReport) -> str:
    """Render ``report`` as the text ``trace2api benchmark`` writes.

    ``--json`` writes the report instead of this text.
    """
    lines = [
        f"Ran the demo workflow seeded {report.seed} against one running instance, "
        "as a browser flow and as a compiled direct client.",
        "",
        f"Browser flow:   {_count(report.browser.requests_sent, 'request')}, "
        f"{report.browser.elapsed_seconds:.3f}s",
        f"Direct client:  {_count(report.direct.requests_sent, 'request')}, "
        f"{report.direct.elapsed_seconds:.3f}s",
        "",
    ]
    if report.requests_match:
        lines.append(
            f"Both sent the same {_count(report.browser.requests_sent, 'request')}, "
            f"{_count(report.critical_path, 'request')} of which the dependency graph "
            "says cannot be sent at once."
        )
    else:
        lines.append(
            "The two sent a different number of requests: the compiled client does not "
            "reproduce this workflow."
        )
    lines.append(
        "Every response the direct client received matched the browser flow's, status and "
        "body alike."
        if report.responses_match
        else "At least one response the direct client received did not match the browser flow's."
    )
    lines.append(
        "Elapsed time is measured on this run, not a guaranteed figure: both flows send the "
        "same requests to the same local process, so it says more about this machine than "
        "about either approach."
    )
    return "\n".join(lines) + "\n"


def _count(number: int, noun: str) -> str:
    """Return ``number`` and ``noun``, pluralized the ordinary way."""
    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"
