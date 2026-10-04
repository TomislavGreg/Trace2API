"""Command line entry point for Trace2API."""

from __future__ import annotations

import os
import time
from enum import StrEnum
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from trace2api import __version__
from trace2api.analyze import (
    DEFAULT_KEPT,
    Relevance,
    classify_capture,
    classify_values,
    detect_pagination,
    diff_captures,
    find_graphql_operations,
    graph_capture,
    render_classification,
    render_diff,
    render_flows,
    render_graph,
    render_graphql,
    render_pagination,
    render_summary,
    render_verification,
    summarize_capture,
    trace_flows,
    verify_capture,
)
from trace2api.benchmark import render_benchmark, run_benchmark
from trace2api.capture import (
    BrowserCaptureError,
    CaptureFileError,
    HarImportError,
    SavedCapture,
    read_capture,
    record_session,
    save_capture,
)
from trace2api.demo import serve_demo_app
from trace2api.generate import (
    compile_python,
    generate_curl,
    generate_javascript,
    generate_pytest_test,
    generate_python,
)
from trace2api.inspection import inspect_capture, render_inspection
from trace2api.models import Capture
from trace2api.replay import MissingSecretError

app = typer.Typer(
    name="trace2api",
    help=(
        "Turn observed browser network workflows into clean, reusable direct HTTP "
        "client code. Analysis runs locally."
    ),
    no_args_is_help=True,
    add_completion=False,
)

BAD_CAPTURE_EXIT_CODE = 2
"""Exit code used when a capture cannot be recorded, read, or written, kept apart from an
ordinary failure."""

VERIFY_FAILED_EXIT_CODE = 1
"""Exit code used when verify ran but did not confirm the workflow, so a caller scripting
around it can tell a mismatch apart from an ordinary success without reading the output."""

DEFAULT_CAPTURE_FILE = Path("capture.json")
"""Where a recording is written when no destination is named."""


class Target(StrEnum):
    """A language a capture can be written out as. More arrive with the tickets for them."""

    CURL = "curl"
    PYTHON = "python"
    JAVASCRIPT = "javascript"


@app.callback()
def cli() -> None:
    """Group the Trace2API commands under one entry point."""


@app.command()
def version() -> None:
    """Print the installed Trace2API version."""
    typer.echo(__version__)


@app.command()
def record(
    url: Annotated[
        str,
        typer.Argument(
            metavar="URL",
            help="Address the browser opens. The workflow is performed from there.",
            show_default=False,
        ),
    ],
    output: Annotated[
        Path,
        typer.Option(
            "--output",
            "-o",
            metavar="FILE",
            help="Where to write the capture. An existing file is replaced.",
        ),
    ] = DEFAULT_CAPTURE_FILE,
    headless: Annotated[
        bool,
        typer.Option(
            "--headless",
            help=(
                "Run the browser without a window. Useful for a workflow that needs no "
                "interaction, since nothing can be clicked."
            ),
        ),
    ] = False,
    timeout: Annotated[
        float | None,
        typer.Option(
            "--timeout",
            metavar="SECONDS",
            help="Stop recording after this long. Without it, recording ends with the browser.",
            show_default=False,
        ),
    ] = None,
) -> None:
    """Record a browser session at URL and save what it requested as a local capture.

    Every http and https exchange the session performs is recorded, until the
    browser is closed. Credentials are removed before anything reaches the disk,
    and the file is written so that only its owner can read it back.

    The session runs in a throwaway browser profile, so it starts signed out and
    leaves no cookie jar, history, or cache behind. The saved capture is what
    inspect and generate read next.
    """
    if timeout is not None and timeout <= 0:
        raise typer.BadParameter("--timeout must be greater than zero.")
    try:
        recorded = record_session(url, headless=headless, timeout_s=timeout)
    except BrowserCaptureError as error:
        _fail(str(error))
    try:
        saved = save_capture(recorded, output)
    except CaptureFileError as error:
        _fail(str(error))
    typer.echo(_recording_summary(saved), nl=False)


@app.command()
def demo(
    port: Annotated[
        int,
        typer.Option("--port", help="Port to listen on. 0 picks one that is free."),
    ] = 0,
    seed: Annotated[
        int,
        typer.Option(
            "--seed",
            help=(
                "Changes the CSRF token and confirmation reference the app hands out, "
                "the way a new signed-in session would."
            ),
        ),
    ] = 0,
    timeout: Annotated[
        float | None,
        typer.Option(
            "--timeout",
            metavar="SECONDS",
            help="Stop serving after this long instead of running until interrupted.",
            show_default=False,
        ),
    ] = None,
) -> None:
    """Serve the local storefront that record and replay can be tried against.

    The app holds a small, fixed set of orders in memory and performs no network calls
    of its own, so it starts instantly and leaves nothing behind once it stops. Point a
    browser at the printed address and run ``trace2api record`` against it to capture
    the workflow, or feed a capture already recorded from it to ``verify``.
    """
    if timeout is not None and timeout <= 0:
        raise typer.BadParameter("--timeout must be greater than zero.")
    with serve_demo_app(seed=seed, port=port) as base_url:
        typer.echo(f"Serving the demo app at {base_url}")
        typer.echo(f"Try: trace2api record {base_url}/orders")
        try:
            if timeout is None:
                while True:
                    time.sleep(3600)
            else:
                time.sleep(timeout)
        except KeyboardInterrupt:
            pass


@app.command()
def benchmark(
    seed: Annotated[
        int,
        typer.Option(
            "--seed",
            help="Seeds the demo app instance both flows run against.",
        ),
    ] = 0,
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Write the report as JSON instead of text."),
    ] = False,
) -> None:
    """Run the demo workflow as a browser flow and as a compiled direct client, compared.

    Both runs start a fresh instance of the demo app and perform the same order workflow
    against it: once the way the browser flow performs it, and once as the Python client
    compiled from what that run recorded. Nothing is read from disk and nothing leaves this
    machine, so the comparison needs no capture recorded in advance.

    Request counts and responses are compared because a difference there is a defect.
    Elapsed time is reported alongside them, but both flows send the same requests to the
    same local process, so it is not a claim about either approach being faster.
    """
    report = run_benchmark(seed=seed)
    if as_json:
        typer.echo(report.as_json())
        return
    typer.echo(render_benchmark(report), nl=False)


def _recording_summary(saved: SavedCapture) -> str:
    """Return what the operator is told once a recording has been written.

    The relevance breakdown comes first because it is what says whether the recording
    caught the workflow. ``trace2api summary`` reports the same counts in full.
    """
    destination = str(saved.path)
    recorded = f"Recorded {_count(len(saved.capture), 'request')} to {destination}"
    counts = classify_capture(saved.capture).counts_by_relevance()
    breakdown = ", ".join(
        f"{counts[relevance]} {relevance.value}"
        for relevance in (*DEFAULT_KEPT, Relevance.NOISE)
        if counts[relevance]
    )
    lines = [f"{recorded}: {breakdown}." if breakdown else f"{recorded}."]
    if saved.redacted_values:
        lines.append(f"Redacted {_count(saved.redacted_values, 'value')} before writing it.")
    else:
        lines.append("No credentials were found to redact.")
    lines.append(f"Inspect it with: trace2api inspect {destination}")
    return "\n".join(lines) + "\n"


def _count(number: int, noun: str) -> str:
    """Return ``number`` and ``noun``, pluralized the ordinary way."""
    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"


@app.command()
def summary(
    capture: Annotated[
        Path,
        typer.Argument(
            metavar="CAPTURE",
            help="Path to a saved capture or a HAR 1.2 archive exported from a browser.",
            show_default=False,
        ),
    ],
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Write the summary as JSON instead of text."),
    ] = False,
) -> None:
    """Count what a capture holds rather than listing it.

    Reports the total traffic, how much of it is kept as likely application requests,
    how much was filtered as noise and by which rule, and what the kept requests
    answered with.

    Credentials are redacted before anything is counted, and no path or payload is
    printed, so a summary describes a recording without quoting it.
    """
    recorded = _load_capture(capture)
    counted = summarize_capture(recorded)
    if as_json:
        typer.echo(counted.as_json())
        return
    typer.echo(render_summary(counted), nl=False)


@app.command()
def inspect(
    capture: Annotated[
        Path,
        typer.Argument(
            metavar="CAPTURE",
            help="Path to a saved capture or a HAR 1.2 archive exported from a browser.",
            show_default=False,
        ),
    ],
    include_noise: Annotated[
        bool,
        typer.Option(
            "--all",
            "-a",
            help=(
                "List the requests filtered as noise as well. The JSON report always includes them."
            ),
        ),
    ] = False,
    explain: Annotated[
        bool,
        typer.Option("--explain", help="Add the rule behind each relevance verdict."),
    ] = False,
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Write the inspection as JSON instead of a table."),
    ] = False,
) -> None:
    """Show what a capture contains: method, host, path, status, type, and relevance.

    Credentials are redacted before anything is printed, and query strings are left out,
    so the output can be pasted into a report or an issue.
    """
    recorded = _load_capture(capture)
    inspection = inspect_capture(recorded)
    if as_json:
        typer.echo(inspection.as_json())
        return
    typer.echo(
        render_inspection(inspection, include_noise=include_noise, explain=explain), nl=False
    )


@app.command()
def diff(
    left: Annotated[
        Path,
        typer.Argument(
            metavar="LEFT",
            help="Path to the first recording of the workflow.",
            show_default=False,
        ),
    ],
    right: Annotated[
        Path,
        typer.Argument(
            metavar="RIGHT",
            help="Path to a second recording of the same workflow.",
            show_default=False,
        ),
    ],
    include_noise: Annotated[
        bool,
        typer.Option(
            "--all",
            "-a",
            help="Compare every captured request, including the ones filtered as noise.",
        ),
    ] = False,
    include_unchanged: Annotated[
        bool,
        typer.Option(
            "--unchanged",
            help="List the paired requests whose values all held still as well.",
        ),
    ] = False,
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Write the comparison as JSON instead of text."),
    ] = False,
) -> None:
    """Compare two recordings of one workflow and report which request values changed.

    Requests are paired by what identifies them rather than by position, and one that has
    no counterpart is reported as unpaired rather than compared with the nearest
    candidate.

    Both captures are redacted first, with one salt, so a credential that did not change
    between the two runs reads as unchanged and one that did is reported without either
    value being shown.
    """
    keep = tuple(Relevance) if include_noise else DEFAULT_KEPT
    compared = diff_captures(_load_capture(left), _load_capture(right), keep=keep)
    if as_json:
        typer.echo(compared.as_json())
        return
    typer.echo(render_diff(compared, include_unchanged=include_unchanged), nl=False)


@app.command()
def classify(
    left: Annotated[
        Path,
        typer.Argument(
            metavar="LEFT",
            help="Path to the first recording of the workflow.",
            show_default=False,
        ),
    ],
    right: Annotated[
        Path,
        typer.Argument(
            metavar="RIGHT",
            help="Path to a second recording of the same workflow.",
            show_default=False,
        ),
    ],
    include_noise: Annotated[
        bool,
        typer.Option(
            "--all",
            "-a",
            help="Classify every captured request, including the ones filtered as noise.",
        ),
    ] = False,
    include_constants: Annotated[
        bool,
        typer.Option(
            "--constants",
            help="List the values that held still as well. The JSON report always includes them.",
        ),
    ] = False,
    explain: Annotated[
        bool,
        typer.Option("--explain", help="Add the rule behind each verdict."),
    ] = False,
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Write the classification as JSON instead of text."),
    ] = False,
) -> None:
    """Say what each value of a workflow is, given two recordings of it.

    A value that held still is a constant. One that differs is read as an input, as
    something generated per request, or as unknown, and a value redaction removed is
    reported as a secret a client supplies from the environment.

    Every verdict names the rule behind it, and a rule that matched on a name reports the
    name rather than the value. Nothing is guessed: a value no rule recognizes is reported
    as unknown.
    """
    keep = tuple(Relevance) if include_noise else DEFAULT_KEPT
    classified = classify_values(_load_capture(left), _load_capture(right), keep=keep)
    if as_json:
        typer.echo(classified.as_json())
        return
    typer.echo(
        render_classification(classified, include_constants=include_constants, explain=explain),
        nl=False,
    )


@app.command()
def paginate(
    left: Annotated[
        Path,
        typer.Argument(
            metavar="LEFT",
            help="Path to the first recording of the workflow.",
            show_default=False,
        ),
    ],
    right: Annotated[
        Path,
        typer.Argument(
            metavar="RIGHT",
            help="Path to a second recording of the same workflow, a page apart.",
            show_default=False,
        ),
    ],
    include_noise: Annotated[
        bool,
        typer.Option(
            "--all",
            "-a",
            help="Read every captured request, including the ones filtered as noise.",
        ),
    ] = False,
    explain: Annotated[
        bool,
        typer.Option("--explain", help="Add the rule behind each pagination value."),
    ] = False,
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Write the detection as JSON instead of text."),
    ] = False,
) -> None:
    """Detect page-number, offset, and cursor pagination across two recordings of a workflow.

    A page index that increments by one, a count of results already seen, and a
    continuation value an earlier response would have handed out are recognized by name,
    the first two confirmed by shape as well, since a page index or a count of results is
    always a whole number.

    Only a value that actually moved between the two recordings is reported, the same as
    diff and classify: a parameter that held still says nothing about how the workflow
    paged this time, whatever its name.
    """
    keep = tuple(Relevance) if include_noise else DEFAULT_KEPT
    detected = detect_pagination(_load_capture(left), _load_capture(right), keep=keep)
    if as_json:
        typer.echo(detected.as_json())
        return
    typer.echo(render_pagination(detected, explain=explain), nl=False)


@app.command()
def graphql(
    capture: Annotated[
        Path,
        typer.Argument(
            metavar="CAPTURE",
            help="Path to a saved capture or a HAR 1.2 archive exported from a browser.",
            show_default=False,
        ),
    ],
    include_noise: Annotated[
        bool,
        typer.Option(
            "--all",
            "-a",
            help="Read every captured request, including the ones filtered as noise.",
        ),
    ] = False,
    explain: Annotated[
        bool,
        typer.Option("--explain", help="Add the rule behind each recognized operation."),
    ] = False,
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Write the operations as JSON instead of text."),
    ] = False,
) -> None:
    """Recognize the requests of a capture that carry a GraphQL operation.

    A request is read for a query, mutation, or subscription document, either in a JSON
    body alongside an operation name or variables, in a raw application/graphql body, or in
    a query string parameter. Only the operation's type, its name, and the names of its
    variables are reported: what it actually asks for, and any literal value its document
    carries, is never printed.
    """
    recorded = _load_capture(capture)
    keep = tuple(Relevance) if include_noise else DEFAULT_KEPT
    operations = find_graphql_operations(recorded, keep=keep)
    if as_json:
        typer.echo(operations.as_json())
        return
    typer.echo(render_graphql(operations, explain=explain), nl=False)


@app.command()
def flow(
    capture: Annotated[
        Path,
        typer.Argument(
            metavar="CAPTURE",
            help="Path to a saved capture or a HAR 1.2 archive exported from a browser.",
            show_default=False,
        ),
    ],
    include_noise: Annotated[
        bool,
        typer.Option(
            "--all",
            "-a",
            help="Read every captured request, including the ones filtered as noise.",
        ),
    ] = False,
    explain: Annotated[
        bool,
        typer.Option("--explain", help="Add the rule behind each link."),
    ] = False,
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Write the links as JSON instead of text."),
    ] = False,
) -> None:
    """Show which request values a capture took from an earlier response.

    An identifier handed out by one response and sent in the path of the next, a cursor
    read from a page of results, a token a server set and the browser sent back: these
    are what a direct client has to read at run time rather than replay as observed.

    A value some request had already sent before the response carried it is not reported,
    since the workflow did not learn it there. Credentials keep one placeholder across a
    capture, so a session handed out by one response is recognized in the next request
    and reported without the value being shown.
    """
    recorded = _load_capture(capture)
    keep = tuple(Relevance) if include_noise else DEFAULT_KEPT
    traced = trace_flows(recorded, keep=keep)
    if as_json:
        typer.echo(traced.as_json())
        return
    typer.echo(render_flows(traced, explain=explain), nl=False)


@app.command()
def graph(
    capture: Annotated[
        Path,
        typer.Argument(
            metavar="CAPTURE",
            help="Path to a saved capture or a HAR 1.2 archive exported from a browser.",
            show_default=False,
        ),
    ],
    include_noise: Annotated[
        bool,
        typer.Option(
            "--all",
            "-a",
            help="Read every captured request, including the ones filtered as noise.",
        ),
    ] = False,
    explain: Annotated[
        bool,
        typer.Option("--explain", help="Add the rule behind each link."),
    ] = False,
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Write the graph as JSON instead of text."),
    ] = False,
) -> None:
    """Show the requests of a capture as a graph of what waits for what.

    The same links flow reports, read request by request: which requests a client can send
    straight away, which ones have to wait for a response, which responses it has to read
    rather than discard, and the chain of round trips it cannot avoid.

    Requests listed under one stage need nothing from each other. A link is named by
    where its value sat rather than by what the value was, so a credential carried from
    one request to the next reads as two places with nothing shown in between.
    """
    recorded = _load_capture(capture)
    keep = tuple(Relevance) if include_noise else DEFAULT_KEPT
    graphed = graph_capture(recorded, keep=keep)
    if as_json:
        typer.echo(graphed.as_json())
        return
    typer.echo(render_graph(graphed, explain=explain), nl=False)


@app.command()
def generate(
    capture: Annotated[
        Path,
        typer.Argument(
            metavar="CAPTURE",
            help="Path to a saved capture or a HAR 1.2 archive exported from a browser.",
            show_default=False,
        ),
    ],
    target: Annotated[
        Target,
        typer.Option(
            "--target",
            "-t",
            help=(
                "Language to write the client in: a cURL script, a Python httpx module, "
                "or a JavaScript fetch module."
            ),
        ),
    ] = Target.CURL,
    include_noise: Annotated[
        bool,
        typer.Option(
            "--all",
            "-a",
            help="Write every captured request, including the ones filtered as noise.",
        ),
    ] = False,
) -> None:
    """Write the requests a capture holds as a direct client, on standard output.

    Credentials are removed from the capture before anything is written. The client
    reads each one from an environment variable listed at the top of the output, so the
    generated code can be committed while the values stay out of it.
    """
    recorded = _load_capture(capture)
    keep = tuple(Relevance) if include_noise else DEFAULT_KEPT
    if target is Target.CURL:
        code = generate_curl(recorded, keep=keep).code
    elif target is Target.PYTHON:
        code = generate_python(recorded, keep=keep).code
    else:
        code = generate_javascript(recorded, keep=keep).code
    typer.echo(code, nl=False)


@app.command("compile")
def compile_client(
    capture: Annotated[
        Path,
        typer.Argument(
            metavar="CAPTURE",
            help="Path to a saved capture or a HAR 1.2 archive exported from a browser.",
            show_default=False,
        ),
    ],
    include_noise: Annotated[
        bool,
        typer.Option(
            "--all",
            "-a",
            help="Compile every captured request, including the ones filtered as noise.",
        ),
    ] = False,
) -> None:
    """Write a capture as a Python client that reads what the workflow depends on.

    Where generate replays every value exactly as it was recorded, compile resolves the
    links the trace found: an identifier a response handed out is read back out of that
    response when the client runs, so the client works against whatever the server answers
    with rather than only against the recording.

    A link that cannot be resolved is replayed as observed and named in the module
    docstring with the reason, so what the client reproduces and what it repeats are both
    readable in the output. Credentials are supplied from the environment as ever.
    """
    recorded = _load_capture(capture)
    keep = tuple(Relevance) if include_noise else DEFAULT_KEPT
    typer.echo(compile_python(recorded, keep=keep).code, nl=False)


@app.command()
def verify(
    capture: Annotated[
        Path,
        typer.Argument(
            metavar="CAPTURE",
            help="Path to a saved capture or a HAR 1.2 archive exported from a browser.",
            show_default=False,
        ),
    ],
    include_noise: Annotated[
        bool,
        typer.Option(
            "--all",
            "-a",
            help="Replay every captured request, including the ones filtered as noise.",
        ),
    ] = False,
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Write the verification as JSON instead of text."),
    ] = False,
) -> None:
    """Replay a capture and report whether each response matches what was observed.

    Every credential a kept request needs is read from the environment, under the same
    variable names generate lists and a compiled client reads. A request needing one that
    is not set stops the command before anything is sent, rather than partway through the
    workflow.

    A response is compared by shape rather than by value: the same status, the same
    declared content type, and where the body is JSON, the same keys, nesting, and array
    lengths. A live server handing out a fresh session token or timestamp on this run is
    not reported as a mismatch.

    Exits with a nonzero status when a request could not be verified, so the command can
    be scripted around without reading its output.
    """
    recorded = _load_capture(capture)
    keep = tuple(Relevance) if include_noise else DEFAULT_KEPT
    try:
        verified = verify_capture(recorded, os.environ, keep=keep)
    except MissingSecretError as error:
        _fail(f"{error.variable} is not set: it supplies {error.location}.")
    if as_json:
        typer.echo(verified.as_json())
    else:
        typer.echo(render_verification(verified), nl=False)
    if not verified.passed:
        raise typer.Exit(code=VERIFY_FAILED_EXIT_CODE)


@app.command()
def test(
    capture: Annotated[
        Path,
        typer.Argument(
            metavar="CAPTURE",
            help="Path to a saved capture or a HAR 1.2 archive exported from a browser.",
            show_default=False,
        ),
    ],
    include_noise: Annotated[
        bool,
        typer.Option(
            "--all",
            "-a",
            help="Have the test replay every captured request, noise filtered ones included.",
        ),
    ] = False,
) -> None:
    """Write a Pytest regression test that replays CAPTURE and checks it still verifies.

    The test rereads CAPTURE at run time rather than embedding it, so rerunning the test
    later checks the capture as it stands on disk, not a copy taken when the test was
    written. It runs the same replay and structural comparison as verify, wrapped in an
    assertion a test suite or continuous integration can run on its own.

    Every credential a kept request needs is read from the environment, under the same
    variable names generate, compile, and verify already use. A credential that is not
    set skips the test instead of failing it.
    """
    recorded = _load_capture(capture)
    keep = tuple(Relevance) if include_noise else DEFAULT_KEPT
    typer.echo(generate_pytest_test(recorded, capture, keep=keep).code, nl=False)


def _load_capture(path: Path) -> Capture:
    """Read a capture from ``path``, reporting an unreadable file rather than raising.

    A saved capture and a HAR archive are both accepted, and which one it is follows from
    what the file holds rather than from what it is called.
    """
    try:
        return read_capture(path)
    except (CaptureFileError, HarImportError) as error:
        _fail(str(error))


def _fail(reason: str) -> NoReturn:
    """Report why a capture could not be obtained and stop with the capture exit code."""
    typer.echo(f"error: {reason}", err=True)
    raise typer.Exit(code=BAD_CAPTURE_EXIT_CODE)


def main() -> None:
    """Run the CLI. Used by the console script and by ``python -m trace2api``."""
    app()


if __name__ == "__main__":
    main()
