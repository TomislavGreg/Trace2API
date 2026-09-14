"""Command line entry point for Trace2API."""

from __future__ import annotations

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
    diff_captures,
    render_classification,
    render_diff,
    render_summary,
    summarize_capture,
)
from trace2api.capture import (
    BrowserCaptureError,
    CaptureFileError,
    HarImportError,
    SavedCapture,
    read_capture,
    record_session,
    save_capture,
)
from trace2api.generate import generate_curl, generate_javascript, generate_python
from trace2api.inspection import inspect_capture, render_inspection
from trace2api.models import Capture

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
