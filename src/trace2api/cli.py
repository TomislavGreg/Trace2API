"""Command line entry point for Trace2API."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from trace2api import __version__
from trace2api.analyze import DEFAULT_KEPT, Relevance
from trace2api.capture import HarImportError, load_har
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
"""Exit code used when a capture cannot be read, kept apart from an ordinary failure."""


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
def inspect(
    capture: Annotated[
        Path,
        typer.Argument(
            metavar="CAPTURE",
            help="Path to a HAR 1.2 archive recorded from a browser session.",
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
def generate(
    capture: Annotated[
        Path,
        typer.Argument(
            metavar="CAPTURE",
            help="Path to a HAR 1.2 archive recorded from a browser session.",
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
    """Read a capture from ``path``, reporting an unreadable archive rather than raising."""
    try:
        return load_har(path)
    except HarImportError as error:
        typer.echo(f"error: {error}", err=True)
        raise typer.Exit(code=BAD_CAPTURE_EXIT_CODE) from None


def main() -> None:
    """Run the CLI. Used by the console script and by ``python -m trace2api``."""
    app()


if __name__ == "__main__":
    main()
