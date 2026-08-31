"""Command line entry point for Trace2API."""

from __future__ import annotations

import typer

from trace2api import __version__

app = typer.Typer(
    name="trace2api",
    help=(
        "Turn observed browser network workflows into clean, reusable direct HTTP "
        "client code. Analysis runs locally."
    ),
    no_args_is_help=True,
    add_completion=False,
)


@app.callback()
def cli() -> None:
    """Keep Trace2API a command group even while only one command exists."""


@app.command()
def version() -> None:
    """Print the installed Trace2API version."""
    typer.echo(__version__)


def main() -> None:
    """Run the CLI. Used by the console script and by ``python -m trace2api``."""
    app()


if __name__ == "__main__":
    main()
