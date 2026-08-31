"""Tests for the Trace2API command line entry point."""

from __future__ import annotations

from typer.testing import CliRunner

from trace2api import __version__
from trace2api.cli import app

runner = CliRunner()


def test_help_exits_successfully() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "trace2api" in result.output


def _unwrapped(text: str) -> str:
    """Collapse the terminal wrapping Typer applies so help text can be matched."""
    return " ".join(text.split())


def test_help_describes_the_product() -> None:
    result = runner.invoke(app, ["--help"])
    output = _unwrapped(result.output)
    assert "direct HTTP client code" in output
    assert "Analysis runs locally." in output


def test_help_lists_the_version_command() -> None:
    result = runner.invoke(app, ["--help"])
    assert "version" in _unwrapped(result.output)


def test_no_arguments_shows_help() -> None:
    result = runner.invoke(app, [])
    assert result.exit_code != 0
    assert "Usage" in result.output


def test_version_command_reports_package_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.output.strip() == __version__


def test_unknown_command_fails() -> None:
    result = runner.invoke(app, ["definitely-not-a-command"])
    assert result.exit_code != 0
