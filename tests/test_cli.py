"""Tests for the Trace2API command line entry point."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from trace2api import __version__
from trace2api.cli import app

runner = CliRunner()

EXAMPLE_HAR = Path(__file__).resolve().parent.parent / "examples" / "storefront-orders.har"


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


def test_help_lists_the_commands() -> None:
    output = _unwrapped(runner.invoke(app, ["--help"]).output)
    assert "version" in output
    assert "inspect" in output
    assert "generate" in output


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


def write_har(path: Path, *entries: dict[str, Any]) -> Path:
    """Write a minimal HAR archive holding ``entries`` and return its path."""
    document = {"log": {"version": "1.2", "entries": list(entries)}}
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def har_entry(url: str, *, resource_type: str = "xhr", **request: Any) -> dict[str, Any]:
    """Build one archived exchange."""
    return {
        "startedDateTime": "2026-09-04T09:15:00.000Z",
        "_resourceType": resource_type,
        "request": {"method": "GET", "url": url, "headers": [], **request},
        "response": {
            "status": 200,
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "content": {"size": 2, "mimeType": "application/json", "text": "{}"},
        },
    }


class TestInspectCommand:
    def test_lists_the_application_requests(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "capture.har",
            har_entry("https://shop.example.com/api/v1/orders"),
            har_entry("https://cdn.example.com/static/app.css", resource_type="stylesheet"),
        )
        result = runner.invoke(app, ["inspect", str(archive)])
        assert result.exit_code == 0
        assert "/api/v1/orders" in result.stdout
        assert "/static/app.css" not in result.stdout
        assert "Showing 1 of 2 requests" in result.stdout

    def test_all_lists_the_filtered_requests_too(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "capture.har",
            har_entry("https://cdn.example.com/static/app.css", resource_type="stylesheet"),
        )
        result = runner.invoke(app, ["inspect", str(archive), "--all"])
        assert result.exit_code == 0
        assert "/static/app.css" in result.stdout

    def test_explain_names_the_rule_behind_a_verdict(self, tmp_path: Path) -> None:
        archive = write_har(tmp_path / "capture.har", har_entry("https://shop.example.com/api/x"))
        result = runner.invoke(app, ["inspect", str(archive), "--explain"])
        assert result.exit_code == 0
        assert "path names an API surface" in result.stdout

    def test_json_reports_every_entry(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "capture.har",
            har_entry("https://shop.example.com/api/v1/orders"),
            har_entry("https://cdn.example.com/static/app.css", resource_type="stylesheet"),
        )
        result = runner.invoke(app, ["inspect", str(archive), "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert [item["path"] for item in payload["entries"]] == [
            "/api/v1/orders",
            "/static/app.css",
        ]

    def test_credentials_are_redacted_before_anything_is_printed(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "capture.har",
            har_entry(
                "https://shop.example.com/api/v1/orders?access_token=super-secret",
                headers=[{"name": "Authorization", "value": "Bearer super-secret"}],
            ),
        )
        result = runner.invoke(app, ["inspect", str(archive), "--json"])
        assert result.exit_code == 0
        assert "super-secret" not in result.output

    def test_a_missing_capture_is_reported_without_a_traceback(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["inspect", str(tmp_path / "absent.har")])
        assert result.exit_code == 2
        assert result.stderr.startswith("error: HAR file could not be read")
        assert result.stdout == ""

    def test_a_malformed_capture_names_the_field_that_failed(self, tmp_path: Path) -> None:
        archive = tmp_path / "capture.har"
        archive.write_text('{"log": {"version": "9.9"}}', encoding="utf-8")
        result = runner.invoke(app, ["inspect", str(archive)])
        assert result.exit_code == 2
        assert "log.version" in result.stderr

    def test_a_capture_is_required(self) -> None:
        assert runner.invoke(app, ["inspect"]).exit_code != 0

    @pytest.mark.parametrize("arguments", [[], ["--all"], ["--explain"], ["--json"]])
    def test_the_shipped_example_inspects(self, arguments: list[str]) -> None:
        result = runner.invoke(app, ["inspect", str(EXAMPLE_HAR), *arguments])
        assert result.exit_code == 0
        assert "shop.example.com" in result.stdout


class TestGenerateCommand:
    def test_writes_a_curl_script_for_the_application_requests(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "capture.har",
            har_entry("https://shop.example.com/api/v1/orders"),
            har_entry("https://cdn.example.com/static/app.css", resource_type="stylesheet"),
        )
        result = runner.invoke(app, ["generate", str(archive)])
        assert result.exit_code == 0
        assert result.stdout.startswith("#!/bin/sh\n")
        assert "curl 'https://shop.example.com/api/v1/orders'" in result.stdout
        assert "/static/app.css" not in result.stdout

    def test_curl_is_the_target_unless_another_is_asked_for(self, tmp_path: Path) -> None:
        archive = write_har(tmp_path / "capture.har", har_entry("https://shop.example.com/api/x"))
        default = runner.invoke(app, ["generate", str(archive)])
        asked = runner.invoke(app, ["generate", str(archive), "--target", "curl"])
        assert default.stdout == asked.stdout

    def test_writes_a_python_client_when_asked_for_one(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "capture.har",
            har_entry("https://shop.example.com/api/v1/orders"),
            har_entry("https://cdn.example.com/static/app.css", resource_type="stylesheet"),
        )
        result = runner.invoke(app, ["generate", str(archive), "--target", "python"])
        assert result.exit_code == 0
        assert result.stdout.startswith('"""Direct client for a workflow recorded ')
        assert "import httpx" in result.stdout
        assert '"https://shop.example.com/api/v1/orders",' in result.stdout
        assert "/static/app.css" not in result.stdout

    def test_a_python_client_keeps_credentials_out_of_the_code(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "capture.har",
            har_entry(
                "https://shop.example.com/api/v1/orders?access_token=secret-in-the-url",
                headers=[{"name": "Authorization", "value": "Bearer secret-in-a-header"}],
            ),
        )
        result = runner.invoke(app, ["generate", str(archive), "--target", "python"])
        assert result.exit_code == 0
        assert "secret-in-the-url" not in result.output
        assert "secret-in-a-header" not in result.output
        assert "<redacted:" not in result.output
        assert 'TRACE2API_AUTHORIZATION = os.environ["TRACE2API_AUTHORIZATION"]' in result.stdout
        assert '("access_token", TRACE2API_QUERY_ACCESS_TOKEN),' in result.stdout

    def test_an_unknown_target_is_refused(self, tmp_path: Path) -> None:
        archive = write_har(tmp_path / "capture.har", har_entry("https://shop.example.com/api/x"))
        assert runner.invoke(app, ["generate", str(archive), "--target", "rust"]).exit_code != 0

    def test_all_writes_the_filtered_requests_too(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "capture.har",
            har_entry("https://cdn.example.com/static/app.css", resource_type="stylesheet"),
        )
        result = runner.invoke(app, ["generate", str(archive), "--all"])
        assert result.exit_code == 0
        assert "/static/app.css" in result.stdout

    def test_credentials_become_variables_rather_than_values(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "capture.har",
            har_entry(
                "https://shop.example.com/api/v1/orders?access_token=secret-in-the-url",
                headers=[{"name": "Authorization", "value": "Bearer secret-in-a-header"}],
            ),
        )
        result = runner.invoke(app, ["generate", str(archive)])
        assert result.exit_code == 0
        assert "secret-in-the-url" not in result.output
        assert "secret-in-a-header" not in result.output
        assert "<redacted:" not in result.output
        assert '"$TRACE2API_AUTHORIZATION"' in result.stdout
        assert '"$TRACE2API_QUERY_ACCESS_TOKEN"' in result.stdout

    def test_a_missing_capture_is_reported_without_a_traceback(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["generate", str(tmp_path / "absent.har")])
        assert result.exit_code == 2
        assert result.stderr.startswith("error: HAR file could not be read")
        assert result.stdout == ""

    def test_a_capture_is_required(self) -> None:
        assert runner.invoke(app, ["generate"]).exit_code != 0

    def test_the_shipped_example_generates(self) -> None:
        result = runner.invoke(app, ["generate", str(EXAMPLE_HAR)])
        assert result.exit_code == 0
        assert "curl 'https://shop.example.com/api/v1/orders?status=open&limit=20'" in result.stdout
