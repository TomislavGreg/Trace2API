"""Tests for the Trace2API command line entry point."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from trace2api import __version__, cli
from trace2api.capture import BrowserCaptureError, save_capture
from trace2api.cli import app
from trace2api.models import (
    Capture,
    CaptureMetadata,
    CaptureSource,
    Entry,
    Headers,
    Request,
    ResourceType,
    Response,
)

runner = CliRunner()

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
EXAMPLE_HAR = EXAMPLES / "storefront-orders.har"
SECOND_RUN_HAR = EXAMPLES / "storefront-orders-second-run.har"


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
    assert "record" in output
    assert "summary" in output
    assert "inspect" in output
    assert "diff" in output
    assert "flow" in output
    assert "graph" in output
    assert "generate" in output
    assert "compile" in output


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


class TestSummaryCommand:
    def test_counts_what_the_capture_holds(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "capture.har",
            har_entry("https://shop.example.com/api/v1/orders"),
            har_entry("https://cdn.example.com/static/app.css", resource_type="stylesheet"),
        )
        result = runner.invoke(app, ["summary", str(archive)])
        assert result.exit_code == 0
        assert "Requests: 2 total, 1 kept, 1 filtered as noise." in result.stdout
        assert "Kept: 1 application." in result.stdout
        assert "Noise: 1 asset-resource-type." in result.stdout
        assert "Kept content types: 1 application/json." in result.stdout

    def test_no_path_is_printed(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "capture.har", har_entry("https://shop.example.com/api/v1/orders")
        )
        result = runner.invoke(app, ["summary", str(archive)])
        assert result.exit_code == 0
        assert "/api/v1/orders" not in result.stdout
        assert "shop.example.com" in result.stdout

    def test_json_reports_the_same_counts(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "capture.har",
            har_entry("https://shop.example.com/api/v1/orders"),
            har_entry("https://cdn.example.com/static/app.css", resource_type="stylesheet"),
        )
        result = runner.invoke(app, ["summary", str(archive), "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["total_requests"] == 2
        assert payload["counts_by_relevance"] == {"application": 1, "noise": 1, "unknown": 0}
        assert payload["noise_by_rule"] == {"asset-resource-type": 1}
        assert payload["kept_content_types"] == [{"media_type": "application/json", "count": 1}]

    def test_credentials_are_redacted_before_anything_is_counted(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "capture.har",
            har_entry(
                "https://shop.example.com/api/v1/orders?access_token=super-secret",
                headers=[{"name": "Authorization", "value": "Bearer super-secret"}],
            ),
        )
        result = runner.invoke(app, ["summary", str(archive), "--json"])
        assert result.exit_code == 0
        assert "super-secret" not in result.output
        assert json.loads(result.stdout)["redacted_values"] == 2

    def test_a_missing_capture_is_reported_without_a_traceback(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["summary", str(tmp_path / "absent.har")])
        assert result.exit_code == 2
        assert result.stderr.startswith("error: capture could not be read")
        assert result.stdout == ""

    def test_a_capture_is_required(self) -> None:
        assert runner.invoke(app, ["summary"]).exit_code != 0

    @pytest.mark.parametrize("arguments", [[], ["--json"]])
    def test_the_shipped_example_summarizes(self, arguments: list[str]) -> None:
        result = runner.invoke(app, ["summary", str(EXAMPLE_HAR), *arguments])
        assert result.exit_code == 0
        assert "shop.example.com" in result.stdout


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
        assert result.stderr.startswith("error: capture could not be read")
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


class TestDiffCommand:
    def test_reports_which_request_values_changed(self, tmp_path: Path) -> None:
        first = write_har(
            tmp_path / "first.har",
            har_entry("https://shop.example.com/api/v1/orders?status=open"),
        )
        second = write_har(
            tmp_path / "second.har",
            har_entry("https://shop.example.com/api/v1/orders?status=shipped"),
        )
        result = runner.invoke(app, ["diff", str(first), str(second)])
        assert result.exit_code == 0
        assert "1 -> 1  GET shop.example.com/api/v1/orders" in result.stdout
        assert 'request.query[status]  changed  "open" -> "shipped"' in result.stdout
        assert "Paired 1 request: 1 changed, 0 unchanged." in result.stdout

    def test_an_unchanged_request_is_counted_rather_than_listed(self, tmp_path: Path) -> None:
        archived = har_entry("https://shop.example.com/api/v1/orders")
        first = write_har(tmp_path / "first.har", archived)
        second = write_har(tmp_path / "second.har", archived)
        result = runner.invoke(app, ["diff", str(first), str(second)])
        assert result.exit_code == 0
        assert "Paired 1 request: 0 changed, 1 unchanged." in result.stdout
        assert "/api/v1/orders" not in result.stdout

    def test_unchanged_requests_can_be_listed(self, tmp_path: Path) -> None:
        archived = har_entry("https://shop.example.com/api/v1/orders")
        first = write_har(tmp_path / "first.har", archived)
        second = write_har(tmp_path / "second.har", archived)
        result = runner.invoke(app, ["diff", str(first), str(second), "--unchanged"])
        assert result.exit_code == 0
        assert "no request value changed" in result.stdout

    def test_noise_is_compared_only_when_asked(self, tmp_path: Path) -> None:
        first = write_har(
            tmp_path / "first.har",
            har_entry("https://cdn.example.com/img/logo.png", resource_type="image"),
        )
        second = write_har(
            tmp_path / "second.har",
            har_entry("https://cdn.example.com/img/logo.png", resource_type="image"),
        )
        without = runner.invoke(app, ["diff", str(first), str(second)])
        assert "Comparing 0 kept requests on the left with 0 on the right." in without.stdout
        with_noise = runner.invoke(app, ["diff", str(first), str(second), "--all"])
        assert "Comparing 1 kept request on the left with 1 on the right." in with_noise.stdout

    def test_json_reports_the_same_comparison(self, tmp_path: Path) -> None:
        first = write_har(
            tmp_path / "first.har",
            har_entry("https://shop.example.com/api/v1/orders?status=open"),
        )
        second = write_har(
            tmp_path / "second.har",
            har_entry("https://shop.example.com/api/v1/orders?status=shipped"),
        )
        result = runner.invoke(app, ["diff", str(first), str(second), "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["pairs"][0]["changes"] == [
            {
                "location": "request.query[status]",
                "kind": "changed",
                "left": "open",
                "right": "shipped",
            }
        ]

    def test_credentials_are_redacted_before_anything_is_compared(self, tmp_path: Path) -> None:
        first = write_har(
            tmp_path / "first.har",
            har_entry(
                "https://shop.example.com/api/v1/orders",
                headers=[{"name": "Authorization", "value": "Bearer super-secret"}],
            ),
        )
        second = write_har(
            tmp_path / "second.har",
            har_entry(
                "https://shop.example.com/api/v1/orders",
                headers=[{"name": "Authorization", "value": "Bearer other-secret"}],
            ),
        )
        result = runner.invoke(app, ["diff", str(first), str(second)])
        assert result.exit_code == 0
        assert "secret" not in result.output
        assert '"Bearer (redacted)" -> "Bearer (redacted)"' in result.stdout

    def test_a_missing_capture_is_reported_without_a_traceback(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "first.har", har_entry("https://shop.example.com/api/v1/orders")
        )
        result = runner.invoke(app, ["diff", str(archive), str(tmp_path / "absent.har")])
        assert result.exit_code == 2
        assert result.stderr.startswith("error: capture could not be read")

    def test_two_captures_are_required(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "first.har", har_entry("https://shop.example.com/api/v1/orders")
        )
        assert runner.invoke(app, ["diff", str(archive)]).exit_code != 0

    def test_the_shipped_examples_compare(self) -> None:
        result = runner.invoke(app, ["diff", str(EXAMPLE_HAR), str(SECOND_RUN_HAR)])
        assert result.exit_code == 0
        assert "Paired 4 requests: 3 changed, 1 unchanged." in result.stdout


class TestClassifyCommand:
    def test_says_what_each_value_that_moved_is(self, tmp_path: Path) -> None:
        first = write_har(
            tmp_path / "first.har",
            har_entry("https://shop.example.com/api/v1/orders?status=open&limit=20"),
        )
        second = write_har(
            tmp_path / "second.har",
            har_entry("https://shop.example.com/api/v1/orders?status=shipped&limit=20"),
        )
        result = runner.invoke(app, ["classify", str(first), str(second)])
        assert result.exit_code == 0
        assert "1 -> 1  GET shop.example.com/api/v1/orders" in result.stdout
        assert 'request.query[status]  input  "open" -> "shipped"' in result.stdout
        assert "Classified 5 values: 1 input, 4 constants." in result.stdout

    def test_a_constant_is_counted_rather_than_listed(self, tmp_path: Path) -> None:
        archived = har_entry("https://shop.example.com/api/v1/orders?status=open")
        first = write_har(tmp_path / "first.har", archived)
        second = write_har(tmp_path / "second.har", archived)
        result = runner.invoke(app, ["classify", str(first), str(second)])
        assert result.exit_code == 0
        assert "request.query[status]" not in result.stdout
        assert "Pass --constants to list them." in result.stdout

    def test_constants_can_be_listed(self, tmp_path: Path) -> None:
        archived = har_entry("https://shop.example.com/api/v1/orders?status=open")
        first = write_har(tmp_path / "first.har", archived)
        second = write_har(tmp_path / "second.har", archived)
        result = runner.invoke(app, ["classify", str(first), str(second), "--constants"])
        assert result.exit_code == 0
        assert 'request.query[status]  constant  "open"' in result.stdout

    def test_explain_names_the_rule_behind_a_verdict(self, tmp_path: Path) -> None:
        first = write_har(
            tmp_path / "first.har",
            har_entry("https://shop.example.com/api/v1/orders?ts=1757066100"),
        )
        second = write_har(
            tmp_path / "second.har",
            har_entry("https://shop.example.com/api/v1/orders?ts=1757069700"),
        )
        result = runner.invoke(app, ["classify", str(first), str(second), "--explain"])
        assert result.exit_code == 0
        assert "generated" in result.stdout
        assert "named after a value that is minted per request: ts" in result.stdout

    def test_noise_is_classified_only_when_asked(self, tmp_path: Path) -> None:
        archived = har_entry("https://cdn.example.com/img/logo.png", resource_type="image")
        first = write_har(tmp_path / "first.har", archived)
        second = write_har(tmp_path / "second.har", archived)
        without = runner.invoke(app, ["classify", str(first), str(second)])
        assert "Classifying the values of 0 paired requests." in without.stdout
        with_noise = runner.invoke(app, ["classify", str(first), str(second), "--all"])
        assert "Classifying the values of 1 paired request." in with_noise.stdout

    def test_json_reports_the_same_verdicts(self, tmp_path: Path) -> None:
        first = write_har(
            tmp_path / "first.har",
            har_entry("https://shop.example.com/api/v1/orders?status=open"),
        )
        second = write_har(
            tmp_path / "second.har",
            har_entry("https://shop.example.com/api/v1/orders?status=shipped"),
        )
        result = runner.invoke(app, ["classify", str(first), str(second), "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        values = {item["location"]: item for item in payload["requests"][0]["values"]}
        assert values["request.query[status]"]["role"] == "input"
        assert values["request.path[1]"]["role"] == "constant"

    def test_credentials_are_redacted_before_anything_is_classified(self, tmp_path: Path) -> None:
        authorized = har_entry(
            "https://shop.example.com/api/v1/orders",
            headers=[{"name": "Authorization", "value": "Bearer s3cr3t-token-value"}],
        )
        first = write_har(tmp_path / "first.har", authorized)
        second = write_har(tmp_path / "second.har", authorized)
        result = runner.invoke(app, ["classify", str(first), str(second), "--constants"])
        assert result.exit_code == 0
        assert "s3cr3t-token-value" not in result.stdout
        assert "request.headers.authorization  secret" in result.stdout
        assert "Redacted 2 values before classifying" in result.stdout

    def test_a_missing_capture_is_reported_without_a_traceback(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "first.har", har_entry("https://shop.example.com/api/v1/orders")
        )
        result = runner.invoke(app, ["classify", str(archive), str(tmp_path / "absent.har")])
        assert result.exit_code == 2
        assert result.stderr.startswith("error: capture could not be read")

    def test_two_captures_are_required(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "first.har", har_entry("https://shop.example.com/api/v1/orders")
        )
        assert runner.invoke(app, ["classify", str(archive)]).exit_code != 0

    def test_the_shipped_examples_classify(self) -> None:
        result = runner.invoke(app, ["classify", str(EXAMPLE_HAR), str(SECOND_RUN_HAR)])
        assert result.exit_code == 0
        assert "Classified 30 values: 7 inputs, 5 secrets, 18 constants." in result.stdout


def har_exchange(url: str, *, returns: str, **request: Any) -> dict[str, Any]:
    """Build one archived exchange whose response hands out ``returns``."""
    archived = har_entry(url, **request)
    archived["response"]["content"] = {
        "size": len(returns),
        "mimeType": "application/json",
        "text": returns,
    }
    return archived


class TestFlowCommand:
    def test_reports_the_values_taken_from_an_earlier_response(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "capture.har",
            har_exchange("https://shop.example.com/api/v1/orders", returns='{"id":"order-55120"}'),
            har_entry("https://shop.example.com/api/v1/orders/order-55120"),
        )
        result = runner.invoke(app, ["flow", str(archive)])
        assert result.exit_code == 0
        assert "2  GET shop.example.com/api/v1/orders/order-55120" in result.stdout
        assert 'request.path[4]  <- 1  response.body.id  "order-55120"' in result.stdout
        assert "1 value flows from a response into a later request." in result.stdout

    def test_a_capture_that_carries_nothing_forward_says_so(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "capture.har", har_entry("https://shop.example.com/api/v1/orders")
        )
        result = runner.invoke(app, ["flow", str(archive)])
        assert result.exit_code == 0
        assert "No value a response carried was sent by a later request." in result.stdout

    def test_explain_names_the_rule_behind_a_link(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "capture.har",
            har_exchange("https://shop.example.com/api/v1/orders", returns='{"id":"order-55120"}'),
            har_entry("https://shop.example.com/api/v1/orders/order-55120"),
        )
        result = runner.invoke(app, ["flow", str(archive), "--explain"])
        assert "the request sent exactly what the earlier response carried" in result.stdout

    def test_noise_is_read_only_when_asked(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "capture.har",
            har_exchange(
                "https://cdn.example.com/static/app.json",
                returns='{"build":"order-55120"}',
                resource_type="stylesheet",
            ),
            har_entry("https://shop.example.com/api/v1/orders/order-55120"),
        )
        without = runner.invoke(app, ["flow", str(archive)])
        assert "No value a response carried was sent by a later request." in without.stdout
        with_noise = runner.invoke(app, ["flow", str(archive), "--all"])
        assert "1 value flows from a response into a later request." in with_noise.stdout

    def test_json_reports_both_ends_of_a_link(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "capture.har",
            har_exchange("https://shop.example.com/api/v1/orders", returns='{"id":"order-55120"}'),
            har_entry("https://shop.example.com/api/v1/orders/order-55120"),
        )
        result = runner.invoke(app, ["flow", str(archive), "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["flows"][0]["source"]["location"] == "response.body.id"
        assert payload["flows"][0]["target"]["location"] == "request.path[4]"
        assert payload["flows"][0]["rule"] == "whole-value"

    def test_a_credential_carried_forward_is_reported_without_its_value(
        self, tmp_path: Path
    ) -> None:
        archived = har_exchange("https://shop.example.com/api/v1/session", returns="{}")
        archived["response"]["headers"].append(
            {"name": "Set-Cookie", "value": "session=super-secret-session-value; HttpOnly"}
        )
        archive = write_har(
            tmp_path / "capture.har",
            archived,
            har_entry(
                "https://shop.example.com/api/v1/orders",
                headers=[{"name": "Cookie", "value": "session=super-secret-session-value"}],
            ),
        )
        result = runner.invoke(app, ["flow", str(archive)])
        assert result.exit_code == 0
        assert "super-secret" not in result.output
        assert "request.headers.cookie  <- 1  response.headers.set-cookie[session]" in result.stdout
        assert "(redacted)" in result.stdout

    def test_a_missing_capture_is_reported_without_a_traceback(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["flow", str(tmp_path / "absent.har")])
        assert result.exit_code == 2
        assert result.stderr.startswith("error: capture could not be read")

    def test_a_capture_is_required(self) -> None:
        assert runner.invoke(app, ["flow"]).exit_code != 0

    def test_the_shipped_example_traces(self) -> None:
        result = runner.invoke(app, ["flow", str(EXAMPLE_HAR)])
        assert result.exit_code == 0
        assert "3 values flow from a response into a later request." in result.stdout
        assert "2 of 4 kept requests depend on a response above them." in result.stdout


class TestGraphCommand:
    def test_lists_the_requests_by_the_stage_they_belong_to(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "capture.har",
            har_exchange("https://shop.example.com/api/v1/orders", returns='{"id":"order-55120"}'),
            har_entry("https://shop.example.com/api/v1/orders/order-55120"),
        )
        result = runner.invoke(app, ["graph", str(archive)])
        assert result.exit_code == 0
        assert "Stage 1: 1 request that needs nothing earlier" in result.stdout
        assert "Stage 2: 1 request that waits for stage 1" in result.stdout
        assert "needs 1  response.body.id  ->  request.path[4]" in result.stdout

    def test_a_workflow_with_no_links_is_one_stage(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "capture.har",
            har_entry("https://shop.example.com/api/v1/orders"),
            har_entry("https://shop.example.com/api/v1/settings"),
        )
        result = runner.invoke(app, ["graph", str(archive)])
        assert result.exit_code == 0
        assert "Stage 1: 2 requests that need nothing earlier" in result.stdout
        assert "0 waiting for an earlier response, 2 able to be sent first." in result.stdout
        assert "Longest chain" not in result.stdout

    def test_explain_names_the_rule_behind_a_link(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "capture.har",
            har_exchange("https://shop.example.com/api/v1/orders", returns='{"id":"order-55120"}'),
            har_entry("https://shop.example.com/api/v1/orders/order-55120"),
        )
        result = runner.invoke(app, ["graph", str(archive), "--explain"])
        assert "the request sent exactly what the earlier response carried" in result.stdout

    def test_noise_is_read_only_when_asked(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "capture.har",
            har_exchange(
                "https://cdn.example.com/static/app.json",
                returns='{"build":"order-55120"}',
                resource_type="stylesheet",
            ),
            har_entry("https://shop.example.com/api/v1/orders/order-55120"),
        )
        without = runner.invoke(app, ["graph", str(archive)])
        assert "1 kept request: 0 waiting for an earlier response" in without.stdout
        with_noise = runner.invoke(app, ["graph", str(archive), "--all"])
        assert "2 kept requests: 1 waiting for an earlier response" in with_noise.stdout

    def test_json_reports_the_nodes_and_the_edges(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "capture.har",
            har_exchange("https://shop.example.com/api/v1/orders", returns='{"id":"order-55120"}'),
            har_entry("https://shop.example.com/api/v1/orders/order-55120"),
        )
        result = runner.invoke(app, ["graph", str(archive), "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert [node["stage"] for node in payload["nodes"]] == [1, 2]
        assert payload["nodes"][1]["depends_on"] == [1]
        assert payload["dependencies"][0]["links"][0]["target_location"] == "request.path[4]"

    def test_a_credential_carried_forward_is_reported_as_two_places(self, tmp_path: Path) -> None:
        archived = har_exchange("https://shop.example.com/api/v1/session", returns="{}")
        archived["response"]["headers"].append(
            {"name": "Set-Cookie", "value": "session=super-secret-session-value; HttpOnly"}
        )
        archive = write_har(
            tmp_path / "capture.har",
            archived,
            har_entry(
                "https://shop.example.com/api/v1/orders",
                headers=[{"name": "Cookie", "value": "session=super-secret-session-value"}],
            ),
        )
        result = runner.invoke(app, ["graph", str(archive)])
        assert result.exit_code == 0
        assert "super-secret" not in result.output
        assert "(redacted)" not in result.output
        assert (
            "needs 1  response.headers.set-cookie[session]  ->  request.headers.cookie"
            in result.stdout
        )

    def test_a_missing_capture_is_reported_without_a_traceback(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["graph", str(tmp_path / "absent.har")])
        assert result.exit_code == 2
        assert result.stderr.startswith("error: capture could not be read")

    def test_a_capture_is_required(self) -> None:
        assert runner.invoke(app, ["graph"]).exit_code != 0

    def test_the_shipped_example_graphs(self) -> None:
        result = runner.invoke(app, ["graph", str(EXAMPLE_HAR)])
        assert result.exit_code == 0
        assert "4 kept requests: 2 waiting for an earlier response, 2 able to be sent first."
        assert "2 responses must be read by the client: 4, 6." in result.stdout
        assert "Longest chain: 4 -> 6 -> 7, 3 requests that cannot be sent at once." in (
            result.stdout
        )


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

    def test_writes_a_javascript_client_when_asked_for_one(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "capture.har",
            har_entry("https://shop.example.com/api/v1/orders"),
            har_entry("https://cdn.example.com/static/app.css", resource_type="stylesheet"),
        )
        result = runner.invoke(app, ["generate", str(archive), "--target", "javascript"])
        assert result.exit_code == 0
        assert result.stdout.startswith("// Direct client for a workflow recorded ")
        assert 'await fetch("https://shop.example.com/api/v1/orders", {' in result.stdout
        assert "/static/app.css" not in result.stdout

    def test_a_javascript_client_keeps_credentials_out_of_the_code(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "capture.har",
            har_entry(
                "https://shop.example.com/api/v1/orders?access_token=secret-in-the-url",
                headers=[{"name": "Authorization", "value": "Bearer secret-in-a-header"}],
            ),
        )
        result = runner.invoke(app, ["generate", str(archive), "--target", "javascript"])
        assert result.exit_code == 0
        assert "secret-in-the-url" not in result.output
        assert "secret-in-a-header" not in result.output
        assert "<redacted:" not in result.output
        assert 'const TRACE2API_AUTHORIZATION = requireEnv("TRACE2API_AUTHORIZATION");' in (
            result.stdout
        )
        assert '["access_token", TRACE2API_QUERY_ACCESS_TOKEN],' in result.stdout

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
        assert result.stderr.startswith("error: capture could not be read")
        assert result.stdout == ""

    def test_a_capture_is_required(self) -> None:
        assert runner.invoke(app, ["generate"]).exit_code != 0

    def test_the_shipped_example_generates(self) -> None:
        result = runner.invoke(app, ["generate", str(EXAMPLE_HAR)])
        assert result.exit_code == 0
        assert "curl 'https://shop.example.com/api/v1/orders?status=open&limit=20'" in result.stdout


class TestCompileCommand:
    def test_reads_a_dependent_value_out_of_the_response_that_handed_it_out(self) -> None:
        result = runner.invoke(app, ["compile", str(EXAMPLE_HAR)])
        assert result.exit_code == 0
        assert result.stdout.startswith('"""Direct client for a workflow recorded ')
        assert 'orders_id = response_4.json()["orders"][0]["id"]' in result.stdout
        assert '"https://shop.example.com/api/v1/orders/" + str(orders_id)' in result.stdout

    def test_the_docstring_accounts_for_the_workflow(self) -> None:
        result = runner.invoke(app, ["compile", str(EXAMPLE_HAR)])
        assert "The workflow runs in 3 stages" in result.stdout
        assert "2 values read from a response as the client runs" in result.stdout

    def test_generate_replays_what_compile_reads(self) -> None:
        replayed = runner.invoke(app, ["generate", str(EXAMPLE_HAR), "--target", "python"])
        compiled = runner.invoke(app, ["compile", str(EXAMPLE_HAR)])
        assert '"https://shop.example.com/api/v1/orders/4711",' in replayed.stdout
        assert '"https://shop.example.com/api/v1/orders/4711",' not in compiled.stdout

    def test_noise_is_left_out_unless_it_is_asked_for(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "capture.har",
            har_entry("https://shop.example.com/api/v1/orders"),
            har_entry("https://cdn.example.com/static/app.css", resource_type="stylesheet"),
        )
        without = runner.invoke(app, ["compile", str(archive)])
        with_noise = runner.invoke(app, ["compile", str(archive), "--all"])
        assert "/static/app.css" not in without.stdout
        assert "/static/app.css" in with_noise.stdout

    def test_credentials_stay_out_of_the_code(self, tmp_path: Path) -> None:
        archive = write_har(
            tmp_path / "capture.har",
            har_entry(
                "https://shop.example.com/api/v1/orders",
                headers=[{"name": "Authorization", "value": "Bearer secret-in-a-header"}],
            ),
        )
        result = runner.invoke(app, ["compile", str(archive)])
        assert result.exit_code == 0
        assert "secret-in-a-header" not in result.output
        assert "<redacted:" not in result.output
        assert 'TRACE2API_AUTHORIZATION = os.environ["TRACE2API_AUTHORIZATION"]' in result.stdout

    def test_a_missing_capture_is_reported_without_a_traceback(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["compile", str(tmp_path / "absent.har")])
        assert result.exit_code == 2
        assert result.stderr.startswith("error: capture could not be read")
        assert result.stdout == ""

    def test_a_capture_is_required(self) -> None:
        assert runner.invoke(app, ["compile"]).exit_code != 0


def saved_capture(path: Path, *entries: Entry, **metadata: Any) -> Path:
    """Write a saved capture holding ``entries`` and return its path."""
    fields: dict[str, Any] = {
        "source": CaptureSource.BROWSER,
        "created_at": datetime(2026, 9, 4, 9, 15, tzinfo=UTC),
        **metadata,
    }
    capture = Capture(metadata=CaptureMetadata(**fields), entries=list(entries))
    return save_capture(capture, path).path


def recorded_entry(
    entry_id: str,
    url: str,
    *,
    resource_type: ResourceType = ResourceType.XHR,
    headers: list[tuple[str, str]] | None = None,
) -> Entry:
    """Build one exchange as the browser recorder would have recorded it."""
    return Entry(
        id=entry_id,
        started_at=datetime(2026, 9, 4, 9, 15, tzinfo=UTC),
        request=Request(method="GET", url=url, headers=Headers.from_pairs(headers or [])),
        response=Response(status=200),
        resource_type=resource_type,
    )


class TestRecordCommand:
    def test_writes_a_capture_the_other_commands_can_read(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        destination = tmp_path / "session.json"
        monkeypatch.setattr(
            cli,
            "record_session",
            lambda url, **kwargs: Capture(
                metadata=CaptureMetadata(
                    source=CaptureSource.BROWSER,
                    created_at=datetime(2026, 9, 4, 9, 15, tzinfo=UTC),
                    start_url=url,
                ),
                entries=[recorded_entry("b0001", "https://shop.example.com/api/v1/orders")],
            ),
        )

        result = runner.invoke(
            app, ["record", "https://shop.example.com/orders", "-o", str(destination)]
        )

        assert result.exit_code == 0
        assert destination.exists()
        inspected = runner.invoke(app, ["inspect", str(destination)])
        assert inspected.exit_code == 0
        assert "/api/v1/orders" in inspected.stdout

    def test_reports_what_was_recorded_and_where_it_went(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        destination = tmp_path / "session.json"
        monkeypatch.setattr(
            cli,
            "record_session",
            lambda url, **kwargs: Capture(
                metadata=CaptureMetadata(
                    source=CaptureSource.BROWSER,
                    created_at=datetime(2026, 9, 4, 9, 15, tzinfo=UTC),
                ),
                entries=[
                    recorded_entry("b0001", "https://shop.example.com/api/v1/orders"),
                    recorded_entry("b0002", "https://shop.example.com/api/v1/orders/4711"),
                ],
            ),
        )

        result = runner.invoke(
            app, ["record", "https://shop.example.com/orders", "-o", str(destination)]
        )

        assert result.exit_code == 0
        assert f"Recorded 2 requests to {destination}: 2 application." in result.stdout
        assert "No credentials were found to redact." in result.stdout
        assert f"trace2api inspect {destination}" in result.stdout

    def test_reports_how_much_of_a_recording_is_noise(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        destination = tmp_path / "session.json"
        monkeypatch.setattr(
            cli,
            "record_session",
            lambda url, **kwargs: Capture(
                metadata=CaptureMetadata(
                    source=CaptureSource.BROWSER,
                    created_at=datetime(2026, 9, 4, 9, 15, tzinfo=UTC),
                ),
                entries=[
                    recorded_entry("b0001", "https://shop.example.com/orders"),
                    recorded_entry("b0002", "https://shop.example.com/api/v1/orders"),
                    recorded_entry(
                        "b0003",
                        "https://cdn.example.com/static/app.css",
                        resource_type=ResourceType.STYLESHEET,
                    ),
                ],
            ),
        )

        result = runner.invoke(
            app, ["record", "https://shop.example.com/orders", "-o", str(destination)]
        )

        assert result.exit_code == 0
        assert f"Recorded 3 requests to {destination}: 2 application, 1 noise." in result.stdout

    def test_reports_an_empty_recording_without_a_breakdown(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        destination = tmp_path / "session.json"
        monkeypatch.setattr(
            cli,
            "record_session",
            lambda url, **kwargs: Capture(
                metadata=CaptureMetadata(
                    source=CaptureSource.BROWSER,
                    created_at=datetime(2026, 9, 4, 9, 15, tzinfo=UTC),
                )
            ),
        )

        result = runner.invoke(
            app, ["record", "https://shop.example.com/orders", "-o", str(destination)]
        )

        assert result.exit_code == 0
        assert f"Recorded 0 requests to {destination}." in result.stdout

    def test_credentials_never_reach_the_saved_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        destination = tmp_path / "session.json"
        monkeypatch.setattr(
            cli,
            "record_session",
            lambda url, **kwargs: Capture(
                metadata=CaptureMetadata(
                    source=CaptureSource.BROWSER,
                    created_at=datetime(2026, 9, 4, 9, 15, tzinfo=UTC),
                ),
                entries=[
                    recorded_entry(
                        "b0001",
                        "https://shop.example.com/api/v1/orders",
                        headers=[("Authorization", "Bearer secret-in-a-header")],
                    )
                ],
            ),
        )

        result = runner.invoke(
            app, ["record", "https://shop.example.com/orders", "-o", str(destination)]
        )

        assert result.exit_code == 0
        assert "secret-in-a-header" not in destination.read_text(encoding="utf-8")
        assert "secret-in-a-header" not in result.output
        assert "Redacted 1 value before writing it." in result.stdout

    def test_passes_the_session_options_through(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: dict[str, Any] = {}

        def fake_record(url: str, **kwargs: Any) -> Capture:
            seen["url"] = url
            seen.update(kwargs)
            return Capture(
                metadata=CaptureMetadata(
                    source=CaptureSource.BROWSER,
                    created_at=datetime(2026, 9, 4, 9, 15, tzinfo=UTC),
                )
            )

        monkeypatch.setattr(cli, "record_session", fake_record)

        result = runner.invoke(
            app,
            [
                "record",
                "https://shop.example.com/orders",
                "-o",
                str(tmp_path / "session.json"),
                "--headless",
                "--timeout",
                "30",
            ],
        )

        assert result.exit_code == 0
        assert seen == {
            "url": "https://shop.example.com/orders",
            "headless": True,
            "timeout_s": 30.0,
        }

    def test_recording_ends_with_the_browser_unless_a_timeout_is_given(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: dict[str, Any] = {}

        def fake_record(url: str, **kwargs: Any) -> Capture:
            seen.update(kwargs)
            return Capture(
                metadata=CaptureMetadata(
                    source=CaptureSource.BROWSER,
                    created_at=datetime(2026, 9, 4, 9, 15, tzinfo=UTC),
                )
            )

        monkeypatch.setattr(cli, "record_session", fake_record)

        runner.invoke(
            app, ["record", "https://shop.example.com/orders", "-o", str(tmp_path / "s.json")]
        )

        assert seen == {"headless": False, "timeout_s": None}

    def test_a_timeout_that_records_nothing_is_refused(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app,
            [
                "record",
                "https://shop.example.com/orders",
                "-o",
                str(tmp_path / "s.json"),
                "--timeout",
                "0",
            ],
        )

        assert result.exit_code != 0
        assert not (tmp_path / "s.json").exists()

    def test_a_recording_that_could_not_start_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def refuse(url: str, **kwargs: Any) -> Capture:
            raise BrowserCaptureError("live recording needs Playwright, which is not installed.")

        monkeypatch.setattr(cli, "record_session", refuse)

        result = runner.invoke(
            app, ["record", "https://shop.example.com/orders", "-o", str(tmp_path / "s.json")]
        )

        assert result.exit_code == 2
        assert result.stderr.startswith("error: live recording needs Playwright")
        assert not (tmp_path / "s.json").exists()

    def test_a_capture_that_cannot_be_written_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            cli,
            "record_session",
            lambda url, **kwargs: Capture(
                metadata=CaptureMetadata(
                    source=CaptureSource.BROWSER,
                    created_at=datetime(2026, 9, 4, 9, 15, tzinfo=UTC),
                )
            ),
        )

        result = runner.invoke(
            app,
            [
                "record",
                "https://shop.example.com/orders",
                "-o",
                str(tmp_path / "absent" / "s.json"),
            ],
        )

        assert result.exit_code == 2
        assert "could not be written" in result.stderr

    def test_a_url_is_required(self) -> None:
        assert runner.invoke(app, ["record"]).exit_code != 0


class TestSavedCaptureInput:
    def test_inspect_reads_a_saved_capture(self, tmp_path: Path) -> None:
        capture_file = saved_capture(
            tmp_path / "session.json",
            recorded_entry("b0001", "https://shop.example.com/api/v1/orders"),
            recorded_entry(
                "b0002",
                "https://cdn.example.com/static/app.css",
                resource_type=ResourceType.STYLESHEET,
            ),
            start_url="https://shop.example.com/orders",
        )

        result = runner.invoke(app, ["inspect", str(capture_file)])

        assert result.exit_code == 0
        assert "from browser" in result.stdout
        assert "Started at: https://shop.example.com/orders" in result.stdout
        assert "/api/v1/orders" in result.stdout
        assert "Showing 1 of 2 requests" in result.stdout

    def test_generate_reads_a_saved_capture(self, tmp_path: Path) -> None:
        capture_file = saved_capture(
            tmp_path / "session.json",
            recorded_entry("b0001", "https://shop.example.com/api/v1/orders"),
        )

        result = runner.invoke(app, ["generate", str(capture_file)])

        assert result.exit_code == 0
        assert "curl 'https://shop.example.com/api/v1/orders'" in result.stdout

    def test_a_client_from_a_saved_capture_names_its_credentials(self, tmp_path: Path) -> None:
        """A saved capture arrives redacted, and the variables must still be named for it."""
        capture_file = saved_capture(
            tmp_path / "session.json",
            recorded_entry(
                "b0001",
                "https://shop.example.com/api/v1/orders",
                headers=[
                    ("Authorization", "Bearer secret-in-a-header"),
                    ("Cookie", "session=secret-in-a-cookie"),
                ],
            ),
        )

        result = runner.invoke(app, ["generate", str(capture_file)])

        assert result.exit_code == 0
        assert "secret-in-a-header" not in result.output
        assert "TRACE2API_AUTHORIZATION   request.headers.authorization" in result.stdout
        assert '"$TRACE2API_AUTHORIZATION"' in result.stdout
        assert '"$TRACE2API_COOKIE_SESSION"' in result.stdout
        assert "TRACE2API_SECRET_" not in result.stdout

    def test_a_file_of_neither_format_is_reported(self, tmp_path: Path) -> None:
        other = tmp_path / "notes.json"
        other.write_text('{"requests": []}', encoding="utf-8")

        result = runner.invoke(app, ["inspect", str(other)])

        assert result.exit_code == 2
        assert "neither a Trace2API capture nor a HAR archive" in result.stderr
