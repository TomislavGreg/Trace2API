"""Tests for the reproducible demo workflow benchmark."""

from __future__ import annotations

import json

from trace2api.benchmark import BenchmarkReport, render_benchmark, run_benchmark
from trace2api.demo.fixture import DemoWorkflowInputs


def test_run_benchmark_matches_the_browser_flow_and_direct_client() -> None:
    report = run_benchmark(seed=0)
    assert report.requests_match
    assert report.responses_match
    assert report.browser.requests_sent == 4
    assert report.direct.requests_sent == 4
    assert report.browser.elapsed_seconds >= 0
    assert report.direct.elapsed_seconds >= 0


def test_run_benchmark_reports_the_dependency_graph_critical_path() -> None:
    report = run_benchmark(seed=0)
    # Two of the four requests, the detail and the confirmation, wait for the same two
    # responses rather than for each other, but neither flow sends them concurrently, so
    # the critical path is one shorter than the number of requests sent.
    assert report.critical_path == 3


def test_run_benchmark_still_matches_with_a_different_seed_and_inputs() -> None:
    report = run_benchmark(seed=7, inputs=DemoWorkflowInputs(payment_method="card", gift_wrap=True))
    assert report.requests_match
    assert report.responses_match


def test_render_benchmark_reports_both_flows() -> None:
    report = run_benchmark(seed=0)
    text = render_benchmark(report)
    assert "Browser flow" in text
    assert "Direct client" in text
    assert "matched the browser flow" in text
    assert "not a guaranteed figure" in text


def test_render_benchmark_reports_a_request_count_mismatch() -> None:
    report = run_benchmark(seed=0)
    mismatched = report.model_copy(
        update={"direct": report.direct.model_copy(update={"requests_sent": 3})}
    )
    assert "does not reproduce this workflow" in render_benchmark(mismatched)


def test_benchmark_report_as_json_round_trips() -> None:
    report = run_benchmark(seed=0)
    restored = BenchmarkReport.model_validate(json.loads(report.as_json()))
    assert restored == report
