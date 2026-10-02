"""Tests for the pluggable second opinion on a value classification left unknown."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from trace2api.analyze import (
    DEFAULT_KEPT,
    ValueClassification,
    ValueRole,
    classify_values,
)
from trace2api.analyze.naming import NamingSuggestion, render_suggestions, suggest_unknowns
from trace2api.models import (
    Body,
    Capture,
    CaptureMetadata,
    CaptureSource,
    Entry,
    Headers,
    Request,
    ResourceType,
    Response,
)

STARTED_AT = datetime(2026, 9, 4, 9, 15, tzinfo=UTC)
SALT = b"test-salt"


def entry(entry_id: str, url: str, *, method: str = "GET", body: Body | None = None) -> Entry:
    """Build one observed exchange."""
    return Entry(
        id=entry_id,
        started_at=STARTED_AT,
        request=Request(method=method, url=url, headers=Headers(), body=body),
        response=Response(status=200, headers=Headers.from_pairs([("Content-Type", "text/plain")])),
        resource_type=ResourceType.XHR,
    )


def capture(*entries: Entry) -> Capture:
    """Build a capture holding ``entries``."""
    return Capture(
        metadata=CaptureMetadata(source=CaptureSource.HAR, created_at=STARTED_AT),
        entries=list(entries),
    )


def classification_of(left: Entry, right: Entry) -> ValueClassification:
    """Classify two single request captures with a fixed redaction salt."""
    return classify_values(capture(left), capture(right), keep=DEFAULT_KEPT, salt=SALT)


class _NoOpinion:
    """A provider that never has anything to say, used to prove nothing is required."""

    def explain(self, value: object) -> None:
        return None


class _NamesEveryUnknown:
    """A provider that always answers, so what it was asked about can be inspected."""

    def __init__(self) -> None:
        self.asked: list[str] = []

    def explain(self, value) -> str:
        self.asked.append(value.location)
        return f"looks like a value tied to {value.location}"


def _unknown_classification() -> ValueClassification:
    left = entry(
        "a", "https://shop.example.com/api/orders", method="POST", body=unreadable("first")
    )
    right = entry(
        "b", "https://shop.example.com/api/orders", method="POST", body=unreadable("second")
    )
    return classification_of(left, right)


def unreadable(text: str) -> Body:
    """Build a payload no structure can be read out of, which classifies as unknown."""
    return Body(mime_type="application/octet-stream", text=text)


class TestSuggestUnknowns:
    def test_a_provider_with_nothing_to_say_yields_no_suggestions(self) -> None:
        classified = _unknown_classification()
        assert suggest_unknowns(classified, _NoOpinion()) == []

    def test_a_provider_is_only_asked_about_unknown_values(self) -> None:
        left = entry("a", "https://shop.example.com/api/orders?status=open&limit=20")
        right = entry("b", "https://shop.example.com/api/orders?status=shipped&limit=20")
        classified = classification_of(left, right)
        provider = _NamesEveryUnknown()
        suggestions = suggest_unknowns(classified, provider)
        assert provider.asked == []
        assert suggestions == []

    def test_a_suggestion_is_offered_for_an_unknown_value(self) -> None:
        classified = _unknown_classification()
        provider = _NamesEveryUnknown()
        suggestions = suggest_unknowns(classified, provider)
        assert provider.asked == ["request.body"]
        assert suggestions == [
            NamingSuggestion(
                location="request.body", explanation="looks like a value tied to request.body"
            )
        ]

    def test_classification_itself_is_never_changed(self) -> None:
        classified = _unknown_classification()
        before = classified.as_json()
        suggest_unknowns(classified, _NamesEveryUnknown())
        assert classified.as_json() == before

    def test_counts_are_unaffected_by_suggestions(self) -> None:
        classified = _unknown_classification()
        suggest_unknowns(classified, _NamesEveryUnknown())
        assert classified.counts_by_role()[ValueRole.UNKNOWN] == 1


class TestRenderSuggestions:
    def test_no_suggestions_renders_plainly(self) -> None:
        assert render_suggestions([]) == "No suggestions offered.\n"

    def test_a_suggestion_is_rendered_under_its_own_heading(self) -> None:
        rendered = render_suggestions(
            [NamingSuggestion(location="request.body", explanation="a signed upload token")]
        )
        assert "Suggestions for the values classification left unknown:" in rendered
        assert "  request.body: a signed upload token" in rendered


class TestNamingSuggestionModel:
    def test_a_suggestion_round_trips_as_json(self) -> None:
        suggestion = NamingSuggestion(location="request.body", explanation="an upload token")
        assert (
            NamingSuggestion.model_validate_json(json.dumps(suggestion.model_dump())) == suggestion
        )
