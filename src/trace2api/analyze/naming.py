"""A pluggable second opinion on a value no deterministic rule recognized.

``classify_values`` is deterministic by design: every verdict names the rule that reached
it, and a value no rule explains is reported as ``unknown`` rather than guessed at. That
restraint is the point, not a gap, but an operator staring at an unknown value sometimes
wants a second opinion anyway, even one that cannot be trusted the way a rule's verdict can.
This module defines the seam such an opinion plugs into.

The seam is narrow on purpose. A ``NamingProvider`` is asked about one value at a time, is
handed nothing beyond what classification already exposes about it, and is never asked
about a value a rule already decided is a secret, a constant, an input, or generated: those
never reach ``unknown`` in the first place. Nothing it returns can change a verdict,
``suggest_unknowns`` never mutates the classification it reads, and a suggestion is
rendered under its own heading so it is never mistaken for a rule's reasoning.

Trace2API ships no provider. The interface exists so one, deterministic or model backed,
can be wired in later without classify_values needing to know it exists; until then
classification runs exactly as it always has.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

from trace2api.analyze.classify import ClassifiedValue, ValueClassification, ValueRole

__all__ = ["NamingProvider", "NamingSuggestion", "render_suggestions", "suggest_unknowns"]


@runtime_checkable
class NamingProvider(Protocol):
    """Something that can suggest what an unrecognized value probably is."""

    def explain(self, value: ClassifiedValue) -> str | None:
        """Return a short suspicion about ``value``, or ``None`` to say nothing.

        ``value.role`` is always ``ValueRole.UNKNOWN`` here: ``suggest_unknowns`` never
        offers a provider a value classification already reached a verdict for.
        """


class NamingSuggestion(BaseModel):
    """One provider's suspicion about a value classification left unknown."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    location: str
    """Where the value sits, spelled exactly as the classification spells it."""

    explanation: str
    """What the provider suspects the value is. Never trusted the way a rule's verdict is."""


def suggest_unknowns(
    classification: ValueClassification, provider: NamingProvider
) -> list[NamingSuggestion]:
    """Ask ``provider`` about every value ``classification`` reached no verdict for.

    Only values already classified as unknown are offered to ``provider``, so a suggestion
    can narrow what a client still has to puzzle out but can never second guess a verdict a
    rule already reached. ``classification`` itself is never changed: skipping this call
    leaves classify_values exactly as deterministic as it always was.
    """
    suggestions = []
    for value in classification.values:
        if value.role is not ValueRole.UNKNOWN:
            continue
        explanation = provider.explain(value)
        if explanation is not None:
            suggestions.append(NamingSuggestion(location=value.location, explanation=explanation))
    return suggestions


def render_suggestions(suggestions: list[NamingSuggestion]) -> str:
    """Render ``suggestions`` as text a caller can print alongside a classification.

    Labeled plainly as suggestions, and kept separate from ``render_classification``, so
    nothing here is mistaken for a verdict classify_values reached on its own.
    """
    if not suggestions:
        return "No suggestions offered.\n"
    lines = ["Suggestions for the values classification left unknown:"]
    lines.extend(f"  {suggestion.location}: {suggestion.explanation}" for suggestion in suggestions)
    return "\n".join(lines) + "\n"
