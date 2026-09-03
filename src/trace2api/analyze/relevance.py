"""Decide which observed requests are worth carrying into the later stages.

A recorded workflow is mostly not the workflow. Stylesheets, images, fonts, bundle
chunks, analytics beacons, and crash reporters outnumber the handful of requests that
actually move data, and every one of them costs the inference stages time and adds noise
to whatever is generated.

Classification is deterministic and rule based. Each entry is matched against the noise
rules first, then the application rules, and the first rule that fires is recorded
alongside the verdict, so a filtered capture can always answer why a request was kept or
set aside. Nothing here scores or ranks: a rule either matched or it did not.

The rules are written to be wrong in one direction. An entry no rule recognizes is
:attr:`Relevance.UNKNOWN` rather than noise, because dropping a request that mattered
breaks a generated client in a way that is hard to see, while keeping one that did not
is visible in the output and easy to remove.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from trace2api.models import Capture, Entry, ResourceType

__all__ = [
    "DEFAULT_KEPT",
    "Classification",
    "FilterReport",
    "FilterResult",
    "FilterRule",
    "Relevance",
    "classify_capture",
    "classify_entry",
    "filter_capture",
]


class Relevance(StrEnum):
    """What a request looks like once the rules have run."""

    APPLICATION = "application"
    """Carries data the workflow depends on. Kept by default."""

    NOISE = "noise"
    """Page furniture or reporting traffic. Dropped by default."""

    UNKNOWN = "unknown"
    """No rule recognized it. Kept by default so nothing is lost silently."""


class FilterRule(StrEnum):
    """The rule that decided an entry.

    Reports carry the rule so a verdict can be traced back to the reason for it.
    """

    ANALYTICS_HOST = "analytics-host"
    REPORTING_PATH = "reporting-path"
    ASSET_RESOURCE_TYPE = "asset-resource-type"
    ASSET_EXTENSION = "asset-extension"
    API_PATH = "api-path"
    DATA_RESOURCE_TYPE = "data-resource-type"
    STRUCTURED_RESPONSE = "structured-response"
    STRUCTURED_REQUEST = "structured-request"
    PAGE_DOCUMENT = "page-document"
    STREAMING_CONNECTION = "streaming-connection"
    NO_RULE_MATCHED = "no-rule-matched"


_ANALYTICS_DOMAINS = frozenset(
    {
        "amplitude.com",
        "analytics.tiktok.com",
        "bugsnag.com",
        "braze.com",
        "clarity.ms",
        "connect.facebook.net",
        "datadoghq.com",
        "doubleclick.net",
        "fullstory.com",
        "google-analytics.com",
        "googletagmanager.com",
        "heap.io",
        "hotjar.com",
        "mixpanel.com",
        "newrelic.com",
        "nr-data.net",
        "optimizely.com",
        "rollbar.com",
        "segment.com",
        "segment.io",
        "sentry.io",
    }
)
"""Hosts whose whole purpose is measurement or crash reporting.

Matched on the domain itself and on subdomains of it, so a regional or per tenant
collector is recognized without listing every one.
"""

_REPORTING_SEGMENTS = frozenset(
    {
        "analytics",
        "beacon",
        "collect",
        "cspreport",
        "gtag",
        "gtm",
        "pageview",
        "pixel",
        "telemetry",
    }
)
"""Path segments that name reporting endpoints on an application's own host.

Deliberately narrow. Words such as ``track``, ``events``, or ``stats`` name reporting
on some sites and ordinary data on others, so they are left to the application rules.
"""

_ASSET_RESOURCE_TYPES = frozenset(
    {
        ResourceType.STYLESHEET,
        ResourceType.IMAGE,
        ResourceType.MEDIA,
        ResourceType.FONT,
        ResourceType.SCRIPT,
        ResourceType.MANIFEST,
    }
)

_ASSET_EXTENSIONS = frozenset(
    {
        "avif",
        "bmp",
        "css",
        "eot",
        "gif",
        "ico",
        "jpeg",
        "jpg",
        "js",
        "map",
        "mjs",
        "mp3",
        "mp4",
        "otf",
        "png",
        "svg",
        "ttf",
        "wasm",
        "webm",
        "webp",
        "woff",
        "woff2",
    }
)
"""Suffixes of files a page loads to render itself.

``json`` and ``xml`` are absent on purpose: they are how APIs answer.
"""

_API_SEGMENTS = frozenset({"api", "gql", "graphql", "jsonrpc", "rest", "rpc"})

_VERSION_SEGMENT = re.compile(r"^v[0-9]+$")

_DATA_RESOURCE_TYPES = frozenset({ResourceType.XHR, ResourceType.FETCH})

_STREAMING_RESOURCE_TYPES = frozenset({ResourceType.WEBSOCKET, ResourceType.EVENTSOURCE})

_STRUCTURED_MEDIA_TYPES = frozenset(
    {
        "application/graphql",
        "application/json",
        "application/x-ndjson",
        "application/x-www-form-urlencoded",
        "application/xml",
        "multipart/form-data",
        "text/xml",
    }
)
"""Media types that carry structured data rather than a rendered page."""

_STRUCTURED_MEDIA_SUFFIXES = ("+json", "+xml")

_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class Classification(BaseModel):
    """One entry's verdict, the rule behind it, and what the rule matched on."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entry_id: str
    relevance: Relevance
    rule: FilterRule
    detail: str | None = None
    """What the rule matched, such as a host or a path segment. Never a value."""

    @property
    def reason(self) -> str:
        """Return a one line explanation of the verdict."""
        text = _RULE_REASONS[self.rule]
        if self.detail is None:
            return text
        return f"{text}: {self.detail}"


_RULE_REASONS: dict[FilterRule, str] = {
    FilterRule.ANALYTICS_HOST: "sent to an analytics or crash reporting host",
    FilterRule.REPORTING_PATH: "path names a reporting endpoint",
    FilterRule.ASSET_RESOURCE_TYPE: "the browser loaded it as a page asset",
    FilterRule.ASSET_EXTENSION: "path ends in a static asset suffix",
    FilterRule.API_PATH: "path names an API surface",
    FilterRule.DATA_RESOURCE_TYPE: "the page issued it as a data request",
    FilterRule.STRUCTURED_RESPONSE: "answered with structured data",
    FilterRule.STRUCTURED_REQUEST: "sent structured data",
    FilterRule.PAGE_DOCUMENT: "a page document, which may carry values later requests reuse",
    FilterRule.STREAMING_CONNECTION: "a streaming connection, not a single HTTP exchange",
    FilterRule.NO_RULE_MATCHED: "no rule recognized it",
}


class FilterReport(BaseModel):
    """Every entry in a capture, with the verdict reached for it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    classifications: list[Classification] = Field(default_factory=list)

    def __len__(self) -> int:
        return len(self.classifications)

    def for_entry(self, entry_id: str) -> Classification | None:
        """Return the verdict recorded for ``entry_id``, or ``None`` when there is none."""
        for classification in self.classifications:
            if classification.entry_id == entry_id:
                return classification
        return None

    def entry_ids(self, relevance: Relevance) -> tuple[str, ...]:
        """Return the ids classified as ``relevance``, in the order they were observed."""
        return tuple(item.entry_id for item in self.classifications if item.relevance is relevance)

    def counts_by_relevance(self) -> dict[Relevance, int]:
        """Return how many entries reached each verdict, including the empty ones."""
        counts = dict.fromkeys(Relevance, 0)
        for classification in self.classifications:
            counts[classification.relevance] += 1
        return counts

    def counts_by_rule(self) -> dict[FilterRule, int]:
        """Return how many entries each rule accounted for, most frequent first."""
        counts: dict[FilterRule, int] = {}
        for classification in self.classifications:
            counts[classification.rule] = counts.get(classification.rule, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


class FilterResult(BaseModel):
    """A capture reduced to the entries that were kept, and the account of the whole."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capture: Capture
    report: FilterReport

    @property
    def removed(self) -> int:
        """Return how many entries the filter left out."""
        return len(self.report) - len(self.capture)


DEFAULT_KEPT = (Relevance.APPLICATION, Relevance.UNKNOWN)
"""Verdicts kept when a caller does not say otherwise."""


def classify_entry(entry: Entry) -> Classification:
    """Return the verdict for one observed exchange.

    Noise rules run before application rules, because a beacon posted as JSON is still a
    beacon. Within each group the more specific rule runs first, so the recorded rule is
    the most informative one that applied.
    """
    match = next(iter(_rule_matches(entry)), None)
    if match is None:
        return Classification(
            entry_id=entry.id, relevance=Relevance.UNKNOWN, rule=FilterRule.NO_RULE_MATCHED
        )
    rule, relevance, detail = match
    return Classification(entry_id=entry.id, relevance=relevance, rule=rule, detail=detail)


def _rule_matches(entry: Entry) -> Iterable[tuple[FilterRule, Relevance, str | None]]:
    """Yield the rules that fire for ``entry``, most specific first."""
    request = entry.request

    domain = _analytics_domain(request.host)
    if domain is not None:
        yield FilterRule.ANALYTICS_HOST, Relevance.NOISE, domain

    segment = _reporting_segment(request.path)
    if segment is not None:
        yield FilterRule.REPORTING_PATH, Relevance.NOISE, segment

    if entry.resource_type in _ASSET_RESOURCE_TYPES:
        yield FilterRule.ASSET_RESOURCE_TYPE, Relevance.NOISE, entry.resource_type.value

    extension = _asset_extension(request.path)
    if extension is not None:
        yield FilterRule.ASSET_EXTENSION, Relevance.NOISE, f".{extension}"

    if entry.resource_type is ResourceType.DOCUMENT:
        yield FilterRule.PAGE_DOCUMENT, Relevance.UNKNOWN, None

    if entry.resource_type in _STREAMING_RESOURCE_TYPES:
        yield FilterRule.STREAMING_CONNECTION, Relevance.UNKNOWN, entry.resource_type.value

    api_segment = _api_segment(request.path)
    if api_segment is not None:
        yield FilterRule.API_PATH, Relevance.APPLICATION, api_segment

    if entry.resource_type in _DATA_RESOURCE_TYPES:
        yield FilterRule.DATA_RESOURCE_TYPE, Relevance.APPLICATION, entry.resource_type.value

    if entry.response is not None and _is_structured(entry.response.content_type):
        yield (
            FilterRule.STRUCTURED_RESPONSE,
            Relevance.APPLICATION,
            _media_type(entry.response.content_type),
        )

    sends_body = request.body is not None and not request.body.is_empty
    if sends_body and request.method not in _READ_METHODS and _is_structured(request.content_type):
        yield (
            FilterRule.STRUCTURED_REQUEST,
            Relevance.APPLICATION,
            _media_type(request.content_type),
        )


def classify_capture(capture: Capture) -> FilterReport:
    """Return a verdict for every entry in ``capture``, in the order observed."""
    return FilterReport(classifications=[classify_entry(entry) for entry in capture.entries])


def filter_capture(capture: Capture, *, keep: Iterable[Relevance] = DEFAULT_KEPT) -> FilterResult:
    """Return ``capture`` reduced to the entries whose verdict is in ``keep``.

    The report covers every entry, kept or not, so the entries that were left out can
    still be listed and explained. Metadata is carried over unchanged: filtering narrows
    what a capture shows, it does not turn it into a different recording.
    """
    kept = frozenset(keep)
    report = classify_capture(capture)
    verdicts = {item.entry_id: item.relevance for item in report.classifications}
    entries = [entry for entry in capture.entries if verdicts[entry.id] in kept]
    return FilterResult(capture=capture.model_copy(update={"entries": entries}), report=report)


def _analytics_domain(host: str) -> str | None:
    """Return the analytics domain ``host`` belongs to, or ``None``."""
    for domain in _ANALYTICS_DOMAINS:
        if host == domain or host.endswith(f".{domain}"):
            return domain
    return None


def _path_segments(path: str) -> list[str]:
    """Return the comparable form of each segment of ``path``.

    A segment is reduced to what comes before its first dot, then to letters and digits,
    so ``/collect.gif`` and ``/v1/csp-report`` are read as the words they name.
    """
    segments = (segment.split(".", 1)[0].lower() for segment in path.split("/") if segment)
    return [stripped for segment in segments if (stripped := re.sub(r"[^a-z0-9]", "", segment))]


def _reporting_segment(path: str) -> str | None:
    """Return the path segment naming a reporting endpoint, or ``None``."""
    for segment in _path_segments(path):
        if segment in _REPORTING_SEGMENTS:
            return segment
    return None


def _api_segment(path: str) -> str | None:
    """Return the path segment naming an API surface, or ``None``.

    A bare version segment counts only when it is not the last one, so ``/v2/orders``
    reads as an API while a page at ``/pricing/v2`` does not.
    """
    segments = _path_segments(path)
    for position, segment in enumerate(segments):
        if segment in _API_SEGMENTS:
            return segment
        if _VERSION_SEGMENT.match(segment) and position < len(segments) - 1:
            return segment
    return None


def _asset_extension(path: str) -> str | None:
    """Return the static asset suffix of the last path segment, or ``None``."""
    last = path.rsplit("/", 1)[-1]
    name, separator, extension = last.rpartition(".")
    if not separator or not name:
        return None
    extension = extension.lower()
    return extension if extension in _ASSET_EXTENSIONS else None


def _media_type(content_type: str | None) -> str | None:
    """Return ``content_type`` without its parameters, lowercased."""
    if content_type is None:
        return None
    media_type = content_type.split(";", 1)[0].strip().lower()
    return media_type or None


def _is_structured(content_type: str | None) -> bool:
    """Return whether a content type describes structured data."""
    media_type = _media_type(content_type)
    if media_type is None:
        return False
    return media_type in _STRUCTURED_MEDIA_TYPES or media_type.endswith(_STRUCTURED_MEDIA_SUFFIXES)
