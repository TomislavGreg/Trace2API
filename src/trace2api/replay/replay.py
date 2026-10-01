"""Send the requests a sanitized capture holds, given the secrets redaction removed.

A generated client reads its credentials from the process environment, because it has
to run somewhere Trace2API is not. Replaying a capture from inside Trace2API does not,
and should not: an engine that reached into the environment on its own would send
whatever happened to be sitting there under a guessed name, and a caller checking what a
replay would do could not tell without reading the process environment itself.

``secrets`` is instead handed to :func:`replay_capture` directly, keyed the same way a
generated client's exports are: by the environment variable name
:func:`trace2api.generate.secrets.bind_secrets` would bind each removed value to. Every
value a kept request needs and cannot read live, as described below, is checked before
anything is sent, so a replay never sends part of a workflow and stalls on a missing
credential halfway through it.

Not every credential has to come from ``secrets``. Where a value the trace recognizes as
flowing from one response into a later request is a credential, such as a session cookie
a login step sets or a CSRF token it hands back, a replay reads the real value out of the
live response it just received instead of asking for it up front: the token a captured
login handed out is not the one a live login will, so asking for the old one supplied in
advance would only replay a session that has already ended. The value is never written
anywhere; it is held in memory for the rest of the replay and substituted the same way an
explicitly supplied secret is. A credential ``secrets`` does supply is used as given,
taking precedence over one a live response could otherwise provide. A credential neither
``secrets`` supplies nor an earlier response in the same replay hands out still has to be
asked for, and still stops the replay before the request that needs it is sent.

Like the HAR importer and the browser recorder, this module does not redact what it
observes. The responses it returns can carry whatever the server actually sent back,
Set-Cookie values included, and must pass through
:func:`~trace2api.sanitize.redact_capture` before they are stored, displayed, or
compared, the same as a live recording would.

Resolving a value redaction removed back into the URL, a header, or a body follows the
same rules a generated client's targets follow: a query string or a form encoded field
that held one is decoded, substituted, and re-encoded, because neither a credential nor
anything else supplied at run time arrives already encoded, and everywhere else the
placeholder is replaced in the text it sits in. A credential redaction found inside a URL
userinfo component is the one case a generated client does not resolve either, and a
replay leaves it as observed for the same reason: nothing about it can be told apart from
a value nobody meant to supply.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping
from enum import StrEnum
from typing import NamedTuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field

from trace2api.analyze.relevance import DEFAULT_KEPT, Relevance, classify_capture
from trace2api.generate.forms import FORM_MEDIA_TYPE
from trace2api.generate.headers import HeaderRule, partition_headers
from trace2api.generate.secrets import SecretBindings, bind_secrets
from trace2api.models import Body, Capture, Entry, Headers, Request, Response
from trace2api.sanitize import redact_capture, split_secrets

__all__ = [
    "REPLAY_OMISSION_REASONS",
    "MissingSecretError",
    "ReplayOutcome",
    "ReplayResult",
    "ReplayedEntry",
    "replay_capture",
]

REPLAY_OMISSION_REASONS: dict[HeaderRule, str] = {
    HeaderRule.COMPUTED_BY_CLIENT: "httpx sets it from the request it sends",
    HeaderRule.HOP_BY_HOP: "it describes one connection rather than the request",
    HeaderRule.PSEUDO_HEADER: "it is an HTTP/2 pseudo header, not a real one",
    HeaderRule.NEGOTIATED_BY_CLIENT: "httpx asks for its own encodings and decodes the reply",
}
"""Why a replay does not send an observed header as it stands, in httpx's own terms."""


class MissingSecretError(RuntimeError):
    """Raised before anything is sent when a request needs a secret ``secrets`` lacks."""

    def __init__(self, variable: str, location: str) -> None:
        super().__init__(f"{variable} was not supplied: it is needed for {location}")
        self.variable = variable
        self.location = location


class ReplayOutcome(StrEnum):
    """What became of one request a replay tried to send."""

    RESPONDED = "responded"
    FAILED = "failed"


class ReplayedEntry(BaseModel):
    """What actually happened when one request of a replay was sent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entry_id: str
    position: int = Field(ge=1)
    """Where the request sits among the requests replayed, matching what ``inspect`` numbers."""

    method: str
    url_without_query: str
    outcome: ReplayOutcome
    response: Response | None = None
    """The response actually received. Unredacted: pass it through ``redact_capture`` first."""

    error: str | None = None
    """Why the request produced no response, set only when ``outcome`` is ``FAILED``."""


class ReplayResult(BaseModel):
    """Every request one replay sent, in the order it sent them."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entries: list[ReplayedEntry] = Field(default_factory=list)
    captured: int = Field(default=0, ge=0)
    """How many requests the capture held, including the ones the replay left out."""

    def __iter__(self):  # type: ignore[override]
        return iter(self.entries)

    def __len__(self) -> int:
        return len(self.entries)


def replay_capture(
    capture: Capture,
    secrets: Mapping[str, str],
    *,
    keep: Iterable[Relevance] = DEFAULT_KEPT,
    salt: bytes | None = None,
    client: httpx.Client | None = None,
) -> ReplayResult:
    """Redact ``capture`` and send the requests worth keeping over the network.

    ``secrets`` supplies the value for every environment variable a generated client
    would read, by name. Nothing is read from the process environment: a request whose
    secret ``secrets`` does not carry raises :class:`MissingSecretError` before this
    function sends anything, rather than partway through the workflow.

    A ``client`` may be supplied, for a caller that wants its own transport, timeouts, or
    proxy; one is opened and closed here otherwise. Redirects are never followed, because
    a redirect the capture observed being followed was recorded as its own request.
    """
    sanitized = redact_capture(capture, salt=salt)
    bindings = bind_secrets(sanitized.report)
    kept = frozenset(keep)
    verdicts = {
        item.entry_id: item.relevance
        for item in classify_capture(sanitized.capture).classifications
    }
    entries = [entry for entry in sanitized.capture.entries if verdicts[entry.id] in kept]
    sources = _credential_sources(entries)
    live_values: dict[str, str] = {}
    resolve = _resolver(bindings, secrets, live_values)
    _check_secrets(entries, bindings, secrets, sources)

    owns_client = client is None
    active = client if client is not None else httpx.Client(follow_redirects=False)
    try:
        replayed: list[ReplayedEntry] = []
        for position, entry in enumerate(entries, start=1):
            replayed_entry = _replay_entry(active, entry, position, resolve)
            replayed.append(replayed_entry)
            _record_live_values(replayed_entry, sources, live_values)
    finally:
        if owns_client:
            active.close()
    return ReplayResult(entries=replayed, captured=len(sanitized.capture))


class _CredentialSource(NamedTuple):
    """Where a flow traced a credential to, among the entries a replay sends."""

    position: int
    location: str


def _credential_sources(entries: list[Entry]) -> dict[str, _CredentialSource]:
    """Map each credential fingerprint to the earlier response a flow traced it from.

    Traced over the same entries and order a replay sends, so a fingerprint found here
    names a response the replay itself will receive live. Nothing else is: a credential
    supplied from elsewhere, or one no response in this replay hands out, is not read
    here and still has to be supplied.
    """
    # Imported here rather than at module level: trace2api.analyze imports trace2api.replay
    # itself for verification, and importing the two packages into each other at the top
    # would make which one loads first decide whether either can be imported at all.
    from trace2api.analyze.flow import trace_value_flows

    sources: dict[str, _CredentialSource] = {}
    for flow in trace_value_flows(entries):
        fingerprint = _only_fingerprint(flow.value)
        if fingerprint is not None and fingerprint not in sources:
            sources[fingerprint] = _CredentialSource(flow.source.position, flow.source.location)
    return sources


def _only_fingerprint(value: str) -> str | None:
    """Return the fingerprint ``value`` is exactly a redaction placeholder for.

    ``None`` where ``value`` is not a credential, or is one sitting inside a longer piece
    of text: a value read live has to come from a place the response addresses on its
    own, not from splicing a fragment out of something larger.
    """
    segments = split_secrets(value)
    if len(segments) == 1 and segments[0].is_secret:
        return segments[0].fingerprint
    return None


def _record_live_values(
    replayed: ReplayedEntry, sources: dict[str, _CredentialSource], live_values: dict[str, str]
) -> None:
    """Read any credential a later request needs out of a response just received live.

    Nothing read here is written anywhere: it is held only in ``live_values``, for the
    rest of this replay to substitute into the requests that need it.
    """
    if replayed.outcome is not ReplayOutcome.RESPONDED or replayed.response is None:
        return
    needed = [
        (fingerprint, source.location)
        for fingerprint, source in sources.items()
        if source.position == replayed.position and fingerprint not in live_values
    ]
    if not needed:
        return
    from trace2api.analyze.flow import response_values

    located = dict(response_values(replayed.response))
    for fingerprint, location in needed:
        value = located.get(location)
        if value:
            live_values[fingerprint] = value


def _resolver(
    bindings: SecretBindings, secrets: Mapping[str, str], live_values: dict[str, str]
) -> Callable[[str], str]:
    """Return a function from a redaction fingerprint to the value supplied or observed for it.

    A value ``secrets`` supplies for a fingerprint is used as given. Otherwise, a
    fingerprint a flow traced to an earlier response in this same replay is read from
    ``live_values``, filled in as each response arrives.
    """

    def resolve(fingerprint: str) -> str:
        variable = bindings.variable_for(fingerprint)
        if variable in secrets:
            return secrets[variable]
        if fingerprint in live_values:
            return live_values[fingerprint]
        raise MissingSecretError(variable, _binding_location(bindings, fingerprint, variable))

    return resolve


def _binding_location(bindings: SecretBindings, fingerprint: str, variable: str) -> str:
    """Return where a fingerprint was first observed, falling back to its variable name."""
    binding = next((b for b in bindings if b.fingerprint == fingerprint), None)
    return binding.location if binding is not None else variable


def _check_secrets(
    entries: list[Entry],
    bindings: SecretBindings,
    secrets: Mapping[str, str],
    sources: dict[str, _CredentialSource],
) -> None:
    """Raise :class:`MissingSecretError` for the first request needing a secret that is
    neither supplied nor traced to an earlier response among the entries replayed."""
    for entry in entries:
        for fingerprint in _fingerprints(entry.request):
            variable = bindings.variable_for(fingerprint)
            if variable in secrets or fingerprint in sources:
                continue
            raise MissingSecretError(variable, _binding_location(bindings, fingerprint, variable))


def _fingerprints(request: Request) -> set[str]:
    """Return every redaction fingerprint a replay of ``request`` would have to resolve."""
    found: set[str] = set()
    for header in request.headers:
        found.update(_text_fingerprints(header.value))
    for parameter in request.query:
        found.update(_text_fingerprints(parameter.value))
    body = request.body
    if body is not None and body.text is not None and body.encoding is None:
        if body.media_type == FORM_MEDIA_TYPE:
            for _, value in parse_qsl(body.text, keep_blank_values=True):
                found.update(_text_fingerprints(value))
        else:
            found.update(_text_fingerprints(body.text))
    return found


def _text_fingerprints(text: str) -> set[str]:
    return {segment.fingerprint for segment in split_secrets(text) if segment.is_secret}


def _replay_entry(
    client: httpx.Client, entry: Entry, position: int, resolve: Callable[[str], str]
) -> ReplayedEntry:
    """Send one already redacted request and report what actually happened."""
    request = entry.request
    url = _resolved_url(request, resolve)
    sendable, _ = partition_headers(request.headers, REPLAY_OMISSION_REASONS)
    headers = [(header.name, _substitute(header.value, resolve)) for header in sendable]
    content = _resolved_body(request.body, resolve)
    try:
        response = client.request(request.method, url, headers=headers, content=content)
    except httpx.RequestError as error:
        return ReplayedEntry(
            entry_id=entry.id,
            position=position,
            method=request.method,
            url_without_query=request.url_without_query,
            outcome=ReplayOutcome.FAILED,
            # The error itself may quote the URL a secret was resolved into, so only the
            # host and the kind of failure are reported.
            error=f"{type(error).__name__} reaching {request.host}",
        )
    return ReplayedEntry(
        entry_id=entry.id,
        position=position,
        method=request.method,
        url_without_query=request.url_without_query,
        outcome=ReplayOutcome.RESPONDED,
        response=_response_from(response),
    )


def _resolved_url(request: Request, resolve: Callable[[str], str]) -> str:
    """Return the request URL with every secret in its query string resolved.

    The query string is decoded, substituted, and re-encoded, because a query parameter
    that held a credential was stored percent encoded along with the rest of it: the
    placeholder is not there to find until the string is read back apart.
    """
    parts = urlsplit(request.url)
    query = parts.query
    if query:
        pairs = parse_qsl(query, keep_blank_values=True)
        query = urlencode([(name, _substitute(value, resolve)) for name, value in pairs])
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def _resolved_body(body: Body | None, resolve: Callable[[str], str]) -> bytes | None:
    """Return the request body with every secret it carries resolved, as bytes to send.

    A binary payload is sent as observed: nothing in one can be found without decoding a
    format this project does not claim to understand. A form encoded payload is decoded,
    substituted, and re-encoded for the same reason the query string is. Everywhere else
    the placeholder is replaced in the text it sits in, escaped for JSON where the payload
    is JSON, so a secret holding a quote or a backslash still leaves the payload valid.
    """
    if body is None or body.is_empty:
        return None
    if body.encoding == "base64":
        return body.as_bytes()
    text = body.text or ""
    if body.media_type == FORM_MEDIA_TYPE:
        pairs = parse_qsl(text, keep_blank_values=True)
        resolved = urlencode([(name, _substitute(value, resolve)) for name, value in pairs])
    elif body.is_json:
        resolved = _substitute_json(text, resolve)
    else:
        resolved = _substitute(text, resolve)
    return body.model_copy(update={"text": resolved}).as_bytes()


def _substitute(text: str, resolve: Callable[[str], str]) -> str:
    """Return ``text`` with every redaction placeholder replaced by its resolved value."""
    return "".join(
        resolve(segment.fingerprint) if segment.is_secret else segment.text
        for segment in split_secrets(text)
    )


def _substitute_json(text: str, resolve: Callable[[str], str]) -> str:
    """Return JSON ``text`` with every placeholder replaced, escaped for a JSON string."""
    return "".join(
        _json_escaped(resolve(segment.fingerprint)) if segment.is_secret else segment.text
        for segment in split_secrets(text)
    )


def _json_escaped(value: str) -> str:
    """Return ``value`` as it would read inside a JSON string, quotes left off."""
    return json.dumps(value)[1:-1]


def _response_from(response: httpx.Response) -> Response:
    """Return the httpx response as a Trace2API :class:`Response`, as it was received."""
    headers = Headers.from_pairs(
        (name.decode("latin-1"), value.decode("latin-1")) for name, value in response.headers.raw
    )
    return Response(
        http_version=response.http_version,
        headers=headers,
        body=Body.from_bytes(response.headers.get("content-type"), response.content),
        status=response.status_code,
        status_text=response.reason_phrase or None,
    )
