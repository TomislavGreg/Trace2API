"""Write the requests a capture holds as a runnable JavaScript client using fetch.

The module this writes is an ES module with no dependency on Trace2API and nothing to
install: `fetch`, `URL`, and `URLSearchParams` are all part of the runtime. The rules
that decide what it looks like are the ones that decide whether it works:

* The capture is redacted first, so no request can carry a credential. Every removed
  value is read from the environment as the module loads, which stops the client before
  it sends anything rather than halfway through a workflow.
* Literal text is written as a quoted string and a secret is concatenated onto it, so a
  body full of braces or backslashes reaches the server as it was observed.
* Bodies are sent as the text that was observed rather than re-serialized from a parsed
  structure that could reorder or reformat them.
* A query string holding a credential is rebuilt through `URLSearchParams` and a form
  encoded body holding a credential, or a value read from an earlier response, has that
  field encoded through `encodeURIComponent`, so the supplied value is encoded either
  way. Every other URL and body is written as observed.
* Headers fetch sets for itself are left out, because sending a stale `Content-Length`
  or a `Host` that disagrees with the URL breaks the request. Every omission names the
  rule behind it.

The provenance the capture supplies is written as `//` comments rather than a `/* */`
block. A block comment can be ended early by text that happens to hold `*/`, and a
recorded URL is not something this module gets to choose.

The generated client awaits the requests one at a time in the order they were observed
and does not follow redirects, because a redirect the browser followed was recorded as
its own request. It hands back the responses so a caller can work with them, and running
the module as a script prints a line per response.

Two clients can be written from one capture. :func:`generate_javascript` replays every
value exactly as it was observed, which reproduces the recording. :func:`compile_javascript`
does the same except where the trace found a value a response handed out: there it reads
the value out of the response as it runs, so the client works against whatever the server
answers with rather than only against the one workflow that was recorded. A link it cannot
resolve is replayed as observed and named in the module preamble together with the reason,
so what the client reproduces and what it merely repeats are both readable in the output.

One kind of link `compile_python` resolves is replayed here regardless: one of several
repeated headers read by position, because `Headers.get` only ever returns the first. It
is named with that reason rather than silently sent as observed with no explanation.
"""

from __future__ import annotations

import json
import textwrap
from collections.abc import Iterable, Sequence
from typing import NamedTuple

from pydantic import BaseModel, ConfigDict, Field

from trace2api.analyze.flow import standalone_index, trace_flows
from trace2api.analyze.graph import RequestGraph, build_graph
from trace2api.analyze.relevance import DEFAULT_KEPT, Relevance, classify_capture
from trace2api.generate.dependencies import (
    AccessorKind,
    DependencyResolution,
    ResolvedDependency,
    ResponseAccessor,
    SiteKind,
    UnresolvedDependency,
    read_json_leaf,
    resolve_dependencies,
    write_json_leaf,
)
from trace2api.generate.forms import FormField, form_field_places, form_fields, form_secrets
from trace2api.generate.headers import HeaderRule, OmittedHeader, partition_headers
from trace2api.generate.secrets import SecretBindings, bind_secrets
from trace2api.models import Body, Capture, Entry, Header, QueryParams, Request
from trace2api.sanitize import RedactionResult, redact_capture, split_secrets

__all__ = [
    "FETCH_OMISSION_REASONS",
    "JavaScriptCall",
    "JavaScriptClient",
    "compile_javascript",
    "generate_javascript",
    "render_call",
]

FETCH_OMISSION_REASONS: dict[HeaderRule, str] = {
    HeaderRule.COMPUTED_BY_CLIENT: "fetch sets it from the request it sends",
    HeaderRule.HOP_BY_HOP: "it describes one connection rather than the request",
    HeaderRule.PSEUDO_HEADER: "it is an HTTP/2 pseudo header, not a real one",
    HeaderRule.NEGOTIATED_BY_CLIENT: "fetch asks for its own encodings and decodes the reply",
}
"""How each omission rule reads in a generated JavaScript client."""

_INDENT = "  "
_RESPONSE_PREFIX = "response"
_URL_PREFIX = "url"
_BODILESS_METHODS = frozenset({"GET", "HEAD"})


class JavaScriptCall(BaseModel):
    """One observed request written as a fetch call."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entry_id: str
    position: int = Field(ge=1)
    """Where the request sits in the capture, matching what ``inspect`` numbers it."""

    method: str
    url_without_query: str
    variable: str
    """The name the response is bound to, so later requests can be written against it."""

    code: str
    omitted_headers: list[OmittedHeader] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    """What the call cannot reproduce, such as a body the capture only sampled."""


class JavaScriptClient(BaseModel):
    """A runnable module for the requests a capture kept, and what it took to write it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str
    calls: list[JavaScriptCall] = Field(default_factory=list)
    secrets: SecretBindings = Field(default_factory=SecretBindings)
    captured: int = Field(default=0, ge=0)
    """How many requests the capture held, including the ones filtered as noise."""

    dependencies: DependencyResolution = Field(default_factory=DependencyResolution)
    """What the client does about each value a later request took from a response.

    Empty for a replayed client, which sends every value as the capture observed it.
    """

    graph: RequestGraph | None = None
    """The workflow the client was compiled from, or ``None`` when it was replayed."""

    def __len__(self) -> int:
        return len(self.calls)

    @property
    def skipped(self) -> int:
        """Return how many captured requests the client leaves out."""
        return self.captured - len(self.calls)

    def omitted_headers(self) -> dict[HeaderRule, tuple[str, ...]]:
        """Return the header names left out across the module, grouped by rule."""
        grouped: dict[HeaderRule, list[str]] = {}
        for call in self.calls:
            for omitted in call.omitted_headers:
                names = grouped.setdefault(omitted.rule, [])
                if omitted.name not in names:
                    names.append(omitted.name)
        return {rule: tuple(sorted(names)) for rule, names in sorted(grouped.items())}


def generate_javascript(
    capture: Capture,
    *,
    keep: Iterable[Relevance] = DEFAULT_KEPT,
    salt: bytes | None = None,
) -> JavaScriptClient:
    """Redact ``capture`` and write the requests worth keeping as a JavaScript module.

    Redaction runs first, so a client can never be written from an unsanitized capture.
    ``keep`` selects which relevance verdicts are reproduced, and a ``salt`` makes the
    redaction fingerprints, and so the variable names, reproducible across runs.
    """
    sanitized = redact_capture(capture, salt=salt)
    return _write(sanitized, keep=keep)


def compile_javascript(
    capture: Capture,
    *,
    keep: Iterable[Relevance] = DEFAULT_KEPT,
    salt: bytes | None = None,
) -> JavaScriptClient:
    """Redact ``capture``, trace what it carries, and write a client that reads it back.

    The result is the module :func:`generate_javascript` writes, except that a value a
    later request took from an earlier response is read out of that response at run time.
    What could not be resolved, including the two kinds of link this target cannot express
    at all, is replayed as observed and reported, so the client never pretends to more
    than it supports.
    """
    sanitized = redact_capture(capture, salt=salt)
    # The trace redacts whatever it is handed and leaves an already sanitized capture
    # alone, so tracing the redacted capture is what keeps one placeholder per credential
    # across both halves of the module: the requests written out and the links read from
    # them are then talking about the same values.
    flows = trace_flows(sanitized.capture, keep=keep, salt=salt)
    resolution = _javascript_resolution(resolve_dependencies(flows, sanitized.capture))
    return _write(sanitized, keep=keep, dependencies=resolution, graph=build_graph(flows))


def _javascript_resolution(resolution: DependencyResolution) -> DependencyResolution:
    """Replay a link this target cannot express yet, naming why, the same as an unresolved one.

    ``Headers.get`` only ever returns the first of a header sent more than once, where
    ``compile_python`` reads one of them by position. That link is resolvable in
    principle, so the trace reports it as resolved; it is only this target that falls
    short, which is why the downgrade happens here rather than in the trace itself.
    """
    resolved: list[ResolvedDependency] = []
    unresolved = list(resolution.unresolved)
    for item in resolution.resolved:
        reason = _unsupported_reason(item)
        if reason is None:
            resolved.append(item)
            continue
        unresolved.append(
            UnresolvedDependency(
                source=item.source,
                target=item.target,
                source_location=item.source_location,
                target_location=item.target_location,
                reason=reason,
            )
        )
    return DependencyResolution(resolved=resolved, unresolved=unresolved)


def _unsupported_reason(item: ResolvedDependency) -> str | None:
    """Return why the JavaScript target cannot resolve ``item``, or ``None`` when it can."""
    if item.accessor.kind is AccessorKind.HEADER and item.accessor.index is not None:
        return "fetch has no way to read one of several repeated headers by position"
    return None


def _write(
    sanitized: RedactionResult,
    *,
    keep: Iterable[Relevance],
    dependencies: DependencyResolution | None = None,
    graph: RequestGraph | None = None,
) -> JavaScriptClient:
    """Write the module for an already redacted capture, compiled or replayed."""
    bindings = bind_secrets(sanitized.report)
    resolution = dependencies if dependencies is not None else DependencyResolution()
    kept = frozenset(keep)
    verdicts = {
        item.entry_id: item.relevance
        for item in classify_capture(sanitized.capture).classifications
    }
    calls = [
        render_call(entry, position=position, secrets=bindings, dependencies=dependencies)
        for position, entry in enumerate(sanitized.capture.entries, start=1)
        if verdicts[entry.id] in kept
    ]
    client = JavaScriptClient(
        code="",
        calls=calls,
        secrets=bindings,
        captured=len(sanitized.capture),
        dependencies=resolution,
        graph=graph,
    )
    return client.model_copy(update={"code": _render_module(client, sanitized.capture)})


def render_call(
    entry: Entry,
    *,
    position: int,
    secrets: SecretBindings,
    dependencies: DependencyResolution | None = None,
) -> JavaScriptCall:
    """Write one already redacted exchange as a fetch call.

    The entry must come from a redacted capture. Passing a raw one would put whatever it
    holds into the generated code, which is why nothing outside this module calls it with
    an entry it did not sanitize.

    Passing ``dependencies`` compiles the call: every value this request took from an
    earlier response is written as the variable that response was read into, and every
    link that could not be resolved becomes a note against the call that replays it.
    """
    request = entry.request
    sent = () if dependencies is None else tuple(dependencies.sent_by(position))
    replayed = () if dependencies is None else tuple(dependencies.replayed_by(position))
    in_form = [item for item in sent if item.site.kind is SiteKind.FORM_FIELD]
    headers, omitted = partition_headers(request.headers, FETCH_OMISSION_REASONS)
    url_lines, url, query_secrets = _url_expression(request, secrets, position=position, sent=sent)
    body, notes, body_secrets = _body_property(request, secrets=secrets, sent=sent)
    variable = f"{_RESPONSE_PREFIX}{position}"

    options = [f"method: {_string(request.method)}"]
    if headers:
        options.append(f"headers: {_headers_value(headers, secrets, sent)}")
    if body is not None:
        options.append(f"body: {body}")
    options.append('redirect: "manual"')

    statements = [
        *url_lines,
        f"const {variable} = await fetch({url}, {_block('{', options, '}')});",
    ]
    return JavaScriptCall(
        entry_id=entry.id,
        position=position,
        method=request.method,
        url_without_query=request.url_without_query,
        variable=variable,
        code="\n".join(statements),
        omitted_headers=omitted,
        notes=[
            f"{secrets.variable_for(fingerprint)} is sent as a search parameter, "
            "so URLSearchParams encodes the supplied value"
            for fingerprint in query_secrets
        ]
        + [
            f"{name} is encoded into the form payload where the capture observed it"
            for name in [
                *(secrets.variable_for(fingerprint) for fingerprint in body_secrets),
                *dict.fromkeys(item.variable for item in in_form),
            ]
        ]
        + notes
        + [
            f"{item.target_location} replays what the capture observed, because {item.reason}"
            for item in replayed
        ],
    )


def _url_expression(
    request: Request,
    secrets: SecretBindings,
    *,
    position: int,
    sent: Sequence[ResolvedDependency] = (),
) -> tuple[list[str], str, tuple[str, ...]]:
    """Return the statements building the URL, the expression to fetch, and its secrets.

    A URL with nothing removed from or read into its query string is written whole, so the
    request goes out spelled the way it was observed. A query string that held a credential
    or carries a value read from a response cannot be: neither comes back encoded, so the
    parameters are rebuilt through ``URLSearchParams`` and encoded by it.
    """
    query = request.query
    fingerprints = tuple(
        segment.fingerprint or ""
        for parameter in query
        for segment in split_secrets(parameter.value)
        if segment.is_secret
    )
    in_path = [item for item in sent if item.site.kind is SiteKind.PATH_SEGMENT]
    in_query = [item for item in sent if item.site.kind is SiteKind.QUERY_PARAMETER]
    if not fingerprints and not in_query:
        return [], _url_path_expression(request, in_path, secrets, whole=True), ()
    variable = f"{_URL_PREFIX}{position}"
    substitutions = _by_query_parameter(query, in_query)
    pairs = [
        _pair(
            _string(parameter.name),
            _pieces(parameter.value, substitutions.get(index, ()), secrets),
        )
        for index, parameter in enumerate(query)
    ]
    statements = [
        f"const {variable} = new URL("
        f"{_url_path_expression(request, in_path, secrets, whole=False)});",
        f"{variable}.search = new URLSearchParams({_block('[', pairs, ']')}).toString();",
    ]
    return statements, variable, fingerprints


def _url_path_expression(
    request: Request,
    dependencies: Sequence[ResolvedDependency],
    secrets: SecretBindings,
    *,
    whole: bool,
) -> str:
    """Return the URL, with any path segment read from a response written as its variable.

    ``whole`` asks for the query string to stay on the URL, which is what happens when the
    parameters are not being handed to ``URLSearchParams`` separately.
    """
    if not dependencies:
        return _string(request.url if whole else request.url_without_query)
    path = request.path
    origin = request.url_without_query[: len(request.url_without_query) - len(path)]
    pieces = [_Piece(origin)]
    segment = 0
    for index, part in enumerate(path.split("/")):
        if index:
            pieces.append(_Piece("/"))
        if not part:
            continue
        segment += 1
        found = [item for item in dependencies if item.site.segment == segment]
        pieces.extend(_split(part, _substitutions(found)))
    if whole and request.query_string:
        pieces.append(_Piece(f"?{request.query_string}"))
    return _render(pieces, secrets)


def _headers_value(
    headers: list[Header], secrets: SecretBindings, sent: Sequence[ResolvedDependency] = ()
) -> str:
    """Return the headers as an object, or as pairs when the request repeated a name.

    An object is what a reader would have written, but it cannot hold a name twice, and a
    request that sent one header twice meant it.
    """
    in_header = [item for item in sent if item.site.kind is SiteKind.HEADER]
    substitutions = _by_header(headers, in_header)
    if _repeats_a_name(headers):
        pairs = [
            _pair(
                _string(header.name), _pieces(header.value, substitutions.get(index, ()), secrets)
            )
            for index, header in enumerate(headers)
        ]
        return _block("[", pairs, "]")
    entries = [
        f"{_string(header.name)}: {_pieces(header.value, substitutions.get(index, ()), secrets)}"
        for index, header in enumerate(headers)
    ]
    return _block("{", entries, "}")


def _repeats_a_name(headers: list[Header]) -> bool:
    """Return whether two of ``headers`` carry the same name."""
    names = [header.name.strip().lower() for header in headers]
    return len(set(names)) != len(names)


def _by_header(
    headers: list[Header], dependencies: Sequence[ResolvedDependency]
) -> dict[int, list[_Substitution]]:
    """Gather the values read into each header, by its place in the rendered list.

    Headers are left out by name rather than one at a time, so counting the repeats of a
    name over what is written reaches the same field the trace counted over the capture.
    """
    places: dict[tuple[str, int], int] = {}
    seen: dict[str, int] = {}
    for index, header in enumerate(headers):
        name = header.name.strip().lower()
        occurrence = seen.get(name, 0)
        seen[name] = occurrence + 1
        places[(name, occurrence)] = index
    return _grouped(dependencies, places)


def _by_query_parameter(
    query: QueryParams, dependencies: Sequence[ResolvedDependency]
) -> dict[int, list[_Substitution]]:
    """Gather the values read into each query parameter, by its place in the query string."""
    places: dict[tuple[str, int], int] = {}
    seen: dict[str, int] = {}
    for index, parameter in enumerate(query):
        occurrence = seen.get(parameter.name, 0)
        seen[parameter.name] = occurrence + 1
        places[(parameter.name, occurrence)] = index
    return _grouped(dependencies, places)


def _grouped(
    dependencies: Sequence[ResolvedDependency], places: dict[tuple[str, int], int]
) -> dict[int, list[_Substitution]]:
    """Gather the substitutions of one kind under the place each one is written into."""
    grouped: dict[int, list[_Substitution]] = {}
    for item in dependencies:
        index = places.get((item.site.name, item.site.index or 0))
        if index is not None:
            grouped.setdefault(index, []).extend(_substitutions([item]))
    return grouped


def _body_property(
    request: Request, *, secrets: SecretBindings, sent: Sequence[ResolvedDependency] = ()
) -> tuple[str | None, list[str], tuple[str, ...]]:
    """Return the body property for ``request``, what it cannot reproduce, and its secrets.

    A form encoded body that held a credential, or that carries a value read from an
    earlier response, has that field encoded where it was sent, for the same reason a
    query string holding either is rebuilt: neither comes back from the environment or
    out of a response encoded. A JSON body with a value read from a response has that
    field rewritten around it; every other body is sent as the text that was captured.
    """
    body: Body | None = request.body
    if body is None or body.is_empty:
        return None, [], ()
    notes: list[str] = []
    if body.truncated:
        notes.append("the capture recorded only part of this body, so the request is incomplete")
    if body.encoding == "base64":
        size = body.size if body.size is not None else len(body.as_bytes())
        notes.append(f"a binary body of {size} bytes was observed here and is not reproduced")
        return None, notes, ()
    if request.method in _BODILESS_METHODS:
        # Sending one throws a TypeError before the request leaves, so the client would
        # not run at all. Reporting the body is the only faithful thing left to do.
        notes.append(
            f"fetch cannot send a body with a {request.method} request, "
            "so the observed body is not reproduced"
        )
        return None, notes, ()
    fields = form_fields(body)
    if fields is not None:
        fingerprints = form_secrets(fields)
        written = _by_form_field(fields, sent)
        if not fingerprints and not written:
            return _expression(body.text or "", secrets), notes, ()
        return _form_expression(fields, written, secrets), notes, fingerprints
    json_fields = [item for item in sent if item.site.kind is SiteKind.JSON_FIELD]
    if not json_fields:
        return _expression(body.text or "", secrets), notes, ()
    content, rebuilt = _json_content(body, secrets, json_fields)
    if rebuilt:
        notes.append(
            "the payload is rebuilt around the values read above, so its spacing "
            "may differ from the capture"
        )
    return content, notes, ()


def _form_expression(
    fields: list[FormField],
    written: dict[int, list[_Substitution]],
    secrets: SecretBindings,
) -> str:
    """Return a form payload with each supplied value encoded where its field was sent.

    Every other field is written as the payload spelled it, so the only parts of the body
    that differ from the capture are the ones the client had to supply.
    """
    parts: list[str] = []
    observed = ""
    for index, field in enumerate(fields):
        separator = "&" if index else ""
        supplied = _form_value(field, written.get(index, ()), secrets)
        if supplied is None:
            observed += separator + field.spelled
            continue
        parts.append(_string(f"{observed}{separator}{field.name}="))
        observed = ""
        parts.append(supplied)
    if observed:
        parts.append(_string(observed))
    return " + ".join(parts)


def _form_value(
    field: FormField, written: Sequence[_Substitution], secrets: SecretBindings
) -> str | None:
    """Return what the client sends for one field, or ``None`` for one it does not supply.

    A credential comes back from the environment as itself and a value read out of a
    response is whatever the response held, so the whole field is encoded around either
    one. The value is rebuilt from what the server read rather than from what the payload
    spelled, because that is the value the trace found the link in.
    """
    if field.is_secret:
        return f"encodeURIComponent({secrets.variable_for(field.fingerprint or '')})"
    if not written:
        return None
    return f"encodeURIComponent({_pieces(field.decoded, written, secrets)})"


def _by_form_field(
    fields: list[FormField], dependencies: Sequence[ResolvedDependency]
) -> dict[int, list[_Substitution]]:
    """Gather the values read into each form field, by its place in the payload."""
    return _grouped(dependencies, form_field_places(fields))


_FIELD_TOKEN = "trace2api-field"


def _json_content(
    body: Body, secrets: SecretBindings, dependencies: Sequence[ResolvedDependency]
) -> tuple[str, bool]:
    """Return a JSON payload with the fields read from a response written as expressions.

    Each such field is replaced by a token, the payload is written back out, and the token
    is then the one place the expression goes. Locating the field this way rather than by
    searching the recorded text is what keeps a value from being spliced into whichever
    other field happened to carry the same characters.
    """
    text = body.text or ""
    try:
        document = json.loads(text)
    except ValueError:  # pragma: no cover - the resolver only names fields it could read
        return _expression(text, secrets), False
    fields: dict[tuple[str | int, ...], list[ResolvedDependency]] = {}
    for item in dependencies:
        fields.setdefault(tuple(item.site.steps), []).append(item)
    substitutions: list[_Substitution] = []
    for order, (steps, group) in enumerate(fields.items()):
        leaf = read_json_leaf(document, steps)
        if leaf is None:  # pragma: no cover - the resolver already followed these steps
            continue
        observed = leaf if isinstance(leaf, str) else json.dumps(leaf, ensure_ascii=False)
        expression = _pieces(observed, _substitutions(group), secrets)
        token = _field_token(order, text)
        substitutions.append(
            _Substitution(
                json.dumps(token),
                f"JSON.stringify({expression})" if group[0].site.quoted else expression,
            )
        )
        write_json_leaf(document, steps, token)
    if not substitutions:  # pragma: no cover - guarded by the resolver, kept honest anyway
        return _expression(text, secrets), False
    dumped = json.dumps(document, separators=(",", ":"), ensure_ascii=False)
    return _pieces(dumped, substitutions, secrets), True


def _field_token(order: int, text: str) -> str:
    """Return a marker for one field that the payload does not already contain."""
    token = f"<{_FIELD_TOKEN}-{order}>"
    while token in text:
        token = f"<{token}>"
    return token


class _Substitution(NamedTuple):
    """One observed value, and the expression that stands in for it."""

    value: str
    expression: str


class _Piece(NamedTuple):
    """One run of a rendered value: literal text, or an expression standing in for it."""

    text: str
    expression: str | None = None


def _substitutions(dependencies: Iterable[ResolvedDependency]) -> list[_Substitution]:
    """Return what each dependency writes in place of the value the capture observed.

    A value read out of a response is whatever the payload held, so it is made text at the
    point of use rather than assumed to be a string.
    """
    return [_Substitution(item.value, f"String({item.variable})") for item in dependencies]


def _split(text: str, substitutions: Sequence[_Substitution]) -> list[_Piece]:
    """Split ``text`` around the observed values, keeping everything between them.

    Each value is placed where it stands on its own, which is the same span the trace
    recognized the link by, so a number found inside a longer number is left alone here
    too.
    """
    pieces = [_Piece(text)]
    for value, expression in substitutions:
        for index, piece in enumerate(pieces):
            if piece.expression is not None:
                continue
            at = standalone_index(value, piece.text)
            if at < 0:
                continue
            before = [_Piece(piece.text[:at])] if at else []
            after = (
                [_Piece(piece.text[at + len(value) :])] if at + len(value) < len(piece.text) else []
            )
            pieces[index : index + 1] = [*before, _Piece(value, expression), *after]
            break
    return pieces


def _pieces(text: str, substitutions: Sequence[_Substitution], secrets: SecretBindings) -> str:
    """Return ``text`` as an expression, with the values read from a response written in."""
    return _render(_split(text, substitutions), secrets)


def _render(pieces: Sequence[_Piece], secrets: SecretBindings) -> str:
    """Return the pieces as one JavaScript expression, quoting the literal runs."""
    parts: list[str] = []
    for piece in _joined(pieces):
        if piece.expression is not None:
            parts.append(piece.expression)
        elif piece.text:
            parts.append(_expression(piece.text, secrets))
    return " + ".join(parts) or '""'


def _joined(pieces: Sequence[_Piece]) -> list[_Piece]:
    """Return ``pieces`` with neighbouring literal runs merged, so each is quoted once."""
    merged: list[_Piece] = []
    for piece in pieces:
        if piece.expression is None and merged and merged[-1].expression is None:
            merged[-1] = _Piece(merged[-1].text + piece.text)
            continue
        merged.append(piece)
    return merged


def _expression(text: str, secrets: SecretBindings) -> str:
    """Return ``text`` as a JavaScript expression, with removed secrets read from the environment.

    Literal runs are quoted and each secret is the name the value is supplied under, so
    ``Bearer <secret>`` becomes ``"Bearer " + TRACE2API_AUTHORIZATION``. Concatenation
    rather than a template literal keeps a body full of braces and backticks literal.
    """
    parts = []
    for segment in split_secrets(text):
        if segment.is_secret:
            parts.append(secrets.variable_for(segment.fingerprint or ""))
        elif segment.text:
            parts.append(_string(segment.text))
    return " + ".join(parts) or '""'


def _string(text: str) -> str:
    """Return ``text`` as a JavaScript string literal.

    JSON string syntax is very nearly a subset of JavaScript's, so this borrows it:
    quotes, backslashes, and control characters come out escaped, which keeps every
    literal on one line. The two exceptions are the line and paragraph separators, which
    JSON leaves bare and older JavaScript parsers read as a line break in the middle of a
    literal, so they are escaped here.

    A JSON body is mostly double quotes, and escaping every one of them makes the payload
    hard to read against the capture it came from, so text holding double quotes and no
    single quotes is written in single quotes instead.
    """
    quoted = json.dumps(text, ensure_ascii=False)
    quoted = quoted.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    if '"' in text and "'" not in text:
        unescaped = quoted[1:-1].replace('\\"', '"')
        return f"'{unescaped}'"
    return quoted


def _pair(name: str, value: str) -> str:
    """Return one name and value as the two element array fetch reads them from."""
    return f"[{name}, {value}]"


def _block(opening: str, items: list[str], closing: str) -> str:
    """Return ``items`` one per line inside brackets, or the empty pair when there are none."""
    if not items:
        return f"{opening}{closing}"
    lines = [opening]
    lines.extend(textwrap.indent(f"{item},", _INDENT) for item in items)
    lines.append(closing)
    return "\n".join(lines)


def _render_module(client: JavaScriptClient, capture: Capture) -> str:
    """Return the whole module: what it came from, what it needs, and the requests."""
    lines = [*_preamble(client, capture), "", 'import { pathToFileURL } from "node:url";']
    if not client.secrets.is_empty:
        lines.extend(["", *_require_env()])
        lines.append("")
        lines.append("// Every credential is read up front, so a missing one stops the client")
        lines.append("// before it sends anything rather than halfway through the workflow.")
        lines.extend(
            f"const {binding.variable} = requireEnv({_string(binding.variable)});"
            for binding in client.secrets
        )
    lines.extend(["", *_run_function(client), "", *_main_function()])
    return "\n".join(lines) + "\n"


def _require_env() -> list[str]:
    """Return the helper that turns a missing credential into a readable failure."""
    return [
        "function requireEnv(name) {",
        f"{_INDENT}const value = process.env[name];",
        f"{_INDENT}if (value === undefined) {{",
        f'{_INDENT * 2}throw new Error(name + " is not set: it supplies a credential '
        'this workflow needs.");',
        f"{_INDENT}}}",
        f"{_INDENT}return value;",
        "}",
    ]


def _run_function(client: JavaScriptClient) -> list[str]:
    """Return the function that sends the recorded requests in order."""
    summary = (
        "Sends the recorded requests in the order they were observed."
        if client.graph is None
        else "Sends the recorded requests, reading on what each one is waiting for."
    )
    lines = [f"// {summary}", "export async function run() {"]
    for call in client.calls:
        lines.append(f"{_INDENT}// {call.position}  {call.method} {call.url_without_query}")
        lines.extend(f"{_INDENT}// note: {note}" for note in call.notes)
        lines.append(textwrap.indent(call.code, _INDENT))
        for read in client.dependencies.read_after(call.position):
            lines.append("")
            lines.extend(
                textwrap.indent(line, _INDENT) for line in _read_lines(read, client.dependencies)
            )
        lines.append("")
    returned = ", ".join(call.variable for call in client.calls)
    lines.append(f"{_INDENT}return [{returned}];")
    lines.append("}")
    return lines


def _read_lines(read: ResolvedDependency, resolution: DependencyResolution) -> list[str]:
    """Return the statement binding one value read out of the response just received."""
    sent_on = ", ".join(str(position) for position in resolution.targets_of(read.variable))
    return [
        f"// {read.source_location}, sent on by {sent_on}",
        f"const {read.variable} = {_read_expression(read)};",
    ]


def _read_expression(read: ResolvedDependency) -> str:
    """Return the expression reading one value out of a fetch response."""
    response = f"{_RESPONSE_PREFIX}{read.source}"
    accessor = read.accessor
    if accessor.kind is AccessorKind.REDIRECT_URL:
        # The client does not follow redirects, so the target is read off the response
        # that carried it rather than from wherever it would have led.
        return f'{response}.headers.get("location")'
    if accessor.kind is AccessorKind.HEADER:
        # A header read by position is replayed as observed instead: see
        # ``_unsupported_reason``.
        return f"{response}.headers.get({_string(accessor.name)})"
    return f"(await {response}.json()){_steps_expression(accessor)}"


def _steps_expression(accessor: ResponseAccessor) -> str:
    """Return the subscripts leading to one field of a parsed payload."""
    return "".join(
        f"[{step}]" if isinstance(step, int) else f"[{_string(step)}]" for step in accessor.steps
    )


def _main_function() -> list[str]:
    """Return the entry point used when the module is run as a script."""
    return [
        "// Runs the workflow and reports what came back.",
        "export async function main() {",
        f"{_INDENT}for (const response of await run()) {{",
        f"{_INDENT * 2}console.log(response.status, response.url);",
        f"{_INDENT}}}",
        "}",
        "",
        'if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {',
        f"{_INDENT}await main();",
        "}",
    ]


def _preamble(client: JavaScriptClient, capture: Capture) -> list[str]:
    """Return the comment block above the code: the recording, and what it needs."""
    metadata = capture.metadata
    lines = [
        f"Direct client for a workflow recorded {metadata.created_at.isoformat()} "
        f"(source: {metadata.source.value})."
    ]
    if metadata.start_url is not None:
        lines.append(f"Recorded from {metadata.start_url}")
    lines.append(f"Reproducing {len(client)} of {_count(client.captured, 'captured request')}.")
    for rule, names in client.omitted_headers().items():
        lines.append(f"Left out ({FETCH_OMISSION_REASONS[rule]}): {', '.join(names)}.")
    lines.extend(_workflow_lines(client))
    lines.append("")
    lines.append("An ES module for a runtime with a global fetch, such as Node 18 or newer.")
    lines.append('Save it as a .mjs file, or as .js in a package declaring "type": "module".')
    if client.secrets.is_empty:
        lines.append("")
        lines.append("The capture held no credentials, so nothing has to be exported.")
        return _commented(lines)
    lines.append("")
    lines.append("Credentials were removed from the capture. Export them before running:")
    width = max(len(binding.variable) for binding in client.secrets)
    lines.extend(
        f"  {binding.variable.ljust(width)}  {binding.location}" for binding in client.secrets
    )
    return _commented(lines)


def _workflow_lines(client: JavaScriptClient) -> list[str]:
    """Return what the preamble says about the workflow, for a compiled client.

    A replayed client says nothing here, because it makes no claim about the workflow
    beyond having sent the requests in the order they were recorded. Neither does a
    compiled client with nothing to send, which the count of reproduced requests covers.
    """
    graph = client.graph
    if graph is None or not graph.nodes:
        return []
    lines = [
        "",
        f"The workflow runs in {_count(len(graph.stages), 'stage')}: "
        f"{graph.dependent_requests} of {graph.graphed_requests} requests "
        f"{'waits' if graph.dependent_requests == 1 else 'wait'} for an earlier response.",
    ]
    resolution = client.dependencies
    if resolution.is_empty:
        lines.append("No value a request sent came from an earlier response.")
        return lines
    lines.extend(_read_summary(resolution))
    lines.extend(_replayed_summary(resolution))
    return lines


def _read_summary(resolution: DependencyResolution) -> list[str]:
    """Return the preamble lines listing what the client reads while it runs."""
    reads = resolution.reads
    if not reads:
        return []
    width = max(len(read.variable) for read in reads)
    located = max(len(read.source_location) for read in reads)
    lines = [
        "",
        f"{_count(len(reads), 'value')} read from a response as the client runs, "
        "rather than replayed as observed:",
    ]
    lines.extend(
        f"  {read.variable.ljust(width)}  {read.source}  "
        f"{read.source_location.ljust(located)}  sent on by "
        f"{', '.join(str(position) for position in resolution.targets_of(read.variable))}"
        for read in reads
    )
    return lines


def _replayed_summary(resolution: DependencyResolution) -> list[str]:
    """Return the preamble lines listing what the client could not read, and why."""
    replayed = resolution.unresolved
    if not replayed:
        return []
    verb = "is" if len(replayed) == 1 else "are"
    lines = [
        "",
        f"{_count(len(replayed), 'value')} the workflow took from a response "
        f"{verb} replayed as observed:",
    ]
    for item in replayed:
        lines.append(
            f"  {item.target} {item.target_location} <- {item.source} {item.source_location}"
        )
        lines.append(f"    {item.reason}")
    return lines


def _commented(lines: list[str]) -> list[str]:
    """Return ``lines`` as line comments, with anything that would escape one removed.

    Line breaks are the only thing that can end a line comment, and a capture records
    text this module did not choose, so any that appear become spaces rather than the
    start of a line the runtime would try to parse.
    """
    flattened = [" ".join(line.splitlines()) for line in lines]
    return [f"// {line}".rstrip() for line in flattened]


def _count(number: int, noun: str) -> str:
    """Return ``number`` and ``noun``, pluralized the ordinary way."""
    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"
