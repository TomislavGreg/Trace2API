"""Write the requests a capture holds as a runnable Python client using httpx.

The module this writes is meant to be read, edited, and kept: ordinary Python with no
Trace2API import, no runtime to install, and no generated abstraction to learn. The rules
that decide what it looks like are the ones that decide whether it works:

* The capture is redacted first, so no request can carry a credential. Every removed
  value is read from an environment variable at import time, which stops the client
  before it sends anything rather than halfway through a workflow.
* Literal text is written as a quoted string and a secret is concatenated onto it, so a
  body full of braces or backslashes reaches the server as it was observed.
* Bodies are sent as ``content``, the exact bytes that were observed, rather than
  re-serialized from a parsed structure that could reorder or reformat them.
* A query string holding a credential is sent as ``params`` and a form encoded body
  holding one has that field encoded through ``urllib.parse.quote_plus``, so the supplied
  value is encoded either way. Every other URL and body is written exactly as observed.
* Headers httpx sets for itself are left out, because sending a stale ``Content-Length``
  or a ``Host`` that disagrees with the URL breaks the request. Every omission names the
  rule behind it.

The generated client sends the requests one at a time in the order they were observed
and does not follow redirects, because a redirect the browser followed was recorded as
its own request. It hands back the responses so a caller can work with them, and running
the module as a script prints a line per response.

Two clients can be written from one capture. :func:`generate_python` replays every value
exactly as it was observed, which reproduces the recording. :func:`compile_python` does the
same except where the trace found a value a response handed out: there it reads the value
out of the response as it runs, so the client works against whatever the server answers
with rather than only against the one workflow that was recorded. A link it cannot resolve
is replayed as observed and named in the module docstring together with the reason, so what
the client reproduces and what it merely repeats are both readable in the output.

Sending stays in the observed order in both. Every link points backwards, so that order is
one a client can actually send in, and the graph the module docstring reports says how much
of the workflow could be sent at once by a client written by hand.
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
    read_json_leaf,
    resolve_dependencies,
    write_json_leaf,
)
from trace2api.generate.forms import FormField, form_fields, form_secrets
from trace2api.generate.headers import HeaderRule, OmittedHeader, partition_headers
from trace2api.generate.secrets import SecretBindings, bind_secrets
from trace2api.models import Body, Capture, Entry, Header, QueryParams, Request
from trace2api.sanitize import RedactionResult, redact_capture, split_secrets

__all__ = [
    "HTTPX_OMISSION_REASONS",
    "PythonCall",
    "PythonClient",
    "compile_python",
    "generate_python",
    "render_call",
]

HTTPX_OMISSION_REASONS: dict[HeaderRule, str] = {
    HeaderRule.COMPUTED_BY_CLIENT: "httpx sets it from the request it sends",
    HeaderRule.HOP_BY_HOP: "it describes one connection rather than the request",
    HeaderRule.PSEUDO_HEADER: "it is an HTTP/2 pseudo header, not a real one",
    HeaderRule.NEGOTIATED_BY_CLIENT: "httpx asks for its own encodings and decodes the reply",
}
"""How each omission rule reads in a generated Python client."""

_INDENT = "    "
_RESPONSE_PREFIX = "response_"


class PythonCall(BaseModel):
    """One observed request written as an httpx call."""

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

    encodes_a_form_field: bool = False
    """Whether the call encodes a credential into a form payload as it is sent."""


class PythonClient(BaseModel):
    """A runnable module for the requests a capture kept, and what it took to write it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str
    calls: list[PythonCall] = Field(default_factory=list)
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


def generate_python(
    capture: Capture,
    *,
    keep: Iterable[Relevance] = DEFAULT_KEPT,
    salt: bytes | None = None,
) -> PythonClient:
    """Redact ``capture`` and write the requests worth keeping as a Python module.

    Redaction runs first, so a client can never be written from an unsanitized capture.
    ``keep`` selects which relevance verdicts are reproduced, and a ``salt`` makes the
    redaction fingerprints, and so the variable names, reproducible across runs.
    """
    sanitized = redact_capture(capture, salt=salt)
    return _write(sanitized, keep=keep)


def compile_python(
    capture: Capture,
    *,
    keep: Iterable[Relevance] = DEFAULT_KEPT,
    salt: bytes | None = None,
) -> PythonClient:
    """Redact ``capture``, trace what it carries, and write a client that reads it back.

    The result is the module :func:`generate_python` writes, except that a value a later
    request took from an earlier response is read out of that response at run time. What
    could not be resolved is replayed as observed and reported, so the client never
    pretends to more than the capture supports.
    """
    sanitized = redact_capture(capture, salt=salt)
    # The trace redacts whatever it is handed and leaves an already sanitized capture
    # alone, so tracing the redacted capture is what keeps one placeholder per credential
    # across both halves of the module: the requests written out and the links read from
    # them are then talking about the same values.
    flows = trace_flows(sanitized.capture, keep=keep, salt=salt)
    return _write(
        sanitized,
        keep=keep,
        dependencies=resolve_dependencies(flows, sanitized.capture),
        graph=build_graph(flows),
    )


def _write(
    sanitized: RedactionResult,
    *,
    keep: Iterable[Relevance],
    dependencies: DependencyResolution | None = None,
    graph: RequestGraph | None = None,
) -> PythonClient:
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
    client = PythonClient(
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
) -> PythonCall:
    """Write one already redacted exchange as an httpx call.

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
    headers, omitted = partition_headers(request.headers, HTTPX_OMISSION_REASONS)
    url, params, query_secrets = _url_arguments(request, secrets, sent)
    body, notes, body_secrets = _body_argument(request.body, secrets=secrets, dependencies=sent)
    variable = f"{_RESPONSE_PREFIX}{position}"

    arguments = [_string(request.method), url]
    if params is not None:
        arguments.append(f"params={params}")
    if headers:
        arguments.append(f"headers={_headers_argument(headers, secrets, sent)}")
    if body is not None:
        arguments.append(body)

    return PythonCall(
        entry_id=entry.id,
        position=position,
        method=request.method,
        url_without_query=request.url_without_query,
        variable=variable,
        code=_call_statement(variable, arguments),
        omitted_headers=omitted,
        notes=[
            f"{secrets.variable_for(fingerprint)} is sent as a query parameter, "
            "so httpx encodes the supplied value"
            for fingerprint in query_secrets
        ]
        + [
            f"{secrets.variable_for(fingerprint)} is encoded into the form payload "
            "where the capture observed it"
            for fingerprint in body_secrets
        ]
        + notes
        + [
            f"{item.target_location} replays what the capture observed, because {item.reason}"
            for item in replayed
        ],
        encodes_a_form_field=bool(body_secrets),
    )


def _url_arguments(
    request: Request, secrets: SecretBindings, dependencies: Sequence[ResolvedDependency]
) -> tuple[str, str | None, tuple[str, ...]]:
    """Return the URL argument, any ``params`` argument, and the secrets in the query.

    A URL with nothing removed from or read into its query string is written whole, so the
    request goes out spelled the way it was observed. A query string that held a credential
    or carries a value read from a response cannot be: neither comes back encoded, so the
    parameters are handed to httpx separately and encoded by it.
    """
    query = request.query
    fingerprints = tuple(
        segment.fingerprint or ""
        for parameter in query
        for segment in split_secrets(parameter.value)
        if segment.is_secret
    )
    in_path = [item for item in dependencies if item.site.kind is SiteKind.PATH_SEGMENT]
    in_query = [item for item in dependencies if item.site.kind is SiteKind.QUERY_PARAMETER]
    if not fingerprints and not in_query:
        return _url_expression(request, in_path, secrets, whole=True), None, ()
    substitutions = _by_query_parameter(query, in_query)
    pairs = [
        f"({_string(parameter.name)}, "
        f"{_pieces(parameter.value, substitutions.get(index, ()), secrets)})"
        for index, parameter in enumerate(query)
    ]
    return (
        _url_expression(request, in_path, secrets, whole=False),
        _sequence("[", pairs, "]"),
        fingerprints,
    )


def _url_expression(
    request: Request,
    dependencies: Sequence[ResolvedDependency],
    secrets: SecretBindings,
    *,
    whole: bool,
) -> str:
    """Return the URL, with any path segment read from a response written as its variable.

    ``whole`` asks for the query string to stay on the URL, which is what happens when the
    parameters are not being handed to httpx separately.
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


def _headers_argument(
    headers: list[Header], secrets: SecretBindings, dependencies: Sequence[ResolvedDependency]
) -> str:
    """Return the headers as a dict, or as pairs when the request repeated a name.

    A dict is what a reader would have written, but it cannot hold a name twice, and a
    request that sent one header twice meant it.
    """
    substitutions = _by_header(headers, dependencies)
    if _repeats_a_name(headers):
        pairs = [
            f"({_string(header.name)}, "
            f"{_pieces(header.value, substitutions.get(index, ()), secrets)})"
            for index, header in enumerate(headers)
        ]
        return _sequence("[", pairs, "]")
    entries = [
        f"{_string(header.name)}: {_pieces(header.value, substitutions.get(index, ()), secrets)}"
        for index, header in enumerate(headers)
    ]
    return _sequence("{", entries, "}")


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
    return _grouped(dependencies, SiteKind.HEADER, places)


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
    return _grouped(dependencies, SiteKind.QUERY_PARAMETER, places)


def _grouped(
    dependencies: Sequence[ResolvedDependency],
    kind: SiteKind,
    places: dict[tuple[str, int], int],
) -> dict[int, list[_Substitution]]:
    """Gather the substitutions of one kind under the place each one is written into."""
    grouped: dict[int, list[_Substitution]] = {}
    for item in dependencies:
        if item.site.kind is not kind:
            continue
        index = places.get((item.site.name, item.site.index or 0))
        if index is not None:
            grouped.setdefault(index, []).extend(_substitutions([item]))
    return grouped


def _body_argument(
    body: Body | None,
    *,
    secrets: SecretBindings,
    dependencies: Sequence[ResolvedDependency] = (),
) -> tuple[str | None, list[str], tuple[str, ...]]:
    """Return the body argument, what the call cannot reproduce, and the secrets it carries.

    A form encoded body that held a credential has the value encoded where it was sent,
    for the same reason a query string holding one is handed to httpx as parameters: the
    value comes back from the environment unencoded. Every other body is sent as the text
    that was captured, with the values read from an earlier response written into it.
    """
    if body is None or body.is_empty:
        return None, [], ()
    notes: list[str] = []
    if body.truncated:
        notes.append("the capture recorded only part of this body, so the request is incomplete")
    if body.encoding == "base64":
        size = body.size if body.size is not None else len(body.as_bytes())
        notes.append(f"a binary body of {size} bytes was observed here and is not reproduced")
        return None, notes, ()
    form = form_fields(body)
    fingerprints = () if form is None else form_secrets(form)
    if form is not None and fingerprints:
        return f"content={_form_expression(form, secrets)}", notes, fingerprints
    fields = [item for item in dependencies if item.site.kind is SiteKind.JSON_FIELD]
    if not fields:
        return f"content={_expression(body.text or '', secrets)}", notes, ()
    content, rebuilt = _json_content(body, secrets, fields)
    if rebuilt:
        notes.append(
            "the payload is rebuilt around the values read above, so its spacing "
            "may differ from the capture"
        )
    return f"content={content}", notes, ()


_QUOTE_FUNCTION = "urllib.parse.quote_plus"
"""What the module calls to encode a credential it writes into a form payload."""


def _form_expression(fields: list[FormField], secrets: SecretBindings) -> str:
    """Return a form payload with each credential encoded where its value was sent.

    Every other field is written as the payload spelled it, so the only part of the body
    that differs from the capture is the one part the client had to supply.
    """
    parts: list[str] = []
    observed = ""
    for index, field in enumerate(fields):
        separator = "&" if index else ""
        if not field.is_secret:
            observed += separator + field.spelled
            continue
        parts.append(_string(f"{observed}{separator}{field.name}="))
        observed = ""
        variable = secrets.variable_for(field.fingerprint or "")
        parts.append(f"{_QUOTE_FUNCTION}({variable})")
    if observed:
        parts.append(_string(observed))
    return " + ".join(parts)


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
                f"json.dumps({expression})" if group[0].site.quoted else expression,
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
    return [_Substitution(item.value, f"str({item.variable})") for item in dependencies]


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
    """Return the pieces as one Python expression, quoting the literal runs."""
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
    """Return ``text`` as a Python expression, with removed secrets read from the environment.

    Literal runs are quoted and each secret is the name the value is supplied under, so
    ``Bearer <secret>`` becomes ``"Bearer " + TRACE2API_AUTHORIZATION``. Concatenation
    rather than an f-string keeps a body full of braces readable and literal.
    """
    parts = []
    for segment in split_secrets(text):
        if segment.is_secret:
            parts.append(secrets.variable_for(segment.fingerprint or ""))
        elif segment.text:
            parts.append(_string(segment.text))
    return " + ".join(parts) or '""'


def _string(text: str) -> str:
    """Return ``text`` as a Python string literal.

    JSON string syntax is a subset of Python's, so this borrows it: quotes, backslashes,
    and control characters come out escaped, which keeps every literal on one line.
    Characters outside ASCII are written as themselves, because JSON escapes an astral
    character as a surrogate pair and Python would read that back as two lone surrogates
    rather than the character the capture recorded.

    A JSON body is mostly double quotes, and escaping every one of them makes the payload
    hard to read against the capture it came from, so text holding double quotes and no
    single quotes is written in single quotes instead.
    """
    quoted = json.dumps(text, ensure_ascii=False)
    if '"' in text and "'" not in text:
        unescaped = quoted[1:-1].replace('\\"', '"')
        return f"'{unescaped}'"
    return quoted


def _sequence(opening: str, items: list[str], closing: str) -> str:
    """Return ``items`` one per line inside brackets, or the empty pair when there are none."""
    if not items:
        return f"{opening}{closing}"
    lines = [opening]
    lines.extend(f"{_INDENT}{item}," for item in items)
    lines.append(closing)
    return "\n".join(lines)


def _call_statement(variable: str, arguments: list[str]) -> str:
    """Return the httpx call, one argument per line so a diff of two clients reads."""
    lines = [f"{variable} = client.request("]
    lines.extend(textwrap.indent(f"{argument},", _INDENT) for argument in arguments)
    lines.append(")")
    return "\n".join(lines)


def _render_module(client: PythonClient, capture: Capture) -> str:
    """Return the whole module: what it came from, what it needs, and the requests."""
    lines = [_docstring(_summary(client, capture))]
    needed = (
        ("json", _rewrites_a_payload(client)),
        ("os", not client.secrets.is_empty),
        ("urllib.parse", _encodes_a_form_field(client)),
    )
    standard = [module for module, required in needed if required]
    if standard:
        lines.append("")
        lines.extend(f"import {module}" for module in standard)
    lines.extend(["", "import httpx"])
    if not client.secrets.is_empty:
        lines.append("")
        lines.append("# Every credential is read up front, so a missing one stops the client")
        lines.append("# before it sends anything rather than halfway through the workflow.")
        lines.extend(
            f"{binding.variable} = os.environ[{_string(binding.variable)}]"
            for binding in client.secrets
        )
    lines.extend(["", "", *_run_function(client), "", "", *_main_function()])
    return "\n".join(lines) + "\n"


def _rewrites_a_payload(client: PythonClient) -> bool:
    """Return whether the module writes a value back into a JSON payload."""
    return any(
        item.site.kind is SiteKind.JSON_FIELD and item.site.quoted
        for item in client.dependencies.resolved
    )


def _encodes_a_form_field(client: PythonClient) -> bool:
    """Return whether the module encodes a credential into a form payload."""
    return any(call.encodes_a_form_field for call in client.calls)


def _run_function(client: PythonClient) -> list[str]:
    """Return the function that sends the recorded requests in order."""
    summary = (
        "Send the recorded requests in the order they were observed."
        if client.graph is None
        else "Send the recorded requests, reading on what each one is waiting for."
    )
    lines = [
        "def run(client: httpx.Client) -> list[httpx.Response]:",
        f'{_INDENT}"""{summary}"""',
    ]
    for call in client.calls:
        lines.append(f"{_INDENT}# {call.position}  {call.method} {call.url_without_query}")
        lines.extend(f"{_INDENT}# note: {note}" for note in call.notes)
        lines.append(textwrap.indent(call.code, _INDENT))
        for read in client.dependencies.read_after(call.position):
            lines.append("")
            lines.extend(
                textwrap.indent(line, _INDENT) for line in _read_lines(read, client.dependencies)
            )
        lines.append("")
    returned = ", ".join(call.variable for call in client.calls)
    lines.append(f"{_INDENT}return [{returned}]")
    return lines


def _read_lines(read: ResolvedDependency, resolution: DependencyResolution) -> list[str]:
    """Return the statement binding one value read out of the response just received."""
    sent_on = ", ".join(str(position) for position in resolution.targets_of(read.variable))
    return [
        f"# {read.source_location}, sent on by {sent_on}",
        f"{read.variable} = {_read_expression(read)}",
    ]


def _read_expression(read: ResolvedDependency) -> str:
    """Return the expression reading one value out of an httpx response."""
    response = f"{_RESPONSE_PREFIX}{read.source}"
    accessor = read.accessor
    if accessor.kind is AccessorKind.REDIRECT_URL:
        # The client does not follow redirects, so the target is read off the response
        # that carried it rather than from wherever it would have led.
        return f'{response}.headers["location"]'
    if accessor.kind is AccessorKind.HEADER:
        if accessor.index is None:
            return f"{response}.headers[{_string(accessor.name)}]"
        return f"{response}.headers.get_list({_string(accessor.name)})[{accessor.index}]"
    return f"{response}.json(){_steps_expression(accessor)}"


def _steps_expression(accessor: ResponseAccessor) -> str:
    """Return the subscripts leading to one field of a parsed payload."""
    return "".join(
        f"[{step}]" if isinstance(step, int) else f"[{_string(step)}]" for step in accessor.steps
    )


def _main_function() -> list[str]:
    """Return the entry point used when the module is run as a script."""
    return [
        "def main() -> None:",
        f'{_INDENT}"""Run the workflow and report what came back."""',
        f"{_INDENT}with httpx.Client() as client:",
        f"{_INDENT * 2}for response in run(client):",
        f"{_INDENT * 3}print(response.status_code, response.request.method, response.request.url)",
        "",
        "",
        'if __name__ == "__main__":',
        f"{_INDENT}main()",
    ]


def _summary(client: PythonClient, capture: Capture) -> list[str]:
    """Return the module docstring: the recording, what is reproduced, and what it needs."""
    metadata = capture.metadata
    lines = [
        f"Direct client for a workflow recorded {metadata.created_at.isoformat()} "
        f"(source: {metadata.source.value}).",
        "",
    ]
    if metadata.start_url is not None:
        lines.append(f"Recorded from {metadata.start_url}")
    lines.append(f"Reproducing {len(client)} of {_count(client.captured, 'captured request')}.")
    for rule, names in client.omitted_headers().items():
        lines.append(f"Left out ({HTTPX_OMISSION_REASONS[rule]}): {', '.join(names)}.")
    lines.extend(_workflow_lines(client))
    if client.secrets.is_empty:
        lines.append("")
        lines.append("The capture held no credentials, so nothing has to be exported.")
        return lines
    lines.append("")
    lines.append("Credentials were removed from the capture. Export them before running:")
    width = max(len(binding.variable) for binding in client.secrets)
    lines.extend(
        f"  {binding.variable.ljust(width)}  {binding.location}" for binding in client.secrets
    )
    return lines


def _workflow_lines(client: PythonClient) -> list[str]:
    """Return what the docstring says about the workflow, for a compiled client.

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
    """Return the docstring lines listing what the client reads while it runs."""
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
    """Return the docstring lines listing what the client could not read, and why."""
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


def _docstring(lines: list[str]) -> str:
    """Return ``lines`` as a module docstring.

    Backslashes and quotes are escaped even though a capture rarely puts either in its
    provenance, because a docstring that ends the literal early would not parse at all.
    """
    body = "\n".join(lines).replace("\\", "\\\\").replace('"', '\\"')
    return f'"""{body}\n"""'


def _count(number: int, noun: str) -> str:
    """Return ``number`` and ``noun``, pluralized the ordinary way."""
    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"
