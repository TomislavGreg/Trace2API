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
* A query string holding a credential is rebuilt through `URLSearchParams`, so the
  supplied value is encoded. Every other URL is written whole, exactly as observed.
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
"""

from __future__ import annotations

import json
import textwrap
from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict, Field

from trace2api.analyze.relevance import DEFAULT_KEPT, Relevance, classify_capture
from trace2api.generate.headers import HeaderRule, OmittedHeader, partition_headers
from trace2api.generate.secrets import SecretBindings, bind_secrets
from trace2api.models import Body, Capture, Entry, Header, Request
from trace2api.sanitize import redact_capture, split_secrets

__all__ = [
    "FETCH_OMISSION_REASONS",
    "JavaScriptCall",
    "JavaScriptClient",
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
    bindings = bind_secrets(sanitized.report)
    kept = frozenset(keep)
    verdicts = {
        item.entry_id: item.relevance
        for item in classify_capture(sanitized.capture).classifications
    }
    calls = [
        render_call(entry, position=position, secrets=bindings)
        for position, entry in enumerate(sanitized.capture.entries, start=1)
        if verdicts[entry.id] in kept
    ]
    client = JavaScriptClient(
        code="",
        calls=calls,
        secrets=bindings,
        captured=len(sanitized.capture),
    )
    return client.model_copy(update={"code": _render_module(client, sanitized.capture)})


def render_call(entry: Entry, *, position: int, secrets: SecretBindings) -> JavaScriptCall:
    """Write one already redacted exchange as a fetch call.

    The entry must come from a redacted capture. Passing a raw one would put whatever it
    holds into the generated code, which is why nothing outside this module calls it with
    an entry it did not sanitize.
    """
    request = entry.request
    headers, omitted = partition_headers(request.headers, FETCH_OMISSION_REASONS)
    url_lines, url, query_secrets = _url_expression(request, secrets, position=position)
    body, notes = _body_property(request, secrets=secrets)
    variable = f"{_RESPONSE_PREFIX}{position}"

    options = [f"method: {_string(request.method)}"]
    if headers:
        options.append(f"headers: {_headers_value(headers, secrets)}")
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
        + notes,
    )


def _url_expression(
    request: Request, secrets: SecretBindings, *, position: int
) -> tuple[list[str], str, tuple[str, ...]]:
    """Return the statements building the URL, the expression to fetch, and its secrets.

    A URL with nothing removed from its query string is written whole, so the request
    goes out spelled the way it was observed. A query string that held a credential
    cannot be: the value comes back from the environment unencoded, so the parameters are
    rebuilt through ``URLSearchParams`` and encoded by it.
    """
    query = request.query
    fingerprints = tuple(
        segment.fingerprint or ""
        for parameter in query
        for segment in split_secrets(parameter.value)
        if segment.is_secret
    )
    if not fingerprints:
        return [], _string(request.url), ()
    variable = f"{_URL_PREFIX}{position}"
    pairs = [
        _pair(_string(parameter.name), _expression(parameter.value, secrets)) for parameter in query
    ]
    statements = [
        f"const {variable} = new URL({_string(request.url_without_query)});",
        f"{variable}.search = new URLSearchParams({_block('[', pairs, ']')}).toString();",
    ]
    return statements, variable, fingerprints


def _headers_value(headers: list[Header], secrets: SecretBindings) -> str:
    """Return the headers as an object, or as pairs when the request repeated a name.

    An object is what a reader would have written, but it cannot hold a name twice, and a
    request that sent one header twice meant it.
    """
    if _repeats_a_name(headers):
        pairs = [
            _pair(_string(header.name), _expression(header.value, secrets)) for header in headers
        ]
        return _block("[", pairs, "]")
    entries = [
        f"{_string(header.name)}: {_expression(header.value, secrets)}" for header in headers
    ]
    return _block("{", entries, "}")


def _repeats_a_name(headers: list[Header]) -> bool:
    """Return whether two of ``headers`` carry the same name."""
    names = [header.name.strip().lower() for header in headers]
    return len(set(names)) != len(names)


def _body_property(request: Request, *, secrets: SecretBindings) -> tuple[str | None, list[str]]:
    """Return the body property for ``request``, and what the call cannot reproduce."""
    body: Body | None = request.body
    if body is None or body.is_empty:
        return None, []
    notes: list[str] = []
    if body.truncated:
        notes.append("the capture recorded only part of this body, so the request is incomplete")
    if body.encoding == "base64":
        size = body.size if body.size is not None else len(body.as_bytes())
        notes.append(f"a binary body of {size} bytes was observed here and is not reproduced")
        return None, notes
    if request.method in _BODILESS_METHODS:
        # Sending one throws a TypeError before the request leaves, so the client would
        # not run at all. Reporting the body is the only faithful thing left to do.
        notes.append(
            f"fetch cannot send a body with a {request.method} request, "
            "so the observed body is not reproduced"
        )
        return None, notes
    return _expression(body.text or "", secrets), notes


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
    lines = [
        "// Sends the recorded requests in the order they were observed.",
        "export async function run() {",
    ]
    for call in client.calls:
        lines.append(f"{_INDENT}// {call.position}  {call.method} {call.url_without_query}")
        lines.extend(f"{_INDENT}// note: {note}" for note in call.notes)
        lines.append(textwrap.indent(call.code, _INDENT))
        lines.append("")
    returned = ", ".join(call.variable for call in client.calls)
    lines.append(f"{_INDENT}return [{returned}];")
    lines.append("}")
    return lines


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
