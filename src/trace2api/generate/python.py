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
* A query string holding a credential is sent as ``params``, so httpx encodes the
  supplied value. Every other URL is written whole, exactly as observed.
* Headers httpx sets for itself are left out, because sending a stale ``Content-Length``
  or a ``Host`` that disagrees with the URL breaks the request. Every omission names the
  rule behind it.

The generated client sends the requests one at a time in the order they were observed
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
    "HTTPX_OMISSION_REASONS",
    "PythonCall",
    "PythonClient",
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


class PythonClient(BaseModel):
    """A runnable module for the requests a capture kept, and what it took to write it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str
    calls: list[PythonCall] = Field(default_factory=list)
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
    client = PythonClient(
        code="",
        calls=calls,
        secrets=bindings,
        captured=len(sanitized.capture),
    )
    return client.model_copy(update={"code": _render_module(client, sanitized.capture)})


def render_call(entry: Entry, *, position: int, secrets: SecretBindings) -> PythonCall:
    """Write one already redacted exchange as an httpx call.

    The entry must come from a redacted capture. Passing a raw one would put whatever it
    holds into the generated code, which is why nothing outside this module calls it with
    an entry it did not sanitize.
    """
    request = entry.request
    headers, omitted = partition_headers(request.headers, HTTPX_OMISSION_REASONS)
    url, params, query_secrets = _url_arguments(request, secrets)
    content, notes = _content_argument(request.body, secrets=secrets)
    variable = f"{_RESPONSE_PREFIX}{position}"

    arguments = [_string(request.method), url]
    if params is not None:
        arguments.append(f"params={params}")
    if headers:
        arguments.append(f"headers={_headers_argument(headers, secrets)}")
    if content is not None:
        arguments.append(f"content={content}")

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
        + notes,
    )


def _url_arguments(
    request: Request, secrets: SecretBindings
) -> tuple[str, str | None, tuple[str, ...]]:
    """Return the URL argument, any ``params`` argument, and the secrets in the query.

    A URL with nothing removed from its query string is written whole, so the request
    goes out spelled the way it was observed. A query string that held a credential
    cannot be: the value comes back from the environment unencoded, so the parameters are
    handed to httpx separately and encoded by it.
    """
    query = request.query
    fingerprints = tuple(
        segment.fingerprint or ""
        for parameter in query
        for segment in split_secrets(parameter.value)
        if segment.is_secret
    )
    if not fingerprints:
        return _string(request.url), None, ()
    pairs = [
        f"({_string(parameter.name)}, {_expression(parameter.value, secrets)})"
        for parameter in query
    ]
    return _string(request.url_without_query), _sequence("[", pairs, "]"), fingerprints


def _headers_argument(headers: list[Header], secrets: SecretBindings) -> str:
    """Return the headers as a dict, or as pairs when the request repeated a name.

    A dict is what a reader would have written, but it cannot hold a name twice, and a
    request that sent one header twice meant it.
    """
    if _repeats_a_name(headers):
        pairs = [
            f"({_string(header.name)}, {_expression(header.value, secrets)})" for header in headers
        ]
        return _sequence("[", pairs, "]")
    entries = [
        f"{_string(header.name)}: {_expression(header.value, secrets)}" for header in headers
    ]
    return _sequence("{", entries, "}")


def _repeats_a_name(headers: list[Header]) -> bool:
    """Return whether two of ``headers`` carry the same name."""
    names = [header.name.strip().lower() for header in headers]
    return len(set(names)) != len(names)


def _content_argument(
    body: Body | None, *, secrets: SecretBindings
) -> tuple[str | None, list[str]]:
    """Return the body argument, and what the call cannot reproduce."""
    if body is None or body.is_empty:
        return None, []
    notes: list[str] = []
    if body.truncated:
        notes.append("the capture recorded only part of this body, so the request is incomplete")
    if body.encoding == "base64":
        size = body.size if body.size is not None else len(body.as_bytes())
        notes.append(f"a binary body of {size} bytes was observed here and is not reproduced")
        return None, notes
    return _expression(body.text or "", secrets), notes


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
    if not client.secrets.is_empty:
        lines.extend(["", "import os"])
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


def _run_function(client: PythonClient) -> list[str]:
    """Return the function that sends the recorded requests in order."""
    lines = [
        "def run(client: httpx.Client) -> list[httpx.Response]:",
        f'{_INDENT}"""Send the recorded requests in the order they were observed."""',
    ]
    for call in client.calls:
        lines.append(f"{_INDENT}# {call.position}  {call.method} {call.url_without_query}")
        lines.extend(f"{_INDENT}# note: {note}" for note in call.notes)
        lines.append(textwrap.indent(call.code, _INDENT))
        lines.append("")
    returned = ", ".join(call.variable for call in client.calls)
    lines.append(f"{_INDENT}return [{returned}]")
    return lines


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
