"""Write the requests a capture holds as a runnable cURL script.

cURL is the first output target because it is the one every reader can check by eye. A
generated script is meant to be run as it stands, so the rules it follows are the ones
that decide whether it works:

* The capture is redacted first, so no command can carry a credential. Each removed
  value becomes a reference to an environment variable, listed at the top of the script,
  and ``set -u`` stops the script rather than sending an empty one.
* Literal text is single quoted and secrets are interpolated as separate shell words, so
  a body full of braces, spaces, or dollar signs reaches the server as it was observed.
* Headers curl derives for itself are left out, because sending a stale
  ``Content-Length`` or a ``Host`` that disagrees with the URL breaks the request. Every
  omission names the rule behind it.

Unlike what ``trace2api inspect`` prints, the script carries full URLs including query
strings. A client that drops them does not reproduce the workflow, and the credentials
that hide in a query string have already been replaced by variable references.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum
from urllib.parse import unquote, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field

from trace2api.analyze.relevance import DEFAULT_KEPT, Relevance, classify_capture
from trace2api.generate.secrets import SecretBindings, bind_secrets
from trace2api.models import Body, Capture, Entry, Header
from trace2api.sanitize import redact_capture, split_secrets

__all__ = [
    "CurlCommand",
    "CurlScript",
    "HeaderOmission",
    "OmittedHeader",
    "generate_curl",
    "render_curl",
]

SHEBANG = "#!/bin/sh"
_INDENT = "  "
_CONTINUATION = " \\"

_READ_METHOD = "GET"


class HeaderOmission(StrEnum):
    """Why an observed header was left out of a generated command."""

    COMPUTED_BY_CURL = "computed-by-curl"
    HOP_BY_HOP = "hop-by-hop"
    PSEUDO_HEADER = "pseudo-header"
    NEGOTIATED_BY_CURL = "negotiated-by-curl"


_OMISSION_REASONS: dict[HeaderOmission, str] = {
    HeaderOmission.COMPUTED_BY_CURL: "curl derives it from the request itself",
    HeaderOmission.HOP_BY_HOP: "it describes one connection rather than the request",
    HeaderOmission.PSEUDO_HEADER: "it is an HTTP/2 pseudo header, not a real one",
    HeaderOmission.NEGOTIATED_BY_CURL: "--compressed asks for it on curl's own terms",
}

_COMPUTED_HEADERS = frozenset({"content-length", "host"})
_HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)
_ENCODING_HEADER = "accept-encoding"
_IDENTITY_ENCODING = "identity"


class OmittedHeader(BaseModel):
    """One observed header the command does not send, and the rule that dropped it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    rule: HeaderOmission

    @property
    def reason(self) -> str:
        """Return a one line explanation of the omission."""
        return _OMISSION_REASONS[self.rule]


class CurlCommand(BaseModel):
    """One observed request written as a curl invocation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entry_id: str
    position: int = Field(ge=1)
    """Where the request sits in the capture, matching what ``inspect`` numbers it."""

    method: str
    url_without_query: str
    code: str
    omitted_headers: list[OmittedHeader] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    """What the command cannot reproduce, such as a body the capture only sampled."""


class CurlScript(BaseModel):
    """A runnable script for the requests a capture kept, and what it took to write it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str
    commands: list[CurlCommand] = Field(default_factory=list)
    secrets: SecretBindings = Field(default_factory=SecretBindings)
    captured: int = Field(default=0, ge=0)
    """How many requests the capture held, including the ones filtered as noise."""

    def __len__(self) -> int:
        return len(self.commands)

    @property
    def skipped(self) -> int:
        """Return how many captured requests the script leaves out."""
        return self.captured - len(self.commands)

    def omitted_headers(self) -> dict[HeaderOmission, tuple[str, ...]]:
        """Return the header names left out across the script, grouped by rule."""
        grouped: dict[HeaderOmission, list[str]] = {}
        for command in self.commands:
            for omitted in command.omitted_headers:
                names = grouped.setdefault(omitted.rule, [])
                if omitted.name not in names:
                    names.append(omitted.name)
        return {rule: tuple(sorted(names)) for rule, names in sorted(grouped.items())}


def generate_curl(
    capture: Capture,
    *,
    keep: Iterable[Relevance] = DEFAULT_KEPT,
    salt: bytes | None = None,
) -> CurlScript:
    """Redact ``capture`` and write the requests worth keeping as a cURL script.

    Redaction runs first, so a script can never be written from an unsanitized capture.
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
    commands = [
        render_curl(entry, position=position, secrets=bindings)
        for position, entry in enumerate(sanitized.capture.entries, start=1)
        if verdicts[entry.id] in kept
    ]
    script = CurlScript(
        code="",
        commands=commands,
        secrets=bindings,
        captured=len(sanitized.capture),
    )
    return script.model_copy(update={"code": _render_script(script, sanitized.capture)})


def render_curl(entry: Entry, *, position: int, secrets: SecretBindings) -> CurlCommand:
    """Write one already redacted exchange as a curl invocation.

    The entry must come from a redacted capture. Passing a raw one would put whatever it
    holds into the generated command, which is why nothing outside this module calls it
    with an entry it did not sanitize.
    """
    request = entry.request
    headers, omitted = _partition_headers(request.headers)
    url, query_secrets = _url_with_visible_secrets(request.url)
    body, body_notes = _body_argument(request.body, secrets=secrets)
    notes = [
        f"{secrets.variable_for(fingerprint)} goes into the query string, "
        "so its value has to be URL encoded"
        for fingerprint in query_secrets
    ]
    notes.extend(body_notes)

    arguments = [_shell_word(url, secrets)]
    if request.method != _READ_METHOD or body is not None:
        arguments.append(f"--request {request.method}")
    arguments.extend(f"--header {_shell_word(_header_line(header), secrets)}" for header in headers)
    if any(item.rule is HeaderOmission.NEGOTIATED_BY_CURL for item in omitted):
        arguments.append("--compressed")
    if body is not None:
        arguments.append(body)

    return CurlCommand(
        entry_id=entry.id,
        position=position,
        method=request.method,
        url_without_query=request.url_without_query,
        code=_join_arguments(arguments),
        omitted_headers=omitted,
        notes=notes,
    )


def _url_with_visible_secrets(url: str) -> tuple[str, tuple[str, ...]]:
    """Return ``url`` with any redacted query value written plainly, and its fingerprint.

    Redaction rewrites a query string through ``urlencode``, which percent encodes the
    placeholder it just put there. Left that way the generated client would send the
    placeholder text as the value. Restoring the plain form here lets the same splicing
    that handles headers and bodies handle the query string too.

    Only a value that is entirely a placeholder is restored, and every other pair is
    carried over exactly as observed, so nothing else about the URL is re-encoded.
    """
    parts = urlsplit(url)
    if not parts.query:
        return url, ()
    fingerprints: list[str] = []
    pairs: list[str] = []
    for pair in parts.query.split("&"):
        name, separator, value = pair.partition("=")
        segments = split_secrets(unquote(value)) if separator else ()
        if len(segments) == 1 and segments[0].is_secret:
            fingerprints.append(segments[0].fingerprint or "")
            pairs.append(f"{name}={segments[0].text}")
        else:
            pairs.append(pair)
    if not fingerprints:
        return url, ()
    restored = urlunsplit((parts.scheme, parts.netloc, parts.path, "&".join(pairs), parts.fragment))
    return restored, tuple(fingerprints)


def _partition_headers(headers: Iterable[Header]) -> tuple[list[Header], list[OmittedHeader]]:
    """Split observed headers into the ones to send and the ones curl handles itself."""
    sent: list[Header] = []
    omitted: list[OmittedHeader] = []
    for header in headers:
        rule = _omission_rule(header)
        if rule is None:
            sent.append(header)
        else:
            omitted.append(OmittedHeader(name=header.name, rule=rule))
    return sent, omitted


def _omission_rule(header: Header) -> HeaderOmission | None:
    """Return why ``header`` must not be sent as observed, or ``None`` to send it."""
    name = header.name.strip().lower()
    if name.startswith(":"):
        return HeaderOmission.PSEUDO_HEADER
    if name in _COMPUTED_HEADERS:
        return HeaderOmission.COMPUTED_BY_CURL
    if name in _HOP_BY_HOP_HEADERS:
        return HeaderOmission.HOP_BY_HOP
    if name == _ENCODING_HEADER and header.value.strip().lower() != _IDENTITY_ENCODING:
        return HeaderOmission.NEGOTIATED_BY_CURL
    return None


def _header_line(header: Header) -> str:
    """Return the header as curl expects it, spelled the way it was observed."""
    return f"{header.name}: {header.value}"


def _body_argument(body: Body | None, *, secrets: SecretBindings) -> tuple[str | None, list[str]]:
    """Return the data argument for ``body``, and what the command cannot reproduce."""
    if body is None or body.is_empty:
        return None, []
    notes: list[str] = []
    if body.truncated:
        notes.append("the capture recorded only part of this body, so the request is incomplete")
    if body.encoding == "base64":
        size = body.size if body.size is not None else len(body.as_bytes())
        notes.append(f"a binary body of {size} bytes was observed here and is not reproduced")
        return None, notes
    return f"--data-raw {_shell_word(body.text or '', secrets)}", notes


def _shell_word(text: str, secrets: SecretBindings) -> str:
    """Return ``text`` as one shell word, with removed secrets read from the environment.

    Literal runs are single quoted so nothing in them is expanded, and each secret is a
    double quoted variable reference spliced into the same word. Concatenating quoted
    pieces this way is ordinary shell, and it keeps a value with spaces in it whole.
    """
    parts = []
    for segment in split_secrets(text):
        if segment.is_secret:
            parts.append(f'"${secrets.variable_for(segment.fingerprint or "")}"')
        elif segment.text:
            parts.append(_single_quote(segment.text))
    return "".join(parts) or "''"


def _single_quote(text: str) -> str:
    """Return ``text`` inside single quotes, ending and reopening them around a quote."""
    escaped = text.replace("'", "'\\''")
    return f"'{escaped}'"


def _join_arguments(arguments: list[str]) -> str:
    """Return a curl invocation with one argument per line."""
    lines = [f"curl {arguments[0]}"] + [f"{_INDENT}{argument}" for argument in arguments[1:]]
    return "\n".join(
        line + _CONTINUATION if index < len(lines) - 1 else line for index, line in enumerate(lines)
    )


def _render_script(script: CurlScript, capture: Capture) -> str:
    """Return the whole script: what it came from, what it needs, and the commands."""
    lines = [SHEBANG]
    lines.extend(_preamble(script, capture))
    lines.append("set -eu")
    for command in script.commands:
        lines.append("")
        lines.append(f"# {command.position}  {command.method} {command.url_without_query}")
        lines.extend(f"# note: {note}" for note in command.notes)
        lines.append(command.code)
    return "\n".join(lines) + "\n"


def _preamble(script: CurlScript, capture: Capture) -> list[str]:
    """Return the comment block above the commands."""
    metadata = capture.metadata
    lines = [
        f"# Direct client for a workflow recorded {metadata.created_at.isoformat()} "
        f"(source: {metadata.source.value})."
    ]
    if metadata.start_url is not None:
        lines.append(f"# Recorded from {metadata.start_url}")
    lines.append(f"# Reproducing {len(script)} of {_count(script.captured, 'captured request')}.")
    for rule, names in script.omitted_headers().items():
        lines.append(f"# Left out ({_OMISSION_REASONS[rule]}): {', '.join(names)}.")
    if script.secrets.is_empty:
        lines.append("# The capture held no credentials, so nothing has to be exported.")
        return lines
    lines.append("#")
    lines.append("# Credentials were removed from the capture. Export them before running:")
    width = max(len(binding.variable) for binding in script.secrets)
    lines.extend(
        f"#   {binding.variable.ljust(width)}  {binding.location}" for binding in script.secrets
    )
    return lines


def _count(number: int, noun: str) -> str:
    """Return ``number`` and ``noun``, pluralized the ordinary way."""
    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"
