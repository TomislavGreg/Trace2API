"""Which observed headers a generated client must not send as they were observed.

Every output target meets the same problem. A capture records headers the browser's HTTP
stack set for itself, and replaying them verbatim either breaks the request or
contradicts it: a ``Content-Length`` describes a body the generated client may have
changed, a ``Host`` copied out of the capture can disagree with the URL the client is
given, hop by hop headers describe a connection that no longer exists, and an
``Accept-Encoding`` asks for a compression the client is the one that has to undo.

The rules live here because they follow from HTTP rather than from any one language.
What differs per target is only the wording, so each target supplies its own explanation
for a rule and the omission carries that explanation with it.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from trace2api.models import Header

__all__ = [
    "HeaderRule",
    "OmittedHeader",
    "omission_rule",
    "partition_headers",
]


class HeaderRule(StrEnum):
    """Why an observed header cannot be replayed as it stands."""

    COMPUTED_BY_CLIENT = "computed-by-client"
    HOP_BY_HOP = "hop-by-hop"
    PSEUDO_HEADER = "pseudo-header"
    NEGOTIATED_BY_CLIENT = "negotiated-by-client"


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
    """One observed header a generated client does not send, and why."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    rule: HeaderRule
    reason: str
    """The explanation in the target's own terms, such as what curl derives itself."""


def partition_headers(
    headers: Iterable[Header], reasons: Mapping[HeaderRule, str]
) -> tuple[list[Header], list[OmittedHeader]]:
    """Split observed headers into the ones to send and the ones the client handles.

    ``reasons`` gives the target's wording for each rule, so an omission can be read
    without knowing which rule numbers mean what.
    """
    sent: list[Header] = []
    omitted: list[OmittedHeader] = []
    for header in headers:
        rule = omission_rule(header)
        if rule is None:
            sent.append(header)
        else:
            omitted.append(OmittedHeader(name=header.name, rule=rule, reason=reasons[rule]))
    return sent, omitted


def omission_rule(header: Header) -> HeaderRule | None:
    """Return why ``header`` must not be sent as observed, or ``None`` to send it."""
    name = header.name.strip().lower()
    if name.startswith(":"):
        return HeaderRule.PSEUDO_HEADER
    if name in _COMPUTED_HEADERS:
        return HeaderRule.COMPUTED_BY_CLIENT
    if name in _HOP_BY_HOP_HEADERS:
        return HeaderRule.HOP_BY_HOP
    if name == _ENCODING_HEADER and header.value.strip().lower() != _IDENTITY_ENCODING:
        return HeaderRule.NEGOTIATED_BY_CLIENT
    return None
