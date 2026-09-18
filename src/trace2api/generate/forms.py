"""Read a form encoded payload the way a generated client has to send it.

A form payload is a query string that travels in the body, and redaction rewrites one
the way it rewrites a query string: the credential is replaced and the payload is encoded
again. That last step percent encodes the placeholder along with everything else, so
``<redacted:d5df841f>`` is stored as ``%3Credacted%3Ad5df841f%3E``. The generators look
for the placeholder in the text they are handed and no longer find it there, so a client
written from that text sends the placeholder to the server and leaves the credential it
asked to be exported unused.

Reading the payload field by field is what answers it. A field whose value is entirely a
placeholder is the one place a generated client has to write something of its own, and
the value it writes has to be encoded, because what comes back from the environment is
the credential itself rather than an encoded form of it.

Every other field is handed back exactly as the payload spells it, so a generated client
changes only the field it had to supply and sends the rest as the capture holds them. A
client that re-encodes what it was not asked to change sends a payload the server never
saw, and the point of a generated client is that its request can be compared with the
observed one.
"""

from __future__ import annotations

from typing import NamedTuple
from urllib.parse import unquote_plus

from trace2api.models import Body
from trace2api.sanitize import split_secrets

__all__ = [
    "FORM_MEDIA_TYPE",
    "FormField",
    "form_fields",
    "form_secrets",
]

FORM_MEDIA_TYPE = "application/x-www-form-urlencoded"


class FormField(NamedTuple):
    """One field of a form encoded payload, as the payload spelled it."""

    name: str
    """The field name, still encoded the way it was sent."""

    spelled: str
    """The whole ``name=value`` pair, exactly as the payload spelled it."""

    fingerprint: str | None = None
    """Set when the value is a credential the client has to supply and encode."""

    @property
    def is_secret(self) -> bool:
        """Return whether this field's value was removed by redaction."""
        return self.fingerprint is not None


def form_fields(body: Body | None) -> list[FormField] | None:
    """Return the fields of ``body``, or ``None`` when it is not a form payload.

    A payload recorded as base64 is not decoded here. A binary body is left as observed
    everywhere else too, because locating anything in one means reading a format this
    project does not claim to understand.
    """
    if body is None or body.is_empty or body.encoding is not None:
        return None
    if body.media_type != FORM_MEDIA_TYPE:
        return None
    return [_field(pair) for pair in (body.text or "").split("&")]


def form_secrets(fields: list[FormField]) -> tuple[str, ...]:
    """Return the fingerprints of the credentials ``fields`` carry, in the order sent."""
    return tuple(field.fingerprint or "" for field in fields if field.is_secret)


def _field(pair: str) -> FormField:
    """Read one ``name=value`` pair, noticing a value redaction replaced whole.

    Only a value that is nothing but a placeholder is recognized. Redaction replaces the
    whole value of a form field, so that is the shape a credential arrives in, and a field
    this cannot account for is left to be sent as observed rather than guessed at.
    """
    name, separator, value = pair.partition("=")
    if not separator:
        return FormField(name, pair)
    segments = split_secrets(unquote_plus(value))
    if len(segments) == 1 and segments[0].is_secret:
        return FormField(name, pair, segments[0].fingerprint)
    return FormField(name, pair)
