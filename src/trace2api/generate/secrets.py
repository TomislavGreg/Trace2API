"""Give the credentials a capture held somewhere to come back from at run time.

Redaction takes a secret out of a capture and leaves a placeholder carrying a
fingerprint of the value, so a token reused across several requests still reads as one
value. Generated code needs the other half of that arrangement: a name the value can be
supplied under when the client actually runs.

Each fingerprint is bound to one environment variable, named after the place the value
was taken from, so the export list reads as an account of what the workflow needed:
``TRACE2API_AUTHORIZATION`` for an ``Authorization`` header, ``TRACE2API_COOKIE_SESSION``
for a ``session`` cookie. Two requests carrying the same token share one variable,
because they shared one value.

Only request side secrets are bound. A ``Set-Cookie`` value a server sent back is not
something a client supplies, and offering a variable for it would suggest otherwise.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from pydantic import BaseModel, ConfigDict, Field

from trace2api.sanitize import RedactionReport

__all__ = [
    "ENVIRONMENT_PREFIX",
    "SecretBinding",
    "SecretBindings",
    "bind_secrets",
    "environment_variable",
]

ENVIRONMENT_PREFIX = "TRACE2API_"
"""Prefix on every generated variable name, so a client's needs stand out in an env."""

_REQUEST_LOCATION = "request."
_FALLBACK_NAME = "SECRET"


class SecretBinding(BaseModel):
    """One removed value and the environment variable that supplies it again."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    fingerprint: str
    variable: str
    location: str
    """Where the value was first observed, such as ``request.headers.authorization``."""


class SecretBindings(BaseModel):
    """Every secret a generated client has to be given, in the order first observed."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    bindings: list[SecretBinding] = Field(default_factory=list)

    def __iter__(self) -> Iterator[SecretBinding]:  # type: ignore[override]
        return iter(self.bindings)

    def __len__(self) -> int:
        return len(self.bindings)

    @property
    def is_empty(self) -> bool:
        """Return whether the client needs no secrets at all."""
        return not self.bindings

    def variable_for(self, fingerprint: str) -> str:
        """Return the variable supplying ``fingerprint``.

        A fingerprint with no binding still gets a usable name rather than an error: the
        alternative is generated code that quietly drops a value the request needed.
        """
        for binding in self.bindings:
            if binding.fingerprint == fingerprint:
                return binding.variable
        return f"{ENVIRONMENT_PREFIX}{_FALLBACK_NAME}_{fingerprint.upper()}"


def bind_secrets(report: RedactionReport) -> SecretBindings:
    """Bind every request side value in ``report`` to an environment variable."""
    bindings: list[SecretBinding] = []
    seen: dict[str, str] = {}
    taken: set[str] = set()
    for redaction in report.redactions:
        if not redaction.location.startswith(_REQUEST_LOCATION):
            continue
        if redaction.fingerprint in seen:
            continue
        variable = _unique(environment_variable(redaction.location), taken)
        seen[redaction.fingerprint] = variable
        taken.add(variable)
        bindings.append(
            SecretBinding(
                fingerprint=redaction.fingerprint,
                variable=variable,
                location=redaction.location,
            )
        )
    return SecretBindings(bindings=bindings)


def environment_variable(location: str) -> str:
    """Return the variable name for a value taken from ``location``.

    The last part of the location names the value: ``request.headers.cookie[session]``
    becomes ``TRACE2API_COOKIE_SESSION``. Deeper structure is dropped because a body
    field is recognizable from its own name, and the full location is reported alongside
    the variable anyway.
    """
    name = location.rsplit(".", 1)[-1]
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper()
    return f"{ENVIRONMENT_PREFIX}{normalized or _FALLBACK_NAME}"


def _unique(variable: str, taken: set[str]) -> str:
    """Return ``variable``, numbered if two different values want the same name."""
    if variable not in taken:
        return variable
    suffix = 2
    while f"{variable}_{suffix}" in taken:
        suffix += 1
    return f"{variable}_{suffix}"
