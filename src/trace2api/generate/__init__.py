"""Turning an analyzed capture into ordinary source code.

Each target in this package writes the same requests in a different language. They share
two rules. A capture is redacted before a single line is written, so generated code
cannot carry a credential, and every secret the workflow needed becomes a reference to
an environment variable named after where the value came from.

The output is meant to be read and edited by hand: no runtime to install, no
project-specific abstractions, nothing that has to be kept in step with Trace2API.
"""

from __future__ import annotations

from trace2api.generate.curl import (
    CurlCommand,
    CurlScript,
    generate_curl,
)
from trace2api.generate.headers import HeaderRule, OmittedHeader
from trace2api.generate.python import (
    PythonCall,
    PythonClient,
    generate_python,
)
from trace2api.generate.secrets import (
    ENVIRONMENT_PREFIX,
    SecretBinding,
    SecretBindings,
    bind_secrets,
    environment_variable,
)

__all__ = [
    "ENVIRONMENT_PREFIX",
    "CurlCommand",
    "CurlScript",
    "HeaderRule",
    "OmittedHeader",
    "PythonCall",
    "PythonClient",
    "SecretBinding",
    "SecretBindings",
    "bind_secrets",
    "environment_variable",
    "generate_curl",
    "generate_python",
]
