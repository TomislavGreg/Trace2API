"""Turning an analyzed capture into ordinary source code.

Each target in this package writes the same requests in a different language. They share
two rules. A capture is redacted before a single line is written, so generated code
cannot carry a credential, and every secret the workflow needed becomes a reference to
an environment variable named after where the value came from.

The output is meant to be read and edited by hand: no runtime to install, no
project-specific abstractions, nothing that has to be kept in step with Trace2API.

`dependencies.py` sits beside the targets rather than among them. It answers, for each
value a request took from an earlier response, whether a client can read that value back
while it runs and where it would have to look, in terms no language appears in, so a
target can write the answer without deciding it.

`forms.py` sits there for the same reason. It reads a form encoded payload field by
field, so a target can send a credential through whatever encodes values for it rather
than splicing the supplied value into a payload that was already encoded.
"""

from __future__ import annotations

from trace2api.generate.curl import (
    CurlCommand,
    CurlScript,
    generate_curl,
)
from trace2api.generate.dependencies import (
    AccessorKind,
    DependencyResolution,
    ResolvedDependency,
    ResponseAccessor,
    SiteKind,
    SubstitutionSite,
    UnresolvedDependency,
    resolve_dependencies,
)
from trace2api.generate.forms import (
    FORM_MEDIA_TYPE,
    FormField,
    form_field_places,
    form_fields,
    form_secrets,
)
from trace2api.generate.headers import HeaderRule, OmittedHeader
from trace2api.generate.javascript import (
    JavaScriptCall,
    JavaScriptClient,
    generate_javascript,
)
from trace2api.generate.python import (
    PythonCall,
    PythonClient,
    compile_python,
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
    "FORM_MEDIA_TYPE",
    "AccessorKind",
    "CurlCommand",
    "CurlScript",
    "DependencyResolution",
    "FormField",
    "HeaderRule",
    "JavaScriptCall",
    "JavaScriptClient",
    "OmittedHeader",
    "PythonCall",
    "PythonClient",
    "ResolvedDependency",
    "ResponseAccessor",
    "SecretBinding",
    "SecretBindings",
    "SiteKind",
    "SubstitutionSite",
    "UnresolvedDependency",
    "bind_secrets",
    "compile_python",
    "environment_variable",
    "form_field_places",
    "form_fields",
    "form_secrets",
    "generate_curl",
    "generate_javascript",
    "generate_python",
    "resolve_dependencies",
]
