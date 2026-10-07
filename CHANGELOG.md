# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-07

Initial public release. The full loop described in the README works end to end against
the deterministic local demo app, HAR archives, and a live browser recording:

### Added

- `trace2api record` captures Fetch and XHR traffic from a live browser session into a
  sanitized, inspectable local capture.
- `trace2api summary` and `trace2api inspect` read a saved capture or a HAR 1.2 archive,
  separating likely application requests from page assets, analytics, and other noise.
- `trace2api diff`, `trace2api classify`, and `trace2api paginate` compare two recordings
  of a workflow, classify every changed value as a constant, an input, a generated value,
  a secret, or unknown, and recognize page-number, offset, and cursor pagination.
- `trace2api graphql` reads a capture for the GraphQL operations it carries.
- `trace2api flow` and `trace2api graph` detect values a later request took from an
  earlier response and build a request dependency graph from those links.
- `trace2api generate` writes a capture out as a runnable cURL script, Python `httpx`
  module, or JavaScript `fetch` module, with every secret replaced by an environment
  variable reference.
- `trace2api compile` writes a Python client against the dependency graph instead of the
  raw recording, reading values a later request depends on back out of the responses that
  hand them out.
- `trace2api verify` replays a capture's requests and compares each response against what
  the browser observed by structure rather than by value; `trace2api test` writes the same
  check out as a Pytest regression module.
- `trace2api demo` serves a deterministic local order workflow app, and
  `trace2api benchmark` runs it both as a browser flow and as a compiled client against one
  freshly started instance to confirm they agree.
- Credential redaction covering headers, cookies, query parameters, JSON and form fields,
  URL userinfo, and token-shaped values found in text bodies, applied before any capture
  is persisted, displayed, or compiled into a client.
- Installable `trace2api` package with a `src/` layout, buildable to a wheel and an sdist,
  installable directly from the git repository with `pipx` or run ad hoc with `uvx`.

See the [Ticket Board](README.md#ticket-board) for the full list of tickets this release
closes.
