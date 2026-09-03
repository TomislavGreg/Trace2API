# Trace2API

Turn an observed browser network workflow into clean, reusable direct HTTP client code.

Browsers already know how to talk to the APIs behind the pages they render. Trace2API
watches a workflow, works out which requests actually matter, which values are inputs,
which values are generated, and how later requests depend on earlier responses, then
emits ordinary source code that reproduces the same result without the browser.

The target experience:

```text
trace2api record
    -> perform a browser workflow
    -> capture relevant Fetch/XHR traffic
    -> remove noise
    -> identify the request chain
    -> infer inputs and dependencies
    -> generate a direct client
    -> replay it
    -> verify the result
```

Planned output targets are cURL, Python using `httpx`, and JavaScript using `fetch`.

Trace2API is intended for authorized development, testing, debugging, integration work,
and permitted data access against systems the operator is allowed to use.

## Status

Early development. The package scaffold, the CLI entry point, the core traffic models,
credential redaction, HAR import, and relevance filtering exist. The remaining analysis,
generation, and verification stages described above are not implemented yet, and no
command exposes any of this yet. The Roadmap and Ticket Board below track what is real
and what is planned.

## Installation

Trace2API is not published to PyPI yet. Install from a clone:

```console
$ git clone https://github.com/TomislavGreg/Trace2API.git
$ cd Trace2API
$ python -m venv .venv
$ . .venv/bin/activate
$ python -m pip install -e .
```

Python 3.12 or newer is required.

## Quick start

Today the CLI exposes its entry point and reports its version. That is the whole of it.

```console
$ trace2api --help

 Usage: trace2api [OPTIONS] COMMAND [ARGS]...

 Turn observed browser network workflows into clean, reusable direct HTTP
 client code. Analysis runs locally.

╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                  │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ───────────────────────────────────────────────────────────────────╮
│ version  Print the installed Trace2API version.                              │
╰──────────────────────────────────────────────────────────────────────────────╯

$ trace2api version
0.0.1
```

## Current Capabilities

- Installable `trace2api` package with a `src/` layout.
- `trace2api --help` and `trace2api version`.
- Typed traffic models for requests, responses, headers, query parameters, bodies,
  timings, entries, and capture metadata, with case insensitive header lookup, URL
  derived query parameters, validation of what cannot be replayed later, and JSON round
  tripping.
- Credential redaction over a capture, covering credential headers, cookie values,
  `Authorization` style values, credential named query parameters, JSON and form fields,
  URL userinfo, and token shaped values, with a report of what was removed by location
  and rule.
- HAR 1.2 import from a file or an already parsed document, covering requests,
  responses, headers, payloads, timings, and resource types, with failures that name the
  position in the archive that caused them. Available as a library function; no command
  exposes it yet.
- Relevance filtering that separates page assets, analytics hosts, and reporting
  endpoints from likely application requests, with every verdict naming the rule behind
  it and what the rule matched. Requests no rule recognizes are kept rather than dropped.
  Available as a library function; no command exposes it yet.
- Ruff format, Ruff lint, and Pytest configuration.
- GitHub Actions CI running the same checks on Python 3.12.

Nothing beyond this list works yet. Capabilities are added here only once the
functionality lands.

## Design principles

- Local first. Core operation must not require uploading captures or credentials.
- Deterministic analysis first. Model assisted analysis may later be optional, never
  required for basic operation.
- Output ordinary source code with no platform lock-in.
- Prefer explainable inference over opaque guesses.
- Verification is part of the product, not an afterthought.
- Conservative security defaults.
- Documented claims match working functionality.

## Security and privacy

Captures contain credentials by nature. Trace2API treats that as a primary constraint:

- Secrets are redacted before anything is persisted, displayed, logged, or written into
  a generated client. A secret is replaced by a placeholder rather than deleted, so a
  token reused across several requests still reads as one value to the analysis stages
  while the value itself is gone.
- Redaction is name based and shape based, so every removal can be explained by the rule
  that caused it. It reports what it removed by location and rule, never by value.
- Bodies that cannot be parsed, such as binary payloads and unknown text formats, are
  left as observed rather than blanked, because the analysis stages read them. A secret
  in such a body is removed only where it also appears in a header, a query string, or a
  structured field.
- Generated clients read secrets from environment variables rather than embedding them.
- Analysis runs on the local machine. No capture is uploaded.
- This repository contains only synthetic or deliberately public test material. Real
  captures, cookies, tokens, browser profiles, and `.env` files are excluded by
  `.gitignore` and must never be committed.

Out of scope by design: bot defense evasion, CAPTCHA solving, credential theft,
fingerprint spoofing, stealth features, and anything whose main purpose is bypassing
access controls.

## Roadmap

### Phase 0: Foundation

Package scaffold, core traffic models, and secret redaction.

### Phase 1: HAR to code

Import HAR 1.2, filter noise, inspect a capture, and generate cURL, Python `httpx`, and
JavaScript `fetch` clients.

### Phase 2: Live capture

Record Fetch and XHR traffic from a real browser session into a sanitized local capture,
with a summary of what was kept and what was filtered.

### Phase 3: Differential inference

Diff equivalent captures, classify changed values, detect values flowing from one
response into later requests, build a dependency graph, and compile a multi-request
client from it.

### Phase 4: Replay and verification

Replay sanitized requests with explicit secret injection, compare observed and replayed
responses, explain mismatches, and emit a regression test.

### Phase 5: Protocol intelligence

Pagination, GraphQL, auth and CSRF dependencies, and an optional model provider
interface for ambiguous naming.

### Phase 6: Public release quality

A deterministic local demo app, a reproducible benchmark, a verified end to end demo,
packaging polish, and the v0.1 release.

## Ticket Board

Statuses: Backlog, Ready, In Progress, Review, Blocked, Done.

### Phase 0: Foundation

| Ticket | Description | Status | Depends on |
| --- | --- | --- | --- |
| T2A-001 | Package scaffold and CLI entry point. `trace2api --help`, tests, and CI work. | Done | |
| T2A-002 | Core traffic models for requests, responses, headers, bodies, timing, and capture metadata. | Done | T2A-001 |
| T2A-003 | Secret redaction before persistence or display, with focused tests. | Done | T2A-002 |

### Phase 1: HAR to code

| Ticket | Description | Status | Depends on |
| --- | --- | --- | --- |
| T2A-004 | HAR 1.2 importer into internal models with clear validation errors. | Done | T2A-002, T2A-003 |
| T2A-005 | Deterministic filtering for obvious assets, analytics, telemetry, and likely application requests. | Done | T2A-004 |
| T2A-006 | `inspect` command showing method, host, path, status, type, and relevance. | Ready | T2A-005 |
| T2A-007 | Sanitized runnable cURL generator. | Ready | T2A-004, T2A-003 |
| T2A-008 | Sanitized runnable Python `httpx` generator. | Backlog | T2A-007 |
| T2A-009 | Sanitized runnable JavaScript `fetch` generator. | Backlog | T2A-007 |

### Phase 2: Live capture

| Ticket | Description | Status | Depends on |
| --- | --- | --- | --- |
| T2A-010 | Browser Fetch/XHR recorder using Playwright or CDP. | Ready | T2A-002 |
| T2A-011 | `trace2api record` produces a sanitized inspectable local capture. | Backlog | T2A-010, T2A-003 |
| T2A-012 | Capture summary with total requests, filtered noise, likely application requests, and content types. | Backlog | T2A-011, T2A-005 |

### Phase 3: Differential inference

| Ticket | Description | Status | Depends on |
| --- | --- | --- | --- |
| T2A-013 | Diff equivalent captures and identify changed request values. | Ready | T2A-004 |
| T2A-014 | Classify changed values as likely inputs, constants, generated values, or unknowns using explainable rules. | Backlog | T2A-013 |
| T2A-015 | Detect values flowing from one response into later URLs, headers, query strings, or bodies. | Ready | T2A-004 |
| T2A-016 | Build and display a request dependency graph. | Backlog | T2A-015 |
| T2A-017 | Compile a direct multi-request client from the inferred graph. | Backlog | T2A-016, T2A-014, T2A-008 |

### Phase 4: Replay and verification

| Ticket | Description | Status | Depends on |
| --- | --- | --- | --- |
| T2A-018 | Replay sanitized request definitions with explicit secret injection. | Ready | T2A-004, T2A-003 |
| T2A-019 | Compare browser observed and replayed responses using deterministic structural checks. | Backlog | T2A-018 |
| T2A-020 | `verify` command explaining success or mismatches. | Backlog | T2A-019 |
| T2A-021 | Generate a minimal Pytest regression test for a compiled workflow. | Backlog | T2A-017, T2A-020 |

### Phase 5: Protocol intelligence

| Ticket | Description | Status | Depends on |
| --- | --- | --- | --- |
| T2A-022 | Detect common cursor, offset, and page number pagination. | Backlog | T2A-013 |
| T2A-023 | Understand GraphQL requests and operation names. | Ready | T2A-004 |
| T2A-024 | Handle common auth and CSRF dependencies without exposing secrets. | Backlog | T2A-015, T2A-003 |
| T2A-025 | Optional model provider interface for ambiguous naming or explanation. Deterministic operation must remain available. | Backlog | T2A-014 |

### Phase 6: Public release quality

| Ticket | Description | Status | Depends on |
| --- | --- | --- | --- |
| T2A-026 | Deterministic local demo app and capture fixture for the full workflow. | Backlog | T2A-011 |
| T2A-027 | Reproducible benchmark comparing the browser flow and direct client on the demo app. | Backlog | T2A-026, T2A-017 |
| T2A-028 | README end to end demo using verified real output. | Backlog | T2A-027, T2A-020 |
| T2A-029 | Installation and packaging polish for `pipx` and `uvx` where supported. | Backlog | T2A-001 |
| T2A-030 | v0.1 release checklist, versioning, changelog, and release notes. | Backlog | T2A-028, T2A-029 |

## Development

```console
$ python -m venv .venv
$ . .venv/bin/activate
$ python -m pip install -e ".[dev]"
```

Run the same checks CI runs:

```console
$ ruff format --check .
$ ruff check .
$ pytest
```

Layout:

```text
src/trace2api/
    __init__.py
    __main__.py
    cli.py
    models.py
    analyze/
        relevance.py
    capture/
        har.py
    sanitize/
        policy.py
        redact.py
tests/
```

`models.py` holds the traffic models the rest of the project is built on. Captures are
treated as evidence: the models are frozen, so a stage that needs to change something
produces a new object rather than editing the record of what was observed.

`capture/` turns a recording of a workflow into those models. `har.py` reads HAR 1.2
archives, keeping what the archive recorded and leaving judgement about relevance to the
analysis stages. Import does not redact, so a capture that comes out of it still holds
whatever was observed.

`sanitize/` removes credentials from a capture. `policy.py` decides what counts as one,
`redact.py` rewrites the capture and records what it took out. Every stage that persists
or displays a capture passes it through `redact_capture` first.

`analyze/` works out what a capture means. `relevance.py` is the first step: it decides
which requests carry the workflow and which are page furniture, and records the rule
behind each verdict so the reasoning can be read rather than trusted.

Further modules (`generate/`, `replay/`) are added as the tickets that need them land.

## Recent Progress

- 2026-09-03 - Added relevance filtering, separating page assets, analytics, and reporting traffic from the requests a workflow depends on, with a stated rule behind every verdict.
- 2026-09-02 - Added HAR 1.2 import, reading an archived workflow into the capture models and reporting where an archive is malformed.
- 2026-09-01 - Added credential redaction, replacing secrets in a capture with explainable placeholders and reporting what was removed without quoting it.
- 2026-08-31 - Added the core traffic models covering requests, responses, headers, query parameters, bodies, timings, and capture metadata.
- 2026-08-31 - Added the installable package scaffold, the `trace2api` CLI entry point, and CI running format, lint, and test checks on Python 3.12.

## License

Apache License 2.0. See [LICENSE](LICENSE).
