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

The output targets are cURL, Python using `httpx`, and JavaScript using `fetch`.

Trace2API is intended for authorized development, testing, debugging, integration work,
and permitted data access against systems the operator is allowed to use.

## Status

Early development. A HAR archive can be imported, redacted, inspected, and written out
as a runnable cURL script, Python `httpx` module, or JavaScript `fetch` module from the
command line. A live browser session can be recorded into the same capture models
through the library, though the `record` command that saves one is not there yet. The
inference, replay, and verification stages described above are not implemented yet. The
Roadmap and Ticket Board below track what is real and what is planned.

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

Recording a live browser session needs a browser, which the rest of the tool does not:

```console
$ python -m pip install -e ".[browser]"
$ playwright install chromium
```

## Quick start

Export a HAR archive from the browser devtools network panel, or use the synthetic one
in this repository, and look at what it holds:

```console
$ trace2api inspect examples/storefront-orders.har
Capture: 8 requests from har, recorded 2026-09-04T09:15:00+00:00
Hosts: cdn.example.com, shop.example.com, www.google-analytics.com

#  METHOD  HOST              PATH                         STATUS  TYPE      RELEVANCE
1  GET     shop.example.com  /orders                      200     document  unknown
4  GET     shop.example.com  /api/v1/orders               200     xhr       application
6  GET     shop.example.com  /api/v1/orders/4711          200     xhr       application
7  POST    shop.example.com  /api/v1/orders/4711/confirm  201     fetch     application

Showing 4 of 8 requests: 3 application, 1 unknown, 4 noise.
Filtered as noise (3 asset-resource-type, 1 analytics-host). Pass --all to list them.
Redacted 6 values before displaying this.
```

Eight recorded requests, four worth reading. The numbering is the position in the
capture, so the four that were filtered are still accounted for rather than renumbered
away.

Nothing here is taken on trust. `--all` lists the filtered requests as well, and
`--explain` names the rule behind every verdict:

```console
$ trace2api inspect examples/storefront-orders.har --all --explain
Capture: 8 requests from har, recorded 2026-09-04T09:15:00+00:00
Hosts: cdn.example.com, shop.example.com, www.google-analytics.com

#  METHOD  HOST                      PATH                         STATUS  TYPE        RELEVANCE    WHY
1  GET     shop.example.com          /orders                      200     document    unknown      a page document, which may carry values later requests reuse
2  GET     cdn.example.com           /static/app.4f2b91.css       200     stylesheet  noise        the browser loaded it as a page asset: stylesheet
3  GET     cdn.example.com           /static/app.4f2b91.js        200     script      noise        the browser loaded it as a page asset: script
4  GET     shop.example.com          /api/v1/orders               200     xhr         application  path names an API surface: api
5  POST    www.google-analytics.com  /collect                     204     xhr         noise        sent to an analytics or crash reporting host: google-analytics.com
6  GET     shop.example.com          /api/v1/orders/4711          200     xhr         application  path names an API surface: api
7  POST    shop.example.com          /api/v1/orders/4711/confirm  201     fetch       application  path names an API surface: api
8  GET     cdn.example.com           /img/logo.png                200     image       noise        the browser loaded it as a page asset: image

Showing 8 of 8 requests: 3 application, 1 unknown, 4 noise.
Redacted 6 values before displaying this.
```

`--json` writes the same account as a JSON document, including the filtered requests, for
feeding into something else.

Credentials are redacted before any of this is printed, and query strings are left out of
the table, so the output can go into an issue or a report as it stands.

Once the capture reads correctly, write those requests out as a client:

```console
$ trace2api generate examples/storefront-orders.har
#!/bin/sh
# Direct client for a workflow recorded 2026-09-04T09:15:00+00:00 (source: har).
# Reproducing 4 of 8 captured requests.
#
# Credentials were removed from the capture. Export them before running:
#   TRACE2API_AUTHORIZATION   request.headers.authorization
#   TRACE2API_COOKIE_SESSION  request.headers.cookie[session]
#   TRACE2API_COOKIE_LOCALE   request.headers.cookie[locale]
#   TRACE2API_X_CSRF_TOKEN    request.headers.x-csrf-token
set -eu

# 1  GET https://shop.example.com/orders
curl 'https://shop.example.com/orders' \
  --header 'Accept: text/html,application/xhtml+xml' \
  --header 'User-Agent: Mozilla/5.0 (X11; Linux x86_64)'

# 4  GET https://shop.example.com/api/v1/orders
curl 'https://shop.example.com/api/v1/orders?status=open&limit=20' \
  --header 'Accept: application/json' \
  --header 'Authorization: Bearer '"$TRACE2API_AUTHORIZATION" \
  --header 'Cookie: session='"$TRACE2API_COOKIE_SESSION"'; locale='"$TRACE2API_COOKIE_LOCALE"

# 6  GET https://shop.example.com/api/v1/orders/4711
curl 'https://shop.example.com/api/v1/orders/4711' \
  --header 'Accept: application/json' \
  --header 'Authorization: Bearer '"$TRACE2API_AUTHORIZATION"

# 7  POST https://shop.example.com/api/v1/orders/4711/confirm
curl 'https://shop.example.com/api/v1/orders/4711/confirm' \
  --request POST \
  --header 'Accept: application/json' \
  --header 'Content-Type: application/json' \
  --header 'Authorization: Bearer '"$TRACE2API_AUTHORIZATION" \
  --header 'X-CSRF-Token: '"$TRACE2API_X_CSRF_TOKEN" \
  --data-raw '{"payment_method":"invoice","confirmation_ref":"CNF-4711-88"}'
```

The token, the session cookie, and the CSRF value the browser sent are not in there. Each
one became a reference to an environment variable named after where it came from, so the
script can be committed, reviewed, and shared while the values stay in the environment
that runs it. `set -eu` stops the script rather than sending a request with an empty
credential.

The numbering matches `inspect`, so a command can be traced back to the exchange it came
from. Requests keep their query strings here, unlike the inspection table: a client that
drops them does not reproduce the workflow, and the credentials that hide in a query
string have already been replaced.

Redirect it to a file, export the variables it lists, and run it:

```console
$ trace2api generate examples/storefront-orders.har > orders.sh
$ export TRACE2API_AUTHORIZATION=... TRACE2API_COOKIE_SESSION=...
$ sh orders.sh
```

The same capture as a Python client, which is where the workflow usually ends up once it
has to be run from somewhere other than a terminal:

```console
$ trace2api generate examples/storefront-orders.har --target python > orders.py
$ head -45 orders.py
"""Direct client for a workflow recorded 2026-09-04T09:15:00+00:00 (source: har).

Reproducing 4 of 8 captured requests.

Credentials were removed from the capture. Export them before running:
  TRACE2API_AUTHORIZATION   request.headers.authorization
  TRACE2API_COOKIE_SESSION  request.headers.cookie[session]
  TRACE2API_COOKIE_LOCALE   request.headers.cookie[locale]
  TRACE2API_X_CSRF_TOKEN    request.headers.x-csrf-token
"""

import os

import httpx

# Every credential is read up front, so a missing one stops the client
# before it sends anything rather than halfway through the workflow.
TRACE2API_AUTHORIZATION = os.environ["TRACE2API_AUTHORIZATION"]
TRACE2API_COOKIE_SESSION = os.environ["TRACE2API_COOKIE_SESSION"]
TRACE2API_COOKIE_LOCALE = os.environ["TRACE2API_COOKIE_LOCALE"]
TRACE2API_X_CSRF_TOKEN = os.environ["TRACE2API_X_CSRF_TOKEN"]


def run(client: httpx.Client) -> list[httpx.Response]:
    """Send the recorded requests in the order they were observed."""
    # 1  GET https://shop.example.com/orders
    response_1 = client.request(
        "GET",
        "https://shop.example.com/orders",
        headers={
            "Accept": "text/html,application/xhtml+xml",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
        },
    )

    # 4  GET https://shop.example.com/api/v1/orders
    response_4 = client.request(
        "GET",
        "https://shop.example.com/api/v1/orders?status=open&limit=20",
        headers={
            "Accept": "application/json",
            "Authorization": "Bearer " + TRACE2API_AUTHORIZATION,
            "Cookie": "session=" + TRACE2API_COOKIE_SESSION + "; locale=" + TRACE2API_COOKIE_LOCALE,
        },
    )
```

The two requests the excerpt cuts off follow the same shape, and the module ends with a
`return` listing every response and a `main` that opens a client and prints a line per
response. Nothing imports Trace2API: it is ordinary Python that can be edited, committed,
and run wherever `httpx` is installed.

`run` takes the client rather than making one, so a caller can configure timeouts,
proxies, or a base client of its own, and it hands the responses back rather than
printing them. The requests go out in the order they were observed, one at a time, and
redirects are not followed, because a redirect the browser followed was recorded as its
own request.

The same capture as a JavaScript module, for the workflows that end up in a Node script
or a serverless function:

```console
$ trace2api generate examples/storefront-orders.har --target javascript > orders.mjs
$ head -40 orders.mjs
// Direct client for a workflow recorded 2026-09-04T09:15:00+00:00 (source: har).
// Reproducing 4 of 8 captured requests.
//
// An ES module for a runtime with a global fetch, such as Node 18 or newer.
// Save it as a .mjs file, or as .js in a package declaring "type": "module".
//
// Credentials were removed from the capture. Export them before running:
//   TRACE2API_AUTHORIZATION   request.headers.authorization
//   TRACE2API_COOKIE_SESSION  request.headers.cookie[session]
//   TRACE2API_COOKIE_LOCALE   request.headers.cookie[locale]
//   TRACE2API_X_CSRF_TOKEN    request.headers.x-csrf-token

import { pathToFileURL } from "node:url";

function requireEnv(name) {
  const value = process.env[name];
  if (value === undefined) {
    throw new Error(name + " is not set: it supplies a credential this workflow needs.");
  }
  return value;
}

// Every credential is read up front, so a missing one stops the client
// before it sends anything rather than halfway through the workflow.
const TRACE2API_AUTHORIZATION = requireEnv("TRACE2API_AUTHORIZATION");
const TRACE2API_COOKIE_SESSION = requireEnv("TRACE2API_COOKIE_SESSION");
const TRACE2API_COOKIE_LOCALE = requireEnv("TRACE2API_COOKIE_LOCALE");
const TRACE2API_X_CSRF_TOKEN = requireEnv("TRACE2API_X_CSRF_TOKEN");

// Sends the recorded requests in the order they were observed.
export async function run() {
  // 1  GET https://shop.example.com/orders
  const response1 = await fetch("https://shop.example.com/orders", {
    method: "GET",
    headers: {
      "Accept": "text/html,application/xhtml+xml",
      "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
    },
    redirect: "manual",
  });
```

Nothing is installed to run it: `fetch`, `URL`, and `URLSearchParams` are part of the
runtime. The module exports `run`, so the workflow can be imported and awaited from
somewhere else, and running the file directly prints a line per response.

## Current Capabilities

- Installable `trace2api` package with a `src/` layout.
- `trace2api --help` and `trace2api version`.
- `trace2api inspect CAPTURE` reads a HAR archive, redacts it, and lists each request by
  method, host, path, status, resource type, and relevance, with the noise summarized
  rather than printed. `--all` lists the filtered requests, `--explain` names the rule
  behind each verdict, and `--json` writes the same account as a JSON document. Query
  strings are never rendered.
- `trace2api generate CAPTURE` writes the requests a capture holds as a runnable cURL
  script on standard output, numbered as `inspect` numbers them. Every credential becomes
  a reference to an environment variable named after where the value came from, listed at
  the top of the script. Headers curl derives for itself are left out with the rule behind
  each omission stated, and a request the script cannot reproduce faithfully, such as one
  with a binary body, says so rather than sending something else. `--all` writes the
  filtered requests too.
- `trace2api generate CAPTURE --target python` writes the same requests as a Python
  module using `httpx`: a `run` function that sends them in the observed order and
  returns the responses, and a `main` that opens a client and reports what came back.
  Every credential is read from an environment variable at import time, so a missing one
  stops the client before it sends anything. Bodies are sent as the text that was
  observed rather than re-serialized, and a query string that held a credential is sent
  as parameters so the supplied value is encoded.
- `trace2api generate CAPTURE --target javascript` writes the same requests as an ES
  module using `fetch`: a `run` function that awaits them in the observed order and
  returns the responses, and a `main` that reports what came back. Every credential is
  read from the environment as the module loads, so a missing one stops the client
  before it sends anything. A query string that held a credential is rebuilt through
  `URLSearchParams`, and a body `fetch` refuses to send, such as one observed on a `GET`
  request, is reported rather than dropped silently.
- A synthetic capture at `examples/storefront-orders.har` that the quick start above
  runs against.
- A browser recorder that watches a live session through Playwright and records every
  http and https exchange it performs, with the response payloads of the requests the
  analysis reads, the durations the browser measured, and the requests that failed or
  were still in flight when recording stopped. It is available to code as
  `trace2api.capture.record_session` and `trace2api.capture.recording`; the command that
  saves a recording is T2A-011. Recording runs in a throwaway browser profile, so a
  session leaves no cookie jar, history, or cache on disk.
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
  position in the archive that caused them.
- Relevance filtering that separates page assets, analytics hosts, and reporting
  endpoints from likely application requests, with every verdict naming the rule behind
  it and what the rule matched. Requests no rule recognizes are kept rather than dropped.
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
- Nothing an inspection prints carries a query string. Query strings routinely hold
  tokens and identifiers, and an endpoint is recognizable from its path alone. A
  generated client is the deliberate exception: it carries the whole URL because it has
  to reproduce the request, and the credentials in it are already variable references.
- Generated clients read secrets from environment variables rather than embedding them.
- A recorded session runs in a throwaway browser profile. The workflow starts signed out,
  and no cookie jar, history, or cache is left behind on disk.
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
| T2A-006 | `inspect` command showing method, host, path, status, type, and relevance. | Done | T2A-005 |
| T2A-007 | Sanitized runnable cURL generator. | Done | T2A-004, T2A-003 |
| T2A-008 | Sanitized runnable Python `httpx` generator. | Done | T2A-007 |
| T2A-009 | Sanitized runnable JavaScript `fetch` generator. | Done | T2A-007 |

### Phase 2: Live capture

| Ticket | Description | Status | Depends on |
| --- | --- | --- | --- |
| T2A-010 | Browser Fetch/XHR recorder using Playwright or CDP. | Done | T2A-002 |
| T2A-011 | `trace2api record` produces a sanitized inspectable local capture. | Ready | T2A-010, T2A-003 |
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

The tests for the JavaScript target run the generated module under Node against a stub
`fetch` and check what it actually sent. They are skipped where `node` is not installed,
so the suite passes either way, but a change to that target is only properly covered
with Node present.

The browser recorder is covered the same way. Most of its tests drive it with stand-in
request objects, and two record a real Chromium session against a local HTTP server.
Those two are skipped where Playwright or a browser build is missing. Where a machine
has a Chromium binary that Playwright did not download itself, `TRACE2API_TEST_CHROMIUM`
points them at it.

Layout:

```text
src/trace2api/
    __init__.py
    __main__.py
    cli.py
    inspection.py
    models.py
    analyze/
        relevance.py
    capture/
        browser.py
        har.py
    generate/
        curl.py
        headers.py
        javascript.py
        python.py
        secrets.py
    sanitize/
        policy.py
        redact.py
examples/
tests/
```

`models.py` holds the traffic models the rest of the project is built on. Captures are
treated as evidence: the models are frozen, so a stage that needs to change something
produces a new object rather than editing the record of what was observed.

`capture/` turns a recording of a workflow into those models. `har.py` reads HAR 1.2
archives, keeping what the archive recorded and leaving judgement about relevance to the
analysis stages. `browser.py` watches a live session instead, listening to the request
events a Playwright browser context emits. It keeps every http and https exchange and
leaves the same judgement to the analysis stages, because a recording that dropped
requests could not report what it left out. Neither one redacts, so a capture that comes
out of them still holds whatever was observed.

Playwright cannot be asked about a request from inside one of its own event handlers, so
the recorder separates noting an event from reading what it refers to: handlers record
that something happened, and draining performs the reads from the thread driving the
session, while the browser still holds the payloads.

`sanitize/` removes credentials from a capture. `policy.py` decides what counts as one,
`redact.py` rewrites the capture and records what it took out. Every stage that persists
or displays a capture passes it through `redact_capture` first.

`analyze/` works out what a capture means. `relevance.py` is the first step: it decides
which requests carry the workflow and which are page furniture, and records the rule
behind each verdict so the reasoning can be read rather than trusted.

`generate/` writes an analyzed capture out as ordinary source code. Each target renders
the same requests in a different language, and they share two rules: the capture is
redacted before a line is written, and every secret becomes a reference to an environment
variable. `secrets.py` decides what those variables are called and reports where each
value came from. `headers.py` holds the rules that decide which observed headers a
client must not send as they stand, because they follow from HTTP rather than from the
language being written. `curl.py`, `python.py`, and `javascript.py` are the targets, and
each states in its own terms what it cannot reproduce rather than sending something
else.

`inspection.py` turns a capture into what a command prints: it redacts first, then
classifies, then renders. Keeping that order in one place means no command can display a
capture that has not been through redaction.

`examples/` holds synthetic archives written for this repository. They contain no real
host, credential, or personal data, and the tests read them so the output shown above
stays true.

Further modules (`replay/`) are added as the tickets that need them land.

## Recent Progress

- 2026-09-08 - Added a browser recorder, so a live session can be watched through Playwright and kept as a capture the rest of the tool already reads.
- 2026-09-07 - Added a JavaScript output target, so a capture can be written as an ES module that sends the observed requests with `fetch`.
- 2026-09-06 - Added a Python output target, so a capture can be written as an `httpx` client that sends the observed requests and returns the responses.
- 2026-09-05 - Added `trace2api generate`, which writes the requests a capture holds as a runnable cURL client that reads every credential from an environment variable.
- 2026-09-04 - Added `trace2api inspect`, which lists what a capture holds and why each request was kept or filtered, with a synthetic archive to run it against.
- 2026-09-03 - Added relevance filtering, separating page assets, analytics, and reporting traffic from the requests a workflow depends on, with a stated rule behind every verdict.
- 2026-09-02 - Added HAR 1.2 import, reading an archived workflow into the capture models and reporting where an archive is malformed.
- 2026-09-01 - Added credential redaction, replacing secrets in a capture with explainable placeholders and reporting what was removed without quoting it.
- 2026-08-31 - Added the core traffic models covering requests, responses, headers, query parameters, bodies, timings, and capture metadata.
- 2026-08-31 - Added the installable package scaffold, the `trace2api` CLI entry point, and CI running format, lint, and test checks on Python 3.12.

## License

Apache License 2.0. See [LICENSE](LICENSE).
