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

Early development. A live browser session can be recorded to a local capture, and a
capture, recorded or imported from a HAR archive, can be summarized, inspected, and
written out as a runnable cURL script, Python `httpx` module, or JavaScript `fetch`
module from the command line. Two recordings of one workflow can be compared to show
which request values differ, and those values can be classified as inputs, constants,
generated values, secrets, or unknowns. A single capture can be read for the values a
later request took from an earlier response, those links can be read as a dependency
graph showing what each request waits for, and a Python client can be compiled from that
graph which reads those values back out of the responses instead of replaying them. A
sanitized capture can be replayed over the network, sending each request with the
secrets redaction removed supplied explicitly rather than read from the environment.
Comparing what came back against what the browser observed, and the `verify` command
that will report it, are not implemented yet. The Roadmap and Ticket Board below track
what is real and what is planned.

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

Record a workflow against a site the operator is allowed to use. A browser opens at the
given address, and everything the session requests is recorded until the window is
closed:

```console
$ trace2api record https://app.example.com/orders --output orders.json
Recorded 41 requests to orders.json: 6 application, 2 unknown, 33 noise.
Redacted 9 values before writing it.
Inspect it with: trace2api inspect orders.json
```

Most of a recorded session is page furniture, so the first line says how much of it was
anything else. Credentials are removed before anything reaches the disk, and the file is
written so that only its owner can read it back. The session runs in a throwaway browser
profile, so it starts signed out and leaves no cookie jar, history, or cache behind.
Recording needs a browser, which the `[browser]` extra above installs.

Every command below reads that file, and reads a HAR archive exported from the devtools
network panel just as well. The rest of this quick start uses the synthetic archives in
this repository, so every line below can be reproduced from a clone.

Count what a capture holds before reading it:

```console
$ trace2api summary examples/storefront-orders.har
Capture: 8 requests from har, recorded 2026-09-04T09:15:00+00:00
Hosts: cdn.example.com, shop.example.com, www.google-analytics.com

Requests: 8 total, 4 kept, 4 filtered as noise.
Kept: 3 application, 1 unknown.
Noise: 3 asset-resource-type, 1 analytics-host.
Kept content types: 3 application/json, 1 text/html.
Redacted 6 values before counting this.
```

That is the whole recording at a glance: how much traffic there was, how much of it looks
like the application, which rules accounted for the rest, and whether what came back was
data or markup. No path or payload is printed, so a summary of a real session can be
shared while the session itself stays local. `--json` writes the same counts as a JSON
document.

Look at what the capture holds request by request:

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

One recording says what the workflow sent. Two say which of it was the input. Record the
same workflow again with something else filled in, and compare the two:

```console
$ trace2api diff examples/storefront-orders.har examples/storefront-orders-second-run.har
Left:  8 requests from har, recorded 2026-09-04T09:15:00+00:00
Right: 7 requests from har, recorded 2026-09-04T09:41:00+00:00
Comparing 4 kept requests on the left with 4 on the right.

4 -> 3  GET shop.example.com/api/v1/orders
  request.query[status]          changed  "open" -> "shipped"
  request.query[page]            added    "2"

6 -> 5  GET shop.example.com/api/v1/orders/4711
  paired on the same path once identifier shaped segments are set aside
  request.path[4]                changed  "4711" -> "5822"

7 -> 6  POST shop.example.com/api/v1/orders/4711/confirm
  paired on the same path once identifier shaped segments are set aside
  request.path[4]                changed  "4711" -> "5822"
  request.headers.x-csrf-token   changed  (redacted) -> (redacted)
  request.body.payment_method    changed  "invoice" -> "card"
  request.body.confirmation_ref  changed  "CNF-4711-88" -> "CNF-5822-40"
  request.body.gift_wrap         added    "true"

Paired 4 requests: 3 changed, 1 unchanged.
8 values differ.
Redacted 12 values before comparing, using one salt for both captures.
```

Requests are paired by what identifies them rather than by where they sit, so the second
run serving a stylesheet from cache does not push everything after it out of line, and a
path carrying an order number still pairs with its counterpart. A pairing that was not
exact prints the rule behind it, and a request with no counterpart is reported as
unpaired rather than compared with the nearest thing available.

Both recordings are redacted first, with one salt shared between them. The access token
was the same on both runs, so it does not appear here at all, while the CSRF token the
server reissued is reported as changed without either value being printed. `--unchanged`
lists the requests that held still as well, `--all` compares the noise too, and `--json`
writes the same comparison as a document.

A comparison says which values moved. What a client needs is what to do with each one,
which is what `classify` answers:

```console
$ trace2api classify examples/storefront-orders.har examples/storefront-orders-second-run.har
Left:  8 requests from har, recorded 2026-09-04T09:15:00+00:00
Right: 7 requests from har, recorded 2026-09-04T09:41:00+00:00
Classifying the values of 4 paired requests.

4 -> 3  GET shop.example.com/api/v1/orders
  request.query[status]          input   "open" -> "shipped"
  request.query[page]            input   "2" (second recording only)
  request.headers.authorization  secret  "Bearer (redacted)"
  request.headers.cookie         secret  "session=(redacted); locale=(redacted)"

6 -> 5  GET shop.example.com/api/v1/orders/4711
  paired on the same path once identifier shaped segments are set aside
  request.path[4]                input   "4711" -> "5822"
  request.headers.authorization  secret  "Bearer (redacted)"

7 -> 6  POST shop.example.com/api/v1/orders/4711/confirm
  paired on the same path once identifier shaped segments are set aside
  request.path[4]                input   "4711" -> "5822"
  request.headers.authorization  secret  "Bearer (redacted)"
  request.headers.x-csrf-token   secret  (redacted) -> (redacted)
  request.body.payment_method    input   "invoice" -> "card"
  request.body.confirmation_ref  input   "CNF-4711-88" -> "CNF-5822-40"
  request.body.gift_wrap         input   "true" (second recording only)

Classified 30 values: 7 inputs, 5 secrets, 18 constants.
Listing the 12 a client has to decide about. Pass --constants to list the rest.
Redacted 12 values before classifying, using one salt for both captures.
```

Thirty values, twelve of them worth a decision. A value that held still is a constant a
client can send as observed, which is most of a request. One that moved is an input where
it reads as something supplied to the workflow, a generated value where it reads as
something a machine minted, and unknown where no rule recognizes it. A value redaction
removed is a secret whether or not it was reissued, so a placeholder is never mistaken for
a constant worth hardcoding.

The verdicts are rules, not guesses, and `--explain` prints the rule behind each one:

```console
$ trace2api classify examples/storefront-orders.har examples/storefront-orders-second-run.har --explain | tail -12 | head -8
  request.headers.x-csrf-token   secret  (redacted) -> (redacted)
      redaction removed it, so a client reads it from the environment
  request.body.payment_method    input   "invoice" -> "card"
      it differs, and every observed value is ordinary text
  request.body.confirmation_ref  input   "CNF-4711-88" -> "CNF-5822-40"
      it differs, and every observed value is ordinary text
  request.body.gift_wrap         input   "true" (second recording only)
      it differs, and every observed value is ordinary text
```

A value is generated where its name says it is minted, such as `nonce`, `ts`, or
`X-Request-Id`, where every observed value is a UUID, a clock reading, or a long opaque
run, or where it is a header the browser maintains from the page it was on. Those rules
are deliberately narrow: a name such as `date` or `id` names a value a workflow is as
likely to be given as to mint, and telling a client to invent one the operator meant to
choose is worse than reporting it as unknown.

`--constants` lists the values that held still as well, `--all` classifies the noise too,
and `--json` writes the same verdicts as a document, constants included.

Some of what a workflow sends was never supplied to it at all. It came out of an earlier
response, and a client that replays the observed value works once. `flow` reads a single
capture and reports those links:

```console
$ trace2api flow examples/storefront-orders.har
Capture: 8 requests from har, recorded 2026-09-04T09:15:00+00:00
Tracing 4 kept requests for values that came from an earlier response.

6  GET shop.example.com/api/v1/orders/4711
  request.path[4]                <- 4  response.body.orders[0].id      "4711"

7  POST shop.example.com/api/v1/orders/4711/confirm
  request.path[4]                <- 4  response.body.orders[0].id      "4711"
  request.body.confirmation_ref  <- 6  response.body.confirmation_ref  "CNF-4711-88"

3 values flow from a response into a later request.
2 of 4 kept requests depend on a response above them.
Redacted 6 values before tracing, using one salt for the whole capture.
```

The order number in the last two paths was read out of the list of orders, and the
confirmation reference the final request posts was read out of the order it confirms.
Neither is an input, and neither can be hardcoded: a client has to read them at run time,
in that order.

One recording is enough here, because a value that came out of a response is evidence on
its own. A value some request had already sent before the response carried it is not
reported, which is what keeps a response echoing its own query string from reading as a
dependency. Where several responses carried the same value, the earliest is named: that is
where the workflow learned it.

Two rules draw a link, and `--explain` prints the one behind each:

```console
$ trace2api flow examples/storefront-orders.har --explain | sed -n '4,8p'
6  GET shop.example.com/api/v1/orders/4711
  request.path[4]                <- 4  response.body.orders[0].id      "4711"
      the request sent exactly what the earlier response carried

7  POST shop.example.com/api/v1/orders/4711/confirm
```

A request either sent exactly what the response carried, or sent it inside something
longer: a cookie a server set and the browser sent back sits inside a `Cookie` header, and
a token handed out at sign in sits inside an `Authorization` header. Credentials keep one
placeholder across a capture, so those links are found and printed as `(redacted)`: the
dependency is visible without the value being shown. `--all` reads the noise too, and
`--json` writes the same links as a document.

Value by value is the grain to check the inference at. Request by request is the grain a
client is written at, and that is what `graph` reports:

```console
$ trace2api graph examples/storefront-orders.har
Capture: 8 requests from har, recorded 2026-09-04T09:15:00+00:00
Reading 4 kept requests as a dependency graph.

Stage 1: 2 requests that need nothing earlier
  1  GET   shop.example.com/orders
  4  GET   shop.example.com/api/v1/orders

Stage 2: 1 request that waits for stage 1
  6  GET   shop.example.com/api/v1/orders/4711
       needs 4  response.body.orders[0].id      ->  request.path[4]

Stage 3: 1 request that waits for stage 2
  7  POST  shop.example.com/api/v1/orders/4711/confirm
       needs 4  response.body.orders[0].id      ->  request.path[4]
       needs 6  response.body.confirmation_ref  ->  request.body.confirmation_ref

4 kept requests: 2 waiting for an earlier response, 2 able to be sent first.
2 responses must be read by the client: 4, 6.
Longest chain: 4 -> 6 -> 7, 3 requests that cannot be sent at once.
Redacted 6 values before reading this, using one salt for the whole capture.
```

Four requests, three rounds. The two in the first stage need nothing from anything above
them, so a client may send them in either order or at the same time. The other two each
wait for a response, and the two responses named are the ones a client has to read rather
than discard. The longest chain is what remains once everything that could be sent at once
has been: three round trips, whatever else the client does.

Every link points backwards, because a value can only have been learned from a response
that had already arrived, so a capture cannot produce a cycle to resolve. A link is named
by where its value sat rather than by what the value was, so a session a server handed out
and the next request sent back reads as `response.headers.set-cookie[session] ->
request.headers.cookie` with nothing in between. `--explain` names the rule behind each
link, `--all` reads the noise too, and `--json` writes the graph as a document.

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

Every client shown so far sends the values the recording held, order `4711` included, so
it reproduces that one workflow and nothing else. `compile` writes the same Python module
against the dependency graph instead, which is the difference between a client that worked
once and a client that works:

```console
$ trace2api compile examples/storefront-orders.har > orders.py
$ head -16 orders.py
"""Direct client for a workflow recorded 2026-09-04T09:15:00+00:00 (source: har).

Reproducing 4 of 8 captured requests.

The workflow runs in 3 stages: 2 of 4 requests wait for an earlier response.

2 values read from a response as the client runs, rather than replayed as observed:
  orders_id         4  response.body.orders[0].id      sent on by 6, 7
  confirmation_ref  6  response.body.confirmation_ref  sent on by 7

Credentials were removed from the capture. Export them before running:
  TRACE2API_AUTHORIZATION   request.headers.authorization
  TRACE2API_COOKIE_SESSION  request.headers.cookie[session]
  TRACE2API_COOKIE_LOCALE   request.headers.cookie[locale]
  TRACE2API_X_CSRF_TOKEN    request.headers.x-csrf-token
"""
```

The first two requests are written exactly as `generate` writes them, since neither waits
for anything. The rest of the workflow is where the graph shows:

```console
$ sed -n '54,82p' orders.py
    # response.body.orders[0].id, sent on by 6, 7
    orders_id = response_4.json()["orders"][0]["id"]

    # 6  GET https://shop.example.com/api/v1/orders/4711
    response_6 = client.request(
        "GET",
        "https://shop.example.com/api/v1/orders/" + str(orders_id),
        headers={
            "Accept": "application/json",
            "Authorization": "Bearer " + TRACE2API_AUTHORIZATION,
        },
    )

    # response.body.confirmation_ref, sent on by 7
    confirmation_ref = response_6.json()["confirmation_ref"]

    # 7  POST https://shop.example.com/api/v1/orders/4711/confirm
    # note: the payload is rebuilt around the values read above, so its spacing may differ from the capture
    response_7 = client.request(
        "POST",
        "https://shop.example.com/api/v1/orders/" + str(orders_id) + "/confirm",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": "Bearer " + TRACE2API_AUTHORIZATION,
            "X-CSRF-Token": TRACE2API_X_CSRF_TOKEN,
        },
        content='{"payment_method":"invoice","confirmation_ref":' + json.dumps(str(confirmation_ref)) + "}",
    )
```

The identifier the recording happened to catch is gone from the code that sends the last
two requests. Whatever order the first page of results names when the client runs is the
order it fetches and confirms, and the confirmation reference comes from the response that
issued it. The comment above each read names where the value sat and which requests send it
on, so a reader can check the inference against `trace2api flow` without leaving the file.

A link the client cannot resolve is replayed as observed and said so, in the docstring and
again as a note on the call that sends it. A credential is the common case: it is supplied
from the environment as ever, because redaction removed the value that would say where in
the response it sat. A value sent in a payload that was not recorded as JSON is the other,
and it keeps the value the recording held until the code is edited by hand.

## Current Capabilities

- Installable `trace2api` package with a `src/` layout.
- `trace2api --help` and `trace2api version`.
- `trace2api record URL` opens a browser at `URL`, records every http and https exchange
  the session performs, and saves the result as a local capture file, reporting how many
  of the recorded requests look like the application and how many were filtered as noise.
  Credentials are removed before the file is written, and it is written with owner only
  permissions. `--output` names the destination, `--headless` runs without a window, and
  `--timeout` ends a recording that would otherwise run until the browser closes.
- `trace2api summary CAPTURE` counts a saved capture or a HAR archive instead of listing
  it: total requests, how many are kept as likely application requests, how many were
  filtered as noise and by which rule, what the kept requests answered with, and how many
  of them never received a response. No path or payload is printed. `--json` writes the
  same counts as a JSON document.
- `trace2api inspect CAPTURE` reads a saved capture or a HAR archive, redacts it, and
  lists each request by method, host, path, status, resource type, and relevance, with
  the noise summarized rather than printed. `--all` lists the filtered requests,
  `--explain` names the rule behind each verdict, and `--json` writes the same account as
  a JSON document. Query strings are never rendered.
- `trace2api diff LEFT RIGHT` compares two recordings of one workflow and reports which
  request values differ: path segments, query parameters, headers, and payload fields,
  each located where it was observed. Requests are paired by what identifies them rather
  than by position, the rule behind a pairing that was not exact is named, and a request
  with no counterpart is reported as unpaired rather than compared with the nearest
  candidate. `--unchanged` lists the paired requests that held still, `--all` compares
  the requests filtered as noise, and `--json` writes the same comparison as a JSON
  document.
- `trace2api classify LEFT RIGHT` reads every value of every paired request and says what
  it is: a constant that held still, an input supplied to the workflow, a value generated
  per request, a secret redaction removed, or unknown where no rule recognizes it. Every
  verdict names the rule behind it, and a rule that matched on a name reports the name
  rather than the value. `--constants` lists the values that held still as well,
  `--explain` adds the rule behind each verdict, `--all` classifies the requests filtered
  as noise, and `--json` writes the same verdicts as a JSON document.
- `trace2api flow CAPTURE` reads one capture and reports the request values that came out
  of an earlier response: an identifier that became a path segment, a cursor that became a
  query parameter, a reference that reached a payload field, a cookie or a token sent back
  inside a header. A value some request had already sent before the response carried it is
  not reported, and where several responses carried it the earliest is named. `--explain`
  adds the rule behind each link, `--all` reads the requests filtered as noise, and
  `--json` writes the same links as a JSON document.
- `trace2api graph CAPTURE` reads those links request by request instead of value by
  value: which requests need nothing earlier and can be sent at once, which ones wait for
  a response, which responses a client has to read rather than discard, and the longest
  chain of requests it cannot avoid sending one after another. A link is named by where
  its value sat rather than by what the value was. `--explain` adds the rule behind each
  link, `--all` reads the requests filtered as noise, and `--json` writes the same graph
  as a JSON document.
- `trace2api generate CAPTURE` writes the requests a saved capture or a HAR archive
  holds as a runnable cURL script on standard output, numbered as `inspect` numbers them.
  Every credential becomes a reference to an environment variable named after where the
  value came from, listed at the top of the script. Headers curl derives for itself are
  left out with the rule behind each omission stated, and a request the script cannot
  reproduce faithfully, such as one with a binary body, says so rather than sending
  something else. A form encoded body that held a credential sends that field through
  `--data-urlencode`, so curl encodes the supplied value. `--all` writes the filtered
  requests too.
- `trace2api generate CAPTURE --target python` writes the same requests as a Python
  module using `httpx`: a `run` function that sends them in the observed order and
  returns the responses, and a `main` that opens a client and reports what came back.
  Every credential is read from an environment variable at import time, so a missing one
  stops the client before it sends anything. Bodies are sent as the text that was
  observed rather than re-serialized, a query string that held a credential is sent as
  parameters, and a form field that held one is encoded through
  `urllib.parse.quote_plus`, so the supplied value is encoded either way.
- `trace2api generate CAPTURE --target javascript` writes the same requests as an ES
  module using `fetch`: a `run` function that awaits them in the observed order and
  returns the responses, and a `main` that reports what came back. Every credential is
  read from the environment as the module loads, so a missing one stops the client
  before it sends anything. A query string that held a credential is rebuilt through
  `URLSearchParams` and a form field that held one is encoded through
  `encodeURIComponent`, and a body `fetch` refuses to send, such as one observed on a
  `GET` request, is reported rather than dropped silently.
- `trace2api compile CAPTURE` writes the same Python module against the dependency graph
  rather than against the recording alone: a value a later request took from an earlier
  response is read back out of that response as the client runs, whether it was sent in a
  path segment, a query parameter, a header, a JSON payload field, or a form encoded one.
  A form field the client supplies is encoded where the payload carried it, and the fields
  it was not asked to change are sent as the capture spelled them. What it could not
  resolve, such as a credential or a value sent in a payload that is neither JSON nor a
  form, is replayed as observed and reported with the reason, in the module docstring and
  as a note on the call that sends it. `--all` compiles the filtered requests too.
- A replay engine, `trace2api.replay.replay_capture`, that redacts a capture and sends the
  requests worth keeping over the network with httpx, given the value of every secret
  redaction removed as an explicit argument rather than read from the environment. A
  request needing a secret the caller did not supply is refused before anything is sent. A
  query string or a form encoded field that held a secret is decoded, substituted, and
  encoded again, and a JSON field is substituted with the value escaped for its place in
  the JSON text, so a secret holding a quote or a backslash still leaves the payload valid.
  A header httpx computes or negotiates for itself, such as `Content-Length` or
  `Connection`, is left for it to set. A request that fails at the network level is
  reported with the reason and the host it was sent to, never the URL or headers a secret
  could have reached. Nothing is redacted on the way out: a replayed response can carry
  whatever the server actually sent back and must pass through `redact_capture` before it
  is stored, displayed, or compared, the same as a live recording would.
- Two synthetic captures, `examples/storefront-orders.har` and
  `examples/storefront-orders-second-run.har`, that the quick start above runs against.
  They record the same storefront workflow with different inputs, which is what the
  comparison needs.
- A browser recorder that watches a live session through Playwright and records every
  http and https exchange it performs, with the response payloads of the requests the
  analysis reads, the durations the browser measured, and the requests that failed or
  were still in flight when recording stopped. It is available to code as
  `trace2api.capture.record_session` and `trace2api.capture.recording`. Recording runs in
  a throwaway browser profile, so a session leaves no cookie jar, history, or cache on
  disk.
- A local capture file that holds a recording as it was observed, including the exchanges
  that never settled, the browser that performed them, and the address the session
  started at, none of which a HAR entry has a field for. Saving redacts first, so a
  recording cannot reach the filesystem through `trace2api.capture.save_capture` with its
  credentials still in it. Reading accepts either a saved capture or a HAR archive, and
  decides which by what the file holds rather than by what it is called.
- Typed traffic models for requests, responses, headers, query parameters, bodies,
  timings, entries, and capture metadata, with case insensitive header lookup, URL
  derived query parameters, validation of what cannot be replayed later, and JSON round
  tripping.
- Credential redaction over a capture, covering credential headers, cookie values,
  `Authorization` style values, credential named query parameters, JSON and form fields,
  URL userinfo, and token shaped values, with a report of what was removed by location
  and rule. A body that is not a structure redaction can read, such as a page or a
  script, is scanned as text instead, so a token assigned to a named field, handed over
  in a `meta` element, or written out in full is removed where it sits while everything
  around it survives.
- HAR 1.2 import from a file or an already parsed document, covering requests,
  responses, headers, payloads, timings, and resource types, with failures that name the
  position in the archive that caused them.
- Relevance filtering that separates page assets, analytics hosts, and reporting
  endpoints from likely application requests, with every verdict naming the rule behind
  it and what the rule matched. Requests no rule recognizes are kept rather than dropped.
- Value classification over two recordings, deciding for each observed value whether it is
  a constant, an input, a generated value, a secret, or unknown, by narrow rules that each
  report what they matched on.
- Dependency detection over one recording, finding the values a workflow took from an
  earlier response and sent again: JSON and form fields, response headers, the cookie in a
  `Set-Cookie` field, and a redirect target, matched either whole or as a value standing on
  its own inside a longer one. A value the workflow had already sent by then is not
  reported as learned from a response.
- A dependency graph over those links, placing each request in a stage after the latest
  response it waits for, gathering the values two requests share into one edge, and
  reporting the responses a client must read and the chain of requests it must send one
  after another.
- Link resolution over that graph, deciding for each link whether a generated client can
  read the value back at run time and naming the reason where it cannot. A value that
  lands in a path segment, a query parameter, a header, a JSON payload field, or a form
  encoded one can be read back; a credential and a payload in a format this project does
  not claim to read cannot. The decision is language independent: it reports where in the
  response the value sits and where in the later request it goes, which is the same
  instruction whichever language is written.
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
- A body that is not a structure redaction can read is read as text. A page hands its own
  scripts a CSRF token that appears nowhere else in a workflow, so a credential named
  field assigned a quoted value, a `meta` element naming what it carries, and a token
  written out in full are all replaced where they sit. Only the values move: the markup
  and code around them are left as observed, because the analysis stages read them.
- Binary payloads are the exception. Nothing in them can be located without decoding a
  format redaction does not claim to understand, so they are left alone, and a secret in
  one is removed only where it also appears in a header, a query string, or a structured
  field.
- An unquoted value is left as observed. A bare word after an equals sign is as likely to
  be an expression, a keyword, or a media type as a secret, and replacing those would cost
  the inference stages more than it protects.
- Nothing an inspection prints carries a query string. Query strings routinely hold
  tokens and identifiers, and an endpoint is recognizable from its path alone. A
  generated client is the deliberate exception: it carries the whole URL because it has
  to reproduce the request, and the credentials in it are already variable references.
- A summary goes further and names no path or payload at all: only hosts, counts, and the
  rules behind them. What a recording contains can be reported where the recording itself
  cannot go.
- Two captures being compared are redacted under one salt, so the same credential reads as
  the same placeholder in both and reports as unchanged. A credential that was reissued
  between the runs is reported as changed, and shown as the word `(redacted)` on each
  side. The fingerprint behind a placeholder is never printed: it is salted per run, so it
  would say nothing except to make the same comparison read differently every time.
- A classification decides credentials before it decides anything else, so a value
  redaction removed is reported as a secret rather than as a constant a client could send
  as observed. A rule that fires on a name reports the name; no rule reports a value, and
  a value that is shown at all goes through the same rendering a comparison uses.
- Generated clients read secrets from environment variables rather than embedding them.
- A credential a workflow sent in a form encoded payload is encoded by the generated
  client where the payload carried it. Redaction stores such a payload with the
  placeholder percent encoded along with everything else, so a client that searched the
  text for a placeholder would find none and send the stored text as the value. The
  payload is read field by field instead, and every field the client did not have to
  supply is sent as the payload spelled it.
- A compiled client never reads a credential out of a response. Redaction replaced the
  value with a placeholder, so the capture no longer says where in the response it sat,
  and inventing a place to read it from would be a guess in the one part of a client where
  a guess costs the most. Such a link is reported as a credential supplied from the
  environment, which is what the client does with it.
- A capture is redacted on the way to disk, not on the way back, so the file itself holds
  no credentials. It is still written with owner only permissions, because a sanitized
  recording still describes hosts, paths, and payloads that were not necessarily meant to
  be shared.
- Redacting a capture that was already redacted leaves it unchanged and still reports
  where each secret belongs. That report, rather than the capture, is what lets a
  generated client name the variable a value comes back under, so reading a capture from
  disk does not cost the explanation of what the workflow needed.
- A recorded session runs in a throwaway browser profile. The workflow starts signed out,
  and no cookie jar, history, or cache is left behind on disk.
- Replaying a capture never reads a secret from the process environment. Every value
  redaction removed is supplied to the replay engine explicitly, by the same name a
  generated client would read it under, and a request needing one that was not supplied is
  refused before anything is sent. The response a replay actually receives is not
  redacted by the engine itself, the same as a live recording is not: it must pass through
  `redact_capture` before it is stored, displayed, or compared.
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
| T2A-031 | Redact credential shaped values inside recorded text bodies, such as a token written into a page script. | Done | T2A-003 |

### Phase 1: HAR to code

| Ticket | Description | Status | Depends on |
| --- | --- | --- | --- |
| T2A-004 | HAR 1.2 importer into internal models with clear validation errors. | Done | T2A-002, T2A-003 |
| T2A-005 | Deterministic filtering for obvious assets, analytics, telemetry, and likely application requests. | Done | T2A-004 |
| T2A-006 | `inspect` command showing method, host, path, status, type, and relevance. | Done | T2A-005 |
| T2A-007 | Sanitized runnable cURL generator. | Done | T2A-004, T2A-003 |
| T2A-008 | Sanitized runnable Python `httpx` generator. | Done | T2A-007 |
| T2A-009 | Sanitized runnable JavaScript `fetch` generator. | Done | T2A-007 |
| T2A-033 | Encode a credential written back into a form encoded payload, which redaction stores with the placeholder percent encoded. | Done | T2A-007, T2A-008, T2A-009 |

### Phase 2: Live capture

| Ticket | Description | Status | Depends on |
| --- | --- | --- | --- |
| T2A-010 | Browser Fetch/XHR recorder using Playwright or CDP. | Done | T2A-002 |
| T2A-011 | `trace2api record` produces a sanitized inspectable local capture. | Done | T2A-010, T2A-003 |
| T2A-012 | Capture summary with total requests, filtered noise, likely application requests, and content types. | Done | T2A-011, T2A-005 |

### Phase 3: Differential inference

| Ticket | Description | Status | Depends on |
| --- | --- | --- | --- |
| T2A-013 | Diff equivalent captures and identify changed request values. | Done | T2A-004 |
| T2A-014 | Classify changed values as likely inputs, constants, generated values, or unknowns using explainable rules. | Done | T2A-013 |
| T2A-015 | Detect values flowing from one response into later URLs, headers, query strings, or bodies. | Done | T2A-004 |
| T2A-016 | Build and display a request dependency graph. | Done | T2A-015 |
| T2A-017 | Compile a direct multi-request client from the inferred graph. | Done | T2A-016, T2A-014, T2A-008 |
| T2A-032 | Resolve links into form encoded payloads when compiling a client. | Done | T2A-017 |

### Phase 4: Replay and verification

| Ticket | Description | Status | Depends on |
| --- | --- | --- | --- |
| T2A-018 | Replay sanitized request definitions with explicit secret injection. | Done | T2A-004, T2A-003 |
| T2A-019 | Compare browser observed and replayed responses using deterministic structural checks. | Backlog | T2A-018 |
| T2A-020 | `verify` command explaining success or mismatches. | Backlog | T2A-019 |
| T2A-021 | Generate a minimal Pytest regression test for a compiled workflow. | Backlog | T2A-017, T2A-020 |

### Phase 5: Protocol intelligence

| Ticket | Description | Status | Depends on |
| --- | --- | --- | --- |
| T2A-022 | Detect common cursor, offset, and page number pagination. | Ready | T2A-013 |
| T2A-023 | Understand GraphQL requests and operation names. | Ready | T2A-004 |
| T2A-024 | Handle common auth and CSRF dependencies without exposing secrets. | Ready | T2A-015, T2A-003 |
| T2A-025 | Optional model provider interface for ambiguous naming or explanation. Deterministic operation must remain available. | Ready | T2A-014 |

### Phase 6: Public release quality

| Ticket | Description | Status | Depends on |
| --- | --- | --- | --- |
| T2A-026 | Deterministic local demo app and capture fixture for the full workflow. | Ready | T2A-011 |
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
points them at it. The tests for the `record` command stand in for the recorder itself,
so what the command does with a recording is checked without a browser.

Layout:

```text
src/trace2api/
    __init__.py
    __main__.py
    cli.py
    inspection.py
    models.py
    analyze/
        classify.py
        diff.py
        flow.py
        graph.py
        relevance.py
        summary.py
    capture/
        browser.py
        har.py
        store.py
    generate/
        curl.py
        dependencies.py
        forms.py
        headers.py
        javascript.py
        python.py
        secrets.py
    sanitize/
        policy.py
        redact.py
    replay/
        replay.py
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

`store.py` is where a capture is kept between runs. Saving redacts before it writes, for
the same reason inspection redacts before it renders: putting the order in one place
means no caller can write a capture that has not been through it. Reading takes a saved
capture or a HAR archive and decides which by what the file holds, so a command does not
have to be told which it was handed.

`sanitize/` removes credentials from a capture. `policy.py` decides what counts as one,
`redact.py` rewrites the capture and records what it took out. Where a payload is a
structure, its fields are judged by their own names and shapes. Where it is not, the text
is searched for the same credentials rather than being handed over whole or blanked,
which is what keeps a token that only ever appeared in a page out of a saved capture. Every stage that persists
or displays a capture passes it through `redact_capture` first. Redacting a capture that
is already redacted is the ordinary case rather than a special one, because that is how a
capture read back from disk arrives: the placeholders stay as they are, and the report
still accounts for each of them, which is what later stages read to learn where a secret
belonged.

`analyze/` works out what a capture means. `relevance.py` is the first step: it decides
which requests carry the workflow and which are page furniture, and records the rule
behind each verdict so the reasoning can be read rather than trusted. `summary.py` counts
those verdicts rather than listing them, because the first question asked of a recording
is whether it caught the workflow at all. It reads the same rules the inspection does, so
the two accounts of one capture cannot disagree.

`diff.py` is the first stage that reads more than one recording. It pairs the requests of
two captures and reports the values that differ between each pair. Pairing is the harder
half: recordings of one workflow do not line up by position, so entries are matched by
what identifies them, by three rules applied most exact first, and the rule that matched
is kept with the pair. Where two candidates would do equally well, neither is chosen, and
both requests are reported as unpaired. A wrong pairing would invent changes that were
never observed, and an unpaired request says plainly that nothing was concluded about it.

`classify.py` is what a comparison is evidence for. It starts from the same pairing and
reads every value of a paired request, the ones that held still included, and reaches one
verdict per value: constant, input, generated, secret, or unknown. Each verdict is a rule
that either matched or did not, recorded alongside it, and the rules are narrow on
purpose. A value no rule recognizes stays unknown rather than being pushed into the
nearest verdict, for the same reason an unpaired request stays unpaired: a client built on
a guess fails in a way that is hard to see. Credentials are decided before anything else,
because a placeholder is not a value and nothing about what a value looks like applies to
one.

`flow.py` asks a different question of the same capture, and needs only one recording to
ask it: which values did the workflow never have until a response handed them over? It
reads what each response carried and what each later request sent, and links the two where
the value matches whole or stands on its own inside something longer. The guard against
reading coincidence as dependency is evidence rather than a threshold: a value some
request had already sent by the time the response carried it was never learned there, so
it is not a source at all. That is what keeps a response echoing its own query string, or
declaring the media type the request asked for, out of the links.

`graph.py` reads those links request by request rather than value by value, which is the
grain a client is written at. An edge is everything one request needs from one earlier
response. Every edge points backwards through the capture, because a value can only have
been learned from a response that had already arrived, so there is no cycle to break and
a request can be placed in a stage by counting the responses it waits for. What comes out
is what compiling a client needs: what can be sent at once, what has to wait, which
responses have to be read rather than discarded, and how many round trips cannot be
avoided.

`generate/` writes an analyzed capture out as ordinary source code. Each target renders
the same requests in a different language, and they share two rules: the capture is
redacted before a line is written, and every secret becomes a reference to an environment
variable. `secrets.py` decides what those variables are called and reports where each
value came from. `headers.py` holds the rules that decide which observed headers a
client must not send as they stand, because they follow from HTTP rather than from the
language being written. `forms.py` reads a form encoded payload field by field, so a
target can encode a credential, or a value read out of an earlier response, where the
payload carried it rather than splice a supplied value into text that was already encoded.
`curl.py`, `python.py`, and `javascript.py` are the targets, and each states in its own
terms what it cannot reproduce rather than sending something else.

`dependencies.py` is what turns the graph into something a target can write. A link is
two locations, and it answers one question about each pair: can a client read that value
back when it runs? Where it can, it says where in the response the value sits and where in
the later request it goes, in terms no language appears in, so the same answer serves every
target. Where it cannot, it says why, and the value is replayed as observed rather than
approximated. Both halves are reported, because a client that quietly replays a value a
reader believed was resolved is worse than one that says which is which. `python.py` is the
first target to use it: a replayed client reproduces the recording, and a compiled one
reads what the workflow depends on.

`inspection.py` turns a capture into what a command prints: it redacts first, then
classifies, then renders. Keeping that order in one place means no command can display a
capture that has not been through redaction.

`replay/` sends an analyzed capture over the network instead of writing it out as source.
`replay.py` redacts the capture the same way `generate/` does, and resolves the same
placeholders back into a request, except the value comes from an argument the caller
passed rather than from an environment variable a generated client reads for itself: an
engine has no process of its own to run in later, so it is given what it needs to send up
front, and a request needing something it was not given is refused before anything goes
out. Like `capture/`, it does not redact what it observes: the response it reports still
holds whatever the server actually sent back, and must pass through `redact_capture`
before it is stored, displayed, or compared.

`examples/` holds synthetic archives written for this repository. They contain no real
host, credential, or personal data, and the tests read them so the output shown above
stays true.

## Recent Progress

- 2026-09-22 - Added a replay engine that sends the requests of a sanitized capture over the network, with every secret redaction removed supplied explicitly instead of read from the environment.
- 2026-09-21 - A compiled client now reads back the values a workflow sent in a form encoded payload, encoding each supplied field where the payload carried it and sending the rest as the capture spelled them.
- 2026-09-18 - A credential a workflow sent in a form encoded payload now reaches the request, encoded where the payload carried it, in the cURL, Python, and JavaScript clients alike.
- 2026-09-17 - Added `trace2api compile`, which writes a Python client that reads the values a workflow depends on out of the responses that hand them out, instead of replaying the ones the recording caught.
- 2026-09-16 - Added `trace2api graph`, which reads the links of a capture as a dependency graph: what a client can send at once, what waits for a response, which responses it has to read, and the chain of round trips it cannot avoid.
- 2026-09-15 - Added `trace2api flow`, which reads one capture and reports the values a request took from an earlier response, such as an identifier that became a path segment or a cookie sent back in a header.
- 2026-09-14 - Added `trace2api classify`, which says whether each value of a workflow is a constant, an input, generated per request, a secret, or unrecognized, with the rule behind every verdict.
- 2026-09-13 - Added `trace2api diff`, which compares two recordings of one workflow and reports which request values changed, with a second synthetic archive to run it against.
- 2026-09-12 - Added `trace2api summary`, which counts what a capture holds without naming a path or a payload, and reports the same breakdown at the end of a recording.
- 2026-09-10 - Redaction now removes the credentials written into pages, scripts, and other text bodies, so a token a workflow only ever showed in a page no longer reaches a saved capture.
- 2026-09-09 - Added `trace2api record`, which saves a live browser session as a sanitized local capture that `inspect` and `generate` read alongside HAR archives.
- 2026-09-08 - Added a browser recorder, so a live session can be watched through Playwright and kept as a capture the rest of the tool already reads.
- 2026-09-07 - Added a JavaScript output target, so a capture can be written as an ES module that sends the observed requests with `fetch`.
- 2026-09-06 - Added a Python output target, so a capture can be written as an `httpx` client that sends the observed requests and returns the responses.

## License

Apache License 2.0. See [LICENSE](LICENSE).
