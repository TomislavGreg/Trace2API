"""Tests for deciding which links of a capture a generated client can resolve."""

from __future__ import annotations

from datetime import UTC, datetime

from trace2api.analyze import trace_flows
from trace2api.generate import (
    AccessorKind,
    DependencyResolution,
    SiteKind,
    resolve_dependencies,
)
from trace2api.models import (
    Body,
    Capture,
    CaptureMetadata,
    CaptureSource,
    Entry,
    Headers,
    Request,
    ResourceType,
    Response,
)
from trace2api.sanitize import redact_capture

STARTED_AT = datetime(2026, 9, 4, 9, 15, tzinfo=UTC)

JSON = "application/json"
FORM = "application/x-www-form-urlencoded"


def entry(
    entry_id: str,
    url: str,
    *,
    method: str = "GET",
    headers: list[tuple[str, str]] | None = None,
    body: Body | None = None,
    answered: Body | None = None,
    answered_headers: list[tuple[str, str]] | None = None,
    redirect_url: str | None = None,
) -> Entry:
    """Build one observed exchange that the relevance rules keep."""
    return Entry(
        id=entry_id,
        started_at=STARTED_AT,
        request=Request(
            method=method,
            url=url,
            headers=Headers.from_pairs(headers or []),
            body=body,
        ),
        response=Response(
            status=200,
            headers=Headers.from_pairs(answered_headers or [("Content-Type", JSON)]),
            body=answered,
            redirect_url=redirect_url,
        ),
        resource_type=ResourceType.XHR,
    )


def capture(*entries: Entry) -> Capture:
    """Build a capture holding ``entries``."""
    return Capture(
        metadata=CaptureMetadata(source=CaptureSource.HAR, created_at=STARTED_AT),
        entries=list(entries),
    )


def json_body(text: str) -> Body:
    """Build a JSON payload holding ``text``."""
    return Body(mime_type=JSON, text=text)


def resolve(*entries: Entry) -> DependencyResolution:
    """Trace a capture the way a generator does, and resolve what it found."""
    sanitized = redact_capture(capture(*entries), salt=b"fixed-salt")
    return resolve_dependencies(
        trace_flows(sanitized.capture, salt=b"fixed-salt"), sanitized.capture
    )


# Values a client can read back


def test_an_identifier_becomes_a_field_read_from_the_response_that_handed_it_out() -> None:
    resolution = resolve(
        entry(
            "a", "https://api.example.com/orders", answered=json_body('{"orders":[{"id":"4711"}]}')
        ),
        entry("b", "https://api.example.com/orders/4711"),
    )
    assert not resolution.unresolved
    [dependency] = resolution.resolved
    assert dependency.source == 1
    assert dependency.target == 2
    assert dependency.accessor.kind is AccessorKind.JSON_FIELD
    assert dependency.accessor.steps == ["orders", 0, "id"]
    assert dependency.site.kind is SiteKind.PATH_SEGMENT
    assert dependency.site.segment == 2


def test_a_value_sent_as_a_query_parameter_names_the_parameter_it_goes_to() -> None:
    resolution = resolve(
        entry("a", "https://api.example.com/page", answered=json_body('{"cursor":"c-9981723"}')),
        entry("b", "https://api.example.com/page?cursor=c-9981723&limit=20"),
    )
    [dependency] = resolution.resolved
    assert dependency.site.kind is SiteKind.QUERY_PARAMETER
    assert dependency.site.name == "cursor"
    assert dependency.site.index == 0


def test_a_value_sent_in_a_header_names_the_header_it_goes_to() -> None:
    resolution = resolve(
        entry("a", "https://api.example.com/page", answered=json_body('{"trace":"tr-9981723"}')),
        entry("b", "https://api.example.com/next", headers=[("X-Trace", "tr-9981723")]),
    )
    [dependency] = resolution.resolved
    assert dependency.site.kind is SiteKind.HEADER
    assert dependency.site.name == "x-trace"


def test_a_value_sent_in_a_payload_names_the_field_it_goes_to() -> None:
    resolution = resolve(
        entry("a", "https://api.example.com/page", answered=json_body('{"ref":"CNF-998172"}')),
        entry(
            "b",
            "https://api.example.com/confirm",
            method="POST",
            headers=[("Content-Type", JSON)],
            body=json_body('{"ref":"CNF-998172"}'),
        ),
    )
    [dependency] = resolution.resolved
    assert dependency.site.kind is SiteKind.JSON_FIELD
    assert dependency.site.steps == ["ref"]
    assert dependency.site.quoted


def test_a_response_header_is_read_from_the_header_that_carried_it() -> None:
    resolution = resolve(
        entry(
            "a",
            "https://api.example.com/page",
            answered=json_body("{}"),
            answered_headers=[("Content-Type", JSON), ("X-Page-Ref", "pg-9981723")],
        ),
        entry("b", "https://api.example.com/page/pg-9981723"),
    )
    [dependency] = resolution.resolved
    assert dependency.accessor.kind is AccessorKind.HEADER
    assert dependency.accessor.name == "x-page-ref"
    assert dependency.accessor.index is None


def test_a_redirect_target_is_read_from_the_response_that_pointed_at_it() -> None:
    resolution = resolve(
        entry(
            "a",
            "https://api.example.com/start",
            answered=json_body("{}"),
            redirect_url="https://api.example.com/landing/9981723",
        ),
        entry(
            "b",
            "https://api.example.com/track?target=https%3A%2F%2Fapi.example.com%2Flanding%2F9981723",
        ),
    )
    [dependency] = resolution.resolved
    assert dependency.accessor.kind is AccessorKind.REDIRECT_URL
    assert dependency.variable == "redirect_url"


def test_a_value_two_requests_send_on_is_read_once() -> None:
    resolution = resolve(
        entry("a", "https://api.example.com/orders", answered=json_body('{"id":"4711998"}')),
        entry("b", "https://api.example.com/orders/4711998"),
        entry("c", "https://api.example.com/orders/4711998/confirm", method="POST"),
    )
    assert len(resolution.resolved) == 2
    [read] = resolution.reads
    assert read.variable == "id_value"
    assert resolution.targets_of("id_value") == [2, 3]
    assert resolution.read_after(1) == [read]
    assert resolution.read_after(2) == []


# Values a client has to replay, and why


def test_a_credential_is_supplied_from_the_environment_rather_than_read_back() -> None:
    resolution = resolve(
        entry(
            "a",
            "https://api.example.com/login",
            method="POST",
            answered=json_body('{"access_token":"example-token-not-a-real-credential"}'),
        ),
        entry(
            "b",
            "https://api.example.com/orders",
            headers=[("Authorization", "Bearer example-token-not-a-real-credential")],
        ),
    )
    assert not resolution.resolved
    [replayed] = resolution.unresolved
    assert replayed.target_location == "request.headers.authorization"
    assert "credential" in replayed.reason


def test_a_value_sent_in_a_form_payload_is_replayed_with_the_reason() -> None:
    resolution = resolve(
        entry("a", "https://api.example.com/page", answered=json_body('{"ref":"CNF-998172"}')),
        entry(
            "b",
            "https://api.example.com/confirm",
            method="POST",
            headers=[("Content-Type", FORM)],
            body=Body(mime_type=FORM, text="ref=CNF-998172"),
        ),
    )
    assert not resolution.resolved
    [replayed] = resolution.unresolved
    assert replayed.reason == "the payload it is sent in was not recorded as JSON"


def test_a_value_taken_from_a_page_is_replayed_with_the_reason() -> None:
    # An unparsable payload only hands out the credential shaped values redaction found, so
    # the reason a reader sees for one is the credential rule rather than the payload.
    resolution = resolve(
        entry(
            "a",
            "https://shop.example.com/orders",
            answered=Body(
                mime_type="text/html", text='<script>var csrf = "kd93jfkKD93jfke93";</script>'
            ),
            answered_headers=[("Content-Type", "text/html")],
        ),
        entry(
            "b",
            "https://shop.example.com/api/orders",
            headers=[("X-CSRF-Token", "kd93jfkKD93jfke93")],
        ),
    )
    assert not resolution.resolved
    [replayed] = resolution.unresolved
    assert replayed.source_location == "response.body"
    assert "credential" in replayed.reason


def test_a_value_sitting_inside_a_number_is_not_spliced_into_it() -> None:
    # A number can only carry a value the way ``-99817234`` carries ``99817234``, and
    # writing anything around a read value there would send a payload of another shape.
    resolution = resolve(
        entry("a", "https://api.example.com/page", answered=json_body('{"code":"99817234"}')),
        entry(
            "b",
            "https://api.example.com/confirm",
            method="POST",
            headers=[("Content-Type", JSON)],
            body=json_body('{"reference":-99817234}'),
        ),
    )
    assert not resolution.resolved
    [replayed] = resolution.unresolved
    assert "number" in replayed.reason


# Naming what is read


def test_a_field_named_like_a_builtin_takes_its_parent_name_as_well() -> None:
    resolution = resolve(
        entry(
            "a",
            "https://api.example.com/orders",
            answered=json_body('{"orders":[{"id":"4711998"}]}'),
        ),
        entry("b", "https://api.example.com/orders/4711998"),
    )
    [dependency] = resolution.resolved
    assert dependency.variable == "orders_id"


def test_two_values_wanting_one_name_are_told_apart() -> None:
    resolution = resolve(
        entry(
            "a",
            "https://api.example.com/page",
            answered=json_body('{"first":{"ref":"AAA-99817"},"second":{"ref":"BBB-99817"}}'),
        ),
        entry("b", "https://api.example.com/items/AAA-99817"),
        entry("c", "https://api.example.com/items/BBB-99817"),
    )
    assert [item.variable for item in resolution.reads] == ["ref", "second_ref"]


def test_a_header_name_becomes_an_identifier() -> None:
    resolution = resolve(
        entry(
            "a",
            "https://api.example.com/page",
            answered=json_body("{}"),
            answered_headers=[("Content-Type", JSON), ("X-Page-Ref", "pg-9981723")],
        ),
        entry("b", "https://api.example.com/page/pg-9981723"),
    )
    [dependency] = resolution.resolved
    assert dependency.variable == "x_page_ref"


# A capture with nothing to resolve


def test_a_capture_holding_no_links_resolves_to_nothing() -> None:
    resolution = resolve(
        entry("a", "https://api.example.com/one", answered=json_body('{"kept":"first"}')),
        entry("b", "https://api.example.com/two", answered=json_body('{"kept":"second"}')),
    )
    assert resolution.is_empty
    assert resolution.variables == 0
    assert resolution.reads == []


def test_a_value_landing_in_a_header_the_client_derives_is_replayed() -> None:
    resolution = resolve(
        entry(
            "a",
            "https://api.example.com/page",
            answered=json_body('{"endpoint":"api.example.com"}'),
        ),
        entry("b", "https://api.example.com/next", headers=[("Host", "api.example.com")]),
    )
    assert not resolution.resolved
    [replayed] = resolution.unresolved
    assert replayed.target_location == "request.headers.host"
    assert replayed.reason == (
        "the client sets that header itself rather than sending what was observed"
    )
