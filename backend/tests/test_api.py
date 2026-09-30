"""The HTTP surface, exercised through the app's real startup.

The ``client`` fixture runs the actual lifespan, so these tests cover the thing
a smoke test would cover -- settings resolved, database created, fixtures
ingested, routes served -- rather than calling route functions directly.

Two claims are checked beyond "it returns data":

* **``/api/personas`` reads the database.** People, identities and entitlements
  come from stored rows, not from JSON held in memory, so a passing test here is
  evidence that ingestion persisted domain data rather than merely parsed it.
* **Nothing in the API can change anyone's access.** AccessLens is
  human-controlled, and that is enforced by the absence of a write route, which
  is exactly the kind of property that is easy to lose one endpoint at a time.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.enums import Coverage, EmploymentStatus, UsageObservation


def test_health_reports_a_working_review_surface(client: TestClient) -> None:
    """Health is not a bare liveness ping; it answers "can we review anyone?"."""
    response = client.get("/api/health")
    assert response.status_code == 200

    body = response.json()
    assert body["status"] == "ok"
    assert body["database"] == "ok"
    assert body["users_loaded"] == 9
    assert body["ingest_status"] == "SUCCEEDED_WITH_REJECTIONS"
    assert body["rejections"] == 3
    assert body["content_hash"], "a run without a content hash cannot be cited"
    assert body["detail"] is None


def test_personas_returns_the_whole_review_population(client: TestClient) -> None:
    response = client.get("/api/personas")
    assert response.status_code == 200

    body = response.json()
    assert body["count"] == len(body["personas"]) == 9
    assert body["analysis_as_of"] == "2026-09-29T06:00:00Z"
    assert body["content_hash"]

    usernames = [persona["username"] for persona in body["personas"]]
    assert usernames == sorted(usernames), "the review list should be stably ordered"
    assert "carol.diaz" in usernames


def test_personas_carry_their_identities_entitlements_and_coverage(
    client: TestClient, oracle: dict
) -> None:
    """Every persona's activity verdict matches the oracle.

    The oracle is the specification, so a change in the coverage gate that
    alters a verdict has to be reconciled against a written expectation rather
    than accepted because the response still looks plausible.
    """
    personas = {p["id"]: p for p in client.get("/api/personas").json()["personas"]}

    for expected in oracle["personas"]:
        persona = personas[expected["user_id"]]
        activity = persona["activity"]

        assert activity["coverage"] == expected["overall_coverage"], persona["username"]
        assert activity["usage_observation"] == expected["usage_observation"], (
            persona["username"]
        )
        assert activity["observed_event_count"] == expected["observed_event_count"], (
            persona["username"]
        )


def test_coverage_is_exposed_so_a_client_cannot_misread_zero(
    client: TestClient,
) -> None:
    """Gina's zero events must arrive with the reason they are not evidence.

    A client rendering only ``observed_event_count`` would show "0" for both
    Gina and Alice. The coverage fields are what let the UI tell "we watched and
    saw nothing" apart from "we could not watch".
    """
    personas = {p["username"]: p for p in client.get("/api/personas").json()["personas"]}

    gina = personas["gina.patel"]["activity"]
    assert gina["coverage"] == Coverage.MISSING.value
    assert gina["usage_observation"] == UsageObservation.UNKNOWN.value
    assert gina["observed_event_count"] == 0
    assert gina["sources_missing"], "her missing source must be named"
    assert gina["gaps"], "a gap with no explanation is not evidence"

    alice = personas["alice.nguyen"]["activity"]
    assert alice["coverage"] == Coverage.COMPLETE.value
    assert alice["usage_observation"] == UsageObservation.NONE_OBSERVED.value
    assert alice["observed_event_count"] == 0


def test_protected_roles_are_surfaced_with_their_reason(client: TestClient) -> None:
    """The protection decision travels with the grant, so a reviewer can audit it."""
    personas = {p["username"]: p for p in client.get("/api/personas").json()["personas"]}
    grants = personas["alice.nguyen"]["entitlements"]

    protected = [grant for grant in grants if grant["protected_role"]]
    assert protected, "alice.nguyen's break-glass grant was not marked protected"
    assert all(grant["protection_reason"] for grant in protected)


def test_terminated_personas_expose_their_identity_timeline(client: TestClient) -> None:
    """The ghost-access story needs both halves: employment end and account end."""
    personas = {p["username"]: p for p in client.get("/api/personas").json()["personas"]}
    carol = personas["carol.diaz"]

    assert carol["employment_status"] == EmploymentStatus.TERMINATED.value
    assert carol["termination_date"] == "2026-08-14T17:00:00Z"

    disabled = [
        identity
        for identity in carol["identities"]
        if identity["deactivated_at"] is not None
    ]
    assert disabled, "carol.diaz has no deactivation timestamp"
    assert all(identity["deactivation_trigger"] for identity in disabled)


def test_duplicate_identity_is_visible_rather_than_hidden(client: TestClient) -> None:
    """Two Okta accounts for one person is a review fact, not a display problem."""
    personas = {p["username"]: p for p in client.get("/api/personas").json()["personas"]}
    henry = personas["henry.okafor"]

    assert len(henry["identities"]) == 2
    assert any(identity["is_duplicate_of"] for identity in henry["identities"])


def test_no_endpoint_can_change_anyones_access(client: TestClient) -> None:
    """The whole product promise, enforced by the route table.

    AccessLens never revokes anything: it produces findings for a human to act
    on. An accidental ``POST /api/access/revoke`` would break that, and no test
    of the existing routes would notice it appear.
    """
    routes = [
        (method.upper(), path)
        for path, operations in client.app.openapi()["paths"].items()
        for method in operations
    ]

    mutating = [
        (method, path)
        for method, path in routes
        if method not in {"GET", "HEAD", "OPTIONS"}
    ]
    assert not mutating, f"AccessLens must not expose a write route; found {mutating}"

    assert {path for _, path in routes} == {
        "/api/health",
        "/api/personas",
        "/api/analysis",
        "/api/analysis/findings/{finding_id}",
        "/api/analysis/findings/{finding_id}/investigation",
    }


def test_an_unknown_route_is_a_404_not_an_empty_result(client: TestClient) -> None:
    """A missing endpoint must not look like a persona with nothing to report.

    The example is deliberately the route a plausible product would have and
    this one must not: a reviewer's instinct on seeing a finding is "can I act
    on it here?", and the honest answer has to be a 404 rather than a form.
    """
    assert client.get("/api/access/revoke").status_code == 404
