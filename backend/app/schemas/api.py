"""Response contracts for the HTTP API.

Kept separate from :mod:`app.schemas.domain` on purpose. The domain schemas are
the engine's vocabulary and change when the security model changes; these are a
wire format and change when a *client* changes. Coupling them would mean a UI
tweak could alter the shape the Phase 2 engine consumes.

The activity fields here exist to make the coverage model visible to a reviewer.
Returning only an event count would let a client render "0 events" for a user we
never actually looked at, which is the exact conflation the domain model exists
to prevent -- so coverage and its gaps are part of the contract rather than
something a client has to ask for separately.
"""

from __future__ import annotations

from pydantic import AwareDatetime, Field

from app.core.enums import Coverage, UsageObservation
from app.core.time import UTCModel

__all__ = [
    "HealthResponse",
    "EntitlementSummary",
    "IdentitySummary",
    "ActivitySummary",
    "PersonaSummary",
    "PersonaListResponse",
]


class HealthResponse(UTCModel):
    """Liveness and readiness in one payload.

    ``database`` and ``ingest`` are reported separately because they fail
    independently: the process can be up with an unreachable database, and a
    reachable database can hold a dataset that never loaded.
    """

    status: str
    app: str
    version: str
    environment: str
    database: str
    users_loaded: int = 0
    ingest_status: str | None = None
    content_hash: str | None = None
    rejections: int = 0
    detail: str | None = None


class EntitlementSummary(UTCModel):
    source: str
    role: str
    risk_level: str
    protected_role: bool = False
    protection_reason: str | None = None
    protection_tags: list[str] = Field(default_factory=list)
    granted_at: AwareDatetime | None = None


class IdentitySummary(UTCModel):
    provider: str
    account_id: str
    login: str
    status: str
    deactivated_at: AwareDatetime | None = None
    deactivation_trigger: str | None = None
    is_duplicate_of: str | None = None


class ActivitySummary(UTCModel):
    """What was observed, and how much of the window is actually vouched for.

    ``usage_observation`` is the coverage-gated verdict. It is ``UNKNOWN``
    whenever coverage is anything but COMPLETE, which is what stops a client
    from reading "no events" as "no activity" for a user whose telemetry never
    arrived.
    """

    coverage: Coverage
    usage_observation: UsageObservation
    observed_event_count: int = 0
    last_activity_at: AwareDatetime | None = None
    sources_queried: list[str] = Field(default_factory=list)
    sources_missing: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)


class PersonaSummary(UTCModel):
    id: str
    username: str
    name: str
    department: str
    employment_status: str
    termination_date: AwareDatetime | None = None
    identities: list[IdentitySummary] = Field(default_factory=list)
    entitlements: list[EntitlementSummary] = Field(default_factory=list)
    activity: ActivitySummary


class PersonaListResponse(UTCModel):
    count: int
    content_hash: str
    analysis_as_of: AwareDatetime
    generated_at: AwareDatetime | None = None
    personas: list[PersonaSummary]
