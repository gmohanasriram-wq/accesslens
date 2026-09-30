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

**The findings contracts are the one place this file does *not* reshape.** The
analysis routes re-serve :class:`~app.schemas.domain.finding.Finding` verbatim
inside :class:`FindingDossierResponse`, and :class:`FindingSummary` drops exactly
one field (``evidence``) and adds exactly two (``subject``, ``evidence_count``).
No field is renamed and no enum is re-spelled. A projection layer here would
create a second name for every fact -- ``severity`` against ``risk``,
``type`` against ``finding_type`` -- and the queue and the dossier could then
disagree about a finding with nothing failing. The engine's word for a thing is
the word an auditor reads.
"""

from __future__ import annotations

from pydantic import AwareDatetime, Field

from app.core.enums import (
    Coverage,
    EvidenceCompleteness,
    FindingStatus,
    FindingType,
    Recommendation,
    RiskLevel,
    Severity,
    UsageObservation,
)
from app.core.time import UTCModel
from app.schemas.domain.finding import Finding

__all__ = [
    "HealthResponse",
    "EntitlementSummary",
    "IdentitySummary",
    "ActivitySummary",
    "PersonaSummary",
    "PersonaListResponse",
    "FindingSubject",
    "FindingSummary",
    "AnalysisResponse",
    "FindingDossierResponse",
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


class FindingSubject(UTCModel):
    """The person a finding is about, in the queue's compact form.

    Deliberately not a :class:`PersonaSummary`. A queue of eight rows is read per
    person, so the row has to say *who* without carrying their identities,
    entitlements and coverage nine times over -- that is what the dossier is for,
    and the dossier fetches the full summary from the same projection
    ``/api/personas`` uses, so the two cannot disagree.
    """

    id: str
    username: str
    name: str
    department: str
    employment_status: str
    termination_date: AwareDatetime | None = None


class FindingSummary(UTCModel):
    """A queue row: the finding without its payload, plus its subject.

    Every field except ``subject`` and ``evidence_count`` is the engine's own,
    carrying the engine's own name. ``evidence`` is the one thing dropped, and
    ``evidence_count`` is the one thing added in its place -- a count is enough
    for a queue row, and shipping sixty evidence records in the list would make
    the list's contract depend on the detail's.
    """

    id: str
    user_id: str
    type: FindingType
    severity: Severity
    status: FindingStatus
    risk_level: RiskLevel
    summary: str
    recommendation: Recommendation
    evidence_completeness: EvidenceCompleteness
    rules_triggered: list[str] = Field(default_factory=list)
    usage: UsageObservation | None = None
    created_at: AwareDatetime

    evidence_count: int
    subject: FindingSubject


class AnalysisResponse(UTCModel):
    """The review queue, with the provenance needed to cite it.

    ``content_hash`` and ``analysis_as_of`` are the same values
    :class:`PersonaListResponse` reports, because they are read off the same
    assembled dataset. Two views of one dataset must not be able to disagree
    about which dataset they are describing.

    ``dataset_fingerprint`` is carried alongside ``content_hash`` because they
    answer different questions: the content hash names the *input files*, which
    is what makes a re-ingest skippable, while the fingerprint names the
    *normalized facts*, which is what a finding cites. ``rejections`` is here
    rather than left to ``/api/health`` because three discarded records is a
    fact about why a finding may be absent, not a fact about the plumbing.
    """

    content_hash: str
    dataset_fingerprint: str
    analysis_as_of: AwareDatetime
    window_start: AwareDatetime
    window_end: AwareDatetime
    rejections: int
    findings: list[FindingSummary]


class FindingDossierResponse(UTCModel):
    """One finding as a citable record: the finding, its subject, its siblings.

    ``finding`` is the domain object unchanged, evidence included. ``subject``
    is the :class:`PersonaSummary` ``/api/personas`` already returns, reused
    rather than re-invented -- the identities, entitlements, coverage and gaps
    the forensic view needs already exist in that shape. ``related_findings``
    carries the person's *other* findings, because Carol carries two facts about
    herself and a dossier that showed one would imply she carries one.
    """

    finding: Finding
    subject: PersonaSummary
    related_findings: list[FindingSummary] = Field(default_factory=list)
