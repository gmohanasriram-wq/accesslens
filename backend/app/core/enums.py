"""Shared vocabulary for AccessLens.

This module is a **leaf**: it must never import from anywhere else in ``app``.
Schemas, ORM models, ingestion, the API and (in Phase 2) the security engine all
import from here, so any import in this file would create a cycle or drag
SQLAlchemy/FastAPI into what should be pure validation.

All enums are ``StrEnum`` so their values serialise as plain JSON strings. That
matters because the Phase 2 test oracles are JSON files, and because audit
evidence has to be readable by something that is not this codebase.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = [
    "EmploymentStatus",
    "IdentityStatus",
    "IdentityProvider",
    "SourceSystem",
    "ActivitySource",
    "EntitlementSource",
    "RiskLevel",
    "Severity",
    "FindingType",
    "FindingStatus",
    "Recommendation",
    "UsageObservation",
    "Coverage",
    "EvidenceCompleteness",
    "EvidenceKind",
    "GapReason",
    "Capability",
    "RecommendationDecision",
    "IngestStatus",
]


# --------------------------------------------------------------------------- #
# People and identity
# --------------------------------------------------------------------------- #


class EmploymentStatus(StrEnum):
    """Employment state as reported by the HR system of record."""

    ACTIVE = "ACTIVE"
    TERMINATED = "TERMINATED"
    ON_LEAVE = "ON_LEAVE"
    UNKNOWN = "UNKNOWN"


class IdentityStatus(StrEnum):
    """Account state as reported by the identity provider.

    Deliberately distinct from :class:`EmploymentStatus`: an employee can be
    ACTIVE in HR while their IdP account is SUSPENDED, and the disagreement
    between the two is itself evidence.
    """

    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    DISABLED = "DISABLED"
    DEPROVISIONED = "DEPROVISIONED"
    UNKNOWN = "UNKNOWN"


class IdentityProvider(StrEnum):
    OKTA = "okta"
    AZURE_AD = "azure_ad"
    GOOGLE_WORKSPACE = "google_workspace"
    UNKNOWN = "unknown"


# --------------------------------------------------------------------------- #
# Sources
# --------------------------------------------------------------------------- #


class SourceSystem(StrEnum):
    """The four upstream systems AccessLens ingests from."""

    HR = "hr"
    IDP = "idp"
    ENTITLEMENT = "entitlement"
    ACTIVITY = "activity"


class ActivitySource(StrEnum):
    """Telemetry feeds. Each has its own wire format; see ``schemas/raw/activity.py``."""

    AWS_CLOUDTRAIL = "aws_cloudtrail"
    GITHUB_AUDIT = "github_audit"
    PROXY_ZSCALER = "proxy_zscaler"
    UNKNOWN = "unknown"


class EntitlementSource(StrEnum):
    """Systems that grant access. Separate from :class:`ActivitySource`
    because a system can grant access without emitting usable telemetry, or
    vice versa -- and that asymmetry is itself a finding (see Erin, whose
    CloudTrail coverage is truncated while her AdministratorAccess is not).
    """

    AWS = "aws"
    GITHUB = "github"
    APPLICATION = "application"
    UNKNOWN = "unknown"


# --------------------------------------------------------------------------- #
# Risk and findings
# --------------------------------------------------------------------------- #


class RiskLevel(StrEnum):
    """How much damage the granted access could do if misused."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class Severity(StrEnum):
    """How urgently a finding needs attention."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingType(StrEnum):
    """What kind of thing the engine concluded.

    ``NO_FINDING`` is an explicit member rather than an absent row. The blueprint
    §16 matrix has two rows whose correct outcome is "nothing is wrong" ("normal
    user", "disabled with no later activity"); those deserve a positive
    assertion, not just an empty list that could also mean "the rule crashed".
    """

    HIGH_PRIVILEGE_LOW_USAGE = "HIGH_PRIVILEGE_LOW_USAGE"
    PROTECTED_BREAK_GLASS = "PROTECTED_BREAK_GLASS"
    GHOST_ACCESS = "GHOST_ACCESS"
    RARELY_USED_PRIVILEGED_PERMISSION = "RARELY_USED_PRIVILEGED_PERMISSION"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    DUPLICATE_IDENTITY = "DUPLICATE_IDENTITY"
    NO_FINDING = "NO_FINDING"


class FindingStatus(StrEnum):
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    PROTECTED = "PROTECTED"
    INVESTIGATION_REQUIRED = "INVESTIGATION_REQUIRED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    INFORMATIONAL = "INFORMATIONAL"
    CLOSED = "CLOSED"


class Recommendation(StrEnum):
    """The action AccessLens suggests to a human reviewer.

    SECURITY INVARIANT: no member of this enum expresses revocation, disabling,
    or any other automatic change to access. AccessLens never changes access; a
    human decides. Encoding that as an enum with no such member means the
    no-auto-revocation rule is enforced by the type system rather than by
    reviewer discipline -- an AI layer in Phase 4 literally cannot express
    "revoke" using this contract.
    """

    MANUAL_REVIEW = "MANUAL_REVIEW"
    SUGGEST_DOWNSCOPE_MANUAL_APPROVAL = "SUGGEST_DOWNSCOPE_MANUAL_APPROVAL"
    NO_ACTION_DOCUMENT_JUSTIFICATION = "NO_ACTION_DOCUMENT_JUSTIFICATION"
    INVESTIGATE_GHOST_ACCESS = "INVESTIGATE_GHOST_ACCESS"
    GATHER_MORE_EVIDENCE = "GATHER_MORE_EVIDENCE"


class UsageObservation(StrEnum):
    """How much a user was *observed* to use, within a window we can vouch for.

    ``UNKNOWN`` is not a synonym for ``NONE_OBSERVED``. ``NONE_OBSERVED`` means
    "we had full log coverage and saw nothing"; ``UNKNOWN`` means "we cannot
    say". Collapsing the two is how an access review reports "safe" when the
    truth is "unmeasured" -- see ``Coverage``.

    ``OBSERVED`` is the Phase 1 verdict: activity happened and the window can be
    vouched for, but the *level* has not been judged. The Phase 2 engine refines
    it into HIGH/MODERATE/LOW using ``Settings.low_utilization_threshold``,
    because that comparison needs the granted-capability set, which a
    per-user activity slice does not hold.
    """

    HIGH = "HIGH"
    MODERATE = "MODERATE"
    LOW = "LOW"
    OBSERVED = "OBSERVED"
    NONE_OBSERVED = "NONE_OBSERVED"
    UNKNOWN = "UNKNOWN"


class Coverage(StrEnum):
    """Whether we actually have logs for a given source and window."""

    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    MISSING = "MISSING"
    NOT_QUERIED = "NOT_QUERIED"


class EvidenceCompleteness(StrEnum):
    """How much of the evidence a finding *should* rest on actually exists."""

    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    MISSING = "MISSING"


class EvidenceKind(StrEnum):
    """What a single piece of evidence is.

    ``COVERAGE_STATEMENT`` exists so that "we could not see X" is itself
    recordable evidence, rather than the silent absence of a row.
    """

    ACTIVITY_EVENT = "ACTIVITY_EVENT"
    TIMELINE_POINT = "TIMELINE_POINT"
    ENTITLEMENT_GRANT = "ENTITLEMENT_GRANT"
    COVERAGE_STATEMENT = "COVERAGE_STATEMENT"
    CONFIG_VALUE = "CONFIG_VALUE"
    REJECTED_RECORD = "REJECTED_RECORD"
    IDENTITY_LINK = "IDENTITY_LINK"


class GapReason(StrEnum):
    """Why a hole in the evidence exists. Every gap must state a reason."""

    SOURCE_MISSING = "SOURCE_MISSING"
    WINDOW_TRUNCATED = "WINDOW_TRUNCATED"
    RECORDS_REJECTED = "RECORDS_REJECTED"
    SOURCE_NOT_QUERIED = "SOURCE_NOT_QUERIED"
    IDENTITY_UNMAPPED = "IDENTITY_UNMAPPED"


class Capability(StrEnum):
    """A coarse, cross-vendor vocabulary of what an action *achieves*.

    Rule A compares granted capabilities against observed ones. AWS actions
    (``s3:GetObject``) and GitHub actions (``repo.clone``) are different
    vocabularies, so both are mapped into this shared set by
    ``core.capabilities``. Coarse on purpose: "can read S3" is the unit a
    reviewer reasons about, not individual API calls.
    """

    S3_READ = "S3_READ"
    S3_WRITE = "S3_WRITE"
    S3_DELETE = "S3_DELETE"
    EC2_READ = "EC2_READ"
    EC2_WRITE = "EC2_WRITE"
    IAM_READ = "IAM_READ"
    IAM_WRITE = "IAM_WRITE"
    KMS_READ = "KMS_READ"
    KMS_WRITE = "KMS_WRITE"
    LOGS_READ = "LOGS_READ"
    LOGS_WRITE = "LOGS_WRITE"
    REPO_READ = "REPO_READ"
    REPO_WRITE = "REPO_WRITE"
    REPO_ADMIN = "REPO_ADMIN"
    ORG_ADMIN = "ORG_ADMIN"
    FINANCE_READ = "FINANCE_READ"
    FINANCE_APPROVE = "FINANCE_APPROVE"
    STS_ASSUME_ROLE = "STS_ASSUME_ROLE"
    UNKNOWN = "UNKNOWN"


class RecommendationDecision(StrEnum):
    """The human's decision. Phase 3 records these; nothing in Phase 1 sets one.

    Separate from :class:`Recommendation` on purpose: the system *suggests*, a
    person *decides*, and the two must never be the same field.
    """

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    DEFERRED = "DEFERRED"


class IngestStatus(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    SUCCEEDED_WITH_REJECTIONS = "SUCCEEDED_WITH_REJECTIONS"
    FAILED = "FAILED"
    SKIPPED_UNCHANGED = "SKIPPED_UNCHANGED"
