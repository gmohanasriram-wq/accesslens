"""Raw wire formats, one per upstream system.

These mirror what the source systems actually emit, so that a malformed record
fails as a record from *that* system. They are converted to the domain model in
:mod:`app.ingestion.normalizer` and are never used by the engine.
"""

from app.schemas.raw.activity import (
    RawActivityEnvelope,
    RawActivityEvent,
    RawAwsCloudTrailEvent,
    RawGitHubAuditEvent,
    RawProxyEvent,
    RawSourceCoverage,
)
from app.schemas.raw.entitlements import RawEntitlement, RawEntitlementEnvelope
from app.schemas.raw.hr import RawHREnvelope, RawHRUser
from app.schemas.raw.idp import RawIdPEnvelope, RawIdPIdentity

__all__ = [
    "RawActivityEnvelope",
    "RawActivityEvent",
    "RawAwsCloudTrailEvent",
    "RawEntitlement",
    "RawEntitlementEnvelope",
    "RawGitHubAuditEvent",
    "RawHREnvelope",
    "RawHRUser",
    "RawIdPEnvelope",
    "RawIdPIdentity",
    "RawProxyEvent",
    "RawSourceCoverage",
]
