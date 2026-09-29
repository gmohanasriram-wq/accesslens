"""Raw activity telemetry, modelled per source.

``activity_logs.json`` is the one input where a single flat shape would be
actively harmful. CloudTrail, GitHub's audit log and a Zscaler proxy export
share almost no field names, so one merged model would make nearly every field
``Optional`` and validation would stop meaning anything.

Instead the file is an envelope containing a coverage manifest plus a
**discriminated union** on ``source``. Pydantic picks the variant by the
``source`` field and validates the real wire format, so a malformed CloudTrail
record fails as a CloudTrail record.

Note what the raw events do *not* contain: an ``actor_id``. Upstream systems
identify people in their own terms -- an IAM ARN, a GitHub login, an email
address -- and mapping those onto an AccessLens user is the normalizer's job
(:mod:`app.ingestion.normalizer`). That mapping is a real, fallible step, and
when it fails the affected user's coverage is downgraded rather than the event
being dropped. Blueprint §10 asks "is the identity mapping reliable?"; this is
the structure that lets the system answer honestly instead of assuming yes.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AwareDatetime, Field

from app.core.enums import ActivitySource, Coverage
from app.core.time import UTCModel

__all__ = [
    "RawSourceCoverage",
    "RawAwsCloudTrailEvent",
    "RawGitHubAuditEvent",
    "RawProxyEvent",
    "RawActivityEvent",
    "RawActivityEnvelope",
]


class RawSourceCoverage(UTCModel):
    """One row of the coverage manifest: did we actually get logs for a source?

    ``MISSING`` is a first-class, explicitly declared state. A source cannot be
    omitted to mean "no data", because the manifest is checked against
    ``Settings.enabled_activity_sources`` -- a missing entry is a validation
    error. That forces the fixture (and, later, a real connector) to *state*
    that data is absent, which is what makes "we could not see this" a fact the
    system can reason about rather than an absence indistinguishable from
    "nothing happened".
    """

    source: ActivitySource
    status: Coverage
    window_start: AwareDatetime | None = None
    window_end: AwareDatetime | None = None
    record_count: int = 0
    note: str | None = None


class _RawEventBase(UTCModel):
    """Fields common to every raw event, plus loader-injected bookkeeping."""

    #: Position of this record in the source array. Injected by the loader (via
    #: ``model_copy``) so that every error message and every stored row can name
    #: the exact record it came from. Never present in the JSON itself.
    raw_index: int = -1

    #: True when the source recorded the attempt as denied/failed. Rule D must
    #: treat a *denied* call as evidence of intent but not as successful use of
    #: the entitlement; without this flag a blocked attempt after deactivation
    #: would be reported as ghost access and overstate severity.
    denied: bool = False

    #: Identifier of the credential used. This is what makes a ghost-access
    #: finding actionable: the story is usually "the IdP account was disabled
    #: but this token was never revoked".
    credential_id: str | None = None


class RawAwsCloudTrailEvent(_RawEventBase):
    """CloudTrail-shaped record (trimmed to the fields AccessLens uses)."""

    source: Literal[ActivitySource.AWS_CLOUDTRAIL] = ActivitySource.AWS_CLOUDTRAIL
    eventID: str
    eventTime: AwareDatetime
    eventName: str
    eventSource: str
    sourceIPAddress: str | None = None
    #: ``arn:aws:iam::<acct>:user/<login>`` -- the normalizer resolves the login.
    userIdentityArn: str
    requestResource: str | None = None
    errorCode: str | None = None

    @property
    def is_denied(self) -> bool:
        return self.errorCode is not None


class RawGitHubAuditEvent(_RawEventBase):
    """GitHub audit-log-shaped record."""

    source: Literal[ActivitySource.GITHUB_AUDIT] = ActivitySource.GITHUB_AUDIT
    event_id: str
    created_at: AwareDatetime
    #: GitHub login, e.g. ``carol.diaz``.
    actor: str
    #: Dotted verb, e.g. ``repo.clone``.
    action: str
    repo: str | None = None
    actor_ip: str | None = None
    token_id: str | None = None


class RawProxyEvent(_RawEventBase):
    """Zscaler/proxy-shaped record.

    The weakest signal in the set: it proves a user reached a resource but says
    nothing about what they did with it. Modelled faithfully rather than
    promoted to something it is not.
    """

    source: Literal[ActivitySource.PROXY_ZSCALER] = ActivitySource.PROXY_ZSCALER
    event_id: str
    timestamp: AwareDatetime
    user: str
    url_category: str
    action: str
    client_ip: str | None = None


RawActivityEvent = Annotated[
    RawAwsCloudTrailEvent | RawGitHubAuditEvent | RawProxyEvent,
    Field(discriminator="source"),
]


class RawActivityEnvelope(UTCModel):
    """The shape of ``data/activity_logs.json``.

    ``source_system`` is optional and the shipped fixture omits it, because this
    file already names its origin per record: the discriminated union means
    every event states which feed it came from, which the other three envelopes
    cannot do. A file-level source would be redundant here and, worse, could
    contradict the per-record tags.
    """

    generated_at: AwareDatetime
    lookback_days: int
    source_system: str | None = None
    coverage: list[RawSourceCoverage]
    events: list[RawActivityEvent]
