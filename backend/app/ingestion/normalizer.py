"""Raw records -> domain objects, and the coverage accounting that qualifies them.

Two jobs live here, and they are close relatives:

1. **Translation.** Each source's wire format becomes the shared domain shape.
   CloudTrail's ``eventTime``/``eventName`` and GitHub's ``created_at``/``action``
   both become :class:`~app.schemas.domain.activity.ActivityEvent`.

2. **Coverage accounting.** Deciding, per person, how much of the window we can
   actually vouch for -- and recording a :class:`CoverageGap` with a stated
   reason for every part we cannot.

The second job is why this module exists at all rather than being a few
``model_validate`` calls. Blueprint §16 contains two rows that are about the
*absence* of evidence, not its content:

    | Missing activity logs   | Insufficient evidence |
    | Invalid timestamp       | Validation error / insufficient evidence |

Neither can be produced by an event-shaped pipeline, because both are statements
about what was *not* loaded. They are produced here, and the gate in
:attr:`ActivitySlice.usage_observation` makes them impossible to bypass later.

**Why coverage is scoped per user, not globally.** The coverage manifest is a
global statement -- "the CloudTrail export for this window is truncated" -- but
its *consequences* are not global. A truncated export can only hide activity
from a source that would have observed the person in question. So a source is
relevant to a user when the user holds access in a system that source watches
(see :data:`ENTITLEMENT_SOURCE_TO_ACTIVITY`), or when we have actually seen an
event for them from it.

This distinction is load-bearing for the demo, not just for tidiness. With
global scoping, one missing source would mark *every* persona
``INSUFFICIENT_EVIDENCE`` and the blueprint's other eight scenarios could never
be exhibited at all. Per-user scoping is also simply the more honest model: a
missing proxy export genuinely cannot hide Bob's AWS usage when Bob's only access
is AWS.

Note the direction of the error, because it is deliberate: relevance is inferred
*only* from access we know about. If a person has access in a system, the
telemetry for that system is relevant whether or not they ever used it. The
model never narrows relevance to make a finding easier.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime

from app.core.config import Settings
from app.core.enums import (
    ActivitySource,
    Coverage,
    EntitlementSource,
    GapReason,
    RiskLevel,
)
from app.core.errors import IngestRejection
from app.ingestion.resolution import IdentityResolver, parse_aws_arn_identity
from app.schemas.domain.activity import ActivityEvent, ActivitySlice, CoverageGap
from app.schemas.domain.entitlement import Entitlement
from app.schemas.domain.identity import Identity
from app.schemas.domain.user import User
from app.schemas.raw.activity import (
    RawActivityEvent,
    RawAwsCloudTrailEvent,
    RawGitHubAuditEvent,
    RawProxyEvent,
    RawSourceCoverage,
)
from app.schemas.raw.entitlements import RawEntitlement
from app.schemas.raw.hr import RawHRUser
from app.schemas.raw.idp import RawIdPIdentity

__all__ = [
    "ENTITLEMENT_SOURCE_TO_ACTIVITY",
    "NormalizationResult",
    "normalize_users",
    "normalize_identities",
    "normalize_entitlements",
    "normalize_events",
    "build_activity_slices",
    "relevant_sources_for",
]


#: Which telemetry feed watches which system. Used to decide whether a gap in a
#: source's coverage can possibly affect a given person.
#:
#: ``APPLICATION`` maps to the proxy because application access is observed on
#: the network, not in the application's own audit log -- which is exactly the
#: weakness of proxy telemetry noted in ``schemas/raw/activity.py``. It proves
#: someone reached the application, not what they did there.
ENTITLEMENT_SOURCE_TO_ACTIVITY: dict[EntitlementSource, frozenset[ActivitySource]] = {
    EntitlementSource.AWS: frozenset({ActivitySource.AWS_CLOUDTRAIL}),
    EntitlementSource.GITHUB: frozenset({ActivitySource.GITHUB_AUDIT}),
    EntitlementSource.APPLICATION: frozenset({ActivitySource.PROXY_ZSCALER}),
    EntitlementSource.UNKNOWN: frozenset(),
}


# --------------------------------------------------------------------------- #
# Users, identities, entitlements
# --------------------------------------------------------------------------- #


def normalize_users(records: Iterable[RawHRUser]) -> list[User]:
    """HR records -> :class:`User`.

    Nearly a field copy, but kept as an explicit step so that the domain shape
    is never accidentally the wire shape. When HR changes its export, this is
    the one function that has to change.
    """
    return [
        User(
            id=raw.id,
            username=raw.username,
            name=raw.name,
            email=raw.email,
            department=raw.department,
            employment_status=raw.employment_status,
            termination_date=raw.termination_date,
            termination_reason=raw.termination_reason,
            manager_id=raw.manager_id,
            hire_date=raw.hire_date,
            source_updated_at=raw.source_updated_at,
        )
        for raw in records
    ]


def normalize_identities(
    records: Iterable[RawIdPIdentity],
    resolver: IdentityResolver,
) -> tuple[list[Identity], list[IngestRejection]]:
    """IdP records -> :class:`Identity`, resolving each account to a person.

    An account whose login and email resolve to nobody is *rejected*, not
    dropped. There is no user to downgrade coverage for, so silence would be the
    only alternative -- and silence about an account we cannot place is how an
    orphaned-but-live account goes unnoticed.

    Accounts that resolve to a person who already has another account in the
    same provider are marked ``is_duplicate_of`` rather than merged. Merging
    would destroy the evidence; the duplicate-identity finding needs both rows
    to exist.
    """
    identities: list[Identity] = []
    rejections: list[IngestRejection] = []

    for raw in records:
        user_id = resolver.resolve(raw.login) or resolver.resolve(raw.email)
        if user_id is None:
            rejections.append(
                IngestRejection(
                    file="idp_state.json",
                    raw_index=raw.raw_index,
                    record_id=raw.account_id,
                    field_path="login",
                    reason=(
                        "identity could not be resolved to a known user; the "
                        "account exists but belongs to nobody we know about"
                    ),
                    raw_value=raw.login,
                    actor_hint=raw.login,
                )
            )
            continue

        identities.append(
            Identity(
                user_id=user_id,
                provider=raw.provider,
                account_id=raw.account_id,
                login=raw.login,
                email=raw.email,
                status=raw.status,
                deactivated_at=raw.deactivated_at,
                deactivation_trigger=raw.deactivation_trigger,
                groups=list(raw.groups),
                mfa_enrolled=raw.mfa_enrolled,
            )
        )

    return _mark_duplicates(identities), rejections


def _mark_duplicates(identities: list[Identity]) -> list[Identity]:
    """Flag people who hold more than one account in the same provider.

    The canonical account is the lexicographically **smallest** ``account_id``,
    not the first one in the file. That distinction is deliberate: "first in the
    export" would make the flag depend on record ordering, so reordering an
    unchanged file would change which account is canonical -- and would change
    ``dataset_fingerprint()``, making two identical datasets hash differently.
    Choosing by value makes the result a property of the facts.

    The duplicate is flagged rather than merged. Merging would delete the very
    evidence the duplicate-identity finding rests on, and the second account is
    usually the interesting one -- a stale account someone forgot to close.
    """
    groups: dict[tuple[str, str], str] = {}
    for identity in identities:
        key = (str(identity.provider), identity.user_id)
        current = groups.get(key)
        if current is None or identity.account_id < current:
            groups[key] = identity.account_id

    # Only keys that appeared more than once are real duplicates; a lone account
    # whose id happens to be the minimum of one is not one.
    counts: dict[tuple[str, str], int] = {}
    for identity in identities:
        key = (str(identity.provider), identity.user_id)
        counts[key] = counts.get(key, 0) + 1

    canonical = {key: value for key, value in groups.items() if counts[key] > 1}

    marked: list[Identity] = []
    for identity in identities:
        key = (str(identity.provider), identity.user_id)
        is_dup_of = canonical.get(key)
        marked.append(
            identity.model_copy(
                update={
                    "is_duplicate_of": (
                        is_dup_of if is_dup_of and is_dup_of != identity.account_id else None
                    )
                }
            )
        )
    return marked


def normalize_entitlements(
    records: Iterable[RawEntitlement],
    resolver: IdentityResolver,
    settings: Settings,
) -> tuple[list[Entitlement], list[IngestRejection]]:
    """Entitlement records -> :class:`Entitlement`.

    Two derived values are filled in here rather than trusted from the source:

    * ``risk_level``, when the record does not state one, is looked up from
      ``Settings`` -- so "which roles are dangerous" is configurable policy
      rather than a constant buried in the fixture.
    * ``protected_role``, when the record does not state one, falls back to the
      role-name patterns in ``Settings``.

    Both are *fallbacks*, and the fixture set states both explicitly so the
    fallback is never load-bearing in the demo. That matters: a protection flag
    that only works by guessing from a role's name is a protection flag that
    will eventually guess wrong.
    """
    entitlements: list[Entitlement] = []
    rejections: list[IngestRejection] = []

    for raw in records:
        user_id = resolver.resolve_principal(raw.principal)
        if user_id is None:
            rejections.append(
                IngestRejection(
                    file="entitlements.json",
                    raw_index=raw.raw_index,
                    record_id=raw.principal,
                    field_path="principal",
                    reason=(
                        "grant could not be attributed to a known user; the "
                        "access exists but belongs to nobody we know about"
                    ),
                    raw_value=raw.principal,
                    actor_hint=raw.principal,
                )
            )
            continue

        protected, reason, tags = _resolve_protection(raw, settings)

        entitlements.append(
            Entitlement(
                user_id=user_id,
                source=raw.source,
                role=raw.role,
                role_arn=raw.role_arn,
                org=raw.org,
                permissions=list(raw.permissions),
                risk_level=_resolve_risk(raw, settings),
                protected_role=protected,
                protection_reason=reason,
                protection_tags=tags,
                granted_at=raw.granted_at,
                principal=raw.principal,
            )
        )

    return entitlements, rejections


def _resolve_risk(raw: RawEntitlement, settings: Settings) -> RiskLevel:
    """The record's own risk level, or one inferred from the role's name.

    Inferred only as a fallback. ``risk_level`` describes the *consequence* of
    misuse, which the granting system is better placed to state than a substring
    match on a role name performed here.
    """
    if raw.risk_level is not RiskLevel.UNKNOWN:
        return raw.risk_level
    if raw.role in settings.critical_risk_entitlement_roles:
        return RiskLevel.CRITICAL
    if raw.role in settings.high_risk_entitlement_roles:
        return RiskLevel.HIGH
    return RiskLevel.UNKNOWN


def _resolve_protection(
    raw: RawEntitlement, settings: Settings
) -> tuple[bool, str | None, list[str]]:
    """Decide whether a grant is break-glass, and record *why*.

    The "why" is not decoration. Rule C suppresses a pruning recommendation on
    the strength of this flag, so the resulting finding has to be able to tell a
    reviewer which policy decision protected it. A boolean alone would make the
    protection unauditable.
    """
    if raw.protected_role:
        reason = raw.protection_reason or "marked protected by the granting system"
        return True, reason, list(raw.protection_tags)

    if raw.role in settings.always_protected_roles:
        return (
            True,
            f"role {raw.role!r} is on the always-protected list",
            ["always_protected_list"],
        )

    lowered = raw.role.lower()
    for pattern in settings.protected_role_patterns:
        if pattern.lower() in lowered:
            return (
                True,
                f"role name {raw.role!r} matches protected pattern {pattern!r}",
                [f"pattern:{pattern}"],
            )

    return False, None, []


# --------------------------------------------------------------------------- #
# Activity
# --------------------------------------------------------------------------- #


@dataclass
class NormalizationResult:
    """Normalised activity plus everything that could not be normalised.

    ``unattributable`` is kept separate from ``rejections`` because the two mean
    different things. A *rejection* is a record we could not read; an
    *unattributable* event is a record we read perfectly well but could not
    connect to a person. Conflating them would hide the more interesting case --
    a valid event with no owner is a different problem from a malformed one, and
    it is the one a real environment produces constantly (shared roles, service
    accounts, assumed-role sessions with no human behind them).
    """

    events: list[ActivityEvent] = field(default_factory=list)
    rejections: list[IngestRejection] = field(default_factory=list)
    unattributable: list[str] = field(default_factory=list)


def normalize_events(
    records: Iterable[RawActivityEvent],
    resolver: IdentityResolver,
) -> NormalizationResult:
    """Raw telemetry -> :class:`ActivityEvent`, resolving each actor.

    An event whose actor cannot be resolved is not silently discarded. It is
    reported as unattributable, and
    :func:`build_activity_slices` decides whether the gap can be pinned on a
    specific person's coverage or has to stay a dataset-level caveat.
    """
    result = NormalizationResult()

    for raw in records:
        actor = _actor_of(raw)
        user_id = resolver.resolve_activity_actor(actor)

        if user_id is None:
            result.unattributable.append(actor or "<no actor field>")
            result.rejections.append(
                IngestRejection(
                    file="activity_logs.json",
                    raw_index=raw.raw_index,
                    record_id=getattr(raw, "eventID", None) or getattr(raw, "event_id", None),
                    field_path="actor",
                    reason=(
                        "event is valid but its actor could not be mapped to a "
                        "person; a shared role or service principal has no human "
                        "to attribute this activity to"
                    ),
                    raw_value=actor,
                    actor_hint=actor,
                    # Carried so the manifest arithmetic can account for this
                    # record. Without it the event counts as *unexplained* in
                    # the declared-versus-parsed reconciliation, which would
                    # mark the whole export truncated and degrade every user of
                    # this source -- punishing everyone for one event that we in
                    # fact read perfectly well, and destroying findings that the
                    # data fully supports.
                    source=str(raw.source),
                )
            )
            continue

        result.events.append(_to_event(raw, user_id))

    return result


def _actor_of(raw: RawActivityEvent) -> str | None:
    """The source-native actor field, whichever variant this is."""
    if isinstance(raw, RawAwsCloudTrailEvent):
        return raw.userIdentityArn
    if isinstance(raw, RawGitHubAuditEvent):
        return raw.actor
    if isinstance(raw, RawProxyEvent):
        return raw.user
    return None


def _to_event(raw: RawActivityEvent, user_id: str) -> ActivityEvent:
    """Collapse one source's wire format into the shared event shape.

    The ``event_id`` is prefixed with the source because ids are only unique
    within a source, and the primary key downstream is the id itself. Without
    the prefix, a CloudTrail ``eventID`` and a GitHub ``event_id`` that happened
    to collide would silently overwrite one another on ingest.
    """
    if isinstance(raw, RawAwsCloudTrailEvent):
        return ActivityEvent(
            event_id=f"aws_{raw.eventID}",
            timestamp=raw.eventTime,
            actor_id=user_id,
            source=raw.source,
            action=raw.eventName,
            resource=raw.requestResource,
            source_ip=raw.sourceIPAddress,
            credential_id=raw.credential_id,
            # A CloudTrail error code means the call was refused. Rule D must not
            # read a refused call as successful use of the entitlement, even
            # though it *is* proof the credential was still live.
            denied=raw.is_denied,
            raw_index=raw.raw_index,
        )

    if isinstance(raw, RawGitHubAuditEvent):
        return ActivityEvent(
            event_id=f"gh_{raw.event_id}",
            timestamp=raw.created_at,
            actor_id=user_id,
            source=raw.source,
            action=raw.action,
            resource=raw.repo,
            source_ip=raw.actor_ip,
            credential_id=raw.token_id,
            denied=raw.denied,
            raw_index=raw.raw_index,
        )

    return ActivityEvent(
        event_id=f"px_{raw.event_id}",
        timestamp=raw.timestamp,
        actor_id=user_id,
        source=raw.source,
        action=raw.action,
        resource=raw.url_category,
        source_ip=raw.client_ip,
        credential_id=raw.credential_id,
        denied=raw.denied,
        raw_index=raw.raw_index,
    )


# --------------------------------------------------------------------------- #
# Coverage
# --------------------------------------------------------------------------- #


def relevant_sources_for(
    user_id: str,
    entitlements: Sequence[Entitlement],
    observed_sources: frozenset[ActivitySource],
) -> frozenset[ActivitySource]:
    """Which telemetry feeds could possibly have observed this person.

    A source is relevant when the user holds access in a system it watches, or
    when we have already seen an event for them from it. The second clause is
    what keeps the model honest in the other direction: if we observed activity
    from a source, that source is relevant by definition, whatever the
    entitlement export says. A missing entitlement record must not be able to
    shrink someone's coverage to nothing.
    """
    relevant: set[ActivitySource] = set(observed_sources)
    for entitlement in entitlements:
        if entitlement.user_id == user_id:
            relevant |= ENTITLEMENT_SOURCE_TO_ACTIVITY.get(
                entitlement.source, frozenset()
            )
    return frozenset(relevant)


@dataclass
class _SourceVerdict:
    """Per-source coverage outcome for one user, before it becomes a gap."""

    status: Coverage
    gap: CoverageGap | None = None


def build_activity_slices(
    *,
    users: Sequence[User],
    entitlements: Sequence[Entitlement],
    events: Sequence[ActivityEvent],
    manifest: Sequence[RawSourceCoverage],
    rejections: Sequence[IngestRejection],
    resolver: IdentityResolver,
    settings: Settings,
    window: tuple[datetime, datetime],
    activity_loaded: bool,
) -> dict[str, ActivitySlice]:
    """Assemble one :class:`ActivitySlice` per user, gaps included.

    ``activity_loaded`` is the whole-file flag: when the telemetry export could
    not be read at all we have not merely lost some records, we have never
    looked. That is a different statement from "the source says it sent nothing"
    and it produces ``NOT_QUERIED`` rather than ``MISSING``, so the two remain
    distinguishable in the evidence.
    """
    window_start, window_end = window

    by_user: dict[str, list[ActivityEvent]] = {user.id: [] for user in users}
    for event in events:
        # An event for an unknown user would mean the resolver produced an id
        # with no HR record behind it; that is an upstream bug worth seeing, not
        # a reason to drop the event quietly.
        by_user.setdefault(event.actor_id, []).append(event)

    manifest_by_source = {entry.source: entry for entry in manifest}
    parsed_by_source = _count_by_source(events)
    rejected_by_source = _rejections_by_source(rejections)

    slices: dict[str, ActivitySlice] = {}
    for user in users:
        user_events = by_user.get(user.id, [])
        observed_sources = frozenset(event.source for event in user_events)
        user_entitlements = [e for e in entitlements if e.user_id == user.id]
        relevant = relevant_sources_for(user.id, entitlements, observed_sources)

        gaps: list[CoverageGap] = []
        queried: set[ActivitySource] = set()
        missing: set[ActivitySource] = set()
        statuses: list[Coverage] = []

        if not activity_loaded:
            # We never looked. Every relevant source is unqueried -- including
            # sources we would only have known to look at because of an
            # entitlement we did load.
            relevant = relevant or frozenset(settings.enabled_activity_sources)
            for source in sorted(relevant, key=str):
                missing.add(source)
                gaps.append(
                    CoverageGap(
                        source=source,
                        reason=GapReason.SOURCE_NOT_QUERIED,
                        detail=(
                            "the activity export could not be read, so no "
                            "telemetry was queried for this window"
                        ),
                    )
                )
            slices[user.id] = ActivitySlice(
                user_id=user.id,
                window_start=window_start,
                window_end=window_end,
                events=user_events,
                sources_queried=frozenset(),
                sources_missing=frozenset(missing),
                gaps=gaps,
                coverage=Coverage.NOT_QUERIED,
            )
            continue

        for source in sorted(relevant, key=str):
            verdict = _verdict_for_source(
                source=source,
                entry=manifest_by_source.get(source),
                parsed_count=parsed_by_source.get(source, 0),
                rejected_count=rejected_by_source.get(source, 0),
                user_rejections=_rejections_for_user(
                    rejections, user.id, source, resolver
                ),
                user_id=user.id,
            )
            statuses.append(verdict.status)
            if verdict.status is Coverage.MISSING:
                missing.add(source)
            else:
                queried.add(source)
            if verdict.gap is not None:
                gaps.append(verdict.gap)

        slices[user.id] = ActivitySlice(
            user_id=user.id,
            window_start=window_start,
            window_end=window_end,
            events=user_events,
            sources_queried=frozenset(queried),
            sources_missing=frozenset(missing),
            gaps=gaps,
            coverage=_overall_coverage(statuses),
        )

    return slices


def _overall_coverage(statuses: Sequence[Coverage]) -> Coverage:
    """Roll per-source statuses into one verdict.

    Deliberately asymmetric, in the safe direction:

    * every relevant source COMPLETE          -> COMPLETE
    * no usable source at all                 -> MISSING
    * anything in between                      -> PARTIAL

    There is no path from "we are missing something" to COMPLETE, and no path
    from PARTIAL to a determinate usage observation -- that second guarantee
    lives in :attr:`ActivitySlice.usage_observation`.
    """
    if not statuses:
        # No access, so no telemetry could have observed this person. Vacuously
        # complete: there is nothing we failed to look at.
        return Coverage.COMPLETE
    if all(status is Coverage.COMPLETE for status in statuses):
        return Coverage.COMPLETE
    if all(status is Coverage.MISSING for status in statuses):
        return Coverage.MISSING
    return Coverage.PARTIAL


def _verdict_for_source(
    *,
    source: ActivitySource,
    entry: RawSourceCoverage | None,
    parsed_count: int,
    rejected_count: int,
    user_rejections: list[IngestRejection],
    user_id: str,
) -> _SourceVerdict:
    """Coverage for one (user, source) pair.

    The order of these checks is the order of decreasing authority: what the
    source says about itself first, then what the numbers say, then what we did
    to this particular user's records.
    """
    if entry is None:
        return _SourceVerdict(
            status=Coverage.MISSING,
            gap=CoverageGap(
                source=source,
                reason=GapReason.SOURCE_NOT_QUERIED,
                detail=(
                    f"{source} is absent from the coverage manifest, so the "
                    "source never declared whether it sent data for this window"
                ),
            ),
        )

    if entry.status is Coverage.MISSING:
        return _SourceVerdict(
            status=Coverage.MISSING,
            gap=CoverageGap(
                source=source,
                reason=GapReason.SOURCE_MISSING,
                window_start=entry.window_start,
                window_end=entry.window_end,
                detail=entry.note
                or f"{source} declared MISSING for this window",
            ),
        )

    if entry.status is Coverage.PARTIAL:
        return _SourceVerdict(
            status=Coverage.PARTIAL,
            gap=CoverageGap(
                source=source,
                reason=GapReason.WINDOW_TRUNCATED,
                window_start=entry.window_start,
                window_end=entry.window_end,
                detail=entry.note or f"{source} declared PARTIAL for this window",
            ),
        )

    # The source claims COMPLETE. Check the claim against what actually arrived:
    # an export can be truncated in transit while still asserting completeness,
    # and a manifest that is trusted without checking is not evidence.
    #
    # Rejections explain part of any shortfall, so they are subtracted before
    # calling it truncation. A record we rejected is accounted for -- it becomes
    # that user's RECORDS_REJECTED gap below, which is a more precise statement
    # than "the whole export is short".
    unexplained = entry.record_count - parsed_count - rejected_count
    if unexplained > 0:
        return _SourceVerdict(
            status=Coverage.PARTIAL,
            gap=CoverageGap(
                source=source,
                reason=GapReason.WINDOW_TRUNCATED,
                window_start=entry.window_start,
                window_end=entry.window_end,
                affected_record_count=unexplained,
                detail=(
                    f"{source} declared COMPLETE and reported "
                    f"{entry.record_count} records, but only {parsed_count} "
                    f"parsed and {rejected_count} were rejected -- "
                    f"{unexplained} records are unaccounted for"
                ),
            ),
        )

    if user_rejections:
        return _SourceVerdict(
            status=Coverage.PARTIAL,
            gap=CoverageGap(
                source=source,
                reason=_rejection_gap_reason(user_rejections),
                affected_record_count=len(user_rejections),
                detail=(
                    f"{len(user_rejections)} record(s) from {source} for this "
                    f"user could not be used: "
                    + "; ".join(sorted({r.reason for r in user_rejections}))
                ),
            ),
        )

    return _SourceVerdict(status=Coverage.COMPLETE)


def _rejection_gap_reason(rejections: Sequence[IngestRejection]) -> GapReason:
    """Attribute the gap to the right failure.

    A record we could not map to a person is a *mapping* failure even though it
    is stored as a rejection, and reporting it as "records rejected" would send
    a reviewer looking for a malformed file when the real problem is an
    incomplete identity join.
    """
    if any(r.field_path == "actor" for r in rejections):
        return GapReason.IDENTITY_UNMAPPED
    return GapReason.RECORDS_REJECTED


def _count_by_source(events: Iterable[ActivityEvent]) -> dict[ActivitySource, int]:
    counts: dict[ActivitySource, int] = {}
    for event in events:
        counts[event.source] = counts.get(event.source, 0) + 1
    return counts


def _rejections_by_source(
    rejections: Iterable[IngestRejection],
) -> dict[ActivitySource, int]:
    """Count rejections per activity source.

    Only used for the shortfall arithmetic, so a rejection whose source could
    not be determined is deliberately *not* counted here -- it stays in the
    unexplained remainder, which degrades coverage. Guessing a source to make a
    number balance would defeat the point of checking the number.
    """
    counts: dict[ActivitySource, int] = {}
    for rejection in rejections:
        if rejection.source is None:
            continue
        try:
            source = ActivitySource(rejection.source)
        except ValueError:
            continue
        counts[source] = counts.get(source, 0) + 1
    return counts


def _rejections_for_user(
    rejections: Sequence[IngestRejection],
    user_id: str,
    source: ActivitySource,
    resolver: IdentityResolver,
) -> list[IngestRejection]:
    """Rejections in ``source`` that can be pinned on ``user_id``.

    Attribution is deliberately conservative. ``actor_hint`` is read off a
    record that failed validation, so it is a hint, not a fact; when it matches
    more than one person it is treated as matching nobody, and the resulting gap
    falls to the dataset level instead of downgrading the wrong person's
    coverage.
    """
    matched: list[IngestRejection] = []
    for rejection in rejections:
        if rejection.source is not None and rejection.source != str(source):
            continue
        if _narrow_to_user(rejection.actor_hint, resolver) == user_id:
            matched.append(rejection)
    return matched


def _narrow_to_user(
    hint: str | None, resolver: IdentityResolver
) -> str | None:
    """Best-effort attribution of a *failed* record to exactly one person.

    Tried in order: the resolver itself, then the ARN form, then a looser pass
    that strips a domain from an email-like hint and a path prefix from an
    ARN-like one. Returns ``None`` unless exactly one person matches.
    """
    if not hint:
        return None

    resolved = resolver.resolve_principal(hint)
    if resolved is not None:
        return resolved

    candidates: set[str] = set()
    if hint.startswith("arn:"):
        parsed = parse_aws_arn_identity(hint)
        if parsed:
            found = resolver.resolve(parsed)
            if found:
                candidates.add(found)
    for form in (hint, hint.rsplit("/", 1)[-1], hint.split("@", 1)[0]):
        found = resolver.resolve(form)
        if found:
            candidates.add(found)

    return next(iter(candidates)) if len(candidates) == 1 else None
