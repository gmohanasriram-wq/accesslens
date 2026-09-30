"""Rule D -- ghost access: access that outlived the right to it.

Blueprint §8:

    IF identity is deactivated AND downstream activity occurs after deactivation
    THEN create GHOST_ACCESS finding

The rule is short, and every word of it is a decision.

**"identity is deactivated", not "the user exists".** The trigger is the
directory's own statement that an account was switched off. A live account
cannot produce a ghost, which is why Alice and Gina are out of scope here
regardless of what else is true about their data -- their verdicts belong to
Rules A, B and C, and pre-empting them would mean this rule issuing a CRITICAL
about a break-glass holder, or about someone whose telemetry never arrived.

**"after deactivation", not "after termination".** Carol is terminated at 17:00
and disabled at 09:12 the next morning. An action in that sixteen-hour gap used
an account the directory still considered live; calling it ghost access would
make the finding's timeline contradict its own conclusion. The comparison is
strict, too: an event stamped at the same instant as the disable is an event
from the moment the control was applied, not evidence that it failed. And it
carries a configurable grace window, because HR, the directory and the audit
logs do not share a clock, and an ordinary offboarding should not produce a
finding out of the few minutes it takes a disable to propagate.

**"activity", not "attempted activity".** ``ActivityEvent.denied`` marks a call
the source refused. Carol has one *after* her account was disabled -- which is
the strongest single piece of evidence in her case, because it proves the
credential was still live -- and it is deliberately excluded from the count that
decides whether ghost access occurred. Recorded, and not counted: the same
distinction the rest of the codebase draws between "the credential exists" and
"the entitlement was used".

Two shapes of the failure exist and both are reported:

* an account that was switched off and then used anyway (Carol);
* an offboarded person whose accounts were never switched off at all, so the
  instant access should have ended is the termination itself. This is the more
  severe case and the one a deactivation-keyed rule cannot see.

**What this rule deliberately does not decide.** ``risk_level`` is left at its
``UNKNOWN`` default. It describes how much damage the *granted* access could do,
which is a question about entitlements -- Rules A and B's subject, not this
one's. Filling it here would mean classifying privilege in a second place, which
is how two rules come to disagree about the same person.

Pure by construction: the dataset in, findings out, no session, no HTTP, no
clock. ``created_at`` comes from ``settings.effective_analysis_as_of()`` rather
than ``utcnow()`` so that two analyses of identical facts produce identical
records -- a finding an auditor cannot reproduce is not evidence.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from app.core.config import Settings
from app.core.enums import (
    Coverage,
    EvidenceCompleteness,
    EvidenceKind,
    FindingStatus,
    FindingType,
    IdentityProvider,
    Recommendation,
    Severity,
)
from app.ingestion import InMemoryDataset
from app.schemas.domain.activity import ActivityEvent, ActivitySlice
from app.schemas.domain.finding import Evidence, Finding
from app.schemas.domain.identity import Identity
from app.schemas.domain.user import User

__all__ = ["RULE_ID", "detect_ghost_access", "evaluate_user"]

#: Cited in ``Finding.rules_triggered`` so a dossier can name the control.
RULE_ID = "RULE_D_GHOST_ACCESS"


#: How a provider is written in a sentence a reviewer will read. The enum values
#: are wire identifiers -- ``okta``, ``azure_ad`` -- and paraphrasing them with
#: a generic title-caser produces "Azure Ad".
_PROVIDER_LABELS = {
    IdentityProvider.OKTA: "Okta",
    IdentityProvider.AZURE_AD: "Azure AD",
    IdentityProvider.GOOGLE_WORKSPACE: "Google Workspace",
    IdentityProvider.UNKNOWN: "the identity provider",
}


def _provider_label(provider: IdentityProvider) -> str:
    return _PROVIDER_LABELS.get(provider, str(provider))


def _plural(count: int, singular: str, plural: str | None = None) -> str:
    return singular if count == 1 else (plural or f"{singular}s")


#: Sentence-initial counts. "1 further attempt was denied" reads like a log line;
#: these findings are read by people deciding whether to open an investigation.
_NUMBER_WORDS = {1: "One", 2: "Two", 3: "Three", 4: "Four", 5: "Five"}


def _count_label(count: int) -> str:
    return _NUMBER_WORDS.get(count, str(count))


# --------------------------------------------------------------------------- #
# The temporal predicate
# --------------------------------------------------------------------------- #


def _deprovisioned_at(user: User, identities: tuple[Identity, ...]) -> datetime | None:
    """The instant after which this person's access should have ended.

    Returns ``None`` when the person is still entitled to access, which is the
    rule's entire off-switch.

    Three cases, in order:

    1. **An account was switched off and none is left open.** The latest
       deactivation is the instant. Latest rather than earliest because a person
       with two accounts is not fully deprovisioned until the last one closes,
       and activity before that could be entirely legitimate.

    2. **An account was switched off, another is still open, and HR says the
       person has left.** The stale account is itself the problem, but the
       cutoff stays the deactivation: the live account was live, and treating
       its activity as ghost access would be inventing a fact.

    3. **Nothing was ever switched off, and HR says the person has left.** There
       is no deactivation to measure from, so the termination is the instant.
       This is the offboarded-but-still-enabled case, which is both the most
       severe form of the failure and the one that never reaches case 1.

    The guard in case 1 is what keeps a routine account migration from becoming
    a CRITICAL. When an old account is closed and a new one opened, the person's
    activity follows the old account's deactivation and means nothing by it.
    Events carry a credential but not an account, so attribution cannot settle
    the question -- and a finding that might be someone's normal Tuesday is not
    a finding. Case 2 is reachable only through HR stating that employment
    ended, which is a fact no migration produces.
    """
    deactivations = [
        identity.deactivated_at
        for identity in identities
        if identity.is_deactivated and identity.deactivated_at is not None
    ]
    all_closed = bool(identities) and all(i.is_deactivated for i in identities)

    if deactivations and (all_closed or user.is_terminated):
        return max(deactivations)
    if user.is_terminated:
        return user.termination_date
    return None


def _cutoff(cutoff: datetime, settings: Settings) -> datetime:
    """Shift the cutoff forward by the configured clock-skew allowance."""
    grace = timedelta(hours=settings.ghost_access_grace_hours)
    return cutoff + grace if grace else cutoff


def _after(
    events: tuple[ActivityEvent, ...] | list[ActivityEvent], cutoff: datetime
) -> list[ActivityEvent]:
    """Events strictly after ``cutoff``, in a stable order."""
    return sorted(
        (e for e in events if e.timestamp > cutoff),
        key=lambda e: (e.timestamp, e.event_id),
    )


# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #


def _describe_credential(event: ActivityEvent) -> str:
    return (
        f"via credential {event.credential_id}"
        if event.credential_id
        else "with no credential recorded"
    )


def _completeness(slice_: ActivitySlice) -> EvidenceCompleteness:
    """How much of the evidence this conclusion should rest on actually exists.

    Note the asymmetry with the usage rules, and why it is correct. Coverage
    gates *usage* because an absence of events is only meaningful if we were
    watching. Ghost access is the opposite kind of claim: it rests on events we
    actually have. A partial export cannot unsee an action that is sitting in
    front of us, so the finding still stands -- but it is marked PARTIAL, so a
    reviewer knows the tally may undercount rather than believing it complete.
    """
    if slice_.coverage is Coverage.COMPLETE:
        return EvidenceCompleteness.COMPLETE
    if slice_.coverage is Coverage.PARTIAL:
        return EvidenceCompleteness.PARTIAL
    return EvidenceCompleteness.MISSING


def _timeline_evidence(
    finding_id: str,
    user: User,
    cutoff: datetime,
    deactivated_identity: Identity | None,
) -> list[Evidence]:
    """The administrative half of the timeline: employment ended, account closed.

    These are facts about other systems, not activity, so they carry no
    ``event_id`` -- nothing happened in AccessLens to link to. Stating them
    explicitly is what lets a reader check the ordering the conclusion depends
    on instead of taking it on trust.
    """
    rows: list[Evidence] = []

    if user.termination_date is not None:
        reason = f" ({user.termination_reason})" if user.termination_reason else ""
        rows.append(
            Evidence(
                evidence_id=f"ev-{user.id}-employment-ended",
                finding_id=finding_id,
                kind=EvidenceKind.TIMELINE_POINT,
                source="hr",
                timestamp=user.termination_date,
                description=(
                    f"HR records employment ending for {user.username} on "
                    f"{user.termination_date.isoformat()}{reason}."
                ),
                detail={
                    "employment_status": str(user.employment_status),
                    "termination_reason": user.termination_reason,
                },
            )
        )

    if deactivated_identity is not None and deactivated_identity.deactivated_at:
        trigger = (
            f" (trigger: {deactivated_identity.deactivation_trigger})"
            if deactivated_identity.deactivation_trigger
            else ""
        )
        rows.append(
            Evidence(
                evidence_id=f"ev-{user.id}-account-disabled",
                finding_id=finding_id,
                kind=EvidenceKind.TIMELINE_POINT,
                source=str(deactivated_identity.provider),
                timestamp=deactivated_identity.deactivated_at,
                description=(
                    f"{_provider_label(deactivated_identity.provider)} account "
                    f"{deactivated_identity.account_id} was disabled on "
                    f"{deactivated_identity.deactivated_at.isoformat()}{trigger}. "
                    "This is the instant the credential should have stopped working."
                ),
                detail={
                    "account_id": deactivated_identity.account_id,
                    "deactivation_trigger": deactivated_identity.deactivation_trigger,
                    "identity_status": str(deactivated_identity.status),
                },
            )
        )

    if not rows:
        # Reachable when a terminated person has no directory account on record
        # at all. The cutoff still exists, so the finding must still be able to
        # say where it came from.
        rows.append(
            Evidence(
                evidence_id=f"ev-{user.id}-cutoff-basis",
                finding_id=finding_id,
                kind=EvidenceKind.CONFIG_VALUE,
                source="hr",
                timestamp=cutoff,
                description=(
                    f"No deactivation is on record for {user.username}; the "
                    "cutoff is the instant the identity record places access "
                    "ending."
                ),
                detail={"cutoff": cutoff.isoformat()},
            )
        )

    return rows


def _activity_evidence(
    finding_id: str,
    user: User,
    cutoff: datetime,
    successful: list[ActivityEvent],
    denied: list[ActivityEvent],
) -> list[Evidence]:
    """The half of the timeline that is activity -- counted and uncounted alike."""
    rows: list[Evidence] = []

    for event in successful:
        rows.append(
            Evidence(
                evidence_id=f"ev-{user.id}-{event.event_id}",
                finding_id=finding_id,
                kind=EvidenceKind.ACTIVITY_EVENT,
                source=str(event.source),
                timestamp=event.timestamp,
                event_id=event.event_id,
                description=(
                    f"Successful {event.action} {_describe_credential(event)} at "
                    f"{event.timestamp.isoformat()}, after the account was disabled."
                ),
                detail={
                    "action": event.action,
                    "credential_id": event.credential_id,
                    "denied": False,
                    "seconds_after_cutoff": int(
                        (event.timestamp - cutoff).total_seconds()
                    ),
                },
            )
        )

    for event in denied:
        rows.append(
            Evidence(
                evidence_id=f"ev-{user.id}-{event.event_id}",
                finding_id=finding_id,
                kind=EvidenceKind.ACTIVITY_EVENT,
                source=str(event.source),
                timestamp=event.timestamp,
                event_id=event.event_id,
                description=(
                    f"Denied {event.action} {_describe_credential(event)} at "
                    f"{event.timestamp.isoformat()}. Recorded because it proves "
                    "the credential was still live; not counted as use of the "
                    "entitlement."
                ),
                detail={
                    "action": event.action,
                    "credential_id": event.credential_id,
                    "denied": True,
                    "counts_as_usage": False,
                },
            )
        )

    return rows


def _tally_evidence(
    finding_id: str,
    user: User,
    slice_: ActivitySlice,
    settings: Settings,
    cutoff: datetime,
    successful: list[ActivityEvent],
    denied: list[ActivityEvent],
) -> list[Evidence]:
    """What was counted, over how much we could see, at which thresholds.

    Three things a reader needs in order to disagree with the conclusion: the
    numbers it rests on, the coverage that qualifies them, and the settings the
    rule was run with. Without the last one, "why did this not fire last month?"
    is unanswerable after a config change.
    """
    window = f"{slice_.window_start.isoformat()} to {slice_.window_end.isoformat()}"
    credentials = sorted(
        {e.credential_id for e in successful if e.credential_id}
    )

    return [
        Evidence(
            evidence_id=f"ev-{user.id}-coverage",
            finding_id=finding_id,
            kind=EvidenceKind.COVERAGE_STATEMENT,
            source="coverage",
            description=(
                f"Coverage for {user.username} over {window} is "
                f"{slice_.coverage}. {len(successful)} successful and "
                f"{len(denied)} denied action(s) fall after the cutoff "
                f"{cutoff.isoformat()}."
            ),
            detail={
                "coverage": str(slice_.coverage),
                "post_deactivation_successful_events": len(successful),
                "post_deactivation_denied_events": len(denied),
                "sources_queried": sorted(str(s) for s in slice_.sources_queried),
                "sources_missing": sorted(str(s) for s in slice_.sources_missing),
                "gap_reasons": sorted({str(g.reason) for g in slice_.gaps}),
                "window_start": slice_.window_start.isoformat(),
                "window_end": slice_.window_end.isoformat(),
                "credential_ids": credentials,
            },
        ),
        Evidence(
            evidence_id=f"ev-{user.id}-thresholds",
            finding_id=finding_id,
            kind=EvidenceKind.CONFIG_VALUE,
            source="settings",
            description=(
                "Rule D thresholds applied: "
                f"ghost_access_min_post_deactivation_events="
                f"{settings.ghost_access_min_post_deactivation_events}, "
                f"ghost_access_grace_hours={settings.ghost_access_grace_hours}."
            ),
            detail={
                "ghost_access_min_post_deactivation_events": (
                    settings.ghost_access_min_post_deactivation_events
                ),
                "ghost_access_grace_hours": settings.ghost_access_grace_hours,
                "lookback_days": settings.lookback_days,
            },
        ),
    ]


def _summarise(
    user: User,
    deactivated_identity: Identity | None,
    successful: list[ActivityEvent],
    denied: list[ActivityEvent],
) -> str:
    """The deterministic one-paragraph statement of the finding.

    Written to be checkable rather than persuasive: every clause is a fact that
    appears in the evidence. Note what it does *not* contain -- no member of
    ``FORBIDDEN_CONCLUSION_PHRASES`` survives here, because the finding may
    report that a credential kept working after it should have stopped, and may
    not conclude that anything should be removed. The final sentence states the
    mechanical fact that the disable did not revoke the token, which is the
    finding, and leaves the decision to a person.
    """
    credentials = sorted({e.credential_id for e in successful if e.credential_id})
    if len(credentials) == 1:
        credential_clause = f"using credential {credentials[0]}"
    elif credentials:
        credential_clause = f"using credentials {', '.join(credentials)}"
    else:
        credential_clause = "with no credential recorded"

    last = successful[-1]
    when = (
        user.termination_date.isoformat()
        if user.termination_date is not None
        else "an unrecorded date"
    )

    if deactivated_identity is not None and deactivated_identity.deactivated_at:
        ending = (
            f"{user.username}'s employment ended on {when} and their "
            f"{_provider_label(deactivated_identity.provider)} account "
            f"{deactivated_identity.account_id} was disabled on "
            f"{deactivated_identity.deactivated_at.isoformat()}"
        )
    else:
        ending = (
            f"{user.username}'s employment ended on {when} and no account "
            "deactivation is on record"
        )

    sentences = [
        f"{ending}, but {len(successful)} successful "
        f"{_plural(len(successful), 'action')} followed, the most recent on "
        f"{last.timestamp.isoformat()} {credential_clause}."
    ]

    if denied:
        # Named separately, and deliberately not folded into the clause above:
        # a denied attempt is often made with a *different* credential from the
        # successful ones, and Carol's case is exactly that. Saying "the
        # credential was still live" without naming which one would be the kind
        # of vague-but-confident sentence this finding is supposed to replace.
        denied_credentials = sorted({e.credential_id for e in denied if e.credential_id})
        count = len(denied)
        subject = (
            f"{_count_label(count)} further {_plural(count, 'attempt')}"
            + (f" using {', '.join(denied_credentials)}" if denied_credentials else "")
        )
        sentences.append(
            f"{subject} {'was' if count == 1 else 'were'} denied after that point, "
            "which shows the credential was still live at the time."
        )

    if deactivated_identity is not None and deactivated_identity.deactivated_at:
        if len(credentials) == 1:
            sentences.append("The account disable did not revoke that credential.")
        elif credentials:
            sentences.append("The account disable did not revoke those credentials.")
        else:
            sentences.append("The account disable did not stop the activity.")
    else:
        # Nothing was switched off, so there is no disable to blame. Saying
        # "the account disable did not revoke it" here would assert a control
        # that was never applied -- and that distinction is the whole reason
        # this branch exists.
        # The first sentence has already said no deactivation is on record, so
        # this one draws the consequence rather than repeating the fact.
        switched = "that credential" if credentials else "the access"
        sentences.append(f"Nothing switched {switched} off.")

    return " ".join(sentences)


# --------------------------------------------------------------------------- #
# The rule
# --------------------------------------------------------------------------- #


def evaluate_user(
    user: User,
    identities: tuple[Identity, ...],
    slice_: ActivitySlice,
    settings: Settings,
) -> Finding | None:
    """Rule D for one person. ``None`` means "this rule has nothing to say".

    Kept separate from the sweep so a single case can be reasoned about -- and
    tested -- without constructing a whole dataset around it.
    """
    cutoff = _deprovisioned_at(user, identities)
    if cutoff is None:
        return None

    effective = _cutoff(cutoff, settings)
    successful = _after(slice_.successful_events, effective)
    if len(successful) < settings.ghost_access_min_post_deactivation_events:
        return None

    # Denied attempts after the cutoff do not count toward the threshold, but
    # they are the clearest proof the credential outlived its account and so
    # they are carried as evidence.
    denied = _after([e for e in slice_.events if e.denied], effective)

    deactivated = [
        i for i in identities if i.is_deactivated and i.deactivated_at is not None
    ]
    deactivated_identity = (
        max(deactivated, key=lambda i: (i.deactivated_at, i.account_id))
        if deactivated
        else None
    )

    finding_id = f"fnd-{user.id}-rule-d"

    return Finding(
        id=finding_id,
        user_id=user.id,
        type=FindingType.GHOST_ACCESS,
        severity=Severity.CRITICAL,
        status=FindingStatus.INVESTIGATION_REQUIRED,
        summary=_summarise(user, deactivated_identity, successful, denied),
        recommendation=Recommendation.INVESTIGATE_GHOST_ACCESS,
        evidence=[
            *_timeline_evidence(finding_id, user, cutoff, deactivated_identity),
            *_activity_evidence(finding_id, user, effective, successful, denied),
            *_tally_evidence(
                finding_id, user, slice_, settings, effective, successful, denied
            ),
        ],
        evidence_completeness=_completeness(slice_),
        rules_triggered=[RULE_ID],
        usage=slice_.usage_observation,
        created_at=settings.effective_analysis_as_of(),
    )


def detect_ghost_access(
    dataset: InMemoryDataset, settings: Settings
) -> list[Finding]:
    """Every ghost-access finding in the dataset, in a stable order.

    A sweep over the population rather than a query, because the engine has no
    database to query. Ordered by ``user_id`` so that two runs -- and two
    machines -- produce the same list, not merely the same set.
    """
    findings: list[Finding] = []

    for user in sorted(dataset.users, key=lambda u: u.id):
        finding = evaluate_user(
            user,
            dataset.identities_for(user.id),
            dataset.slice_for(user.id),
            settings,
        )
        if finding is not None:
            findings.append(finding)

    return findings
