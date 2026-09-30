"""Rule A -- privilege utilization: granted capabilities against observed ones.

Blueprint §8:

    granted capabilities -> observed capabilities -> compare -> observed utilization

and, immediately after it, the sentence that governs every line below:

    This is **observed utilization**, not proof that unused access is unnecessary.

Rule D has a concrete event to key on -- a successful action after a
deactivation instant -- and can be wrong only about its timestamps. Rule A has
no event. It has a *ratio*, and a ratio is a claim about two sets, so every way
of getting the sets wrong becomes a wrong accusation against a real person.
Four of them carry the design:

**A ratio is over capabilities, not over whatever the data happens to say.**
``Entitlement.permissions`` holds policy strings and ``ActivityEvent.action``
holds API calls; neither is comparable to the other. ``core.capabilities``
translates both into one vocabulary, and that is why this module is a set
computation and nothing more. Two consequences: a capability the user was never
granted cannot count toward utilisation (it is a different finding, not a better
ratio), and an unclassifiable permission yields ``{UNKNOWN}`` rather than
silence, so a vocabulary gap cannot quietly shrink the denominator and hide
privilege.

**A ratio over an unmeasured set is not a small number, it is no number.** The
oracle says this in as many words: Gina is 0/1 with zero events and Ivan is 2/10
with four, so both clear every numeric threshold for a low-usage finding, "and
any implementation that computes the ratio before consulting coverage accuses
two innocent people on the very first run." The coverage check is therefore the
*first* branch in :func:`evaluate_user`, ahead of every comparison, and an
unmeasured user gets ``INSUFFICIENT_EVIDENCE`` rather than a quiet pass. That
direction matters: "we could not tell" and "nothing to see" are the two answers
an access review most easily conflates and least tolerates conflating.
:func:`_insufficient_evidence` also refuses to record the ratio it could have
computed, because a number in the audit trail reads as the conclusion.

**Inactivity is the intended state of break-glass access.** Alice has COMPLETE
coverage and zero events, so the evidence genuinely supports "not used" -- and
that is exactly why she is the sharpest case in the set. A rule that maps "not
observed in use" to "suggest reducing it" produces the arithmetically correct
answer and the wrong security decision. She gets ``PROTECTED_BREAK_GLASS``, whose
recommendation is ``NO_ACTION_DOCUMENT_JUSTIFICATION``: the finding exists to
record that the protection applies, not to ask for anything.

Protection is evaluated **per grant**, never per person. A user holding both a
break-glass role and an unused administrator role must still be reviewed for the
administrator role; letting one protected grant launder the other would make
protection a way to silence a real finding.

**One threshold, therefore one level.** ``Settings.low_utilization_threshold``
is the only configured boundary, so the only level this rule can assign is
``LOW``. ``HIGH`` and ``MODERATE`` exist in the enum for a configuration that
separates them, and are deliberately not guessed at here: inventing a second
boundary inside the rule would put a number in the audit trail that nobody
configured and nobody can review.

The comparison is strict (``<``). Carol sits at exactly 0.25 and is not a
low-usage case -- she is the ghost-access case, and two rules must not both
claim her.

Pure by construction: dataset in, findings out, no session, no HTTP, no clock.
``created_at`` comes from ``settings.effective_analysis_as_of()``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from app.core.config import Settings
from app.core.enums import (
    Capability,
    Coverage,
    EvidenceCompleteness,
    EvidenceKind,
    FindingStatus,
    FindingType,
    GapReason,
    Recommendation,
    RiskLevel,
    Severity,
    UsageObservation,
)
from app.ingestion import InMemoryDataset
from app.schemas.domain.activity import ActivityEvent, ActivitySlice
from app.schemas.domain.entitlement import Entitlement
from app.schemas.domain.finding import Evidence, Finding
from app.schemas.domain.user import User

__all__ = [
    "RULE_ID",
    "Utilization",
    "detect_low_utilization",
    "evaluate_user",
    "utilization_for",
]

#: Cited in ``Finding.rules_triggered`` so a dossier can name the control.
RULE_ID = "RULE_A_PRIVILEGE_UTILIZATION"


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #


def _iso(moment: datetime) -> str:
    """Render an instant the way the source data and the oracles write it.

    ``datetime.isoformat()`` produces ``+00:00`` where every fixture file, every
    coverage window and every oracle writes ``Z``. An evidence row is meant to be
    comparable against the export it came from, so it uses the export's spelling.
    """
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _plural(count: int, singular: str, plural: str | None = None) -> str:
    return singular if count == 1 else (plural or f"{singular}s")


def _capability_list(capabilities: frozenset[Capability]) -> str:
    if not capabilities:
        return "none"
    return ", ".join(sorted(c.value for c in capabilities))


def _grant_sort_key(entitlement: Entitlement) -> tuple[str, str]:
    """Total order for a person's grants, so evidence ids do not depend on input order."""
    return (str(entitlement.source), entitlement.role)


def _ratio(
    used: frozenset[Capability], granted: frozenset[Capability]
) -> float | None:
    """``used / granted``, or ``None`` when there is nothing to divide by.

    ``None`` rather than ``0.0``: dividing by an empty denominator is not a
    ratio, and returning zero would report the most extreme low-usage value
    possible for somebody who holds nothing -- the exact inversion of the facts.
    Every caller is forced to handle ``None``, so "no grants" cannot be silently
    compared as if it were "no usage".
    """
    if not granted:
        return None
    return len(used) / len(granted)


# --------------------------------------------------------------------------- #
# Protection
# --------------------------------------------------------------------------- #


def _is_protected(entitlement: Entitlement, settings: Settings) -> bool:
    """Whether this grant is break-glass, by flag or by configured policy.

    Protection is read from three places, unioned, and the union is deliberately
    the conservative direction:

    1. the granting system's own flag, which is authoritative because it is the
       only source that can mark a role whose *name* gives nothing away;
    2. ``always_protected_roles``, an explicit list;
    3. ``protected_role_patterns``, matched against the role name.

    Ingestion already resolves this and stores the result on the entitlement, so
    it is worth being clear about why the rule re-checks the configuration
    rather than trusting the flag. A security team that classifies a role as
    break-glass this morning must have it treated as break-glass by the next
    analysis -- not after the next import. Protection that lags the policy is
    protection that misses the case it was written for, and the failure mode
    here is recommending a reduction to an emergency role.
    """
    if entitlement.protected_role:
        return True
    if entitlement.role in settings.always_protected_roles:
        return True
    lowered = entitlement.role.lower()
    return any(pattern.lower() in lowered for pattern in settings.protected_role_patterns)


#: Higher wins. ``UNKNOWN`` sorts lowest so an unclassified role can never
#: present itself as the most dangerous thing a person holds.
_RISK_ORDER: dict[RiskLevel, int] = {
    RiskLevel.UNKNOWN: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}


def _highest_risk(entitlements: tuple[Entitlement, ...]) -> RiskLevel:
    """The most damaging grant in a set -- the person's exposure from it.

    Read from the entitlement's already-resolved ``risk_level`` rather than
    re-derived from ``settings.high_risk_entitlement_roles``. Classifying
    privilege in two places is how two rules come to disagree about the same
    person; ingestion resolves it once and every rule consumes it.
    """
    if not entitlements:
        return RiskLevel.UNKNOWN
    return max((e.risk_level for e in entitlements), key=lambda r: _RISK_ORDER[r])


def _is_privileged(entitlements: tuple[Entitlement, ...]) -> bool:
    return any(e.is_high_risk for e in entitlements)


def _is_under_utilised(ratio: float | None, settings: Settings) -> bool:
    """Strictly below the configured threshold, and only when there is a ratio.

    ``None`` is not under-utilised: an empty capability set has no utilisation to
    be low. That is what keeps a user whose only protection is a grant that
    confers nothing from producing a finding about a set that does not exist.
    """
    return ratio is not None and ratio < settings.low_utilization_threshold


# --------------------------------------------------------------------------- #
# The measurement
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Utilization:
    """The two sets a privilege review is a comparison of, plus their context.

    A value object rather than a function that returns a number, because the
    number is the least interesting part of it. A reviewer disagreeing with a
    utilisation verdict needs the sets: "2 of 13" can be argued with and "0.154"
    cannot. The oracle's ``utilization_arithmetic`` block records the same
    numbers for the same reason.
    """

    user_id: str
    granted: frozenset[Capability]
    observed: frozenset[Capability]

    #: The two halves of ``granted``, split by whether a grant is protected.
    #: An unprotected grant is measured against its own denominator, so holding
    #: an emergency role cannot dilute the utilisation of an administrator role.
    reviewable_granted: frozenset[Capability]
    protected_granted: frozenset[Capability]

    observed_event_count: int
    coverage: Coverage

    #: The Phase 1 verdict, which is ``UNKNOWN`` unless coverage is COMPLETE.
    observation: UsageObservation

    window: tuple[datetime, datetime]

    @property
    def used(self) -> frozenset[Capability]:
        """Granted capabilities the window shows in use -- the numerator."""
        return self.granted & self.observed

    @property
    def never_exercised(self) -> frozenset[Capability]:
        """Granted capabilities with no observed use. Not the same as "unneeded"."""
        return self.granted - self.observed

    @property
    def ratio(self) -> float | None:
        return _ratio(self.used, self.granted)

    @property
    def reviewable_ratio(self) -> float | None:
        return _ratio(self.reviewable_granted & self.observed, self.reviewable_granted)

    @property
    def protected_ratio(self) -> float | None:
        return _ratio(self.protected_granted & self.observed, self.protected_granted)

    @property
    def is_measurable(self) -> bool:
        """Whether the window can carry a utilisation conclusion at all.

        Taken from the slice's own coverage gate rather than re-derived from
        ``coverage``, so that this rule and ``ActivitySlice.usage_observation``
        cannot drift apart about what "we could not see" means.
        """
        return self.observation is not UsageObservation.UNKNOWN


def utilization_for(
    user_id: str,
    entitlements: tuple[Entitlement, ...],
    slice_: ActivitySlice,
    settings: Settings,
) -> Utilization:
    """Measure one person's observed utilisation of their granted capabilities.

    ``settings`` is used only to decide which grants are protected -- the
    arithmetic itself has no configuration in it. Splitting it out and asserting
    on it directly is what lets the oracle's ``utilization_arithmetic`` block be
    checked without asserting on a whole finding.
    """
    granted: set[Capability] = set()
    reviewable: set[Capability] = set()
    protected: set[Capability] = set()

    for entitlement in entitlements:
        capabilities = entitlement.capabilities
        granted |= capabilities
        if _is_protected(entitlement, settings):
            protected |= capabilities
        else:
            reviewable |= capabilities

    return Utilization(
        user_id=user_id,
        granted=frozenset(granted),
        observed=slice_.observed_capabilities,
        reviewable_granted=frozenset(reviewable),
        protected_granted=frozenset(protected),
        observed_event_count=slice_.observed_event_count,
        coverage=slice_.coverage,
        observation=slice_.usage_observation,
        window=(slice_.window_start, slice_.window_end),
    )


def _usage_level(
    ratio: float | None, fallback: UsageObservation, settings: Settings
) -> UsageObservation:
    """Refine a Phase 1 verdict into a level, using the one configured boundary.

    Only ``LOW`` is assignable, because only one boundary is configured -- see
    the module docstring. Anything at or above the threshold keeps the Phase 1
    verdict rather than being given a level nobody defined.
    """
    return (
        UsageObservation.LOW
        if _is_under_utilised(ratio, settings)
        else fallback
    )


# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #


def _completeness(coverage: Coverage) -> EvidenceCompleteness:
    if coverage is Coverage.COMPLETE:
        return EvidenceCompleteness.COMPLETE
    if coverage is Coverage.PARTIAL:
        return EvidenceCompleteness.PARTIAL
    return EvidenceCompleteness.MISSING


def _grant_evidence(
    finding_id: str,
    evidence_prefix: str,
    user_id: str,
    entitlements: tuple[Entitlement, ...],
    observed: frozenset[Capability],
) -> list[Evidence]:
    """One row per grant, naming what it confers and how much of it was used.

    Rule A's claim is about a grant, so a finding that does not name the role
    makes the reviewer go and look it up -- which is the work the finding was
    supposed to have done. The exercised/never-exercised split is per grant so
    that a person holding two grants sees which one is in question.
    """
    rows: list[Evidence] = []

    for index, entitlement in enumerate(entitlements, start=1):
        capabilities = entitlement.capabilities
        exercised = capabilities & observed
        rows.append(
            Evidence(
                evidence_id=f"ev-{user_id}-{evidence_prefix}-grant-{index}",
                finding_id=finding_id,
                kind=EvidenceKind.ENTITLEMENT_GRANT,
                source=str(entitlement.source),
                timestamp=entitlement.granted_at,
                description=(
                    f"{entitlement.role} was granted in {entitlement.source} and "
                    f"confers {len(capabilities)} "
                    f"{_plural(len(capabilities), 'capability', 'capabilities')}, "
                    f"{len(exercised)} of which the window shows in use. Raw "
                    f"permissions: {', '.join(sorted(entitlement.permissions)) or 'none'}"
                    "."
                ),
                detail={
                    "role": entitlement.role,
                    "source": str(entitlement.source),
                    "risk_level": str(entitlement.risk_level),
                    "protected_role": entitlement.protected_role,
                    "protection_reason": entitlement.protection_reason,
                    "capabilities": sorted(c.value for c in capabilities),
                    "exercised_capabilities": sorted(c.value for c in exercised),
                    "permissions": sorted(entitlement.permissions),
                },
            )
        )

    return rows


def _activity_evidence(
    finding_id: str, user_id: str, events: tuple[ActivityEvent, ...]
) -> list[Evidence]:
    """The observed half: the successful actions the numerator was read from.

    Denied attempts are absent by construction -- ``successful_events`` excludes
    them, and a refused call is evidence a credential was live rather than
    evidence an entitlement was used.

    Present so the numerator can be checked. The reviewer's question is about
    what was *not* used, and the only way to judge a claim about absence is to
    see what was there.
    """
    rows: list[Evidence] = []

    for event in events:
        capabilities = sorted(c.value for c in event.capabilities)
        rows.append(
            Evidence(
                evidence_id=f"ev-{user_id}-review-{event.event_id}",
                finding_id=finding_id,
                kind=EvidenceKind.ACTIVITY_EVENT,
                source=str(event.source),
                timestamp=event.timestamp,
                event_id=event.event_id,
                description=(
                    f"Successful {event.action} at {_iso(event.timestamp)}, exercising "
                    f"{', '.join(capabilities) if capabilities else 'no capability in the shared vocabulary'}."
                ),
                detail={
                    "action": event.action,
                    "capabilities": capabilities,
                    "denied": False,
                    "counts_as_usage": True,
                },
            )
        )

    return rows


def _coverage_evidence(
    evidence_id: str,
    finding_id: str,
    user: User,
    slice_: ActivitySlice,
    extra: dict[str, object] | None = None,
) -> Evidence:
    """The window behind the number, and which sources stand behind the window.

    Without this a reviewer cannot tell whether a utilisation figure was measured
    over a complete export or over the part of one that arrived -- which is the
    difference between a finding and a guess.
    """
    detail: dict[str, object] = {
        "coverage": str(slice_.coverage),
        "window_start": _iso(slice_.window_start),
        "window_end": _iso(slice_.window_end),
        "sources_queried": sorted(str(s) for s in slice_.sources_queried),
        "sources_missing": sorted(str(s) for s in slice_.sources_missing),
        "gap_reasons": sorted({str(g.reason) for g in slice_.gaps}),
        "visible_successful_events": slice_.observed_event_count,
    }
    detail.update(extra or {})

    return Evidence(
        evidence_id=evidence_id,
        finding_id=finding_id,
        kind=EvidenceKind.COVERAGE_STATEMENT,
        source="coverage",
        description=(
            f"Coverage for {user.username} over {_iso(slice_.window_start)} to "
            f"{_iso(slice_.window_end)} is {slice_.coverage}. "
            f"{slice_.observed_event_count} successful "
            f"{_plural(slice_.observed_event_count, 'action')} are visible in it."
        ),
        detail=detail,
    )


def _threshold_evidence(
    evidence_id: str, finding_id: str, settings: Settings
) -> Evidence:
    """The settings the rule was run with.

    Without them, "why did this not fire last month?" can only be answered by
    whoever remembers what the configuration was, which is not an audit trail.
    """
    return Evidence(
        evidence_id=evidence_id,
        finding_id=finding_id,
        kind=EvidenceKind.CONFIG_VALUE,
        source="settings",
        description=(
            "Rule A thresholds applied: "
            f"low_utilization_threshold={settings.low_utilization_threshold}, "
            f"min_observed_events_for_confidence="
            f"{settings.min_observed_events_for_confidence}."
        ),
        detail={
            "low_utilization_threshold": settings.low_utilization_threshold,
            "min_observed_events_for_confidence": (
                settings.min_observed_events_for_confidence
            ),
            "lookback_days": settings.lookback_days,
        },
    )


def _arithmetic_evidence(
    evidence_id: str, finding_id: str, util: Utilization, granted: frozenset[Capability]
) -> Evidence:
    """Both sides of the comparison, with the ratio and the difference.

    ``never_exercised`` is the difference between the two sets and is named for
    exactly that -- a fact about the window, not a judgement about the job. The
    field name is part of the contract: "never exercised" is checkable against
    the export, and "not needed" would not be.
    """
    used = granted & util.observed
    never = granted - util.observed
    ratio = _ratio(used, granted)

    return Evidence(
        evidence_id=evidence_id,
        finding_id=finding_id,
        kind=EvidenceKind.CONFIG_VALUE,
        source="engine",
        description=(
            f"{len(used)} of {len(granted)} granted capabilities were exercised in "
            f"the window, an observed utilisation of "
            f"{'undefined' if ratio is None else f'{ratio:.3f}'}. "
            f"{len(never)} were never exercised."
        ),
        detail={
            "granted_capability_count": len(granted),
            "used_capability_count": len(used),
            "observed_event_count": util.observed_event_count,
            "observed_utilisation": None if ratio is None else round(ratio, 3),
            "used": sorted(c.value for c in used),
            "never_exercised": sorted(c.value for c in never),
        },
    )


def _remedy(slice_: ActivitySlice) -> str:
    """What would actually settle the question, read off the recorded gap reason.

    A finding that says "we could not tell" and stops asks the reviewer to take
    the hole on trust. Naming the missing artefact turns it into a task.
    """
    reasons = {g.reason for g in slice_.gaps}

    if reasons & {GapReason.SOURCE_MISSING, GapReason.SOURCE_NOT_QUERIED}:
        return "obtaining the missing export is what would settle the question"
    if reasons & {GapReason.RECORDS_REJECTED, GapReason.IDENTITY_UNMAPPED}:
        return "recovering the unusable records is what would settle the question"
    if GapReason.WINDOW_TRUNCATED in reasons:
        return "obtaining the complete window is what would settle the question"
    return "the absent telemetry is what would settle the question"


# --------------------------------------------------------------------------- #
# Summaries
# --------------------------------------------------------------------------- #


def _summarise_low_usage(
    user: User,
    entitlements: tuple[Entitlement, ...],
    util: Utilization,
    settings: Settings,
) -> str:
    """The deterministic statement of a low-usage finding.

    Every clause is a fact that appears in the evidence. Note the last sentence:
    the finding reports a measurement and hands the judgement to a person. It
    may say that eleven of thirteen capabilities were never exercised in the
    window; it may not say what that means about the job, because the engine has
    no idea what the job is.
    """
    granted = util.reviewable_granted
    used = granted & util.observed
    never = granted - util.observed
    roles = ", ".join(sorted(f"{e.role} ({e.source})" for e in entitlements))

    return (
        f"{user.username} holds {len(granted)} capabilities granted by {roles}, and "
        f"the window {_iso(util.window[0])} to {_iso(util.window[1])} shows "
        f"{util.observed_event_count} successful "
        f"{_plural(util.observed_event_count, 'action')} exercising {len(used)} of "
        f"them: {_capability_list(used)}. The {len(never)} granted capabilities with "
        f"no observed use in that window were {_capability_list(never)}. Observed "
        f"utilisation is {util.reviewable_ratio:.3f} against the configured review "
        f"threshold of {settings.low_utilization_threshold}, on COMPLETE coverage of "
        f"every source that could have observed this person, and "
        f"{util.observed_event_count} observed "
        f"{_plural(util.observed_event_count, 'event')} clears the confidence floor of "
        f"{settings.min_observed_events_for_confidence}. A reviewer decides whether "
        "the grant still matches the work; AccessLens does not change access."
    )


def _summarise_protected(
    user: User,
    entitlements: tuple[Entitlement, ...],
    util: Utilization,
    settings: Settings,
) -> str:
    """The statement that protection applies, and that nothing is being asked for.

    ``must_not_say`` in the oracle lists revoke, remove, unused, unnecessary and
    prune for this persona, and every one of them would be *accurate* about her
    data. That is the lesson: "this access was not used" is a measurement, and
    "this access is unused" is a judgement the evidence does not license.

    The protection *reasons* are deliberately not quoted here, though they are
    the most explanatory thing available -- Alice's own reason text reads
    "deliberately held unused so it is available when the identity provider is
    unavailable". Splicing that sentence in would put the forbidden word in the
    engine's mouth: a reader cannot tell which words this rule chose and which
    it merely copied, and the copied ones are exactly the claims it is declining
    to make. So the summary is entirely engine-authored, and source free text
    lives in evidence where it is attributed to the field it came from. Rule D
    draws the same line with ``termination_reason``: recorded in
    ``_timeline_evidence``, never interpolated into ``_summarise``.
    """
    roles = ", ".join(sorted(f"{e.role} ({e.source})" for e in entitlements))

    return (
        f"{user.username} holds {len(util.protected_granted)} capabilities across "
        f"{len(entitlements)} protected {_plural(len(entitlements), 'grant')}: "
        f"{roles}. The window {_iso(util.window[0])} to {_iso(util.window[1])} shows "
        f"{util.observed_event_count} successful "
        f"{_plural(util.observed_event_count, 'action')} from these grants, an "
        f"observed utilisation of {util.protected_ratio:.3f} against the review "
        f"threshold of {settings.low_utilization_threshold}. Coverage is "
        f"{util.coverage}, so this is an observed absence of activity rather than a "
        "gap in the telemetry. Inactivity is the intended state of break-glass "
        f"access, so AccessLens suggests no change: this finding records the "
        "protection that applies without asking for anything, and leaves the "
        "reviewer to confirm that the policy naming these grants is still the "
        "policy they intend. The reason each grant is protected is carried in "
        "the evidence."
    )


def _summarise_insufficient(
    user: User,
    entitlements: tuple[Entitlement, ...],
    util: Utilization,
    slice_: ActivitySlice,
    settings: Settings,
) -> str:
    """The statement that the question is unanswerable, and what would answer it.

    There is deliberately no ratio in this text. The ratio exists and could be
    printed -- Ivan's is 0.2 -- and printing it would hand a reader the very
    conclusion this finding was written to withhold.
    """
    roles = ", ".join(sorted(f"{e.role} ({e.source})" for e in entitlements))
    gaps = "; ".join(sorted(g.detail for g in slice_.gaps))
    absent = (
        f", with {', '.join(sorted(str(s) for s in slice_.sources_missing))} absent"
        if slice_.sources_missing and not slice_.gaps
        else ""
    )

    return (
        f"{user.username} holds {len(util.granted)} "
        f"{_plural(len(util.granted), 'capability', 'capabilities')} granted by "
        f"{roles}. Coverage of the window {_iso(util.window[0])} to "
        f"{_iso(util.window[1])} is {util.coverage}{absent}."
        + (f" {gaps}" if gaps else "")
        + f" {util.observed_event_count} successful "
        f"{_plural(util.observed_event_count, 'action')} "
        f"{'is' if util.observed_event_count == 1 else 'are'} visible, and a "
        "utilisation ratio computed over a window AccessLens cannot vouch for would "
        "rest on a denominator it cannot vouch for either, so no utilisation verdict "
        f"is recorded here. {_remedy(slice_)}."
    )


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #


def _low_usage_finding(
    user: User,
    entitlements: tuple[Entitlement, ...],
    slice_: ActivitySlice,
    util: Utilization,
    settings: Settings,
) -> Finding:
    finding_id = f"fnd-{user.id}-rule-a"
    granted = util.reviewable_granted

    return Finding(
        id=finding_id,
        user_id=user.id,
        type=FindingType.HIGH_PRIVILEGE_LOW_USAGE,
        severity=Severity.HIGH,
        status=FindingStatus.REVIEW_REQUIRED,
        risk_level=_highest_risk(entitlements),
        summary=_summarise_low_usage(user, entitlements, util, settings),
        recommendation=Recommendation.SUGGEST_DOWNSCOPE_MANUAL_APPROVAL,
        evidence=[
            *_grant_evidence(
                finding_id, "review", user.id, entitlements, util.observed
            ),
            *_activity_evidence(finding_id, user.id, slice_.successful_events),
            _coverage_evidence(
                f"ev-{user.id}-review-coverage", finding_id, user, slice_
            ),
            _threshold_evidence(
                f"ev-{user.id}-review-thresholds", finding_id, settings
            ),
            _arithmetic_evidence(
                f"ev-{user.id}-review-utilization", finding_id, util, granted
            ),
        ],
        # Always COMPLETE: any other coverage diverts to INSUFFICIENT_EVIDENCE
        # before this function is reached. Stating it explicitly rather than
        # defaulting means the guarantee is visible where it is relied on.
        evidence_completeness=EvidenceCompleteness.COMPLETE,
        rules_triggered=[RULE_ID],
        usage=_usage_level(util.reviewable_ratio, util.observation, settings),
        created_at=settings.effective_analysis_as_of(),
    )


def _protected_finding(
    user: User,
    entitlements: tuple[Entitlement, ...],
    slice_: ActivitySlice,
    util: Utilization,
    settings: Settings,
) -> Finding:
    finding_id = f"fnd-{user.id}-rule-a-protected"

    return Finding(
        id=finding_id,
        user_id=user.id,
        type=FindingType.PROTECTED_BREAK_GLASS,
        severity=Severity.INFO,
        status=FindingStatus.PROTECTED,
        risk_level=_highest_risk(entitlements),
        summary=_summarise_protected(user, entitlements, util, settings),
        recommendation=Recommendation.NO_ACTION_DOCUMENT_JUSTIFICATION,
        evidence=[
            *_grant_evidence(
                finding_id, "protected", user.id, entitlements, util.observed
            ),
            _coverage_evidence(
                f"ev-{user.id}-protected-coverage", finding_id, user, slice_
            ),
            Evidence(
                evidence_id=f"ev-{user.id}-protected-basis",
                finding_id=finding_id,
                kind=EvidenceKind.CONFIG_VALUE,
                source="settings",
                description=(
                    "Protection is read from the granting system's own flag where "
                    "it is set, and otherwise from the configured protected-role "
                    "policy. Both are checked, so protection cannot lag a policy "
                    "change."
                ),
                detail={
                    "protected_roles": [
                        {
                            "role": e.role,
                            "source": str(e.source),
                            "flag": e.protected_role,
                            "reason": e.protection_reason,
                            "tags": sorted(e.protection_tags),
                        }
                        for e in entitlements
                    ],
                    "always_protected_roles": sorted(settings.always_protected_roles),
                    "protected_role_patterns": sorted(
                        settings.protected_role_patterns
                    ),
                },
            ),
            _threshold_evidence(
                f"ev-{user.id}-protected-thresholds", finding_id, settings
            ),
            _arithmetic_evidence(
                f"ev-{user.id}-protected-utilization",
                finding_id,
                util,
                util.protected_granted,
            ),
        ],
        evidence_completeness=EvidenceCompleteness.COMPLETE,
        rules_triggered=[RULE_ID],
        # The Phase 1 verdict, unrefined. This finding is a statement about
        # protection, not a usage level, and refining it would invite a reader to
        # read a low-usage verdict into a finding whose recommendation is that
        # nothing be done.
        usage=util.observation,
        created_at=settings.effective_analysis_as_of(),
    )


def _insufficient_evidence_finding(
    user: User,
    entitlements: tuple[Entitlement, ...],
    slice_: ActivitySlice,
    util: Utilization,
    settings: Settings,
) -> Finding:
    """What is reported when the window cannot carry a utilisation conclusion.

    This finding carries the grants and the gaps and deliberately *not* the
    events or the ratio. Listing the events would invite a reader to draw the
    conclusion from them anyway, which is precisely the inference the finding
    exists to refuse.
    """
    finding_id = f"fnd-{user.id}-rule-a-insufficient-evidence"

    return Finding(
        id=finding_id,
        user_id=user.id,
        type=FindingType.INSUFFICIENT_EVIDENCE,
        severity=Severity.INFO,
        status=FindingStatus.INSUFFICIENT_EVIDENCE,
        risk_level=_highest_risk(entitlements),
        summary=_summarise_insufficient(user, entitlements, util, slice_, settings),
        recommendation=Recommendation.GATHER_MORE_EVIDENCE,
        evidence=[
            *_grant_evidence(
                finding_id, "gap", user.id, entitlements, util.observed
            ),
            *[
                Evidence(
                    evidence_id=f"ev-{user.id}-gap-{gap.source}",
                    finding_id=finding_id,
                    kind=EvidenceKind.COVERAGE_STATEMENT,
                    source=str(gap.source),
                    timestamp=gap.window_start,
                    description=gap.detail,
                    detail={
                        "source": str(gap.source),
                        "gap_reason": str(gap.reason),
                        "affected_record_count": gap.affected_record_count,
                        "window_start": (
                            _iso(gap.window_start) if gap.window_start else None
                        ),
                        "window_end": _iso(gap.window_end) if gap.window_end else None,
                    },
                )
                for gap in sorted(
                    slice_.gaps, key=lambda g: (str(g.source), str(g.reason), g.detail)
                )
            ],
            _coverage_evidence(
                f"ev-{user.id}-gap-coverage", finding_id, user, slice_
            ),
            _threshold_evidence(f"ev-{user.id}-gap-thresholds", finding_id, settings),
        ],
        evidence_completeness=_completeness(util.coverage),
        rules_triggered=[RULE_ID],
        usage=util.observation,
        created_at=settings.effective_analysis_as_of(),
    )


# --------------------------------------------------------------------------- #
# The rule
# --------------------------------------------------------------------------- #


def evaluate_user(
    user: User,
    entitlements: tuple[Entitlement, ...],
    slice_: ActivitySlice,
    settings: Settings,
) -> list[Finding]:
    """Rule A for one person. An empty list means "this rule has nothing to say".

    The order of the checks is the rule's most important decision, so it is
    spelled out:

    1. **No granted capabilities** -- there is no access to measure, so there is
       nothing to report, whatever the telemetry says. A gap in the evidence for
       somebody who holds nothing is not a gap in anything.
    2. **The window is unmeasurable** -- before any arithmetic. A ratio over an
       unmeasured set is not a small number, and computing it first is how two
       innocent people get accused on the first run.
    3. **Protected grants that are privileged and under-used** -- the break-glass
       case. Checked without the confidence floor, because this branch asks for
       nothing: suppressing it on thin evidence would produce silence
       indistinguishable from a bug, and would tell a reviewer nothing about
       where the protection is.
    4. **Reviewable grants that are privileged and under-used** -- the finding
       that asks for a review, and so must clear the confidence floor.

    A person can reach both 3 and 4, and should: two grants, two independent
    judgements. Protection is a property of the grant, not of the person.
    """
    ordered = tuple(sorted(entitlements, key=_grant_sort_key))
    util = utilization_for(user.id, ordered, slice_, settings)

    if not util.granted:
        return []

    if not util.is_measurable:
        return [_insufficient_evidence_finding(user, ordered, slice_, util, settings)]

    reviewable = tuple(e for e in ordered if not _is_protected(e, settings))
    protected = tuple(e for e in ordered if _is_protected(e, settings))

    findings: list[Finding] = []

    if (
        _is_privileged(reviewable)
        and _is_under_utilised(util.reviewable_ratio, settings)
        and util.observed_event_count >= settings.min_observed_events_for_confidence
    ):
        findings.append(_low_usage_finding(user, reviewable, slice_, util, settings))

    if _is_privileged(protected) and _is_under_utilised(
        util.protected_ratio, settings
    ):
        findings.append(_protected_finding(user, protected, slice_, util, settings))

    return findings


def detect_low_utilization(
    dataset: InMemoryDataset, settings: Settings
) -> list[Finding]:
    """Every Rule A finding in the dataset, in a stable order.

    A sweep over the population rather than a query, because the engine has no
    database to query. Ordered by ``user_id`` so that two runs -- and two
    machines -- produce the same list, not merely the same set.
    """
    findings: list[Finding] = []

    for user in sorted(dataset.users, key=lambda u: u.id):
        findings.extend(
            evaluate_user(
                user,
                dataset.entitlements_for(user.id),
                dataset.slice_for(user.id),
                settings,
            )
        )

    return findings
