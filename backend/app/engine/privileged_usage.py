"""Rule B -- rarely used privileged permission.

Blueprint §16's matrix carries a row the utilisation rule cannot reach:

    Rarely used privileged permission | Review, not automatic removal

Erin is that row, and she is why this is a separate rule rather than a second
branch of Rule A. Her observed utilisation is 9 of 17 capabilities -- 0.529,
comfortably above the 0.25 threshold -- so the utilisation rule correctly finds
nothing at all. She also never once exercised IAM_WRITE, KMS_WRITE, LOGS_WRITE,
S3_DELETE, REPO_ADMIN or ORG_ADMIN. She uses her access constantly; she has
never used the part of it that can destroy things.

That is the whole distinction, and a ratio cannot express it. Rule A's answer is
one number over the whole granted set, and six capabilities out of seventeen are
invisible in it. Rule B asks a different question about a subset -- *is the
dangerous part used at all* -- and the answer is not a number, it is a set.

Three clauses make the rule correct, and none of them is in the blueprint.

**This rule is the complement of the utilisation rule.** Bob holds exactly the
same four never-exercised privileged capabilities as Erin and has a ratio of
0.154. "Never exercised a dangerous capability" therefore does not separate them;
the ratio does, and only the ratio. Without the complement clause every low-usage
person would carry both findings: one measurement, reported twice, under two
names, with two recommendations pointing the same way. So this rule fires
precisely where Rule A declines -- ``reviewable_ratio >= low_utilization_threshold``
-- and the two partition the space instead of overlapping in it.

The threshold is ``>=`` and not ``>``: Carol sits at exactly 0.25, the comparison
in Rule A is strict, so 0.25 is this rule's territory. Move either operator and
Carol changes hands.

**Protected grants are excluded, per grant.** Alice holds
break-glass-emergency-admin, which confers IAM_WRITE, KMS_WRITE, LOGS_WRITE and
S3_DELETE, and she has COMPLETE coverage with zero events -- every one of them is
provably never exercised. A rule that read grants without reading protection
would hand her a REVIEW_REQUIRED finding to sit beside her
``PROTECTED_BREAK_GLASS``, inverting the sharpest case in the fixture set. So the
exposure is computed over unprotected grants only, and a user whose grants are
*all* protected has no subject at all.

**An unmeasurable window is silence here and a verdict next door.** Ivan has
PARTIAL coverage and holds KMS_WRITE, LOGS_WRITE and S3_DELETE never exercised;
Gina has MISSING. Absence of evidence is not evidence of absence, so neither is
accused -- but neither is dropped either. The utilisation rule already reports
``INSUFFICIENT_EVIDENCE`` for both, and that is the division of labour: Rule 7
("missing evidence must not be treated as safe") is a property of the rule *set*,
not an obligation on every rule to restate the same caution. Emitting a second
insufficient-evidence finding here would report one gap twice.

The confidence floor does apply, and for the same reason Rule A has one. Without
it a COMPLETE window with no events would report every privileged capability its
holder owns as never exercised -- true, and also true of everything else they
hold, and a finding for every idle account in the estate.

The finding is ``REVIEW_REQUIRED`` with ``MANUAL_REVIEW``, severity MEDIUM, and
``usage`` left at the window's own verdict rather than stamped ``LOW``. Erin's
usage is not low; it is *narrow*, and labelling it LOW would contradict the
finding's own rationale and hand the reader the conclusion this rule exists to
avoid. The recommendation asks a person to look, never to remove: Erin's grant
may be exactly right for her job, and the engine has no idea what her job is.

Two rules, one user, no suppression. Findings are independent, so Carol carries
a CRITICAL ``GHOST_ACCESS`` from Rule D and this finding from Rule B at the same
time. A rule that stayed quiet because an unrelated rule had already spoken
would be concealing a fact on the strength of a different fact.

Pure by construction: dataset in, findings out, no session, no HTTP, no clock.
``created_at`` comes from ``settings.effective_analysis_as_of()``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app.core.config import Settings
from app.core.enums import (
    Capability,
    Coverage,
    EvidenceCompleteness,
    EvidenceKind,
    FindingStatus,
    FindingType,
    Recommendation,
    Severity,
    UsageObservation,
)
from app.ingestion import InMemoryDataset
from app.schemas.domain.activity import ActivitySlice
from app.schemas.domain.entitlement import Entitlement
from app.schemas.domain.finding import Evidence, Finding
from app.schemas.domain.user import User

# Imported from Rule A rather than reimplemented. These three encode decisions
# that must not be able to differ between the two rules: what counts as a
# protected grant, what order a person's grants are listed in, and how a risk
# level is read off them. Two rules disagreeing about whether Alice is protected
# is precisely the bug this whole design is arranged to prevent, and the cheapest
# way to prevent it is to have one implementation.
#
# The leading underscores are a smell -- a shared helper private to one module
# and imported by another would be better named as its own module. Extracting
# them into `app/engine/_shared.py` is the right follow-up; it is deliberately not
# done here so that Rule A remains byte-identical while Rule B is added, per the
# instruction to leave Rule A unchanged unless a failing test demonstrates a
# shared-contract problem.
from app.engine.utilization import (
    _activity_evidence,
    _capability_list,
    _coverage_evidence,
    _grant_evidence,
    _grant_sort_key,
    _highest_risk,
    _is_protected,
    _iso,
    _plural,
)

__all__ = [
    "RULE_ID",
    "PrivilegedExposure",
    "detect_rarely_used_privileged_permissions",
    "evaluate_user",
    "privileged_exposure",
]

#: Cited in ``Finding.rules_triggered`` so a dossier can name the control.
RULE_ID = "RULE_B_PRIVILEGED_PERMISSION_USAGE"


# --------------------------------------------------------------------------- #
# The measurement
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class PrivilegedExposure:
    """The privileged subset of what a person holds, against what they used.

    A value object rather than a boolean, for the same reason Rule A's
    ``Utilization`` is one: a reviewer who disagrees with the finding needs to
    see the sets. "You never exercised these six capabilities" can be argued
    with; "RARELY_USED_PRIVILEGED_PERMISSION" cannot.

    ``privileged`` is the configured policy set, carried on the measurement
    rather than read from ``settings`` at each use, so evidence can report the
    exact policy a finding was produced under.
    """

    user_id: str

    #: The capabilities policy currently calls dangerous. Configuration, not a
    #: property of this person.
    privileged: frozenset[Capability]

    #: Granted capabilities from grants that are *not* protected. Protection is
    #: a property of a grant, so a break-glass role cannot be diluted into a
    #: utilisation figure, and cannot be accused by this rule either.
    reviewable_granted: frozenset[Capability]

    observed: frozenset[Capability]
    observed_event_count: int
    coverage: Coverage

    #: The Phase 1 verdict, ``UNKNOWN`` unless coverage is COMPLETE.
    observation: UsageObservation

    window: tuple[datetime, datetime]

    @property
    def used(self) -> frozenset[Capability]:
        return self.reviewable_granted & self.observed

    @property
    def reviewable_ratio(self) -> float | None:
        """Utilisation over unprotected grants -- the number Rule A also uses.

        Computed here as well so this rule can state *why* the utilisation rule
        declined, in the finding, without calling into Rule A. An empty
        denominator yields ``None``: no grants, no ratio, no finding.
        """
        if not self.reviewable_granted:
            return None
        return len(self.used) / len(self.reviewable_granted)

    @property
    def privileged_granted(self) -> frozenset[Capability]:
        """Privileged capabilities actually held -- the policy set, intersected.

        A policy list longer than what this person holds is not evidence about
        this person, so the intersection is what gets reported.
        """
        return self.privileged & self.reviewable_granted

    @property
    def never_exercised_privileged(self) -> frozenset[Capability]:
        """Privileged capabilities with no observed use in the window.

        Named for the fact, not the judgement. "Never exercised" is checkable
        against the export; "unnecessary" would not be, and is not claimable.
        """
        return self.privileged_granted - self.observed

    @property
    def is_measurable(self) -> bool:
        """Whether the window can carry any conclusion about usage at all.

        Taken from the slice's own coverage gate rather than re-derived from
        ``coverage``, so that this rule and ``ActivitySlice.usage_observation``
        cannot drift apart about what "we could not see" means.
        """
        return self.observation is not UsageObservation.UNKNOWN


def privileged_exposure(
    user_id: str,
    entitlements: tuple[Entitlement, ...],
    slice_: ActivitySlice,
    settings: Settings,
) -> PrivilegedExposure:
    """Measure the privileged capabilities one person holds but never exercised.

    ``settings`` is used for two things and neither is arithmetic: which grants
    are protected, and which capabilities count as privileged. The set
    computation itself has no configuration in it, which is what lets the
    oracle's ``never_exercised_privileged_capabilities`` block be asserted
    directly against this function rather than through a whole finding.
    """
    reviewable: set[Capability] = set()
    for entitlement in entitlements:
        if not _is_protected(entitlement, settings):
            reviewable |= entitlement.capabilities

    return PrivilegedExposure(
        user_id=user_id,
        privileged=frozenset(settings.privileged_capabilities),
        reviewable_granted=frozenset(reviewable),
        observed=slice_.observed_capabilities,
        observed_event_count=slice_.observed_event_count,
        coverage=slice_.coverage,
        observation=slice_.usage_observation,
        window=(slice_.window_start, slice_.window_end),
    )


def _declined_by_the_utilisation_rule(
    ratio: float | None, settings: Settings
) -> bool:
    """Whether Rule A said nothing about this person -- the complement.

    Spelled out as its own comparison rather than as ``not _is_under_utilised``.
    Both are equivalent today and only one of them stays correct if Rule A's
    boundary ever moves: this rule's correctness is *defined* by being the
    complement, so it states the complement.

    ``None`` is not a decline: a person with no unprotected grants has no ratio
    for Rule A to have judged, and the caller has already returned before
    reaching here.
    """
    return ratio is not None and ratio >= settings.low_utilization_threshold


# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #


def _privileged_policy_evidence(
    evidence_id: str, finding_id: str, settings: Settings
) -> Evidence:
    """The policy set this finding was selected by, in full.

    The reviewer's first question is "why these capabilities and not others?",
    and the answer has to be the organisation's configuration rather than this
    rule's opinion. Without this row the finding asserts a judgement about
    danger that nobody can audit, disagree with, or change.
    """
    configured = list(settings.privileged_capabilities)

    return Evidence(
        evidence_id=evidence_id,
        finding_id=finding_id,
        kind=EvidenceKind.CONFIG_VALUE,
        source="settings",
        description=(
            f"The privileged capability set applied here is "
            f"{_capability_list(frozenset(configured))}. Membership is policy "
            "owned by the organisation, not a property of this person, and is "
            "revisable in configuration without a change to the rule."
        ),
        detail={"privileged_capabilities": [c.value for c in configured]},
    )


def _thresholds_evidence(
    evidence_id: str, finding_id: str, settings: Settings
) -> Evidence:
    """The boundaries this rule and the one it complements were run under.

    Both numbers are recorded, not just this rule's, because the finding's
    central claim is a relationship between the two rules -- that utilisation is
    high enough for Rule A to stay silent. A reader who cannot see the threshold
    cannot check that claim.
    """
    return Evidence(
        evidence_id=evidence_id,
        finding_id=finding_id,
        kind=EvidenceKind.CONFIG_VALUE,
        source="settings",
        description=(
            "The utilisation rule reports a person below an observed utilisation "
            f"of {settings.low_utilization_threshold}; this rule covers the "
            "people it therefore reports nothing about. The confidence floor of "
            f"{settings.min_observed_events_for_confidence} observed events "
            "applies to both."
        ),
        detail={
            "low_utilization_threshold": settings.low_utilization_threshold,
            "min_observed_events_for_confidence": (
                settings.min_observed_events_for_confidence
            ),
            "lookback_days": settings.lookback_days,
        },
    )


def _exposure_evidence(
    evidence_id: str, finding_id: str, exposure: PrivilegedExposure
) -> Evidence:
    """Both sides of the subset comparison, and the ratio that is not the point.

    The utilisation figure is present precisely because it is *not* what this
    finding is about: it is the number that clears the threshold, and recording
    it is how a reader sees that this person is not a low-usage case. Reporting
    the set without it would leave the finding looking like a restatement of
    Rule A.
    """
    never = exposure.never_exercised_privileged
    ratio = exposure.reviewable_ratio

    return Evidence(
        evidence_id=evidence_id,
        finding_id=finding_id,
        kind=EvidenceKind.CONFIG_VALUE,
        source="engine",
        description=(
            f"{len(exposure.used)} of {len(exposure.reviewable_granted)} granted "
            "capabilities were exercised in the window, an observed utilisation of "
            f"{'undefined' if ratio is None else f'{ratio:.3f}'}, and "
            f"{len(exposure.privileged_granted)} of the granted capabilities are in "
            f"the configured privileged set. {len(never)} of those privileged "
            f"capabilities have no observed use: {_capability_list(never)}."
        ),
        detail={
            "reviewable_granted_capability_count": len(exposure.reviewable_granted),
            "used_capability_count": len(exposure.used),
            "observed_event_count": exposure.observed_event_count,
            "observed_utilisation": None if ratio is None else round(ratio, 3),
            "privileged_granted": sorted(c.value for c in exposure.privileged_granted),
            "never_exercised_privileged": sorted(c.value for c in never),
        },
    )


# --------------------------------------------------------------------------- #
# The finding
# --------------------------------------------------------------------------- #


def _summarise(
    user: User,
    entitlements: tuple[Entitlement, ...],
    exposure: PrivilegedExposure,
    settings: Settings,
) -> str:
    """The deterministic statement of a rarely-used-privileged-permission finding.

    Every clause is a fact that appears in the evidence, and the last one is the
    point: the finding reports a subset of capabilities with no observed use and
    hands the judgement to a person. It may say that six capabilities were never
    exercised; it may not say what that means about the job, because the engine
    has no idea what the job is.

    Note what this says about utilisation explicitly. A reader who meets a
    privileged-permission finding and assumes it is another way of saying "this
    person barely uses their access" has the wrong idea, and the number that
    refutes it belongs in the sentence rather than only in the evidence.
    """
    never = exposure.never_exercised_privileged
    roles = ", ".join(sorted(f"{e.role} ({e.source})" for e in entitlements))
    ratio = exposure.reviewable_ratio
    ratio_text = "undefined" if ratio is None else f"{ratio:.3f}"

    return (
        f"{user.username} holds {len(exposure.reviewable_granted)} capabilities "
        f"granted by {roles}, and the window {_iso(exposure.window[0])} to "
        f"{_iso(exposure.window[1])} shows {len(exposure.used)} of them exercised: "
        f"an observed utilisation of {ratio_text}, at or above the configured "
        f"review threshold of {settings.low_utilization_threshold}, so the "
        "utilisation rule reports nothing about this person. What it does not "
        f"describe is that {len(never)} of the capabilities in the configured "
        f"privileged set {('has' if len(never) == 1 else 'have')} no observed use "
        f"in that window: {_capability_list(never)}. Observed on COMPLETE coverage "
        f"of every source that could have recorded this person, over "
        f"{exposure.observed_event_count} observed "
        f"{_plural(exposure.observed_event_count, 'event')}. A reviewer decides "
        "whether the grant still matches the work; AccessLens does not change "
        "access, and this finding records what was not exercised rather than what "
        "is needed."
    )


def _privileged_finding(
    user: User,
    entitlements: tuple[Entitlement, ...],
    slice_: ActivitySlice,
    exposure: PrivilegedExposure,
    settings: Settings,
) -> Finding:
    finding_id = f"fnd-{user.id}-rule-b"

    return Finding(
        id=finding_id,
        user_id=user.id,
        type=FindingType.RARELY_USED_PRIVILEGED_PERMISSION,
        severity=Severity.MEDIUM,
        status=FindingStatus.REVIEW_REQUIRED,
        risk_level=_highest_risk(entitlements),
        summary=_summarise(user, entitlements, exposure, settings),
        recommendation=Recommendation.MANUAL_REVIEW,
        evidence=[
            *_grant_evidence(
                finding_id, "rule-b", user.id, entitlements, exposure.observed
            ),
            *_activity_evidence(finding_id, user.id, slice_.successful_events),
            _coverage_evidence(
                f"ev-{user.id}-rule-b-coverage", finding_id, user, slice_
            ),
            _privileged_policy_evidence(
                f"ev-{user.id}-rule-b-privileged-policy", finding_id, settings
            ),
            _thresholds_evidence(
                f"ev-{user.id}-rule-b-thresholds", finding_id, settings
            ),
            _exposure_evidence(
                f"ev-{user.id}-rule-b-exposure", finding_id, exposure
            ),
        ],
        # Always COMPLETE: any other coverage returns before this function is
        # reached. Stated explicitly rather than defaulted, so the guarantee is
        # visible where it is relied on.
        evidence_completeness=EvidenceCompleteness.COMPLETE,
        rules_triggered=[RULE_ID],
        # The window's own verdict, not a hardcoded OBSERVED. With the default
        # configuration these coincide -- clearing the utilisation threshold
        # means capabilities were observed, so the observation is OBSERVED --
        # but a threshold configured to 0.0 would let a zero-event window
        # through, and stamping OBSERVED on a NONE_OBSERVED window would be the
        # finding asserting something its own data contradicts.
        usage=exposure.observation,
        created_at=settings.effective_analysis_as_of(),
    )


# --------------------------------------------------------------------------- #
# Entry points
# --------------------------------------------------------------------------- #


def evaluate_user(
    user: User,
    entitlements: tuple[Entitlement, ...],
    slice_: ActivitySlice,
    settings: Settings,
) -> list[Finding]:
    """This rule's verdict on one person: zero or one finding.

    The clauses are ordered so the cheapest and most consequential run first.
    Protection comes before the measurement, because a person with nothing
    reviewable is not a subject for this rule at all. Coverage comes before any
    set comparison, because a set difference over a window AccessLens cannot
    vouch for is not a smaller set difference, it is no measurement -- and the
    silence here is only honest because the utilisation rule speaks for that
    person instead.

    ``_is_protected`` is applied twice, here and inside
    :func:`privileged_exposure`, and the duplication is deliberate rather than
    overlooked. This filter exists because the evidence rows need the
    ``Entitlement`` objects, which a capability set cannot supply;
    ``privileged_exposure`` filters because it is a public function that must be
    safe for a caller holding a person's raw grant list, which is exactly how
    the oracle test uses it. It is one pure predicate applied to the same input,
    so the two cannot disagree -- and the mutation check confirmed that only the
    inner one is load-bearing for silence, so removing *either* would be the
    wrong simplification.
    """
    ordered = tuple(sorted(entitlements, key=_grant_sort_key))
    reviewable = tuple(e for e in ordered if not _is_protected(e, settings))

    if not reviewable:
        return []

    exposure = privileged_exposure(user.id, ordered, slice_, settings)

    if not exposure.is_measurable:
        return []

    if not exposure.never_exercised_privileged:
        return []

    if not _declined_by_the_utilisation_rule(exposure.reviewable_ratio, settings):
        return []

    if exposure.observed_event_count < settings.min_observed_events_for_confidence:
        return []

    return [_privileged_finding(user, reviewable, slice_, exposure, settings)]


def detect_rarely_used_privileged_permissions(
    dataset: InMemoryDataset, settings: Settings
) -> list[Finding]:
    """Run this rule over every person in the dataset.

    Deterministic order -- users by id -- so two runs over identical facts
    produce identically ordered findings, which is what makes the engine's
    output diffable and a finding's position reproducible.
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
