"""Rule A -- privilege utilization.

Blueprint §8 draws Rule A as a comparison rather than a condition::

    granted capabilities -> observed capabilities -> compare -> observed utilization

and is explicit about what the result is *not*: "This is **observed
utilization**, not proof that unused access is unnecessary."

That sentence is the whole difficulty. Rule D has a concrete event to key on --
activity after a deactivation instant -- and can be wrong only about its
timestamps. Rule A has no event. It has a *ratio*, and a ratio is a claim about
two sets, so every way of getting the sets wrong turns directly into a wrong
accusation against a real person. Three of them matter enough to be the spine of
this file:

**The denominator is a vocabulary, not a list.** ``Entitlement.permissions``
holds policy strings (``AdministratorAccess``, ``repo:admin``) and
``ActivityEvent.action`` holds API calls (``s3:GetObject``, ``repo.clone``).
Neither can be compared to the other. ``core.capabilities`` is the translation,
and it is tested separately in ``test_capabilities.py`` precisely so that this
rule can be a set computation over two ``frozenset[Capability]`` values and
nothing else. A capability the user was *not* granted does not count toward
utilisation: it is a different finding, not a better ratio.

**A ratio over an unmeasured set is not a small number, it is no number.** This
is the failure the oracle calls out by name: Gina is 0/1 with zero events and
Ivan is 2/10 with four, so both clear every numeric threshold for a low-usage
finding, "and any implementation that computes the ratio before consulting
coverage accuses two innocent people on the very first run." Their telemetry is
missing and partial respectively, so the honest answer is neither "uses
everything" nor "uses nothing" -- it is that the question is unanswerable, and
that must be a *finding*, because in an access review "we could not tell" and
"nothing to see" are the two answers most easily confused and least alike.

**Inactivity is the intended state of break-glass access.** Alice has COMPLETE
coverage and zero events, so the evidence genuinely supports "not used" -- and
that is exactly why she is the sharpest case in the set. A rule that maps
"not observed in use" to "suggest reducing it" produces the *correct* numeric
answer and the *wrong* security decision. The oracle's ``must_not_say`` list for
her (revoke, remove, unused, unnecessary, prune) has been sitting in the fixture
file unasserted since Phase 1; the tests below are what finally hold that line.

The rule answers one question -- *does this person hold privileged access the
window shows them not using?* -- and there are exactly three honest answers:
yes, and it should be reviewed; yes, but it is protected and by design; and we
cannot tell, because we could not see. Silence is not among them.
"""

from __future__ import annotations

import inspect
from datetime import datetime

import pytest
from pydantic import TypeAdapter

from app.core.config import Settings
from app.core.enums import (
    ActivitySource,
    Capability,
    Coverage,
    EmploymentStatus,
    EntitlementSource,
    EvidenceCompleteness,
    EvidenceKind,
    FindingStatus,
    FindingType,
    Recommendation,
    RiskLevel,
    UsageObservation,
)
from app.ingestion import InMemoryDataset
from app.schemas.domain.activity import ActivityEvent, ActivitySlice
from app.schemas.domain.entitlement import Entitlement
from app.schemas.domain.user import User

from app.engine.utilization import (
    RULE_ID,
    detect_low_utilization,
    evaluate_user,
    utilization_for,
)

AWARE = TypeAdapter(datetime)

WINDOW_START = "2026-07-01T06:00:00Z"
WINDOW_END = "2026-09-29T06:00:00Z"


def _at(text: str) -> datetime:
    return AWARE.validate_python(text)


# --------------------------------------------------------------------------- #
# Hand-built cases
#
# The fixture set is nine people and cannot contain the boundary the rule turns
# on: a user who is one property away from a false accusation. Because the
# engine is pure, such a case is a dozen lines here instead of a new fixture
# file -- and a boundary asserted only in prose is a boundary that moves.
# --------------------------------------------------------------------------- #


def _user(user_id: str = "u_test", username: str = "test.user") -> User:
    return User(
        id=user_id,
        username=username,
        name="Test User",
        email=f"{username}@example.com",
        department="Engineering",
        employment_status=EmploymentStatus.ACTIVE,
        source_updated_at=_at(WINDOW_END),
    )


def _grant(
    *,
    user_id: str = "u_test",
    source: EntitlementSource = EntitlementSource.AWS,
    role: str = "AdministratorAccess",
    permissions: tuple[str, ...] = ("AdministratorAccess",),
    risk_level: RiskLevel = RiskLevel.CRITICAL,
    protected_role: bool = False,
    protection_reason: str | None = None,
    protection_tags: tuple[str, ...] = (),
) -> Entitlement:
    return Entitlement(
        user_id=user_id,
        source=source,
        role=role,
        permissions=list(permissions),
        risk_level=risk_level,
        protected_role=protected_role,
        protection_reason=protection_reason,
        protection_tags=list(protection_tags),
        principal=f"arn:aws:iam::123456789012:user/{user_id}",
    )


def _event(
    action: str,
    *,
    actor_id: str = "u_test",
    event_id: str | None = None,
    denied: bool = False,
    source: ActivitySource = ActivitySource.AWS_CLOUDTRAIL,
) -> ActivityEvent:
    return ActivityEvent(
        event_id=event_id or f"evt-{action}",
        timestamp=_at("2026-08-01T12:00:00Z"),
        actor_id=actor_id,
        source=source,
        action=action,
        denied=denied,
    )


def _slice(
    user_id: str = "u_test",
    *,
    events: list[ActivityEvent] | None = None,
    coverage: Coverage = Coverage.COMPLETE,
) -> ActivitySlice:
    return ActivitySlice(
        user_id=user_id,
        window_start=_at(WINDOW_START),
        window_end=_at(WINDOW_END),
        events=list(events or []),
        sources_queried=frozenset({ActivitySource.AWS_CLOUDTRAIL}),
        coverage=coverage,
    )


def _dataset(
    users: list[User],
    entitlements: list[Entitlement],
    slices: dict[str, ActivitySlice],
) -> InMemoryDataset:
    return InMemoryDataset(
        users=tuple(users),
        identities=(),
        entitlements=tuple(entitlements),
        slices=slices,
        window=(_at(WINDOW_START), _at(WINDOW_END)),
        coverage_manifest=(),
        rejections=(),
        unattributable_actors=(),
    )


def _one_person(
    *,
    grants: list[Entitlement] | None = None,
    events: list[ActivityEvent] | None = None,
    coverage: Coverage = Coverage.COMPLETE,
) -> InMemoryDataset:
    user = _user()
    return _dataset(
        [user],
        grants if grants is not None else [_grant()],
        {user.id: _slice(events=events, coverage=coverage)},
    )


def _for_user(findings: list, user_id: str) -> list:
    return [f for f in findings if f.user_id == user_id]


def _by_username(dataset: InMemoryDataset, username: str) -> User:
    return next(u for u in dataset.users if u.username == username)


# --------------------------------------------------------------------------- #
# The oracle's arithmetic
#
# `utilization_arithmetic` is the one block of the oracle that specifies Rule A
# directly rather than through a finding. It records, persona by persona, the
# two numbers the rule is a comparison of -- measured from the fixture set, not
# predicted from the implementation -- so that a threshold or vocabulary change
# fails as a specific disagreement ("Bob is 2/13, not 3/13") rather than as a
# vague mismatch.
# --------------------------------------------------------------------------- #


def test_granted_and_observed_capability_counts_match_the_oracle(
    dataset: InMemoryDataset, settings: Settings, oracle: dict
) -> None:
    """The denominator, the numerator and the ratio, for every persona.

    Compared as a batch so one failure lists every persona that drifted, rather
    than stopping at the first -- the point of the block is to make a vocabulary
    regression legible, and that only works if the whole picture is visible.
    """
    arithmetic = oracle["utilization_arithmetic"]["by_user"]
    failures: list[str] = []

    for user in dataset.users:
        expected = arithmetic.get(user.id)
        assert expected is not None, f"oracle has no arithmetic for {user.username}"

        util = utilization_for(
            user.id, dataset.entitlements_for(user.id), dataset.slice_for(user.id), settings
        )

        if len(util.granted) != expected["granted"]:
            failures.append(
                f"{user.username}: granted {len(util.granted)}, oracle says "
                f"{expected['granted']}"
            )
        if len(util.used) != expected["used"]:
            failures.append(
                f"{user.username}: used {len(util.used)}, oracle says {expected['used']}"
            )
        if round(util.ratio, 3) != expected["ratio"]:
            failures.append(
                f"{user.username}: ratio {round(util.ratio, 3)}, oracle says "
                f"{expected['ratio']}"
            )

        never = sorted(c.value for c in util.never_exercised)
        if never != sorted(expected["never_capabilities"]):
            failures.append(
                f"{user.username}: never-exercised was {never}, oracle says "
                f"{sorted(expected['never_capabilities'])}"
            )

    assert not failures, "utilization oracle mismatches:\n  " + "\n  ".join(failures)


def test_nobody_below_the_confidence_floor_is_ever_accused_of_low_usage(
    dataset: InMemoryDataset, settings: Settings, oracle: dict
) -> None:
    """The floor, checked against the oracle and then against the rule.

    Alice and Gina are the two personas who do not clear it. Both have a ratio of
    0.0 -- the most extreme value the metric can produce -- and neither may be
    accused. That is the point of expressing the floor as a count of observed
    events rather than as a property of the ratio: 0.0 computed over zero events
    and 0.0 computed over a thousand are the same number and opposite facts.

    The first loop checks that the oracle's own `clears_confidence_floor` flags
    agree with its event counts, so the fixture cannot drift; the second checks
    that the rule obeys them.
    """
    floor = oracle["utilization_arithmetic"]["threshold_min_events"]
    arithmetic = oracle["utilization_arithmetic"]["by_user"]

    for persona in oracle["personas"]:
        clears = persona["observed_event_count"] >= floor
        assert clears is arithmetic[persona["user_id"]]["clears_confidence_floor"], (
            f"{persona['username']}: the oracle's floor flag disagrees with its own "
            "event count"
        )

    findings = detect_low_utilization(dataset, settings)
    for persona in oracle["personas"]:
        if arithmetic[persona["user_id"]]["clears_confidence_floor"]:
            continue
        accused = [
            f
            for f in findings
            if f.user_id == persona["user_id"]
            and f.type is FindingType.HIGH_PRIVILEGE_LOW_USAGE
        ]
        assert accused == [], (
            f"{persona['username']} does not clear the confidence floor but was "
            "accused of low usage"
        )


def test_a_capability_the_user_was_never_granted_does_not_count_as_utilisation(
    settings: Settings,
) -> None:
    """The observed set is intersected with the granted set, not unioned into it.

    Somebody who reaches a capability they were never granted has a finding --
    an interesting one -- but it is not *this* finding, and letting it into the
    numerator would raise their utilisation and quietly excuse the access they
    actually hold and do not use.
    """
    ds = _one_person(
        grants=[_grant(role="repo:read", permissions=("repo:read",))],
        events=[_event("s3:GetObject")],
    )
    util = utilization_for("u_test", ds.entitlements, ds.slice_for("u_test"), settings)

    assert util.observed == frozenset({Capability.S3_READ})
    assert util.granted == frozenset({Capability.REPO_READ})
    assert util.used == frozenset()
    assert util.ratio == 0.0


def test_utilisation_is_undefined_rather_than_zero_when_nothing_is_granted(
    settings: Settings,
) -> None:
    """``None``, not ``0.0``. Dividing by an empty denominator is not a ratio.

    Returning 0.0 would report the most extreme low-usage value possible for a
    person who holds nothing at all -- the exact inversion of the truth.
    """
    ds = _one_person(grants=[])

    util = utilization_for("u_test", (), ds.slice_for("u_test"), settings)

    assert util.granted == frozenset()
    assert util.ratio is None


# --------------------------------------------------------------------------- #
# The oracle's findings
# --------------------------------------------------------------------------- #


def _assert_matches_oracle_finding(finding, persona: dict) -> None:
    expected = persona["finding"]
    assert finding.type.value == expected["type"], persona["scenario"]
    assert finding.status.value == expected["status"], persona["scenario"]
    assert finding.severity.value == expected["severity"], persona["scenario"]
    assert finding.recommendation.value == expected["recommendation"], (
        persona["scenario"]
    )
    assert finding.evidence_completeness.value == expected["evidence_completeness"], (
        persona["scenario"]
    )
    assert finding.rules_triggered == [RULE_ID]


def _persona(oracle: dict, user_id: str) -> dict:
    return next(p for p in oracle["personas"] if p["user_id"] == user_id)


def test_bob_produces_the_high_privilege_low_usage_finding_the_oracle_specifies(
    dataset: InMemoryDataset, settings: Settings, oracle: dict
) -> None:
    """The core finding: 13 capabilities granted, 2 exercised, 4 events.

    He clears the confidence floor, so the ratio is meaningful rather than
    noise, and it is well under the threshold. This is the finding the product
    exists to produce, and it is a finding *about* the access -- the
    recommendation asks a person to review it and never changes it.
    """
    bob = _by_username(dataset, "bob.chen")
    findings = _for_user(detect_low_utilization(dataset, settings), bob.id)

    assert len(findings) == 1
    _assert_matches_oracle_finding(findings[0], _persona(oracle, "u_bob"))
    assert findings[0].usage is UsageObservation.LOW
    assert findings[0].risk_level is RiskLevel.CRITICAL


def test_alice_produces_the_protected_break_glass_finding_the_oracle_specifies(
    dataset: InMemoryDataset, settings: Settings, oracle: dict
) -> None:
    """The sharpest case: the numeric answer and the security answer differ.

    Alice's coverage is COMPLETE and she has zero events, so "not observed in
    use" is a fact we can prove -- the evidence genuinely supports it. The
    correct outcome is still that nothing is suggested, because inactivity is
    what a break-glass role is *for*.
    """
    alice = _by_username(dataset, "alice.nguyen")
    findings = _for_user(detect_low_utilization(dataset, settings), alice.id)

    assert len(findings) == 1
    _assert_matches_oracle_finding(findings[0], _persona(oracle, "u_alice"))
    assert findings[0].usage is UsageObservation.NONE_OBSERVED


@pytest.mark.parametrize("username", ["gina.patel", "ivan.petrov"])
def test_the_unmeasured_personas_reach_insufficient_evidence(
    dataset: InMemoryDataset, settings: Settings, oracle: dict, username: str
) -> None:
    """Two people whose numbers look decisive and whose evidence does not.

    Gina's proxy export was never delivered and one of Ivan's CloudTrail records
    was rejected. Both clear the numeric thresholds for a low-usage finding --
    Gina is 0/1 and Ivan is 2/10 -- and both must reach INSUFFICIENT_EVIDENCE
    instead, because a ratio is only as good as the window it was measured over.
    """
    user = _by_username(dataset, username)
    persona = _persona(oracle, user.id)
    findings = _for_user(detect_low_utilization(dataset, settings), user.id)

    assert len(findings) == 1
    _assert_matches_oracle_finding(findings[0], persona)
    assert findings[0].usage is UsageObservation.UNKNOWN
    assert findings[0].type is not FindingType.HIGH_PRIVILEGE_LOW_USAGE


@pytest.mark.parametrize(
    "username",
    ["carol.diaz", "dave.okonkwo", "erin.walsh", "frank.moreau", "henry.okafor"],
)
def test_rule_a_claims_nobody_else_in_the_fixture_set(
    dataset: InMemoryDataset, settings: Settings, username: str
) -> None:
    """Silence in the fixture set has to mean something specific.

    Each of these five is claimed by a different rule or by none, and Rule A
    must not reach any of them: Carol is Rule D's, Dave and Frank are clean,
    Erin's finding is about the privileged subset she never exercised rather
    than about her utilisation, and Henry's is about a duplicate account. A rule
    that fires on everyone passes every interesting persona and fails this test.
    """
    user = _by_username(dataset, username)

    assert _for_user(detect_low_utilization(dataset, settings), user.id) == []


def test_carol_sits_exactly_on_the_threshold_and_the_comparison_is_strict(
    dataset: InMemoryDataset, settings: Settings, oracle: dict
) -> None:
    """4 of 16 is exactly 0.25, and 0.25 is not below 0.25.

    Worth its own test because it is the one persona where a `<=` instead of a
    `<` changes the answer, and because of *which* answer it changes: Carol is
    the ghost-access case, and a utilisation rule that also claimed her would
    give one person two findings for one fact.
    """
    carol = _by_username(dataset, "carol.diaz")
    util = utilization_for(
        carol.id, dataset.entitlements_for(carol.id), dataset.slice_for(carol.id), settings
    )

    assert util.ratio == settings.low_utilization_threshold
    assert _for_user(detect_low_utilization(dataset, settings), carol.id) == []


def test_the_fixture_set_yields_exactly_four_rule_a_findings(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """One per persona that has something to say, and no duplicates.

    The count is asserted as well as the membership, because the failure this
    catches is a rule that emits both a reviewable and a protected finding for
    the same grant -- which reads as two problems where there is one.
    """
    findings = detect_low_utilization(dataset, settings)

    assert len(findings) == 4
    assert [f.user_id for f in findings] == sorted(f.user_id for f in findings)


# --------------------------------------------------------------------------- #
# The oracle's `must_not_say`
#
# Written into the fixture file in Phase 1 and asserted by nothing until now.
# The forbidden-phrase validator on `Finding.summary` is a backstop, but it only
# catches the eight phrases somebody thought to list; these are the words that
# would make these particular findings *wrong* rather than merely ill-phrased.
# For Alice, "unused" is true and must not be said.
# --------------------------------------------------------------------------- #


def _assert_never_says(findings: list, words: list[str], who: str) -> None:
    for finding in findings:
        lowered = finding.summary.lower()
        for word in words:
            assert word.lower() not in lowered, (
                f"{who}'s finding says {word!r}: {finding.summary!r}"
            )


def test_the_protected_finding_never_uses_the_language_of_removal(
    dataset: InMemoryDataset, settings: Settings, oracle: dict
) -> None:
    """Alice's ``must_not_say``, enforced at last.

    Every word on this list is *accurate* about her data and none of them is
    admissible, which is the entire lesson of the break-glass case: "this access
    was not used" is a measurement, and "this access is unused" is a judgement
    that the evidence does not license.
    """
    alice = _by_username(dataset, "alice.nguyen")
    persona = _persona(oracle, "u_alice")

    _assert_never_says(
        _for_user(detect_low_utilization(dataset, settings), alice.id),
        persona["must_not_say"],
        "Alice",
    )


@pytest.mark.parametrize("username", ["gina.patel", "ivan.petrov"])
def test_the_insufficient_evidence_findings_never_report_an_absence_as_a_verdict(
    dataset: InMemoryDataset, settings: Settings, oracle: dict, username: str
) -> None:
    """The other two ``must_not_say`` lists.

    "No activity" and "clean" are the two ways of stating a hole as though it
    were an observation, and "low usage" is the conclusion this finding exists
    to decline to draw.
    """
    user = _by_username(dataset, username)
    persona = _persona(oracle, user.id)

    _assert_never_says(
        _for_user(detect_low_utilization(dataset, settings), user.id),
        persona["must_not_say"],
        user.username,
    )


# --------------------------------------------------------------------------- #
# The coverage gate
# --------------------------------------------------------------------------- #


def _low_usage_shape(**kwargs) -> InMemoryDataset:
    """A user who is unmistakably under-using, with coverage as the variable.

    Four events, all of them S3 reads, against a thirteen-capability
    administrator grant: 1/13 = 0.077, well under the 0.25 threshold, and four
    events clears the three-event floor. Everything below varies only whether we
    were watching.
    """
    return _one_person(
        grants=[_grant(risk_level=RiskLevel.CRITICAL)],
        events=[
            _event("s3:GetObject"),
            _event("s3:ListBucket"),
            _event("s3:GetObjectVersion"),
            _event("s3:ListAllMyBuckets"),
        ],
        **kwargs,
    )


def test_a_complete_window_accuses_the_user_who_under_uses_their_access(
    settings: Settings,
) -> None:
    """The control for the two tests below: this shape *does* produce a finding."""
    findings = detect_low_utilization(_low_usage_shape(coverage=Coverage.COMPLETE), settings)

    assert [f.type for f in findings] == [FindingType.HIGH_PRIVILEGE_LOW_USAGE]


@pytest.mark.parametrize(
    ("coverage", "completeness"),
    [
        (Coverage.MISSING, EvidenceCompleteness.MISSING),
        (Coverage.PARTIAL, EvidenceCompleteness.PARTIAL),
        (Coverage.NOT_QUERIED, EvidenceCompleteness.MISSING),
    ],
)
def test_an_incomplete_window_turns_the_accusation_into_insufficient_evidence(
    settings: Settings, coverage: Coverage, completeness: EvidenceCompleteness
) -> None:
    """Identical usage, identical grant, different verdict -- only coverage moved.

    Parametrised over every non-COMPLETE state so that adding one to the enum
    without deciding what it means for utilisation fails here, rather than
    defaulting to whatever the branch happens to do.
    """
    findings = detect_low_utilization(_low_usage_shape(coverage=coverage), settings)

    assert [f.type for f in findings] == [FindingType.INSUFFICIENT_EVIDENCE]
    assert findings[0].evidence_completeness is completeness


def test_the_ratio_is_never_computed_before_coverage_is_consulted(
    settings: Settings,
) -> None:
    """The oracle's warning, as an executable assertion.

    "Any implementation that computes the ratio before consulting coverage
    accuses two innocent people on the very first run." The assertion is on what
    is *absent*: no utilisation arithmetic may appear in the evidence of a
    finding that rests on a window we cannot vouch for. Recording the ratio
    would put a number in the audit trail that a reader would reasonably take as
    the conclusion.
    """
    findings = detect_low_utilization(_low_usage_shape(coverage=Coverage.MISSING), settings)

    assert len(findings) == 1
    for row in findings[0].evidence:
        assert "never_exercised" not in row.detail
        assert "ratio" not in row.detail


def test_no_observed_activity_and_unmeasured_activity_reach_opposite_conclusions(
    settings: Settings,
) -> None:
    """Alice and Gina's contrast, with everything but coverage held equal.

    Two people, same grant, same zero events, same window. One is fully
    observed and one was never looked at, and they must not share an answer --
    "we watched and saw nothing" and "we never watched" are the two statements
    an access review most easily conflates and least tolerates conflating,
    because the first is safe to act on and the second is not safe to act on at
    all.
    """
    watched = _user("u_watched", "watched.user")
    unwatched = _user("u_unwatched", "unwatched.user")
    ds = _dataset(
        [watched, unwatched],
        [_grant(user_id="u_watched"), _grant(user_id="u_unwatched")],
        {
            "u_watched": _slice("u_watched", coverage=Coverage.COMPLETE),
            "u_unwatched": _slice("u_unwatched", coverage=Coverage.MISSING),
        },
    )

    findings = detect_low_utilization(ds, settings)
    watched_findings = _for_user(findings, "u_watched")
    unwatched_findings = _for_user(findings, "u_unwatched")

    assert watched_findings == [], "a fully observed idle account is not a finding"
    assert [f.type for f in unwatched_findings] == [FindingType.INSUFFICIENT_EVIDENCE]
    assert unwatched_findings[0].usage is UsageObservation.UNKNOWN


def test_someone_who_holds_nothing_is_not_told_their_evidence_is_missing(
    settings: Settings,
) -> None:
    """Insufficient evidence is a finding *about access*, not about a person.

    With no grant there is no access to measure, so a hole in the telemetry is
    not a hole in anything. Reporting it anyway would fill the review with
    people who have nothing to review, which is how a queue stops being read.
    """
    ds = _one_person(grants=[], coverage=Coverage.MISSING)

    assert detect_low_utilization(ds, settings) == []


def test_a_grant_conferring_no_capability_is_not_a_utilisation_question(
    settings: Settings,
) -> None:
    """``sts:GetCallerIdentity`` reports who you already are and confers nothing.

    A grant whose permission list classifies to the empty set has no
    capabilities to under-use, so there is no ratio to compute and no finding to
    make -- the same distinction ``test_capabilities.py`` holds on the
    vocabulary side.
    """
    ds = _one_person(
        grants=[_grant(role="IdentityCheck", permissions=("sts:GetCallerIdentity",))],
        events=[],
        coverage=Coverage.MISSING,
    )

    assert detect_low_utilization(ds, settings) == []


# --------------------------------------------------------------------------- #
# Protected / break-glass access
#
# Verified explicitly, and from both directions: protection must suppress the
# review recommendation when it applies, and must not suppress it when it does
# not. A guard tested only in the suppressing direction is indistinguishable
# from a rule that never fires.
# --------------------------------------------------------------------------- #


def test_a_protected_grant_is_never_recommended_for_downscoping(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """Alice holds 12 capabilities and used none of them, and nothing is suggested.

    Asserted on the recommendation rather than on the finding type, because the
    recommendation is the field a reviewer acts on. ``NO_ACTION_*`` is the
    strongest statement available in the enum, which is by design: it is the
    only enum member that closes a case without asking for anything.
    """
    findings = detect_low_utilization(dataset, settings)
    alice = next(f for f in findings if f.user_id == "u_alice")

    assert alice.recommendation is Recommendation.NO_ACTION_DOCUMENT_JUSTIFICATION
    assert alice.status is FindingStatus.PROTECTED
    assert alice.type is not FindingType.HIGH_PRIVILEGE_LOW_USAGE


def test_protection_is_read_from_the_granting_systems_own_flag(
    settings: Settings,
) -> None:
    """A role nobody would recognise, marked protected upstream.

    The flag is authoritative because the granting system knows things a role
    name does not. This is the case a pattern-matching implementation gets
    wrong: the name gives no hint, and only the flag does.
    """
    ds = _one_person(
        grants=[
            _grant(
                role="svc-continuity-holder",
                protected_role=True,
                protection_reason="protected by the cloud team's continuity policy",
                protection_tags=("continuity",),
            )
        ],
        events=[],
    )

    findings = detect_low_utilization(ds, settings)

    assert [f.type for f in findings] == [FindingType.PROTECTED_BREAK_GLASS]


def test_protection_is_also_read_from_the_configured_role_patterns(
    settings: Settings,
) -> None:
    """The fallback still applies when the flag is absent.

    Protection policy has to be changeable without re-running ingestion: a role
    classified as break-glass this morning must be treated as break-glass by the
    next analysis, not after the next import. So the rule re-checks the
    configured patterns rather than trusting the flag alone -- the union of the
    two is the conservative direction, and the failure it prevents is
    recommending a reduction to an emergency role.
    """
    ds = _one_person(
        grants=[
            _grant(
                role="disaster-recovery-operator",
                permissions=("disaster-recovery-operator",),
                risk_level=RiskLevel.HIGH,
                protected_role=False,
            )
        ],
        events=[],
    )

    findings = detect_low_utilization(ds, settings)

    assert [f.type for f in findings] == [FindingType.PROTECTED_BREAK_GLASS]


def test_a_protected_role_that_is_actually_used_produces_no_finding(
    settings: Settings,
) -> None:
    """The suppressing branch must be capable of *not* suppressing.

    A break-glass role in daily use is a different problem from an idle one, and
    it is not this finding. Emitting PROTECTED_BREAK_GLASS unconditionally would
    label a heavily-used emergency account as safe -- mistaking a control that
    is working for a control that is quiet.
    """
    ds = _one_person(
        grants=[
            _grant(
                role="break-glass-emergency-admin",
                permissions=("break-glass-emergency-admin",),
                protected_role=True,
            )
        ],
        events=[
            _event("s3:GetObject"),
            _event("ec2:DescribeInstances"),
            _event("iam:CreateRole"),
            _event("kms:Decrypt"),
            _event("logs:GetLogEvents"),
        ],
    )

    assert detect_low_utilization(ds, settings) == []


def test_protection_does_not_launder_an_unprotected_grant_held_alongside_it(
    settings: Settings,
) -> None:
    """A person can hold two grants, and only one of them is protected.

    Protection is a property of a *grant*, not of a person. Marking the whole
    user safe because one of their two roles is break-glass would mean the
    emergency role acts as cover for an administrator role nobody is using --
    which is a worse outcome than never having built the guard at all.
    """
    ds = _one_person(
        grants=[
            _grant(
                role="break-glass-emergency-admin",
                permissions=("break-glass-emergency-admin",),
                protected_role=True,
                protection_reason="emergency role",
            ),
            _grant(
                role="AdministratorAccess",
                permissions=("AdministratorAccess",),
                protected_role=False,
            ),
        ],
        events=[
            _event("s3:GetObject", event_id="evt-1"),
            _event("s3:ListBucket", event_id="evt-2"),
            _event("ec2:DescribeInstances", event_id="evt-3"),
            _event("ec2:DescribeVolumes", event_id="evt-4"),
        ],
    )

    findings = detect_low_utilization(ds, settings)
    types = sorted(f.type.value for f in findings)

    assert types == ["HIGH_PRIVILEGE_LOW_USAGE", "PROTECTED_BREAK_GLASS"]

    reviewable = next(
        f for f in findings if f.type is FindingType.HIGH_PRIVILEGE_LOW_USAGE
    )
    # The protected distribution is excluded from the number that asks for a
    # review. Without that, a person could shield an unused administrator grant
    # from review by holding an emergency role beside it.
    arithmetic = next(
        r
        for r in reviewable.evidence
        if r.kind is EvidenceKind.CONFIG_VALUE and "never_exercised" in r.detail
    )
    assert arithmetic.detail["granted_capability_count"] == 13

    # And the finding names only the grant it is about, so a reviewer is not
    # sent to examine a role that is not in question.
    grants = [r for r in reviewable.evidence if r.kind is EvidenceKind.ENTITLEMENT_GRANT]
    assert [r.detail["role"] for r in grants] == ["AdministratorAccess"]


def test_a_protected_grant_that_is_not_privileged_is_not_a_break_glass_finding(
    settings: Settings,
) -> None:
    """Protection is not itself the finding; idle *privileged* protection is.

    A low-risk role marked protected has nothing to protect anyone from, and
    reporting it would put rows in the review that carry no decision.
    """
    ds = _one_person(
        grants=[
            _grant(
                role="break-glass-readonly",
                permissions=("SupportReadOnlyAccess",),
                risk_level=RiskLevel.LOW,
                protected_role=True,
            )
        ],
        events=[],
    )

    assert detect_low_utilization(ds, settings) == []


# --------------------------------------------------------------------------- #
# Thresholds live in configuration, not in the code
# --------------------------------------------------------------------------- #


def test_the_utilisation_threshold_comes_from_settings_not_from_the_code(
    settings: Settings,
) -> None:
    """The same dataset, two thresholds, two answers.

    This is what makes the threshold reviewable: a security team that disagrees
    with 0.25 can change it in configuration and see the effect, instead of
    discovering it as a constant in a rule file.

    The dataset's ratio is 0.077, and the configured value is the point *below
    which* access is called under-used. Raise it to 0.99 and almost any account
    qualifies; drop it to 0.01 and only an account that exercised essentially
    nothing does. Both are legitimate policies, and neither is in the code.
    """
    ds = _low_usage_shape()

    almost_anything_qualifies = Settings(
        analysis_as_of=WINDOW_END, low_utilization_threshold=0.99, _env_file=None
    )
    only_near_zero_qualifies = Settings(
        analysis_as_of=WINDOW_END, low_utilization_threshold=0.01, _env_file=None
    )

    assert [f.type for f in detect_low_utilization(ds, almost_anything_qualifies)] == [
        FindingType.HIGH_PRIVILEGE_LOW_USAGE
    ]
    assert detect_low_utilization(ds, only_near_zero_qualifies) == []


def test_the_confidence_floor_comes_from_settings_not_from_the_code(
    settings: Settings,
) -> None:
    """A ratio computed from two events is not a measurement.

    The floor is what stops a single quiet month from reading as a pattern. With
    it raised above the evidence, the same dataset stops producing the finding.
    """
    ds = _low_usage_shape()

    unreachable = Settings(
        analysis_as_of=WINDOW_END,
        min_observed_events_for_confidence=50,
        _env_file=None,
    )

    assert [f.type for f in detect_low_utilization(ds, settings)] == [
        FindingType.HIGH_PRIVILEGE_LOW_USAGE
    ]
    assert detect_low_utilization(ds, unreachable) == []


def test_a_user_below_the_confidence_floor_is_not_accused(
    settings: Settings,
) -> None:
    """Fresh contrast with Alice: for an *unprotected* grant, few events mean silence.

    Alice produces a finding with zero events because hers is the protected
    branch, which asks for nothing and so needs no confidence. An unprotected
    grant gets no such licence: a review demand built on two events would be a
    demand built on noise, so the honest output is nothing at all.
    """
    ds = _one_person(
        grants=[_grant(risk_level=RiskLevel.CRITICAL, protected_role=False)],
        events=[_event("s3:GetObject")],
    )

    assert detect_low_utilization(ds, settings) == []


# --------------------------------------------------------------------------- #
# What the finding carries
# --------------------------------------------------------------------------- #


def test_the_finding_records_both_sides_of_the_comparison(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """The denominator, the numerator, and the difference between them.

    A reviewer disagreeing with a utilisation verdict needs the two sets, not
    the quotient: "2 of 13" can be argued with, and "0.154" cannot.
    """
    findings = detect_low_utilization(dataset, settings)
    bob = next(f for f in findings if f.user_id == "u_bob")

    arithmetic = next(
        r for r in bob.evidence if r.kind is EvidenceKind.CONFIG_VALUE
        and "never_exercised" in r.detail
    )

    assert arithmetic.detail["granted_capability_count"] == 13
    assert arithmetic.detail["used_capability_count"] == 2
    assert arithmetic.detail["observed_event_count"] == 4
    assert arithmetic.detail["never_exercised"] == [
        "EC2_WRITE",
        "FINANCE_READ",
        "IAM_READ",
        "IAM_WRITE",
        "KMS_READ",
        "KMS_WRITE",
        "LOGS_READ",
        "LOGS_WRITE",
        "S3_DELETE",
        "S3_WRITE",
        "STS_ASSUME_ROLE",
    ]


def test_the_finding_names_the_grant_it_is_about(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """The entitlement row, so the reviewer can see what was actually granted.

    Rule A's whole claim is about a grant. A finding that does not name the role
    makes the reviewer go and look it up, which is the work the finding was
    supposed to have done.
    """
    findings = detect_low_utilization(dataset, settings)
    bob = next(f for f in findings if f.user_id == "u_bob")

    grants = [r for r in bob.evidence if r.kind is EvidenceKind.ENTITLEMENT_GRANT]

    assert len(grants) == 1
    assert grants[0].detail["role"] == "AdministratorAccess"
    assert grants[0].detail["risk_level"] == "CRITICAL"
    assert grants[0].detail["protected_role"] is False


def test_the_finding_records_the_coverage_the_number_rests_on(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """Every finding carries the window and the sources behind it.

    Without this a reviewer cannot tell whether 0.154 was measured over a
    complete export or over the part of one that arrived.
    """
    findings = detect_low_utilization(dataset, settings)
    bob = next(f for f in findings if f.user_id == "u_bob")

    coverage = next(r for r in bob.evidence if r.kind is EvidenceKind.COVERAGE_STATEMENT)

    assert coverage.detail["coverage"] == "COMPLETE"
    assert coverage.detail["window_start"] == "2026-07-01T06:00:00Z"
    assert coverage.detail["window_end"] == "2026-09-29T06:00:00Z"
    assert coverage.detail["sources_queried"] == ["aws_cloudtrail"]


def test_the_insufficient_evidence_finding_states_the_gap_it_suffered(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """Missing evidence is itself evidenced, with a reason.

    The alternative -- a finding that says "we could not tell" and stops -- asks
    the reviewer to take the hole on trust, which is the same failure as
    reporting an absence as a verdict with the sign flipped.
    """
    findings = detect_low_utilization(dataset, settings)
    gina = next(f for f in findings if f.user_id == "u_gina")

    gaps = [
        r for r in gina.evidence
        if r.kind is EvidenceKind.COVERAGE_STATEMENT and "gap_reason" in r.detail
    ]

    assert len(gaps) == 1
    assert gaps[0].detail["gap_reason"] == "SOURCE_MISSING"
    assert gaps[0].detail["source"] == "proxy_zscaler"


def test_the_finding_records_the_thresholds_it_was_run_with(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """"Why did this not fire last month?" must be answerable after a config change.

    Without the thresholds on the finding, that question can only be answered by
    whoever remembers what the settings were, which is not an audit trail.
    """
    findings = detect_low_utilization(dataset, settings)
    bob = next(f for f in findings if f.user_id == "u_bob")

    thresholds = next(
        r for r in bob.evidence if r.kind is EvidenceKind.CONFIG_VALUE
        and "low_utilization_threshold" in r.detail
    )

    assert thresholds.detail["low_utilization_threshold"] == 0.25
    assert thresholds.detail["min_observed_events_for_confidence"] == 3


def test_the_low_usage_summary_states_the_measurement_and_declines_the_judgement(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """The summary may report the ratio and may not conclude from it.

    "2 of 13 capabilities were exercised" is a measurement. "This access is
    over-provisioned" is a judgement about someone's job, and the finding does
    not have the evidence for it -- nor would it, if the number were 1 of 13.
    """
    findings = detect_low_utilization(dataset, settings)
    bob = next(f for f in findings if f.user_id == "u_bob")

    assert "bob.chen" in bob.summary
    assert "13" in bob.summary and "2" in bob.summary
    assert "0.25" in bob.summary
    assert "reviewer" in bob.summary


# --------------------------------------------------------------------------- #
# Purity and determinism
#
# The same boundary Rule D is held to. Rule A adds one more way to break it: a
# set computation iterated in a non-deterministic order produces findings that
# differ between runs over identical facts.
# --------------------------------------------------------------------------- #


def test_the_same_dataset_produces_identical_findings(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """Stability across runs is what makes a finding evidence."""
    first = detect_low_utilization(dataset, settings)
    second = detect_low_utilization(dataset, settings)

    assert [f.model_dump(mode="json") for f in first] == [
        f.model_dump(mode="json") for f in second
    ]


def test_findings_are_stamped_with_the_analysis_instant_not_the_wall_clock(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """A finding an auditor cannot reproduce is not evidence."""
    for finding in detect_low_utilization(dataset, settings):
        assert finding.created_at == settings.effective_analysis_as_of()


def test_the_rule_does_not_mutate_the_dataset_it_is_given(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """Purity is what lets the same dataset be handed to four rules."""
    before = dataset.dataset_fingerprint()

    detect_low_utilization(dataset, settings)

    assert dataset.dataset_fingerprint() == before


def test_the_rule_can_only_see_the_dataset_and_the_settings() -> None:
    """No session, no client, no clock -- enforced by the signature itself."""
    assert list(inspect.signature(detect_low_utilization).parameters) == [
        "dataset",
        "settings",
    ]


def test_every_finding_and_evidence_identifier_is_unique(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """Ids are the join key for the dossier, so a collision silently merges rows."""
    findings = detect_low_utilization(dataset, settings)

    ids = [f.id for f in findings]
    assert len(ids) == len(set(ids))

    evidence_ids = [e.evidence_id for f in findings for e in f.evidence]
    assert len(evidence_ids) == len(set(evidence_ids))


def test_low_usage_never_recommends_changing_access(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """The enum has no revoke-like member, and the summary must not invent one.

    The type system already makes "just take it away" inexpressible; this
    asserts the other half -- that the prose a reviewer reads does not reach for
    the phrasing the type system refuses.
    """
    prescriptive = ("should be revoked", "must be revoked", "safe to remove", "remove")

    for finding in detect_low_utilization(dataset, settings):
        assert finding.recommendation is not None
        for phrase in prescriptive:
            assert phrase not in finding.summary.lower(), finding.summary


def test_evaluate_user_agrees_with_the_sweep(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """One person, judged alone, reaches the same answer as the sweep.

    The rule reasons about exactly one person's grants and one person's slice,
    so it must not be able to see anything else. If it could, a finding would
    depend on who else happened to be in the export.
    """
    bob = _by_username(dataset, "bob.chen")

    alone = evaluate_user(
        bob,
        dataset.entitlements_for(bob.id),
        dataset.slice_for(bob.id),
        settings,
    )
    swept = _for_user(detect_low_utilization(dataset, settings), bob.id)

    assert [f.model_dump(mode="json") for f in alone] == [
        f.model_dump(mode="json") for f in swept
    ]
