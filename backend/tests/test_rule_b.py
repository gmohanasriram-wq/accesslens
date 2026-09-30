"""Rule B -- rarely used privileged permission.

Blueprint section 16's matrix has a row Rule A cannot reach:

    Rarely used privileged permission | Review, not automatic removal

It is a different row from "high privilege + low observed usage", and Erin is
the persona that makes the difference concrete. Her utilisation is 9/17, well
*above* the 0.25 threshold, so the utilisation rule correctly finds nothing --
and she still never once exercised IAM_WRITE, KMS_WRITE, LOGS_WRITE, S3_DELETE,
REPO_ADMIN or ORG_ADMIN. She uses her access constantly and has never used the
part of it that can destroy things.

That is the whole rule, and it is why this module cannot be a variant of Rule A.
Rule A asks *how much of the grant is used* and answers with one number over the
whole set; the destructive capabilities are six of seventeen and are invisible
in that number. Rule B asks *whether the dangerous part is used at all*, which
is a question about a subset and has no ratio in it.

Three clauses make the rule correct, and the blueprint states none of them.

**Rule B is the complement of Rule A.** Bob has exactly the same four
never-exercised privileged capabilities as Erin and a ratio of 0.154. "Never
exercised a dangerous capability" therefore does not distinguish them -- the
ratio does, and only the ratio. If Rule B ignored it, every low-usage user would
carry both findings: one measurement reported twice, under two names, with two
recommendations that point the same way. So Rule B declines exactly where Rule A
accepts, and the two partition the space.

**Protected grants are excluded, or Alice carries a finding that contradicts
herself.** Alice holds break-glass-emergency-admin, which confers IAM_WRITE,
KMS_WRITE, LOGS_WRITE and S3_DELETE, and she has COMPLETE coverage with zero
events -- so every one of them is provably never exercised. A Rule B that read
grants without reading protection would hand her a REVIEW_REQUIRED finding
alongside her PROTECTED_BREAK_GLASS, inverting the sharpest case in the fixture
set. Same rule as Rule A: protection is a property of the grant.

**An unmeasurable window produces silence from this rule, not a verdict.** Ivan
has PARTIAL coverage and holds KMS_WRITE, LOGS_WRITE and S3_DELETE never
exercised. Absence of evidence is not evidence of absence, so he is not accused.
He is also not merely dropped: Rule A already reports INSUFFICIENT_EVIDENCE for
him, and the test below asserts he carries exactly one finding between the two
rules rather than zero. Rule 7 is satisfied by the rule set, not by every rule
restating it.

The finding is REVIEW_REQUIRED and its recommendation is MANUAL_REVIEW. Erin's
grant may well be exactly right for her job -- the engine has no idea what her
job is -- so the finding reports a fact about a capability and asks a person to
consider it. It may not conclude that the permission should go.

This rule reports independently of the others. Carol carries a CRITICAL
GHOST_ACCESS finding and, because her utilisation sits exactly on the threshold
where Rule A declines her, a Rule B finding too. Those are two different facts
about her and neither suppresses the other; `additional_findings` in the oracle
records that as the intended shape rather than an accident.
"""

from __future__ import annotations

import ast
import inspect
import pathlib
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

from app.engine.privileged_usage import (
    RULE_ID,
    detect_rarely_used_privileged_permissions,
    evaluate_user,
    privileged_exposure,
)

AWARE = TypeAdapter(datetime)

WINDOW_START = "2026-07-01T06:00:00Z"
WINDOW_END = "2026-09-29T06:00:00Z"


def _at(text: str) -> datetime:
    return AWARE.validate_python(text)


# --------------------------------------------------------------------------- #
# Hand-built cases
#
# The fixture set cannot contain the boundaries this rule turns on, because it
# has exactly one persona per scenario. A protected grant that is one property
# away from an accusation is a dozen lines here, and the engine's purity is what
# makes that cheap.
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
) -> Entitlement:
    return Entitlement(
        user_id=user_id,
        source=source,
        role=role,
        permissions=list(permissions),
        risk_level=risk_level,
        protected_role=protected_role,
        protection_reason=protection_reason,
        principal=f"arn:aws:iam::123456789012:user/{user_id}",
    )


def _event(
    action: str,
    *,
    actor_id: str = "u_test",
    event_id: str | None = None,
    source: ActivitySource = ActivitySource.AWS_CLOUDTRAIL,
) -> ActivityEvent:
    return ActivityEvent(
        event_id=event_id or f"evt-{action}",
        timestamp=_at("2026-08-01T12:00:00Z"),
        actor_id=actor_id,
        source=source,
        action=action,
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


def _persona(oracle: dict, user_id: str) -> dict:
    return next(p for p in oracle["personas"] if p["user_id"] == user_id)


def _settings(**overrides) -> Settings:
    return Settings(analysis_as_of=WINDOW_END, _env_file=None, **overrides)


#: The five AWS actions below exercise S3_READ, S3_WRITE, EC2_READ, EC2_WRITE
#: and IAM_READ, and deliberately none of the privileged set. Five of
#: AdministratorAccess's thirteen capabilities is 0.385 -- above the 0.25
#: threshold, which is what makes this shape Rule B's and not Rule A's.
_BUSY_BUT_HARMLESS = [
    "s3:GetObject",
    "s3:PutObject",
    "ec2:DescribeInstances",
    "ec2:RunInstances",
    "iam:GetRole",
]


def _busy_events() -> list[ActivityEvent]:
    return [_event(a, event_id=f"evt-{i}") for i, a in enumerate(_BUSY_BUT_HARMLESS)]


def _narrow_usage_shape(**kwargs) -> InMemoryDataset:
    """Constant usage, constant grant -- the only variable is what is varied.

    Every synthetic below builds on this, so a difference in the verdict can
    only come from the property named in the test that varies it.
    """
    return _one_person(
        grants=[_grant(risk_level=RiskLevel.CRITICAL)],
        events=_busy_events(),
        **kwargs,
    )


# --------------------------------------------------------------------------- #
# The oracle's privileged-capability specification
#
# `never_exercised_privileged_capabilities` was written in Phase 1 and read by
# nothing until this module. It listed five capabilities while the prose beside
# it named six: S3_DELETE is granted by AdministratorAccess and was never
# exercised, so the field was wrong and the prose was right. These tests are what
# makes that class of drift fail instead of sitting in the file.
# --------------------------------------------------------------------------- #


def test_the_oracle_privileged_capability_list_matches_the_fixture(
    dataset: InMemoryDataset, settings: Settings, oracle: dict
) -> None:
    """Every persona's privileged exposure, as the oracle specifies it."""
    failures: list[str] = []

    for persona in oracle["personas"]:
        row = persona.get("never_exercised_privileged_capabilities")
        if row is None:
            continue

        user = _by_username(dataset, persona["username"])
        exposure = privileged_exposure(
            user.id,
            dataset.entitlements_for(user.id),
            dataset.slice_for(user.id),
            settings,
        )
        actual = sorted(c.value for c in exposure.never_exercised_privileged)

        if actual != sorted(row):
            failures.append(
                f"{persona['username']}: never-exercised privileged was {actual}, "
                f"oracle says {sorted(row)}"
            )

    assert not failures, "privileged-capability oracle mismatches:\n  " + "\n  ".join(
        failures
    )


def test_the_additional_findings_block_matches_the_personas_that_carry_it(
    dataset: InMemoryDataset, settings: Settings, oracle: dict
) -> None:
    """A persona with two findings, checked against the rule that produces each.

    Carol is the case: her utilisation is exactly the threshold, so Rule A
    declines her, and five of her privileged capabilities were never exercised,
    so Rule B does not. Two rules, two findings, one person -- and the oracle now
    says so explicitly rather than leaving it to whichever rule happened to run
    first.
    """
    carol = _by_username(dataset, "carol.diaz")
    persona = _persona(oracle, "u_carol")

    assert len(persona["additional_findings"]) == 1
    expected = persona["additional_findings"][0]

    findings = _for_user(detect_rarely_used_privileged_permissions(dataset, settings), carol.id)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.type.value == expected["type"]
    assert finding.status.value == expected["status"]
    assert finding.severity.value == expected["severity"]
    assert finding.recommendation.value == expected["recommendation"]
    assert finding.evidence_completeness.value == expected["evidence_completeness"]

    exposure = privileged_exposure(
        carol.id, dataset.entitlements_for(carol.id), dataset.slice_for(carol.id), settings
    )
    assert sorted(c.value for c in exposure.never_exercised_privileged) == sorted(
        expected["never_exercised_privileged_capabilities"]
    )


# --------------------------------------------------------------------------- #
# Erin: the finding itself
# --------------------------------------------------------------------------- #


def test_erin_produces_the_finding_the_oracle_specifies(
    dataset: InMemoryDataset, settings: Settings, oracle: dict
) -> None:
    """The persona this rule exists for, asserted field for field.

    Note `usage`: it is OBSERVED, not LOW. Rule A's review finding says LOW,
    because low usage is what it found. Here the observation is good and the
    usage is *narrow*, so stamping LOW would contradict the finding's own
    rationale and hand a reader the conclusion this rule was written to avoid.
    """
    erin = _by_username(dataset, "erin.walsh")
    persona = _persona(oracle, "u_erin")
    expected = persona["finding"]

    findings = _for_user(detect_rarely_used_privileged_permissions(dataset, settings), erin.id)

    assert len(findings) == 1
    finding = findings[0]

    assert finding.id == "fnd-u_erin-rule-b"
    assert finding.type is FindingType.RARELY_USED_PRIVILEGED_PERMISSION
    assert finding.type.value == expected["type"]
    assert finding.status is FindingStatus.REVIEW_REQUIRED
    assert finding.status.value == expected["status"]
    assert finding.severity.value == expected["severity"]
    assert finding.recommendation is Recommendation.MANUAL_REVIEW
    assert finding.recommendation.value == expected["recommendation"]
    assert finding.evidence_completeness.value == expected["evidence_completeness"]
    assert finding.rules_triggered == [RULE_ID]
    assert finding.usage is UsageObservation.OBSERVED
    assert finding.user_id == erin.id


def test_erin_is_not_a_low_usage_case_and_the_rule_must_say_so(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """The measurement that makes this a different finding from Bob's.

    9 of 17 is 0.529, comfortably above the 0.25 threshold. A reader who sees a
    privileged-permission finding and assumes it is another way of saying "this
    person barely uses their access" has the wrong idea, and the numbers that
    refute it are in the finding.
    """
    erin = _by_username(dataset, "erin.walsh")

    exposure = privileged_exposure(
        erin.id, dataset.entitlements_for(erin.id), dataset.slice_for(erin.id), settings
    )

    assert exposure.reviewable_ratio is not None
    assert round(exposure.reviewable_ratio, 3) == 0.529
    assert exposure.reviewable_ratio > settings.low_utilization_threshold
    assert exposure.observed_event_count == 10


def test_the_finding_names_the_capabilities_and_the_policy_that_selected_them(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """A capability judgement a reviewer cannot audit is a capability judgement
    they cannot disagree with.

    The reviewer's first question is "why these six?", and the answer has to be
    the configured policy rather than the rule's opinion.
    """
    erin = _by_username(dataset, "erin.walsh")
    finding = _for_user(
        detect_rarely_used_privileged_permissions(dataset, settings), erin.id
    )[0]

    kinds = {e.kind for e in finding.evidence}
    assert EvidenceKind.ENTITLEMENT_GRANT in kinds
    assert EvidenceKind.CONFIG_VALUE in kinds

    policy = [
        e
        for e in finding.evidence
        if e.kind is EvidenceKind.CONFIG_VALUE
        and "privileged_capabilities" in e.detail
    ]
    assert len(policy) == 1
    assert sorted(policy[0].detail["privileged_capabilities"]) == sorted(
        c.value for c in settings.privileged_capabilities
    )

    exposure_rows = [
        e for e in finding.evidence if "never_exercised_privileged" in e.detail
    ]
    assert len(exposure_rows) == 1
    assert sorted(exposure_rows[0].detail["never_exercised_privileged"]) == [
        "IAM_WRITE",
        "KMS_WRITE",
        "LOGS_WRITE",
        "ORG_ADMIN",
        "REPO_ADMIN",
        "S3_DELETE",
    ]


def test_the_finding_records_why_the_utilisation_rule_declined(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """The reviewer's other first question: why did the ratio rule miss this?

    Because the ratio is 0.529 and the threshold is 0.25. Both numbers belong in
    the finding, or the finding reads as a rule that ignores its own metric.
    """
    erin = _by_username(dataset, "erin.walsh")
    finding = _for_user(
        detect_rarely_used_privileged_permissions(dataset, settings), erin.id
    )[0]

    rows = [e for e in finding.evidence if "observed_utilisation" in e.detail]
    assert len(rows) == 1
    assert rows[0].detail["observed_utilisation"] == 0.529

    thresholds = [e for e in finding.evidence if "low_utilization_threshold" in e.detail]
    assert len(thresholds) == 1
    assert thresholds[0].detail["low_utilization_threshold"] == 0.25


def test_the_erin_finding_does_not_ask_for_the_permission_to_be_taken_away(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """Erin has no ``must_not_say`` list, so this is the backstop for her.

    ``Finding.summary`` rejects the eight forbidden phrases at validation time,
    but silence about *removal* as a concept is a stronger property than silence
    about eight spellings of it: the finding may say a capability was never
    exercised and may not conclude that it should go.

    ``delete`` is deliberately *not* in the list. The capability this finding is
    most about is named ``S3_DELETE``, so any honest summary contains the
    substring, and a rule that forbade the word would have to stop naming the
    thing it found. The words that are listed are the prescriptive ones -- the
    ones that turn an observation into an instruction.
    """
    erin = _by_username(dataset, "erin.walsh")
    finding = _for_user(
        detect_rarely_used_privileged_permissions(dataset, settings), erin.id
    )[0]

    lowered = finding.summary.lower()
    for word in ("revoke", "remove", "unused", "unnecessary", "no longer needed",
                 "not needed", "safe to", "prune"):
        assert word not in lowered, f"Rule B said {word!r}: {finding.summary!r}"

    assert finding.recommendation is Recommendation.MANUAL_REVIEW
    # The finding must name the capability, though -- the test above is about
    # diction, and a summary that avoided every forbidden word by naming nothing
    # would be useless rather than careful.
    assert "S3_DELETE" in finding.summary


# --------------------------------------------------------------------------- #
# Rule independence, and the complement that keeps the two rules from
# reporting one measurement twice
# --------------------------------------------------------------------------- #


def test_rule_b_does_not_restate_rule_a_for_the_same_person(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """Bob is Rule A's, and this rule must leave him alone.

    He has the same four never-exercised privileged capabilities as Erin and a
    ratio of 0.154. Without the complement clause he would carry both findings --
    one measurement, two names, two recommendations pointing the same way. The
    distinction being drawn is between low usage and narrow usage, and Bob is the
    former.
    """
    from app.engine.utilization import detect_low_utilization

    bob = _by_username(dataset, "bob.chen")

    assert [
        f.type for f in _for_user(detect_low_utilization(dataset, settings), bob.id)
    ] == [FindingType.HIGH_PRIVILEGE_LOW_USAGE]

    assert (
        _for_user(detect_rarely_used_privileged_permissions(dataset, settings), bob.id)
        == []
    )


def test_the_two_rules_partition_rather_than_overlap(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """No fixture user may be the subject of both rules.

    Every user the utilisation rule reports -- Bob's low usage, Alice's protected
    break-glass, Ivan's and Gina's insufficiency -- must be one this rule says
    nothing about, and the two people this rule does report must be ones the
    utilisation rule declined. Stated over the whole population rather than
    persona by persona, because the failure this guards against is a rule that
    fires on everyone: that passes every individually interesting persona and
    shows up only here.
    """
    from app.engine.utilization import detect_low_utilization

    low_usage = {f.user_id for f in detect_low_utilization(dataset, settings)}
    privileged = {
        f.user_id for f in detect_rarely_used_privileged_permissions(dataset, settings)
    }

    assert low_usage & privileged == set()


def test_the_two_rules_still_cover_erins_persona_between_them(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """Partitioning must not leave a gap: Erin is claimed by exactly one rule."""
    from app.engine.utilization import detect_low_utilization

    erin = _by_username(dataset, "erin.walsh")

    assert _for_user(detect_low_utilization(dataset, settings), erin.id) == []
    assert len(
        _for_user(detect_rarely_used_privileged_permissions(dataset, settings), erin.id)
    ) == 1


def test_carol_carries_both_her_findings_and_neither_suppresses_the_other(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """Rule independence, made executable.

    She sits exactly on the threshold -- 4 of 16 is 0.25 and 0.25 is not below
    0.25 -- so Rule A declines her, and five privileged capabilities were never
    exercised, so Rule B does not. Meanwhile Rule D reports the ghost access.
    Two findings for two different facts, and a rule that suppressed its own
    observation because a CRITICAL finding already existed would be hiding
    evidence on the strength of an unrelated one.
    """
    from app.engine.ghost_access import detect_ghost_access
    from app.engine.utilization import detect_low_utilization

    carol = _by_username(dataset, "carol.diaz")

    everything = (
        detect_ghost_access(dataset, settings)
        + detect_low_utilization(dataset, settings)
        + detect_rarely_used_privileged_permissions(dataset, settings)
    )

    assert [f.type for f in _for_user(everything, carol.id)] == [
        FindingType.GHOST_ACCESS,
        FindingType.RARELY_USED_PRIVILEGED_PERMISSION,
    ]


def test_carol_sits_on_the_threshold_where_rule_a_declines_and_rule_b_accepts(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """One persona, and the only place in the fixture set where the complement
    clause changes the answer.

    Both rules compare against the same 0.25 and the comparison is strict, so
    0.25 is Rule B's territory and 0.249 would be Rule A's. A `<=` anywhere in
    either rule moves Carol between them.
    """
    carol = _by_username(dataset, "carol.diaz")

    exposure = privileged_exposure(
        carol.id, dataset.entitlements_for(carol.id), dataset.slice_for(carol.id), settings
    )

    assert exposure.reviewable_ratio == settings.low_utilization_threshold
    assert not exposure.reviewable_ratio < settings.low_utilization_threshold


@pytest.mark.parametrize(
    "username",
    [
        "alice.nguyen",
        "bob.chen",
        "dave.okonkwo",
        "frank.moreau",
        "gina.patel",
        "henry.okafor",
        "ivan.petrov",
    ],
)
def test_rule_b_claims_nobody_else_in_the_fixture_set(
    dataset: InMemoryDataset, settings: Settings, username: str
) -> None:
    """The other seven personas, each for a different reason.

    Alice is protected, Bob and Ivan are Rule A's (or unmeasurable), Dave and
    Frank have never-exercised nothing, Gina cannot be seen, Henry has no
    privileged capability at all. Erin and Carol are the two who belong to this
    rule, and they are asserted above.
    """
    user = _by_username(dataset, username)

    assert (
        _for_user(
            detect_rarely_used_privileged_permissions(dataset, settings), user.id
        )
        == []
    )


# --------------------------------------------------------------------------- #
# Coverage: an unmeasurable window is silence here and a verdict next door
# --------------------------------------------------------------------------- #


def test_a_complete_window_produces_the_finding(settings: Settings) -> None:
    """The control for the tests below: this shape *does* fire."""
    findings = detect_rarely_used_privileged_permissions(
        _narrow_usage_shape(coverage=Coverage.COMPLETE), settings
    )

    assert [f.type for f in findings] == [FindingType.RARELY_USED_PRIVILEGED_PERMISSION]


@pytest.mark.parametrize(
    "coverage",
    [Coverage.MISSING, Coverage.PARTIAL, Coverage.NOT_QUERIED],
)
def test_an_unmeasurable_window_produces_no_privileged_finding(
    settings: Settings, coverage: Coverage
) -> None:
    """Identical usage, identical grant, and the rule says nothing.

    Not a clean result -- the assertion below is that the *other* rule is the
    one that speaks, so the user is reported as unmeasurable rather than as
    fine. Parametrised over every non-COMPLETE state so a new one has to be
    decided rather than defaulted.
    """
    from app.engine.utilization import detect_low_utilization

    ds = _narrow_usage_shape(coverage=coverage)

    assert detect_rarely_used_privileged_permissions(ds, settings) == []
    assert [f.type for f in detect_low_utilization(ds, settings)] == [
        FindingType.INSUFFICIENT_EVIDENCE
    ]


def test_an_unmeasurable_user_carries_exactly_one_finding_between_the_two_rules(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """Rule 7, satisfied by the rule set rather than by every rule repeating it.

    Ivan and Gina must not be reported clean, and must not be reported twice.
    Rule B's silence is only correct because Rule A speaks.
    """
    from app.engine.utilization import detect_low_utilization

    combined = detect_low_utilization(dataset, settings) + (
        detect_rarely_used_privileged_permissions(dataset, settings)
    )

    for username in ("ivan.petrov", "gina.patel"):
        user = _by_username(dataset, username)
        findings = _for_user(combined, user.id)

        assert [f.type for f in findings] == [FindingType.INSUFFICIENT_EVIDENCE], username


def test_the_privileged_finding_is_never_emitted_with_incomplete_evidence(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """It only exists where coverage is COMPLETE, so it must not claim otherwise.

    Rule A's INSUFFICIENT_EVIDENCE finding is the one that carries PARTIAL and
    MISSING completeness. If a privileged-permission finding ever showed up
    marked PARTIAL, the two rules' verdicts would have crossed.
    """
    for finding in detect_rarely_used_privileged_permissions(dataset, settings):
        assert finding.evidence_completeness is EvidenceCompleteness.COMPLETE


def test_a_window_below_the_confidence_floor_produces_no_finding(
    settings: Settings,
) -> None:
    """This rule makes a review demand, so the floor applies to it too.

    Without the floor, a user with COMPLETE coverage and no events at all would
    have every privileged capability they hold reported as never exercised --
    which is true, and is also true of every other capability, and would fire on
    every idle account in the estate.
    """
    ds = _narrow_usage_shape()

    unreachable = _settings(min_observed_events_for_confidence=50)

    assert [
        f.type
        for f in detect_rarely_used_privileged_permissions(ds, unreachable)
    ] == []
    assert [
        f.type for f in detect_rarely_used_privileged_permissions(ds, settings)
    ] == [FindingType.RARELY_USED_PRIVILEGED_PERMISSION]


# --------------------------------------------------------------------------- #
# Protection
# --------------------------------------------------------------------------- #


def test_a_protected_grant_with_untouched_privileged_capabilities_is_left_alone(
    settings: Settings,
) -> None:
    """Alice's shape, in isolation.

    break-glass-emergency-admin confers IAM_WRITE, KMS_WRITE, LOGS_WRITE and
    S3_DELETE, and this user never exercises any of them -- and exercises enough
    of the rest to clear the threshold. Reporting it would hand a break-glass
    holder a REVIEW_REQUIRED finding, which is the one outcome the whole
    protection model exists to prevent.

    Note that two separate things protect this grant: the source system's own
    flag, set here, and the role's *name*, which configuration classifies. The
    flag alone is isolated in the pair below.
    """
    protected = _one_person(
        grants=[
            _grant(
                role="break-glass-emergency-admin",
                permissions=("break-glass-emergency-admin",),
                protected_role=True,
                protection_reason="Emergency break-glass role.",
            )
        ],
        events=_busy_events(),
    )

    assert detect_rarely_used_privileged_permissions(protected, settings) == []


def test_a_grant_protected_only_by_its_own_flag_is_left_alone(
    settings: Settings,
) -> None:
    """Protection from the source system's flag, with configuration silent.

    The role name is one that neither ``always_protected_roles`` nor
    ``protected_role_patterns`` classifies, so the flag is the only thing that
    can protect it. This test and the one below differ in exactly one argument.

    Written this way because the first draft of this pair used
    break-glass-emergency-admin and cleared the flag, which isolated nothing:
    the *name* is protected by configuration, so the grant stayed protected and
    the "unprotected" half of the pair failed. The implementation was right and
    the test was wrong, which is the useful direction for that to go.
    """
    by_flag = _one_person(
        grants=[
            _grant(
                role="AdministratorAccess",
                protected_role=True,
                protection_reason="Held for the DR failover the runbook names.",
            )
        ],
        events=_busy_events(),
    )

    assert detect_rarely_used_privileged_permissions(by_flag, settings) == []


def test_the_same_grant_with_the_flag_cleared_is_reported(
    settings: Settings,
) -> None:
    """The pair for the test above: the flag is the only variable.

    Without this, the previous test passes for any implementation that returns
    nothing at all -- including one that never looks at grants.
    """
    unprotected = _one_person(
        grants=[_grant(role="AdministratorAccess", protected_role=False)],
        events=_busy_events(),
    )

    assert [
        f.type
        for f in detect_rarely_used_privileged_permissions(unprotected, settings)
    ] == [FindingType.RARELY_USED_PRIVILEGED_PERMISSION]


def test_protection_by_configuration_is_honoured_too(settings: Settings) -> None:
    """A role named in policy but not flagged by the source system.

    Protection is unioned from the grant's own flag and from configuration, and
    the second half is what lets a security team classify a role without waiting
    for the next import.
    """
    by_policy = _one_person(
        grants=[
            _grant(
                role="break-glass-emergency-admin",
                permissions=("break-glass-emergency-admin",),
                protected_role=False,
            )
        ],
        events=_busy_events(),
    )

    unchecked = _settings(always_protected_roles=(), protected_role_patterns=())

    assert [
        f.type for f in detect_rarely_used_privileged_permissions(by_policy, unchecked)
    ] == [FindingType.RARELY_USED_PRIVILEGED_PERMISSION]
    assert detect_rarely_used_privileged_permissions(by_policy, settings) == []


def test_an_unprotected_grant_is_still_reported_alongside_a_protected_one(
    settings: Settings,
) -> None:
    """Protection attaches to a grant, not to a person.

    A break-glass role and an ordinary administrator role on the same account
    are two grants. Letting the protected one cover the unprotected one would
    make protection a way to silence a real finding.
    """
    user = _user()
    ds = _dataset(
        [user],
        [
            _grant(
                user_id=user.id,
                role="break-glass-emergency-admin",
                permissions=("break-glass-emergency-admin",),
                protected_role=True,
                protection_reason="Emergency break-glass role.",
            ),
            _grant(
                user_id=user.id,
                role="AdministratorAccess",
                permissions=("AdministratorAccess",),
                risk_level=RiskLevel.CRITICAL,
            ),
        ],
        {
            user.id: _slice(
                user_id=user.id,
                events=_busy_events(),
            )
        },
    )

    findings = detect_rarely_used_privileged_permissions(ds, settings)

    assert [f.type for f in findings] == [FindingType.RARELY_USED_PRIVILEGED_PERMISSION]
    assert len(findings) == 1


def test_a_user_whose_only_grants_are_protected_produces_nothing(
    settings: Settings,
) -> None:
    """Alice's actual fixture shape: no reviewable grant, so no subject."""
    ds = _one_person(
        grants=[
            _grant(
                role="break-glass-emergency-admin",
                permissions=("break-glass-emergency-admin",),
                protected_role=True,
                protection_reason="Emergency break-glass role.",
            )
        ],
        events=[],
    )

    assert detect_rarely_used_privileged_permissions(ds, settings) == []


def test_a_protected_grant_confers_nothing_reviewable(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """Alice's exposure at the level of the measurement, not the verdict.

    Protection is applied inside ``privileged_exposure`` as well as at the entry
    point, and only the entry point is exercised by the tests above -- so
    dropping the inner filter changes no verdict, because ``evaluate_user`` has
    already returned. Alice has no oracle entry for this rule precisely because
    the answer about her is *nothing*, which is what makes that filter easy to
    delete without a test noticing.

    Every number here would be non-empty without it: her grant confers
    IAM_WRITE, KMS_WRITE, LOGS_WRITE and S3_DELETE and she exercised none of
    them, on COMPLETE coverage, so this is not an absence of evidence -- it is
    the case the protection model exists for.
    """
    alice = _by_username(dataset, "alice.nguyen")

    exposure = privileged_exposure(
        alice.id,
        dataset.entitlements_for(alice.id),
        dataset.slice_for(alice.id),
        settings,
    )

    assert exposure.reviewable_granted == frozenset()
    assert exposure.privileged_granted == frozenset()
    assert exposure.never_exercised_privileged == frozenset()
    assert exposure.reviewable_ratio is None


# --------------------------------------------------------------------------- #
# The privileged set is configuration
# --------------------------------------------------------------------------- #


def test_the_privileged_set_comes_from_settings_and_not_from_the_code(
    settings: Settings,
) -> None:
    """Three policies, three answers, on one unchanged dataset.

    Erin's data does not move. What moves is which capabilities the
    organisation has decided are dangerous, and that decision belongs in
    configuration where a security team can see and change it without a release.
    """
    ds = _narrow_usage_shape()

    nothing_is_privileged = _settings(privileged_capabilities=())
    only_what_is_used = _settings(privileged_capabilities=(Capability.S3_READ,))

    assert [
        f.type for f in detect_rarely_used_privileged_permissions(ds, settings)
    ] == [FindingType.RARELY_USED_PRIVILEGED_PERMISSION]
    assert (
        detect_rarely_used_privileged_permissions(ds, nothing_is_privileged) == []
    )
    assert detect_rarely_used_privileged_permissions(ds, only_what_is_used) == []


def test_the_rule_hardcodes_no_capability_names() -> None:
    """The policy lives in config, proven rather than asserted.

    Parsed rather than grepped so the module may discuss capabilities in prose
    while being unable to name one in code. Both spellings are checked: the
    string literal and the enum attribute.
    """
    import app.engine.privileged_usage as module

    source = pathlib.Path(module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)

    vocabulary = {c.value for c in Capability}

    literals = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    attributes = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "Capability"
    }

    assert literals & vocabulary == set(), "a capability name is hardcoded as a string"
    assert attributes == set(), f"a capability is hardcoded: {attributes}"


def test_the_confidence_floor_used_is_the_shared_one(settings: Settings) -> None:
    """Rule B does not invent a second floor.

    Two floors would mean two rules disagreeing about what counts as enough
    evidence, which is the same failure as two thresholds.
    """
    ds = _narrow_usage_shape()

    for floor in (3, 50):
        configured = _settings(min_observed_events_for_confidence=floor)
        expected = (
            [FindingType.RARELY_USED_PRIVILEGED_PERMISSION]
            if ds.slice_for("u_test").observed_event_count >= floor
            else []
        )
        assert [
            f.type
            for f in detect_rarely_used_privileged_permissions(ds, configured)
        ] == expected


# --------------------------------------------------------------------------- #
# Purity
# --------------------------------------------------------------------------- #


def test_identical_input_produces_identical_findings(settings: Settings) -> None:
    """Rule 2: the same facts produce the same finding, across runs."""
    ds = _narrow_usage_shape()

    first = detect_rarely_used_privileged_permissions(ds, settings)
    second = detect_rarely_used_privileged_permissions(ds, settings)

    assert [f.model_dump(mode="json") for f in first] == [
        f.model_dump(mode="json") for f in second
    ]


def test_the_rule_does_not_mutate_the_dataset(settings: Settings) -> None:
    """A rule that edits its input cannot be re-run, and cannot be trusted."""
    ds = _narrow_usage_shape()
    before = ds.dataset_fingerprint()

    detect_rarely_used_privileged_permissions(ds, settings)

    assert ds.dataset_fingerprint() == before


def test_the_rule_reads_only_the_dataset_and_the_settings() -> None:
    """The signature is the purity guarantee: there is nowhere for a session,
    an HTTP client or a clock to be passed in."""
    assert list(inspect.signature(detect_rarely_used_privileged_permissions).parameters) == [
        "dataset",
        "settings",
    ]
    assert list(inspect.signature(evaluate_user).parameters) == [
        "user",
        "entitlements",
        "slice_",
        "settings",
    ]


def test_finding_ids_are_unique_and_stable(settings: Settings) -> None:
    """One finding per person from this rule, and the id says which rule."""
    ds = _narrow_usage_shape()

    findings = detect_rarely_used_privileged_permissions(ds, settings)
    ids = [f.id for f in findings]

    assert len(ids) == len(set(ids))
    assert ids == ["fnd-u_test-rule-b"]


def test_the_sweep_agrees_with_the_per_user_entry_point(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """`evaluate_user` is the rule; the sweep only chooses who to run it on.

    If they can disagree, one of them is wrong and a caller cannot tell which.
    """
    swept = detect_rarely_used_privileged_permissions(dataset, settings)
    swept_pairs = sorted((f.user_id, f.id) for f in swept)

    expected_pairs = sorted(
        (user.id, f.id)
        for user in dataset.users
        for f in evaluate_user(
            user,
            dataset.entitlements_for(user.id),
            dataset.slice_for(user.id),
            settings,
        )
    )

    assert swept_pairs == expected_pairs
