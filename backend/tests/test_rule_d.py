"""Rule D -- ghost access.

Blueprint §8 states the rule in three lines::

    IF identity is deactivated AND downstream activity occurs after deactivation
    THEN create GHOST_ACCESS finding

Every word of that turns out to be load-bearing, and each one is a way to get
the rule wrong:

* **"identity is deactivated"** -- not "the user exists". A live account is not
  a ghost. Alice's and Gina's accounts are ACTIVE, so Rule D must not reach
  either of them, whatever else is true about their data.
* **"after deactivation"** -- not "after termination". Carol is terminated at
  17:00 and disabled at 09:12 the next morning; an action in that sixteen-hour
  gap happened while the account was still live and is not ghost access. The
  comparison is also strict: an event *at* the deactivation instant is not
  after it.
* **"activity"** -- not "attempted activity". A denied call proves the
  credential was still live, which is why it belongs in the evidence, but it is
  not use of the entitlement and must not count toward the finding's threshold.

The two fixture personas that make this real are Carol and Frank. Both are
terminated, both were disabled, and they differ in exactly one respect: whether
anything happened afterwards. Frank is why the rule cannot be keyed on "is
terminated" or on "has activity in the window" -- both of those fire on him and
produce a false CRITICAL.

Alice and Gina are the other half of the obligation. Their expected verdicts
(PROTECTED_BREAK_GLASS and INSUFFICIENT_EVIDENCE) belong to Rules C, A and B,
which do not exist yet. Rule D's duty toward them is therefore not to produce
those verdicts but to *not pre-empt them* -- a CRITICAL ghost-access finding
against a break-glass holder or against someone whose telemetry never arrived
would be exactly the confident-wrong answer this product exists to avoid.

The engine is a pure function, so the boundary cases live here as small
hand-built datasets rather than as new fixture files. That is the point of the
purity: a case that no fixture covers is three lines of construction away.
"""

from __future__ import annotations

import inspect
from datetime import datetime

import pytest
from pydantic import TypeAdapter

from app.core.config import Settings
from app.core.enums import (
    ActivitySource,
    Coverage,
    EvidenceCompleteness,
    EvidenceKind,
    EmploymentStatus,
    FindingStatus,
    FindingType,
    IdentityProvider,
    IdentityStatus,
    Recommendation,
    Severity,
    UsageObservation,
)
from app.ingestion import InMemoryDataset
from app.schemas.domain.activity import ActivityEvent, ActivitySlice
from app.schemas.domain.identity import Identity
from app.schemas.domain.user import User

from app.engine.ghost_access import detect_ghost_access

AWARE = TypeAdapter(datetime)


def _at(text: str) -> datetime:
    return AWARE.validate_python(text)


# --------------------------------------------------------------------------- #
# The oracle personas
# --------------------------------------------------------------------------- #


def _for_user(findings: list, user_id: str) -> list:
    return [f for f in findings if f.user_id == user_id]


def test_carol_produces_the_ghost_access_finding_the_oracle_specifies(
    dataset: InMemoryDataset, settings: Settings, oracle: dict
) -> None:
    """The whole contract of one finding, checked against the written oracle."""
    expected = next(
        row for row in oracle["personas"] if row["user_id"] == "u_carol"
    )["finding"]

    findings = detect_ghost_access(dataset, settings)
    mine = _for_user(findings, "u_carol")

    assert len(mine) == 1, f"expected exactly one finding for carol.diaz, got {len(mine)}"

    finding = mine[0]
    assert finding.type is FindingType[expected["type"]]
    assert finding.severity is Severity[expected["severity"]]
    assert finding.status is FindingStatus[expected["status"]]
    assert finding.recommendation is Recommendation[expected["recommendation"]]
    assert finding.evidence_completeness is EvidenceCompleteness[
        expected["evidence_completeness"]
    ]
    assert finding.rules_triggered == ["RULE_D_GHOST_ACCESS"]
    assert finding.usage is UsageObservation.OBSERVED


def test_frank_produces_no_ghost_access_finding(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """The negative control, and the reason the rule is not keyed on termination.

    Frank is terminated and was disabled on the same evening. His last action is
    the day *before* he was terminated. A rule that fires on "terminated and has
    activity in the window" produces a CRITICAL here; the correct answer is that
    nothing happened after his access ended.
    """
    findings = detect_ghost_access(dataset, settings)

    assert _for_user(findings, "u_frank") == []


@pytest.mark.parametrize(
    "user_id",
    [
        "u_alice",
        "u_bob",
        "u_dave",
        "u_erin",
        "u_frank",
        "u_gina",
        "u_henry",
        "u_ivan",
    ],
)
def test_rule_d_claims_nobody_else_in_the_fixture_set(
    dataset: InMemoryDataset, settings: Settings, user_id: str
) -> None:
    """Carol is the only person in the population whose access outlived its end.

    A rule that fires on more than the one person the data supports is not
    conservative, it is noisy -- and a CRITICAL that appears against eight
    innocent colleagues is a CRITICAL nobody reads.
    """
    assert _for_user(detect_ghost_access(dataset, settings), user_id) == []


def test_alice_is_not_pre_empted_by_the_ghost_access_rule(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """Her verdict is PROTECTED_BREAK_GLASS, and that is Rule C's to produce.

    Rule D's obligation toward her is narrower and worth stating separately: she
    holds neither of the two facts the rule requires. She is not terminated and
    her account is ACTIVE, so there is no deactivation for activity to follow.
    A ghost-access rule that treated "we can prove she never used it" as
    suspicious would convict the one persona the product is built to protect.
    """
    alice = next(u for u in dataset.users if u.id == "u_alice")

    assert not alice.is_terminated
    assert all(
        not identity.is_deactivated for identity in dataset.identities_for(alice.id)
    )
    assert _for_user(detect_ghost_access(dataset, settings), "u_alice") == []


def test_gina_is_not_pre_empted_by_the_ghost_access_rule(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """Her verdict is INSUFFICIENT_EVIDENCE, and a CRITICAL here would be a lie.

    Her account is active, so Rule D has no deactivation to measure from. What
    makes her worth naming is the shape of the danger: she is the persona with
    the least evidence in the set, and the failure mode for a rule that reaches
    past its evidence is loudest on exactly the people it can see least.
    """
    gina = next(u for u in dataset.users if u.id == "u_gina")

    assert not gina.is_terminated
    assert all(
        not identity.is_deactivated for identity in dataset.identities_for(gina.id)
    )
    assert _for_user(detect_ghost_access(dataset, settings), "u_gina") == []


# --------------------------------------------------------------------------- #
# The temporal predicate, at its boundaries
#
# These cases are built by hand because no fixture sits on the boundary. The
# engine being pure is what makes that cheap: constructing a dataset is a few
# lines, and a boundary that is only asserted in prose is a boundary that will
# move without anyone noticing.
# --------------------------------------------------------------------------- #

TERMINATION = "2026-08-14T17:00:00Z"
DEACTIVATION = "2026-08-15T09:12:00Z"


def _user(
    *,
    user_id: str = "u_test",
    employment: EmploymentStatus = EmploymentStatus.TERMINATED,
    termination_date: str | None = TERMINATION,
) -> User:
    return User(
        id=user_id,
        username="test.user",
        name="Test User",
        email="test.user@example.com",
        department="Engineering",
        employment_status=employment,
        termination_date=_at(termination_date) if termination_date else None,
        source_updated_at=_at("2026-09-29T06:00:00Z"),
    )


def _identity(
    *,
    user_id: str = "u_test",
    account_id: str = "00u_test01",
    status: IdentityStatus = IdentityStatus.DISABLED,
    deactivated_at: str | None = DEACTIVATION,
) -> Identity:
    return Identity(
        user_id=user_id,
        provider=IdentityProvider.OKTA,
        account_id=account_id,
        login="test.user",
        status=status,
        deactivated_at=_at(deactivated_at) if deactivated_at else None,
        deactivation_trigger="hr_termination" if deactivated_at else None,
    )


def _event(
    when: str,
    *,
    event_id: str = "evt-1",
    denied: bool = False,
    action: str = "repo.clone",
    source: ActivitySource = ActivitySource.GITHUB_AUDIT,
    credential_id: str = "ghp_test",
) -> ActivityEvent:
    return ActivityEvent(
        event_id=event_id,
        timestamp=_at(when),
        actor_id="u_test",
        source=source,
        action=action,
        credential_id=credential_id,
        denied=denied,
    )


def _dataset(
    *,
    user: User | None = None,
    identities: list[Identity] | None = None,
    events: list[ActivityEvent] | None = None,
    coverage: Coverage = Coverage.COMPLETE,
) -> InMemoryDataset:
    """A one-person dataset, for cases the fixtures do not contain."""
    user = user or _user()
    identities = identities if identities is not None else [_identity()]
    events = events or []

    return InMemoryDataset(
        users=(user,),
        identities=tuple(identities),
        entitlements=(),
        slices={
            user.id: ActivitySlice(
                user_id=user.id,
                window_start=_at("2026-07-01T06:00:00Z"),
                window_end=_at("2026-09-29T06:00:00Z"),
                events=list(events),
                sources_queried=frozenset({ActivitySource.GITHUB_AUDIT}),
                coverage=coverage,
            )
        },
        window=(_at("2026-07-01T06:00:00Z"), _at("2026-09-29T06:00:00Z")),
        coverage_manifest=(),
        rejections=(),
        unattributable_actors=(),
    )


def test_activity_before_deactivation_is_not_ghost_activity(settings: Settings) -> None:
    """Frank's shape in miniature: the account was still live when it happened."""
    ds = _dataset(events=[_event("2026-08-15T08:00:00Z")])

    assert detect_ghost_access(ds, settings) == []


def test_activity_exactly_at_the_deactivation_instant_is_not_ghost_activity(
    settings: Settings,
) -> None:
    """The comparison is strict. "After" does not include "at".

    Worth pinning because the inclusive version reads as harmless and is not: an
    event stamped at the same second as the disable is an event from the moment
    the control was applied, not evidence that it failed.
    """
    ds = _dataset(events=[_event(DEACTIVATION, event_id="evt-at")])

    assert detect_ghost_access(ds, settings) == []


def test_activity_one_second_after_deactivation_is_ghost_activity(
    settings: Settings,
) -> None:
    """The other side of the same boundary, so the strictness is not vacuous."""
    ds = _dataset(events=[_event("2026-08-15T09:12:01Z", event_id="evt-after")])

    findings = detect_ghost_access(ds, settings)

    assert len(findings) == 1
    assert findings[0].type is FindingType.GHOST_ACCESS


def test_the_cutoff_is_deactivation_and_not_termination(settings: Settings) -> None:
    """An action between termination and deactivation is not ghost access.

    Carol's own gap is sixteen hours. Someone acting in it was using an account
    the directory still considered live, and reporting that as a CRITICAL would
    make the finding's timeline contradict its own conclusion.
    """
    ds = _dataset(events=[_event("2026-08-15T02:00:00Z", event_id="evt-gap")])

    assert detect_ghost_access(ds, settings) == []


def test_a_denied_attempt_after_deactivation_is_not_ghost_activity(
    settings: Settings,
) -> None:
    """Carol's 2026-08-16 AWS call, isolated.

    It is after her deactivation and it is not usage: the source refused it. It
    is evidence the credential was live, which is a different claim from the
    claim that the entitlement was exercised -- and only the second one belongs
    in the count that decides whether ghost access occurred.
    """
    ds = _dataset(events=[_event("2026-08-16T07:30:12Z", denied=True)])

    assert detect_ghost_access(ds, settings) == []


def test_a_terminated_user_whose_accounts_are_all_still_live_is_ghost_access(
    settings: Settings,
) -> None:
    """The fallback cutoff, for the case with no deactivation to measure from.

    Nobody switched this account off, so the instant access should have ended is
    the termination itself. Without the fallback the most severe form of the
    failure -- offboarded, still fully enabled, still being used -- would be the
    one shape the rule could not see.
    """
    ds = _dataset(
        user=_user(),
        identities=[
            _identity(status=IdentityStatus.ACTIVE, deactivated_at=None)
        ],
        events=[_event("2026-09-01T10:00:00Z")],
    )

    findings = detect_ghost_access(ds, settings)

    assert len(findings) == 1
    assert findings[0].type is FindingType.GHOST_ACCESS


def test_one_deactivated_account_beside_a_live_one_is_not_ghost_access(
    settings: Settings,
) -> None:
    """The account-migration false positive, which the fixture set cannot show.

    A person whose old account was closed and whose new one is open is still
    working legitimately. Their activity follows the old account's deactivation
    and means nothing by it. Events carry a credential but not an account, so
    attribution cannot settle the question -- and a CRITICAL that might be
    someone's normal Tuesday is not a finding, it is noise.
    """
    ds = _dataset(
        user=_user(employment=EmploymentStatus.ACTIVE, termination_date=None),
        identities=[
            _identity(account_id="00u_old", status=IdentityStatus.DISABLED),
            _identity(
                account_id="00u_new",
                status=IdentityStatus.ACTIVE,
                deactivated_at=None,
            ),
        ],
        events=[_event("2026-09-01T10:00:00Z")],
    )

    assert detect_ghost_access(ds, settings) == []


def test_a_suspended_account_is_not_treated_as_deprovisioned(
    settings: Settings,
) -> None:
    """SUSPENDED is not DISABLED. A suspension is reversible and is not an ending.

    Nothing in the fixture set exercises this, which is exactly why it is here:
    the status list has four non-active-looking members and it is tempting to
    treat them as one.
    """
    ds = _dataset(
        user=_user(employment=EmploymentStatus.ACTIVE, termination_date=None),
        identities=[
            _identity(status=IdentityStatus.SUSPENDED, deactivated_at=None)
        ],
        events=[_event("2026-09-01T10:00:00Z")],
    )

    assert detect_ghost_access(ds, settings) == []


# --------------------------------------------------------------------------- #
# Thresholds live in configuration
# --------------------------------------------------------------------------- #


def test_the_event_floor_comes_from_settings_not_from_the_code(
    settings: Settings,
) -> None:
    """One post-deactivation action is not enough when policy says two are.

    Proving the threshold is read from configuration rather than written into
    the rule: the same dataset reaches opposite conclusions under two settings,
    so an operator can tighten the rule without a release.
    """
    ds = _dataset(events=[_event("2026-09-01T10:00:00Z")])

    assert detect_ghost_access(ds, settings) != []

    stricter = settings.model_copy(
        update={"ghost_access_min_post_deactivation_events": 2}
    )
    assert detect_ghost_access(ds, stricter) == []


def test_the_grace_window_absorbs_clock_skew_between_systems(settings: Settings) -> None:
    """An hour of skew is a clock disagreement, not a ghost.

    HR, the directory and GitHub do not share a clock. Without a grace window
    every ordinary offboarding produces a finding from the few minutes it takes
    the disable to propagate, which is how a rule trains its readers to ignore
    it.
    """
    ds = _dataset(events=[_event("2026-08-15T10:12:00Z", event_id="evt-skew")])

    lenient = settings.model_copy(update={"ghost_access_grace_hours": 2})
    assert detect_ghost_access(ds, lenient) == []

    assert detect_ghost_access(ds, settings) != [], (
        "with no grace window the same event must be visible"
    )


# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #


def test_the_finding_carries_the_exact_timeline_the_blueprint_requires(
    dataset: InMemoryDataset, settings: Settings, oracle: dict
) -> None:
    """§8: "Every ghost-access finding should contain the exact timeline."

    The timeline is not decoration. Four instants in order -- employment ended,
    account disabled, a credential still trying, a credential succeeding -- *is*
    the finding; a reader who cannot see the sequence cannot check the
    conclusion.
    """
    expected = next(
        row for row in oracle["personas"] if row["user_id"] == "u_carol"
    )["timeline"]

    finding = _for_user(detect_ghost_access(dataset, settings), "u_carol")[0]
    stamps = [e.timestamp for e in finding.evidence if e.timestamp is not None]

    for instant in expected:
        assert _at(instant["at"]) in stamps, f"{instant['what']} is missing from the evidence"

    # The two administrative instants are stated as facts about other systems,
    # not as activity -- they carry no event_id because no event happened.
    assert any(
        e.kind is EvidenceKind.TIMELINE_POINT and e.timestamp == _at(expected[0]["at"])
        for e in finding.evidence
    )
    assert any(
        e.kind is EvidenceKind.TIMELINE_POINT and e.timestamp == _at(expected[1]["at"])
        for e in finding.evidence
    )


def test_each_successful_ghost_action_is_evidence_naming_its_credential(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """"Access is still live" is not actionable. "This token still works" is.

    All three of Carol's post-deactivation actions use the same GitHub
    credential, and naming it is what turns the finding into a task someone can
    finish.

    Note the deliberate filter. Her denied AWS call is *also* an
    ``ACTIVITY_EVENT`` and also sits after the deactivation, so selecting on
    "activity event after the cutoff" would return four rows and quietly assert
    that the denied call was one of the successful ones -- the precise
    conflation this rule exists to avoid, reproduced in the test written to
    check it.
    """
    finding = _for_user(detect_ghost_access(dataset, settings), "u_carol")[0]

    activity = [
        e
        for e in finding.evidence
        if e.kind is EvidenceKind.ACTIVITY_EVENT
        and e.timestamp > _at(DEACTIVATION)
        and e.detail.get("denied") is False
    ]

    assert len(activity) == 3
    assert all(e.event_id for e in activity), "evidence must point at its source row"
    assert len({e.event_id for e in activity}) == 3, "each action appears once"
    assert all("ghp_carol_legacy" in e.description for e in activity)


def test_the_denied_attempt_is_recorded_as_evidence_without_being_counted(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """Dropping it would lose the proof; counting it would overstate the case.

    Carol's denied AWS call on 2026-08-16 is the only direct evidence that her
    AWS credential survived her Okta account being disabled. It is deliberately
    present in the evidence and deliberately absent from the tally, and this
    test is what keeps those two decisions from collapsing into one.
    """
    finding = _for_user(detect_ghost_access(dataset, settings), "u_carol")[0]
    denied = next(
        (e for e in finding.evidence if e.event_id == "aws_evt-aws-0007"), None
    )

    assert denied is not None, "the denied post-deactivation attempt is missing"
    assert denied.timestamp == _at("2026-08-16T07:30:12Z")
    assert denied.detail.get("denied") is True

    # Recorded, and still not counted: the tally the rule acted on is three
    # successful actions after deactivation, not four events.
    tally = next(
        e for e in finding.evidence if e.kind is EvidenceKind.COVERAGE_STATEMENT
    )
    assert tally.detail["post_deactivation_successful_events"] == 3
    assert tally.detail["post_deactivation_denied_events"] == 1


def test_the_finding_records_the_coverage_it_rests_on(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """A finding that cites events must also cite how much it could have seen."""
    finding = _for_user(detect_ghost_access(dataset, settings), "u_carol")[0]

    statements = [
        e for e in finding.evidence if e.kind is EvidenceKind.COVERAGE_STATEMENT
    ]

    assert statements, "the finding does not state the completeness of its evidence"
    assert all(e.description for e in statements)


def test_ghost_activity_is_still_reported_when_coverage_is_only_partial(
    settings: Settings,
) -> None:
    """Presence of evidence is not the same question as absence of it.

    The coverage gate exists to stop a *hole* being read as a clean result. It
    must not stop a positive fact from being reported: an event after
    deactivation is something we saw, and a partial export cannot unsee it. The
    honest response is to report the ghost access and mark the evidence partial,
    which is what this pins.
    """
    ds = _dataset(
        events=[_event("2026-09-01T10:00:00Z")],
        coverage=Coverage.PARTIAL,
    )

    findings = detect_ghost_access(ds, settings)

    assert len(findings) == 1
    assert findings[0].evidence_completeness is EvidenceCompleteness.PARTIAL


def test_the_summary_states_the_finding_without_prescribing_removal(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """The wording rule, checked on the one summary Rule D actually produces.

    ``Finding`` refuses to validate a summary containing any of these phrases,
    so this asserts the same property from the outside -- which matters because
    a template change that tripped it would otherwise surface as a crash in
    production rather than as a failing test.
    """
    from app.schemas.domain.finding import FORBIDDEN_CONCLUSION_PHRASES

    finding = _for_user(detect_ghost_access(dataset, settings), "u_carol")[0]
    lowered = finding.summary.lower()

    for phrase in FORBIDDEN_CONCLUSION_PHRASES:
        assert phrase not in lowered, f"summary prescribes removal: {phrase!r}"

    assert "ghp_carol_legacy" in finding.summary, (
        "the summary must name the credential that survived deprovisioning"
    )


# --------------------------------------------------------------------------- #
# Determinism and purity
# --------------------------------------------------------------------------- #


def test_the_same_dataset_produces_byte_identical_findings(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """Blueprint rule 2, in the only form that can actually be checked.

    Identifiers and timestamps included: a finding whose id or created_at moved
    between runs could not be cited by an auditor, and "the same conclusion" is
    not the same thing as "the same record".
    """
    first = detect_ghost_access(dataset, settings)
    second = detect_ghost_access(dataset, settings)

    assert [f.model_dump() for f in first] == [f.model_dump() for f in second]


def test_findings_are_stamped_with_the_analysis_instant_not_the_wall_clock(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """The engine has no clock, and that is a security property.

    Stamping with ``utcnow()`` would make two analyses of identical facts
    disagree, and would silently anchor a dated fixture set to the day the tests
    happened to run.
    """
    for finding in detect_ghost_access(dataset, settings):
        assert finding.created_at == settings.effective_analysis_as_of()


def test_the_rule_does_not_mutate_the_dataset_it_is_given(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """Purity in the direction that is easy to lose by accident.

    A rule that reordered ``slice.events`` while iterating would produce
    findings that depend on evaluation order -- and the mutation would be
    invisible until some later rule read the same slice.
    """
    before = dataset.dataset_fingerprint()

    detect_ghost_access(dataset, settings)

    assert dataset.dataset_fingerprint() == before


def test_the_rule_can_only_see_the_dataset_and_the_settings() -> None:
    """No session, no client, no clock parameter -- enforced at the signature.

    The engine README states this contract. Checking it here means a later rule
    cannot quietly widen the interface to reach a database, which is how a
    deterministic engine stops being one.
    """
    parameters = list(inspect.signature(detect_ghost_access).parameters)

    assert parameters == ["dataset", "settings"]


def test_every_finding_and_evidence_identifier_is_unique(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """Two findings sharing an id would collide on the primary key they will get."""
    findings = detect_ghost_access(dataset, settings)

    finding_ids = [f.id for f in findings]
    assert len(finding_ids) == len(set(finding_ids))

    evidence_ids = [e.evidence_id for f in findings for e in f.evidence]
    assert evidence_ids, "a finding with no evidence is an assertion"
    assert len(evidence_ids) == len(set(evidence_ids))


def test_ghost_access_never_recommends_changing_access(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """The product promise, checked on the one rule that exists to break it.

    Ghost access is the finding with the strongest case for automatic
    remediation, so it is the one where an auto-revoke recommendation would
    appear first. ``Recommendation`` has no revoke-like member, and this asserts
    the rule stays inside that vocabulary.
    """
    findings = detect_ghost_access(dataset, settings)
    assert findings, "this test is vacuous unless the rule actually fired"

    for finding in findings:
        assert finding.recommendation is Recommendation.INVESTIGATE_GHOST_ACCESS
        assert finding.status is FindingStatus.INVESTIGATION_REQUIRED

    # And the vocabulary itself cannot express the action, so no future edit to
    # this rule can reach for one.
    prohibited = {"revoke", "remove", "disable", "delete", "prune", "terminate"}
    for member in Recommendation:
        words = set(member.value.lower().split("_"))
        assert not (words & prohibited), f"{member} expresses a change to access"
