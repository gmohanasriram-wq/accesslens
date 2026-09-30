"""Rule C -- duplicate identity.

Blueprint section 16's matrix carries a row no other rule can reach:

    Duplicate identity | Investigation required

Henry is the persona. He holds two Okta accounts that share one login and one
email -- ``00u_henry01`` (MFA enrolled, engineering + support-readonly) and
``00u_henry98-legacy`` (no MFA, engineering only). Both are ACTIVE. He is one
person with two principals, and nothing in the activity feed can say which of
them did anything: his events arrive as ``arn:aws:iam::123456789012:user/
henry.okafor`` and ``ghp_henry_primary``, neither of which is an Okta account
id. That is the finding. He is not accused of anything else -- his utilisation
is 3/4.

Three things make this rule unlike the other three, and each one is load-bearing.

**It is not a telemetry rule.** Rules A, B and D all reason about activity, and
all three are therefore gated by coverage: an unmeasurable window must not be
read as an idle one. Rule C makes a claim about the *directory*, which is a
different source with a different failure mode, so none of that apparatus
applies. ``dataset.window`` is never read, ``low_utilization_threshold`` is never
read, ``min_observed_events_for_confidence`` is never read, and a user with
MISSING coverage and zero events is reported exactly the same as one with
COMPLETE coverage and a thousand. Silencing a directory defect because an
unrelated CloudTrail export was truncated would hide the defect behind a gap
that has nothing to do with it.

**The decision belongs to the engine, not to ingestion.** ``Identity.
is_duplicate_of`` already exists and is already populated at ingest by
``normalizer._mark_duplicates``. Reading it would be one line, and it would put
the security decision in ``app/ingestion/``, where the engine cannot be tested
against it independently. So the rule recomputes the grouping from
``dataset.identities``, and ``is_duplicate_of`` stays ingestion-derived display
metadata. Two tests below exist purely to hold that line: the engine must still
fire when the ingestion flag is absent, and must stay silent when the flag is
present but the accounts are not actually duplicated. A further test pins the
two implementations in agreement across the whole fixture set, so drift between
them fails by name rather than silently.

**An account that belongs to nobody is not a duplicate.** ``00u_svcbackup`` is
in the IdP export and resolves to no HR user, so ingestion *rejects* it and it
never reaches ``dataset.identities`` at all. That is an ``IDENTITY_UNMAPPED``
fact, not this rule's. The tests below assert the boundary rather than pretending
the rule declines a record it is never shown.

Completeness is scoped to the person, not the source. There is one IdP rejection
in the fixture set -- ``svc.backup`` -- and it concerns an account that is not
Henry's, so Henry's identity evidence is COMPLETE. A global "any IdP rejection
means partial" reading would contradict his oracle entry, which was written
before the engine existed.

The finding is INVESTIGATION_REQUIRED / MEDIUM / MANUAL_REVIEW, and it does not
prescribe. "The legacy account should be removed" is exactly the conclusion the
evidence does not support: the engine can prove the ambiguity, and it cannot
prove which account is the mistake -- the legacy one may be the one in use.
"""

from __future__ import annotations

import ast
import inspect
import pathlib
from datetime import datetime

import pytest
from pydantic import TypeAdapter, ValidationError

from app.core.config import Settings
from app.core.enums import (
    ActivitySource,
    Coverage,
    EmploymentStatus,
    EntitlementSource,
    EvidenceCompleteness,
    EvidenceKind,
    FindingStatus,
    FindingType,
    IdentityProvider,
    IdentityStatus,
    Recommendation,
    RiskLevel,
    Severity,
)
from app.core.errors import IngestRejection
from app.ingestion import InMemoryDataset
from app.schemas.domain.activity import ActivityEvent, ActivitySlice
from app.schemas.domain.entitlement import Entitlement
from app.schemas.domain.finding import Finding
from app.schemas.domain.identity import Identity
from app.schemas.domain.user import User

from app.engine.duplicate_identity import (
    RULE_ID,
    detect_duplicate_identities,
    evaluate_user,
)

AWARE = TypeAdapter(datetime)

WINDOW_START = "2026-07-01T06:00:00Z"
WINDOW_END = "2026-09-29T06:00:00Z"

#: The oracle's own account pair, so the synthetic cases below are built from the
#: same shape the specification was written against.
HENRY_ACCOUNTS = ("00u_henry01", "00u_henry98-legacy")


def _at(text: str) -> datetime:
    return AWARE.validate_python(text)


# --------------------------------------------------------------------------- #
# Hand-built cases
#
# The fixture set has exactly one persona per scenario, so it cannot contain the
# boundaries this rule turns on: a pair split across providers, three accounts in
# one provider, an ingestion flag that disagrees with the directory. Those are a
# dozen lines each here, which the engine's purity is what makes cheap.
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


def _identity(
    account_id: str,
    *,
    user_id: str = "u_test",
    provider: IdentityProvider = IdentityProvider.OKTA,
    login: str = "test.user",
    email: str | None = "test.user@example.com",
    status: IdentityStatus = IdentityStatus.ACTIVE,
    mfa_enrolled: bool = True,
    groups: tuple[str, ...] = (),
    is_duplicate_of: str | None = None,
) -> Identity:
    return Identity(
        user_id=user_id,
        provider=provider,
        account_id=account_id,
        login=login,
        email=email,
        status=status,
        groups=list(groups),
        mfa_enrolled=mfa_enrolled,
        is_duplicate_of=is_duplicate_of,
    )


def _event(action: str = "s3:GetObject", actor_id: str = "u_test") -> ActivityEvent:
    return ActivityEvent(
        event_id=f"evt-{action}",
        timestamp=_at("2026-08-01T12:00:00Z"),
        actor_id=actor_id,
        source=ActivitySource.AWS_CLOUDTRAIL,
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


def _grant(role: str = "AdministratorAccess", permissions: list[str] | None = None) -> Entitlement:
    return Entitlement(
        user_id="u_test",
        source=EntitlementSource.AWS,
        role=role,
        permissions=permissions if permissions is not None else ["iam:*", "s3:*"],
        risk_level=RiskLevel.HIGH,
    )


def _dataset(
    users: list[User],
    identities: list[Identity],
    *,
    entitlements: list[Entitlement] | None = None,
    slices: dict[str, ActivitySlice] | None = None,
    rejections: tuple[IngestRejection, ...] = (),
    window: tuple[datetime, datetime] | None = None,
    generated_at: datetime | None = _at(WINDOW_END),
) -> InMemoryDataset:
    return InMemoryDataset(
        users=tuple(users),
        identities=tuple(identities),
        entitlements=tuple(entitlements or ()),
        slices=slices if slices is not None else {},
        window=window if window is not None else (_at(WINDOW_START), _at(WINDOW_END)),
        coverage_manifest=(),
        rejections=rejections,
        unattributable_actors=(),
        generated_at=generated_at,
    )


def _one_person(
    identities: list[Identity],
    *,
    coverage: Coverage = Coverage.COMPLETE,
    events: list[ActivityEvent] | None = None,
    slice_: bool = True,
    **dataset_kwargs,
) -> InMemoryDataset:
    """One user, the given directory accounts, and activity they are not asked about."""
    user = _user()
    slices = {user.id: _slice(events=events, coverage=coverage)} if slice_ else {}
    return _dataset([user], identities, slices=slices, **dataset_kwargs)


def _duplicated_pair(**kwargs) -> InMemoryDataset:
    """The minimal shape that must fire, with one property varied per test."""
    return _one_person([_identity(HENRY_ACCOUNTS[0]), _identity(HENRY_ACCOUNTS[1])], **kwargs)


def _settings(**overrides) -> Settings:
    return Settings(analysis_as_of=WINDOW_END, _env_file=None, **overrides)


def _persona(oracle: dict, user_id: str) -> dict:
    return next(p for p in oracle["personas"] if p["user_id"] == user_id)


def _by_username(dataset: InMemoryDataset, username: str) -> User:
    return next(u for u in dataset.users if u.username == username)


#: Every persona in the fixture set except Henry, who is the one that must fire.
OTHERS = [
    "u_alice",
    "u_bob",
    "u_carol",
    "u_dave",
    "u_erin",
    "u_frank",
    "u_gina",
    "u_ivan",
]


# --------------------------------------------------------------------------- #
# (a) The oracle case -- Henry
# --------------------------------------------------------------------------- #


def test_henry_is_the_only_persona_the_rule_reports(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """One finding, for one person, in a fixture set of nine."""
    findings = detect_duplicate_identities(dataset, settings)

    assert [f.user_id for f in findings] == ["u_henry"]


def test_henrys_finding_matches_the_oracle_field_for_field(
    dataset: InMemoryDataset, settings: Settings, oracle: dict
) -> None:
    """The oracle's row is the specification; this is the assertion."""
    user = _by_username(dataset, "henry.okafor")
    expected = _persona(oracle, "u_henry")["finding"]

    findings = detect_duplicate_identities(dataset, settings)
    finding = next(f for f in findings if f.user_id == user.id)

    assert finding.type is FindingType.DUPLICATE_IDENTITY
    assert finding.type.value == expected["type"]
    assert finding.status is FindingStatus.INVESTIGATION_REQUIRED
    assert finding.status.value == expected["status"]
    assert finding.severity is Severity.MEDIUM
    assert finding.severity.value == expected["severity"]
    assert finding.recommendation is Recommendation.MANUAL_REVIEW
    assert finding.recommendation.value == expected["recommendation"]
    assert finding.evidence_completeness is EvidenceCompleteness.COMPLETE
    assert finding.evidence_completeness.value == expected["evidence_completeness"]


def test_henrys_finding_cites_this_rule_and_nothing_else(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    finding = detect_duplicate_identities(dataset, settings)[0]

    assert finding.rules_triggered == [RULE_ID]
    assert RULE_ID == "RULE_C_DUPLICATE_IDENTITY"


def test_the_finding_id_names_the_user_and_the_provider(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """D1: one finding per (user, provider), so the id has to carry the provider.

    Without the provider suffix a person duplicated in Okta *and* GitHub would
    produce two findings sharing one id, and the second would be indistinguishable
    from the first in a dossier keyed by ``Finding.id``.
    """
    finding = detect_duplicate_identities(dataset, settings)[0]

    assert finding.id == "fnd-u_henry-rule-c-okta"


def test_the_risk_level_is_unknown_and_the_usage_verdict_is_absent(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """D4 and D5.

    ``risk_level`` describes how much damage the *granted* access could do, which
    is Rule A and Rule B's subject and not this rule's -- Rule D leaves it UNKNOWN
    for the same reason. ``usage`` would be a telemetry verdict, and this rule
    reaches no telemetry conclusion at all.
    """
    finding = detect_duplicate_identities(dataset, settings)[0]

    assert finding.risk_level is RiskLevel.UNKNOWN
    assert finding.usage is None


def test_both_of_henrys_accounts_appear_in_the_evidence(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    finding = detect_duplicate_identities(dataset, settings)[0]

    described = " ".join(
        [e.description for e in finding.evidence]
        + [str(e.detail.get("account_id", "")) for e in finding.evidence]
    )
    for account_id in HENRY_ACCOUNTS:
        assert account_id in described, f"{account_id} is missing from the evidence"


def test_the_evidence_links_each_account_to_the_one_treated_as_canonical(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """The ambiguity is the finding, so the link between the two is the evidence.

    ``_mark_duplicates`` picks the lexicographically smallest account id as
    canonical; the engine recomputes the same rule rather than trusting the flag.
    """
    finding = detect_duplicate_identities(dataset, settings)[0]
    links = [e for e in finding.evidence if e.kind is EvidenceKind.IDENTITY_LINK]

    assert len(links) == len(HENRY_ACCOUNTS)

    by_account = {e.detail["account_id"]: e for e in links}
    assert set(by_account) == set(HENRY_ACCOUNTS)
    assert by_account["00u_henry01"].detail.get("is_duplicate_of") is None
    assert by_account["00u_henry98-legacy"].detail.get("is_duplicate_of") == "00u_henry01"


def test_the_evidence_is_all_identity_links(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """``IDENTITY_LINK`` is defined and used by nothing else; this is its first caller."""
    finding = detect_duplicate_identities(dataset, settings)[0]

    assert finding.evidence
    assert {e.kind for e in finding.evidence} == {EvidenceKind.IDENTITY_LINK}


def test_no_activity_event_is_cited_as_evidence(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """Henry has six observed events. None of them belongs in this finding.

    The finding is that the directory cannot say which principal did anything --
    citing an event would assert the attribution the finding says is impossible.
    """
    finding = detect_duplicate_identities(dataset, settings)[0]

    assert not [e for e in finding.evidence if e.kind is EvidenceKind.ACTIVITY_EVENT]


def test_the_finding_does_not_assign_activity_to_either_account(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """The claim under test is non-attribution, and the summary has to make it."""
    finding = detect_duplicate_identities(dataset, settings)[0]
    lowered = finding.summary.lower()

    assert "attribut" in lowered, f"summary does not raise attribution: {finding.summary!r}"
    assert "performed" not in lowered
    assert "executed" not in lowered
    for action in ("s3:", "ec2:", "repo.clone", "iam:"):
        assert action not in lowered, f"summary names an action ({action!r})"


# --------------------------------------------------------------------------- #
# (b) Structure -- what counts as a duplicate
# --------------------------------------------------------------------------- #


def test_two_accounts_in_one_provider_produce_one_finding(settings: Settings) -> None:
    findings = detect_duplicate_identities(_duplicated_pair(), settings)

    assert len(findings) == 1
    assert findings[0].id == "fnd-u_test-rule-c-okta"


def test_one_account_produces_nothing(settings: Settings) -> None:
    """The control case. Every other persona in the fixture set is this shape."""
    assert detect_duplicate_identities(_one_person([_identity("00u_a")]), settings) == []


def test_a_user_with_no_directory_accounts_is_not_reported(settings: Settings) -> None:
    dataset = _one_person([], slice_=False)

    assert detect_duplicate_identities(dataset, settings) == []


def test_two_accounts_in_different_providers_are_not_a_duplicate(settings: Settings) -> None:
    """A person with an Okta account and a Google account is a person with a job.

    Two accounts in *one* directory means one of them is probably a mistake; the
    same login in two directories is how federated identity is supposed to work.
    The grouping key is (provider, user_id), which is what ingestion already
    assumes -- and what the agreement test below pins.
    """
    dataset = _one_person(
        [
            _identity("00u_a", provider=IdentityProvider.OKTA),
            _identity("gw_a", provider=IdentityProvider.GOOGLE_WORKSPACE),
        ]
    )

    assert detect_duplicate_identities(dataset, settings) == []


def test_a_duplicate_in_each_of_two_providers_produces_two_findings(
    settings: Settings,
) -> None:
    """D1's consequence: two directories, two separate hygiene facts."""
    dataset = _one_person(
        [
            _identity("00u_a", provider=IdentityProvider.OKTA),
            _identity("00u_b", provider=IdentityProvider.OKTA),
            _identity("gw_a", provider=IdentityProvider.GOOGLE_WORKSPACE),
            _identity("gw_b", provider=IdentityProvider.GOOGLE_WORKSPACE),
        ]
    )

    findings = detect_duplicate_identities(dataset, settings)

    assert [f.id for f in findings] == [
        "fnd-u_test-rule-c-google_workspace",
        "fnd-u_test-rule-c-okta",
    ]


def test_three_accounts_in_one_provider_are_one_finding_not_two(settings: Settings) -> None:
    """One finding per duplicated group, not per pair.

    Three accounts is 3 pairs and 1 hygiene problem. Reporting pairs would grow
    quadratically and would give the reviewer the same fact three times.
    """
    dataset = _one_person([_identity("00u_a"), _identity("00u_b"), _identity("00u_c")])

    findings = detect_duplicate_identities(dataset, settings)

    assert len(findings) == 1
    linked = {
        e.detail["account_id"]
        for e in findings[0].evidence
        if e.kind is EvidenceKind.IDENTITY_LINK
    }
    assert linked == {"00u_a", "00u_b", "00u_c"}


def test_only_the_duplicated_person_is_reported(settings: Settings) -> None:
    """The rule is per person; a clean neighbour must not be swept up."""
    clean = _user("u_clean", "clean.user")
    duplicated = _user("u_dup", "dup.user")
    dataset = _dataset(
        [clean, duplicated],
        [
            _identity("00u_clean01", user_id=clean.id, login=clean.username),
            _identity("00u_dup01", user_id=duplicated.id, login=duplicated.username),
            _identity("00u_dup02", user_id=duplicated.id, login=duplicated.username),
        ],
    )

    findings = detect_duplicate_identities(dataset, settings)

    assert [f.user_id for f in findings] == [duplicated.id]


def test_findings_are_ordered_by_user_then_provider(settings: Settings) -> None:
    """Stable order, or two identical runs produce differently ordered dossiers."""
    beta = _user("u_beta", "beta.user")
    alpha = _user("u_alpha", "alpha.user")
    dataset = _dataset(
        [beta, alpha],
        [
            _identity("00u_b1", user_id=beta.id),
            _identity("00u_b2", user_id=beta.id),
            _identity("gw_a1", user_id=alpha.id, provider=IdentityProvider.GOOGLE_WORKSPACE),
            _identity("gw_a2", user_id=alpha.id, provider=IdentityProvider.GOOGLE_WORKSPACE),
            _identity("00u_a1", user_id=alpha.id),
            _identity("00u_a2", user_id=alpha.id),
        ],
    )

    findings = detect_duplicate_identities(dataset, settings)

    assert [f.id for f in findings] == [
        "fnd-u_alpha-rule-c-google_workspace",
        "fnd-u_alpha-rule-c-okta",
        "fnd-u_beta-rule-c-okta",
    ]


def test_the_sweep_agrees_with_the_per_user_entry_point(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """``detect_duplicate_identities`` is a loop over the same computation as
    ``evaluate_user``, not a second implementation of it.

    The two are compared with the dataset-level facts removed, and the reason is
    structural rather than a convenience. ``evaluate_user`` is given one person's
    accounts and nothing else, so it cannot see ``dataset.generated_at`` (D2's
    evidence anchor) or the ingest rejections (D6's completeness scope) -- both
    are properties of the export, not of the person, and neither is reachable
    from its three arguments. Supplying exactly those two facts is the sweep's
    entire extra job. Everything else -- ids, type, status, severity,
    recommendation, summary, risk_level, usage, rules_triggered, created_at, and
    every evidence row's id, kind, description, detail and order -- must be
    identical, and that is what this asserts.
    """

    def without_dataset_level_facts(finding: Finding) -> Finding:
        return finding.model_copy(
            update={
                "evidence": [
                    e.model_copy(update={"timestamp": None}) for e in finding.evidence
                ],
                "evidence_completeness": EvidenceCompleteness.COMPLETE,
            }
        )

    swept = {f.id: f for f in detect_duplicate_identities(dataset, settings)}

    per_user = {}
    for user in dataset.users:
        for finding in evaluate_user(user, dataset.identities_for(user.id), settings):
            per_user[finding.id] = finding

    assert swept.keys() == per_user.keys()
    assert {k: without_dataset_level_facts(f) for k, f in swept.items()} == {
        k: without_dataset_level_facts(f) for k, f in per_user.items()
    }


def test_the_per_user_entry_point_reports_unanchored_partial_evidence(
    settings: Settings,
) -> None:
    """The other half of the split above, stated rather than left implicit.

    A per-user caller gets no export anchor, so it must say so instead of
    inventing one -- the alternative is a timestamp a reader cannot reproduce.
    ``detect_duplicate_identities`` is what supplies ``dataset.generated_at`` and
    the rejections; without them, unanchored and PARTIAL is the honest answer.
    """
    dataset = _duplicated_pair()
    user = dataset.users[0]

    finding = evaluate_user(user, dataset.identities_for(user.id), settings)[0]

    assert finding.evidence
    assert {e.timestamp for e in finding.evidence} == {None}
    assert finding.evidence_completeness is EvidenceCompleteness.PARTIAL

    # ...and the same person through the sweep is anchored and complete, so the
    # PARTIAL above is a fact about the entry point and not about the data.
    swept = detect_duplicate_identities(dataset, settings)[0]
    assert {e.timestamp for e in swept.evidence} == {dataset.generated_at}
    assert swept.evidence_completeness is EvidenceCompleteness.COMPLETE


# --------------------------------------------------------------------------- #
# (c) Not a telemetry rule -- nothing about activity may gate it
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "coverage",
    [Coverage.COMPLETE, Coverage.PARTIAL, Coverage.MISSING, Coverage.NOT_QUERIED],
)
def test_activity_coverage_does_not_gate_the_rule(
    coverage: Coverage, settings: Settings
) -> None:
    """Rules A, B and D are coverage-gated because they reason about activity.

    This one reasons about the directory. A truncated CloudTrail export says
    nothing about whether a person holds two Okta accounts, and silencing the
    finding would hide a directory defect behind an unrelated telemetry gap.
    """
    findings = detect_duplicate_identities(_duplicated_pair(coverage=coverage), settings)

    assert len(findings) == 1
    assert findings[0].evidence_completeness is EvidenceCompleteness.COMPLETE


def test_zero_observed_events_does_not_gate_the_rule(settings: Settings) -> None:
    findings = detect_duplicate_identities(_duplicated_pair(events=[]), settings)

    assert len(findings) == 1


def test_heavy_observed_activity_does_not_gate_the_rule(settings: Settings) -> None:
    """The other direction: no amount of legitimate use resolves an ambiguity."""
    events = [_event(f"s3:GetObject-{i}") for i in range(50)]
    findings = detect_duplicate_identities(_duplicated_pair(events=events), settings)

    assert len(findings) == 1


@pytest.mark.parametrize("threshold", [0.0, 0.01, 0.25, 0.99, 1.0])
def test_the_utilisation_threshold_does_not_gate_the_rule(
    threshold: float, settings: Settings
) -> None:
    """Decision 4, tested directly: mutate the threshold, not a comment."""
    tuned = _settings(low_utilization_threshold=threshold)

    findings = detect_duplicate_identities(_duplicated_pair(), tuned)

    assert len(findings) == 1


@pytest.mark.parametrize("floor", [0, 1, 3, 1000])
def test_the_confidence_floor_does_not_gate_the_rule(
    floor: int, settings: Settings
) -> None:
    tuned = _settings(min_observed_events_for_confidence=floor)

    assert len(detect_duplicate_identities(_duplicated_pair(), tuned)) == 1


@pytest.mark.parametrize("lookback", [1, 30, 90, 3650])
def test_the_lookback_window_does_not_gate_the_rule(
    lookback: int, settings: Settings
) -> None:
    tuned = _settings(lookback_days=lookback)

    assert len(detect_duplicate_identities(_duplicated_pair(), tuned)) == 1


def test_the_analysis_window_is_never_read(settings: Settings) -> None:
    """Two datasets differing only in window reach the same conclusion.

    An account pair is a fact about a directory, not about a period.
    """
    narrow = _duplicated_pair(window=(_at("2026-09-28T00:00:00Z"), _at(WINDOW_END)))
    wide = _duplicated_pair(window=(_at("2020-01-01T00:00:00Z"), _at(WINDOW_END)))

    narrow_finding = detect_duplicate_identities(narrow, settings)[0]
    wide_finding = detect_duplicate_identities(wide, settings)[0]

    assert narrow_finding.id == wide_finding.id
    assert narrow_finding.summary == wide_finding.summary
    assert narrow_finding.evidence == wide_finding.evidence


def test_the_rule_fires_for_a_user_with_no_activity_slice_at_all(
    settings: Settings,
) -> None:
    """A person with no slice is not a person with no accounts."""
    dataset = _one_person(
        [_identity("00u_a"), _identity("00u_b")], slice_=False, coverage=Coverage.NOT_QUERIED
    )

    assert len(detect_duplicate_identities(dataset, settings)) == 1


# --------------------------------------------------------------------------- #
# (d) Conservation and independence
# --------------------------------------------------------------------------- #


def test_exactly_one_rule_c_finding_exists_in_the_fixture_set(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    assert len(detect_duplicate_identities(dataset, settings)) == 1


@pytest.mark.parametrize("user_id", OTHERS)
def test_no_other_persona_carries_a_duplicate_identity_finding(
    user_id: str, dataset: InMemoryDataset, settings: Settings
) -> None:
    findings = detect_duplicate_identities(dataset, settings)

    assert [f for f in findings if f.user_id == user_id] == []


def test_the_rule_does_not_suppress_another_rules_finding_for_the_same_person(
    settings: Settings,
) -> None:
    """Findings are independent. A duplicated person may also be a ghost, or
    under-utilised, and neither fact cancels the other.

    The grant is load-bearing, not decoration. Rule A's first check is "no granted
    capabilities -> nothing to say": a gap in the evidence for somebody who holds
    nothing is not a gap in anything, so a user with no entitlements gets no
    insufficient-evidence finding and the case would prove nothing. Giving them a
    real grant is what makes the overlap testable at all.
    """
    from app.engine.utilization import detect_low_utilization

    user = _user()
    dataset = _dataset(
        [user],
        [_identity("00u_a"), _identity("00u_b")],
        entitlements=[_grant()],
        slices={user.id: _slice(coverage=Coverage.MISSING)},
    )

    duplicate = detect_duplicate_identities(dataset, settings)
    unmeasurable = detect_low_utilization(dataset, settings)

    assert len(duplicate) == 1
    assert len(unmeasurable) == 1
    assert duplicate[0].type is FindingType.DUPLICATE_IDENTITY
    assert unmeasurable[0].type is FindingType.INSUFFICIENT_EVIDENCE
    assert duplicate[0].id != unmeasurable[0].id


# --------------------------------------------------------------------------- #
# (e) The boundary -- an account that belongs to nobody is not a duplicate
# --------------------------------------------------------------------------- #


def test_the_unmapped_account_is_rejected_rather_than_duplicated(
    dataset: InMemoryDataset,
) -> None:
    """``svc.backup`` is in the IdP export and resolves to no HR user.

    Ingestion rejects it, which is a statement about identity *mapping*, not about
    duplication. The assertion belongs here because it is the boundary this rule
    must not absorb.
    """
    idp_rejections = [r for r in dataset.rejections if r.file == "idp_state.json"]

    assert idp_rejections, "the fixture is expected to contain an unmapped IdP account"
    assert any("svc.backup" in str(r.actor_hint or r.raw_value) for r in idp_rejections)


def test_the_unmapped_account_never_reaches_the_engine(dataset: InMemoryDataset) -> None:
    """Structural, not behavioural: an unresolvable account is dropped at ingest,
    so Rule C is never shown it. A test claiming the rule 'declines' it would be
    testing nothing."""
    assert not [i for i in dataset.identities if i.account_id == "00u_svcbackup"]
    assert not [i for i in dataset.identities if i.login == "svc.backup"]


def test_no_finding_names_the_unmapped_account(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    findings = detect_duplicate_identities(dataset, settings)
    rendered = " ".join(f.summary + " " + " ".join(e.description for e in f.evidence) for f in findings)

    assert "svc.backup" not in rendered
    assert "00u_svcbackup" not in rendered


# --------------------------------------------------------------------------- #
# (f) The engine decides, not ingestion
#
# These three are the reason the rule recomputes the grouping instead of reading
# ``Identity.is_duplicate_of``. Without them, moving the decision into the
# normalizer would be invisible.
# --------------------------------------------------------------------------- #


def test_the_engine_fires_even_when_the_ingestion_flag_is_absent(
    settings: Settings,
) -> None:
    """Two real accounts, no ingest-time metadata -- the directory is enough."""
    dataset = _one_person(
        [
            _identity("00u_a", is_duplicate_of=None),
            _identity("00u_b", is_duplicate_of=None),
        ]
    )

    assert len(detect_duplicate_identities(dataset, settings)) == 1


def test_the_engine_stays_silent_when_the_flag_disagrees_with_the_directory(
    settings: Settings,
) -> None:
    """A stale or wrong flag must not create a finding out of one account.

    If the rule trusted ``is_duplicate_of``, this dataset would report a duplicate
    that does not exist -- and the reviewer would have no way to tell.
    """
    dataset = _one_person([_identity("00u_a", is_duplicate_of="00u_ghost")])

    assert detect_duplicate_identities(dataset, settings) == []


def test_the_engine_and_ingestion_agree_across_the_whole_fixture_set(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """The drift pin.

    Two implementations of the same judgement exist by design -- one in the
    normalizer, one in the engine -- so the only thing keeping them honest is a
    test that compares them on every person in the set.
    """
    disagreements: list[str] = []

    reported = {f.user_id for f in detect_duplicate_identities(dataset, settings)}

    for user in dataset.users:
        identities = dataset.identities_for(user.id)
        flagged = any(i.is_duplicate_of for i in identities)
        if flagged != (user.id in reported):
            disagreements.append(
                f"{user.username}: ingestion flagged={flagged}, engine reported="
                f"{user.id in reported} ({sorted(i.account_id for i in identities)})"
            )

    assert not disagreements, "engine and ingestion disagree:\n  " + "\n  ".join(disagreements)


def test_henrys_ingestion_metadata_and_the_engines_grouping_agree(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """The same pin, stated for the one persona it is actually exercised on."""
    identities = dataset.identities_for("u_henry")
    flagged = next(i for i in identities if i.is_duplicate_of)

    finding = detect_duplicate_identities(dataset, settings)[0]
    linked = {
        e.detail["account_id"]: e.detail.get("is_duplicate_of")
        for e in finding.evidence
        if e.kind is EvidenceKind.IDENTITY_LINK
    }

    assert linked[flagged.account_id] == flagged.is_duplicate_of


# --------------------------------------------------------------------------- #
# (g) Completeness and the evidence timestamp (D2, D3, D6)
# --------------------------------------------------------------------------- #


def test_the_fixture_dataset_carries_a_generated_at(dataset: InMemoryDataset) -> None:
    """D2's precondition. Without it every finding would be PARTIAL, and the
    completeness tests below would be failing for a reason of their own."""
    assert dataset.generated_at is not None


def test_identity_evidence_for_henry_is_complete(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    finding = detect_duplicate_identities(dataset, settings)[0]

    assert finding.evidence_completeness is EvidenceCompleteness.COMPLETE


def test_an_unrelated_idp_rejection_does_not_downgrade_the_completeness(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """D3, scoped per user.

    The fixture contains exactly one IdP rejection and it concerns ``svc.backup``,
    an account that is not Henry's. A global reading -- 'any IdP rejection means
    the identity source is partial' -- would mark every person in the company
    PARTIAL for a defect in one unrelated account, and would contradict Henry's
    oracle entry, which was written before this rule existed.
    """
    assert [r for r in dataset.rejections if r.file == "idp_state.json"]

    finding = next(
        f
        for f in detect_duplicate_identities(dataset, settings)
        if f.user_id == "u_henry"
    )

    assert finding.evidence_completeness is EvidenceCompleteness.COMPLETE


def test_an_idp_rejection_about_this_person_alone_downgrades_the_completeness(
    settings: Settings,
) -> None:
    """ENGINE-AUTHORED POLICY -- NOT AN ORACLE REQUIREMENT (D6).

    No fixture produces this case, and the oracle does not specify it. The reading
    implemented here is the narrowest one that keeps D3 honest: a directory record
    that could not be placed, and whose actor hint names one of this person's own
    logins, means this person's directory evidence is incomplete -- a second
    account could have been in the record we could not read. A rejection naming
    somebody else is somebody else's problem and must not reach this person.
    """
    user = _user("u_test", "test.user")
    rejection = IngestRejection(
        file="idp_state.json",
        raw_index=0,
        reason="identity could not be resolved to a known user",
        record_id="00u_could_not_read",
        field_path="login",
        raw_value="test.user",
        actor_hint="test.user",
    )
    dataset = _dataset(
        [user],
        [_identity("00u_a", login="test.user"), _identity("00u_b", login="test.user")],
        rejections=(rejection,),
    )

    finding = detect_duplicate_identities(dataset, settings)[0]

    assert finding.evidence_completeness is EvidenceCompleteness.PARTIAL


def test_a_rejection_naming_somebody_else_leaves_this_person_complete(
    settings: Settings,
) -> None:
    """The other half of D6's policy, stated so the scoping cannot silently widen."""
    user = _user("u_test", "test.user")
    rejection = IngestRejection(
        file="idp_state.json",
        raw_index=0,
        reason="identity could not be resolved to a known user",
        record_id="00u_svcbackup",
        field_path="login",
        raw_value="svc.backup",
        actor_hint="svc.backup",
    )
    dataset = _dataset(
        [user],
        [_identity("00u_a", login="test.user"), _identity("00u_b", login="test.user")],
        rejections=(rejection,),
    )

    finding = detect_duplicate_identities(dataset, settings)[0]

    assert finding.evidence_completeness is EvidenceCompleteness.COMPLETE


def test_an_activity_rejection_is_not_an_identity_rejection(
    settings: Settings,
) -> None:
    """A rejected CloudTrail record says nothing about the directory."""
    user = _user("u_test", "test.user")
    rejection = IngestRejection(
        file="activity_logs.json",
        raw_index=3,
        reason="truncated eventTime",
        record_id="evt-aws-0028",
        field_path="eventTime",
        actor_hint="test.user",
    )
    dataset = _dataset(
        [user],
        [_identity("00u_a", login="test.user"), _identity("00u_b", login="test.user")],
        rejections=(rejection,),
    )

    finding = detect_duplicate_identities(dataset, settings)[0]

    assert finding.evidence_completeness is EvidenceCompleteness.COMPLETE


def test_activity_coverage_gaps_do_not_downgrade_identity_completeness(
    settings: Settings,
) -> None:
    for coverage in (Coverage.PARTIAL, Coverage.MISSING, Coverage.NOT_QUERIED):
        finding = detect_duplicate_identities(_duplicated_pair(coverage=coverage), settings)[0]
        assert finding.evidence_completeness is EvidenceCompleteness.COMPLETE, coverage


def test_the_evidence_timestamp_comes_from_the_dataset_not_the_clock(
    settings: Settings,
) -> None:
    """D2: ``Identity`` has no created/updated field, so the only honest anchor is
    the export's own ``generated_at`` -- never 'now', and never the analysis
    instant, which is a period boundary rather than an observation."""
    exported_at = _at("2026-05-01T00:00:00Z")
    dataset = _duplicated_pair(generated_at=exported_at)

    finding = detect_duplicate_identities(dataset, settings)[0]

    assert finding.evidence
    assert {e.timestamp for e in finding.evidence} == {exported_at}


def test_a_dataset_without_a_generated_at_reports_partial(settings: Settings) -> None:
    """D2's fallback. An evidence row with no timestamp is an under-evidenced
    finding, and saying so is the only honest option -- the alternative is
    stamping it with the wall clock, which no reader could reproduce."""
    dataset = _duplicated_pair(generated_at=None)

    finding = detect_duplicate_identities(dataset, settings)[0]

    assert finding.evidence_completeness is EvidenceCompleteness.PARTIAL
    assert {e.timestamp for e in finding.evidence} == {None}


# --------------------------------------------------------------------------- #
# (h) Diction -- the finding may not prescribe
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "phrase",
    [
        "unnecessary",
        "no longer needed",
        "not needed",
        "safe to remove",
        "safe to delete",
        "should be revoked",
        "must be revoked",
        "automatically revoke",
    ],
)
def test_the_finding_contract_still_rejects_unsupported_conclusions(
    phrase: str, dataset: InMemoryDataset, settings: Settings
) -> None:
    """The existing guard, checked against this finding's shape rather than assumed."""
    finding = detect_duplicate_identities(dataset, settings)[0]
    payload = finding.model_dump()
    payload["summary"] = f"{finding.summary} ({phrase})"

    with pytest.raises(ValidationError):
        Finding(**payload)


#: A duplicate-identity summary has no reason to use any of these, and the
#: tempting phrasing -- "the legacy account should be removed" -- is precisely the
#: conclusion the evidence cannot support. The engine can prove the ambiguity; it
#: cannot prove which of the two accounts is the mistake.
_REMEDIATION_WORDS = (
    "remove",
    "delete",
    "decommission",
    "clean up",
    "unnecessary",
    "no longer needed",
    "not needed",
    "safe to",
    "revoke",
    "prune",
    "should be",
    "must be",
)


def test_the_summary_uses_no_remediation_language(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    finding = detect_duplicate_identities(dataset, settings)[0]
    lowered = finding.summary.lower()

    for word in _REMEDIATION_WORDS:
        assert word not in lowered, f"Rule C said {word!r}: {finding.summary!r}"


def test_the_summary_names_the_person_and_the_duplicated_provider(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    finding = detect_duplicate_identities(dataset, settings)[0]

    assert "henry.okafor" in finding.summary
    assert "okta" in finding.summary.lower()


def test_the_summary_does_not_single_out_one_of_the_accounts(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """Either account could be the intended one, so the summary must present the
    pair or neither.

    Naming only ``00u_henry98-legacy`` -- the account whose id happens to read as
    "legacy" -- would put a thumb on the scale the evidence does not support, and
    a reviewer skimming the summary would carry that bias into the decision.
    """
    finding = detect_duplicate_identities(dataset, settings)[0]
    named = [a for a in HENRY_ACCOUNTS if a in finding.summary]

    assert len(named) in (0, len(HENRY_ACCOUNTS)), (
        f"summary names only {named}: {finding.summary!r}"
    )


# --------------------------------------------------------------------------- #
# (i) Purity and determinism
# --------------------------------------------------------------------------- #


def test_two_runs_produce_identical_findings(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    assert detect_duplicate_identities(dataset, settings) == detect_duplicate_identities(
        dataset, settings
    )


def test_finding_and_evidence_ids_are_unique(settings: Settings) -> None:
    dataset = _dataset(
        [
            _user("u_alpha", "alpha.user"),
            _user("u_beta", "beta.user"),
        ],
        [
            _identity("00u_a1", user_id="u_alpha"),
            _identity("00u_a2", user_id="u_alpha"),
            _identity("00u_b1", user_id="u_beta"),
            _identity("00u_b2", user_id="u_beta"),
        ],
    )

    findings = detect_duplicate_identities(dataset, settings)

    ids = [f.id for f in findings]
    assert len(ids) == len(set(ids))

    evidence_ids = [e.evidence_id for f in findings for e in f.evidence]
    assert len(evidence_ids) == len(set(evidence_ids))


def test_the_dataset_is_not_mutated(dataset: InMemoryDataset, settings: Settings) -> None:
    """The fingerprint covers the normalized users/identities/activity but not
    ``generated_at`` or ``rejections`` -- both of which this rule reads -- so both
    are captured explicitly."""
    before = (
        dataset.dataset_fingerprint(),
        dataset.generated_at,
        dataset.rejections,
        dataset.identities,
    )

    detect_duplicate_identities(dataset, settings)

    assert (
        dataset.dataset_fingerprint(),
        dataset.generated_at,
        dataset.rejections,
        dataset.identities,
    ) == before


def test_the_entry_points_take_the_documented_arguments() -> None:
    """The shared contract every rule in this package keeps."""
    assert list(inspect.signature(detect_duplicate_identities).parameters) == [
        "dataset",
        "settings",
    ]
    assert list(inspect.signature(evaluate_user).parameters) == [
        "user",
        "identities",
        "settings",
    ]


def _module_ast() -> ast.Module:
    import app.engine.duplicate_identity as module

    return ast.parse(pathlib.Path(module.__file__).read_text(encoding="utf-8"))


def test_the_rule_reads_no_clock_and_no_io() -> None:
    """Purity, enforced structurally rather than promised in a docstring."""
    forbidden = {"utcnow", "now", "today", "time", "random", "open", "input"}

    called = {
        node.func.id
        for node in ast.walk(_module_ast())
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }

    assert not (called & forbidden), f"impure call(s): {sorted(called & forbidden)}"


def test_the_rule_imports_nothing_outside_the_engine_and_its_contracts() -> None:
    """A DB session, an HTTP client or a model client must be impossible to add
    without this test failing."""
    allowed_roots = {
        "__future__",
        "dataclasses",
        "datetime",
        "typing",
        "collections",
        "itertools",
        "app.core",
        "app.ingestion",
        "app.schemas",
        "app.engine",
    }

    def allowed(module: str) -> bool:
        return any(module == root or module.startswith(root + ".") for root in allowed_roots)

    offenders: list[str] = []
    for node in ast.walk(_module_ast()):
        if isinstance(node, ast.Import):
            offenders += [a.name for a in node.names if not allowed(a.name)]
        elif isinstance(node, ast.ImportFrom) and node.module:
            if not allowed(node.module):
                offenders.append(node.module)

    assert not offenders, f"unexpected imports: {sorted(set(offenders))}"


def test_the_rule_hardcodes_no_provider_or_account_name() -> None:
    """The grouping key is the provider *field*, not a list of providers.

    A rule that enumerated ``IdentityProvider`` members would need editing every
    time the organisation added a directory, and would silently skip the new one.
    """
    tree = _module_ast()

    provider_values = {p.value for p in IdentityProvider} | {p.name for p in IdentityProvider}
    literals = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }

    assert not (literals & provider_values), f"hardcoded provider: {literals & provider_values}"
    assert not [s for s in literals if s.startswith("00u_")]

    attribute_uses = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "IdentityProvider"
    ]
    assert not attribute_uses, "the rule references a specific IdentityProvider member"
