"""Rule C -- duplicate identity.

Blueprint §16's matrix carries a row no other rule can reach:

    Duplicate identity | Investigation required

Henry is the persona. He holds two Okta accounts that share one login and one
email -- ``00u_henry01`` (MFA enrolled, engineering + support-readonly) and
``00u_henry98-legacy`` (no MFA, engineering only). Both are ACTIVE. He is one
person with two principals, and the directory cannot say which of them is the one
in use: his events arrive as ``arn:aws:iam::123456789012:user/henry.okafor`` and
``ghp_henry_primary``, neither of which is an Okta account id. That is the
finding. He is not accused of anything else -- his observed utilisation is 3/4.

Four decisions make this rule correct, and the first three are why it does not
look like the other three.

**It is not a telemetry rule.** Rules A, B and D all reason about activity, and
all three are therefore gated by coverage: an unmeasurable window must not be read
as an idle one. Rule C makes a claim about the *directory*, which is a different
source with a different failure mode, so none of that apparatus applies. Nothing
here reads ``dataset.window``, ``dataset.slices``, ``low_utilization_threshold``,
``min_observed_events_for_confidence`` or ``lookback_days``. A person with MISSING
coverage and zero events is reported exactly like one with COMPLETE coverage and a
thousand. Silencing a directory defect because an unrelated CloudTrail export was
truncated would hide the defect behind a gap that has nothing to do with it.

**The decision belongs to the engine, not to ingestion.** ``Identity.
is_duplicate_of`` already exists and is already populated at ingest by
``normalizer._mark_duplicates``. Reading it would be one line, and it would put
the security decision in ``app/ingestion/``, where the engine cannot be tested
against it independently. So this module recomputes the grouping from the
identities it is given and never consults the flag; ``is_duplicate_of`` stays
ingestion-derived display metadata. Where the two do overlap -- the canonical
account, which both define as the smallest ``account_id`` -- a test in
``tests/test_rule_c.py`` sweeps every person in the fixture set and fails by name
if they ever drift apart.

**An account that belongs to nobody is not a duplicate.** ``00u_svcbackup`` is in
the IdP export and resolves to no HR user, so ingestion *rejects* it and it never
reaches ``dataset.identities`` at all. That is an ``IDENTITY_UNMAPPED`` fact, not
this rule's, and this rule cannot be shown a record it is never given.

**Completeness is scoped to the person, not to the source.** There is one IdP
rejection in the fixture set -- ``svc.backup`` -- and it concerns an account that
is not Henry's, so Henry's identity evidence is COMPLETE. A global "any IdP
rejection means partial" reading would mark every person in the company PARTIAL
for a defect in one unrelated account, and would contradict Henry's oracle entry,
which was written before this rule existed. So a rejection downgrades a person
only when it names one of *that person's own* logins, addresses or account ids.

The finding is INVESTIGATION_REQUIRED / MEDIUM / MANUAL_REVIEW and it does not
prescribe. "The legacy account should be removed" is exactly the conclusion the
evidence does not support: the engine can prove the ambiguity, and it cannot prove
which of the two accounts is the mistake -- the legacy one may be the one in use.
``risk_level`` is left UNKNOWN because risk describes what the *granted access*
could do, which is Rules A and B's subject and not this one's, and ``usage`` is
left None because this rule reaches no telemetry verdict at all.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from datetime import datetime

from app.core.config import Settings
from app.core.enums import (
    EvidenceCompleteness,
    EvidenceKind,
    FindingStatus,
    FindingType,
    Recommendation,
    RiskLevel,
    Severity,
    SourceSystem,
)
from app.core.errors import IngestRejection
from app.ingestion import InMemoryDataset
from app.schemas.domain.finding import Evidence, Finding
from app.schemas.domain.identity import Identity
from app.schemas.domain.user import User

__all__ = ["RULE_ID", "detect_duplicate_identities", "evaluate_user"]

#: Rule identifiers are stable strings: they are persisted alongside a finding and
#: read back by reviewers, so renaming one silently invalidates history.
RULE_ID = "RULE_C_DUPLICATE_IDENTITY"

_SLUG = "rule-c"


#: Filenames whose rejections are statements about identity resolution.
#:
#: Keyed by filename rather than by ``IngestRejection.source`` because ``source``
#: is ``None`` for precisely the rejections that matter here: a record the loader
#: could not place has no source to attribute it to, and that is the whole reason
#: it was rejected. The filename is the only handle the rejection carries that
#: survives the failure it records.
_IDENTITY_SOURCE_FILES: frozenset[str] = frozenset({"idp_state.json"})


# --------------------------------------------------------------------------- #
# Grouping
# --------------------------------------------------------------------------- #


def _duplicate_groups(
    identities: Sequence[Identity],
) -> list[tuple[str, list[Identity]]]:
    """This person's accounts, grouped by provider, keeping the duplicated groups.

    The grouping key is ``(provider, user_id)`` and the ``user_id`` half is
    implicit -- every identity passed in already belongs to one person. Two
    accounts in *one* directory means one of them is probably a mistake; the same
    login in two directories is how federated identity is supposed to work, so the
    provider is part of the key and a cross-provider pair is not a duplicate.

    A group of one is not a duplicate and is dropped. Three accounts in a provider
    is *one* hygiene problem and not three pairs, which is why this groups first
    and reports once: pair-wise reporting would grow quadratically and hand the
    reviewer the same fact three times.

    Ordered by provider so two runs over the same facts produce identically
    ordered findings.
    """
    grouped: dict[str, list[Identity]] = defaultdict(list)
    for identity in identities:
        grouped[identity.provider.value].append(identity)

    return [
        (provider, sorted(accounts, key=lambda i: i.account_id))
        for provider, accounts in sorted(grouped.items())
        if len(accounts) > 1
    ]


def _canonical_account_id(accounts: Sequence[Identity]) -> str:
    """The account the others are recorded as duplicating.

    The smallest ``account_id``, which is the same tie-break
    ``normalizer._mark_duplicates`` uses at ingest. It is recomputed here rather
    than read from ``Identity.is_duplicate_of`` so that the engine's answer does
    not depend on a field the engine is not allowed to have decided -- but it is
    deliberately the *same* rule, because two canonical accounts for one group
    would make the evidence row and the display metadata contradict each other.
    """
    return min(identity.account_id for identity in accounts)


# --------------------------------------------------------------------------- #
# Completeness
# --------------------------------------------------------------------------- #


def _person_names(user: User, identities: Sequence[Identity]) -> frozenset[str]:
    """Every string by which a rejection could plausibly name this person.

    Built from the person and their own accounts, so the match below cannot reach
    across people. Lowercased because the comparison is about identity, not
    spelling -- an export that writes ``Henry.Okafor`` is naming the same human.
    """
    names = {user.id, user.username, user.name}
    if user.email:
        names.add(user.email)
    for identity in identities:
        names.add(identity.login)
        names.add(identity.account_id)
        if identity.email:
            names.add(identity.email)
    return frozenset(name.strip().lower() for name in names if name)


def _names_person(rejection: IngestRejection, names: frozenset[str]) -> bool:
    """Whether this rejection points at one of ``names``.

    ``raw_value`` is typed ``Any`` and is genuinely sometimes a datetime or a
    whole record rather than a string, so it is only consulted when it is one.
    """
    candidates = (rejection.actor_hint, rejection.record_id, rejection.raw_value)
    return any(
        isinstance(candidate, str) and candidate.strip().lower() in names
        for candidate in candidates
    )


def _completeness(
    user: User,
    identities: Sequence[Identity],
    generated_at: datetime | None,
    rejections: Sequence[IngestRejection],
) -> EvidenceCompleteness:
    """How much of this conclusion actually rests on evidence that exists.

    Two ways to be under-evidenced, and both are recorded rather than worked
    around:

    * the export carries no ``generated_at``, so no evidence row can be anchored
      to a moment -- see D2, and note that the alternative is stamping the wall
      clock, which no reader could reproduce;
    * an identity record was rejected *and it named this person*, so a second
      account could have been in the record that could not be read.

    The second is scoped on purpose. A rejection naming somebody else is somebody
    else's incomplete picture, and letting it reach this person would make one
    unmapped service account in the export mark the entire company's identity
    evidence PARTIAL.
    """
    if generated_at is None:
        return EvidenceCompleteness.PARTIAL

    scoped = [
        rejection
        for rejection in rejections
        if rejection.file in _IDENTITY_SOURCE_FILES
    ]
    names = _person_names(user, identities)
    if any(_names_person(rejection, names) for rejection in scoped):
        return EvidenceCompleteness.PARTIAL

    return EvidenceCompleteness.COMPLETE


# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #


def _link_evidence(
    finding_id: str,
    user: User,
    provider: str,
    accounts: Sequence[Identity],
    canonical_id: str,
    generated_at: datetime | None,
) -> list[Evidence]:
    """One ``IDENTITY_LINK`` row per account in the duplicated group.

    Both accounts are recorded, not just the one treated as canonical. The
    finding *is* the pair: naming only the second account would suggest the first
    is the real one and the second is the problem, which is the judgement this
    rule expressly does not make. The evidence says which account the group is
    anchored to, so a reader can check the tie-break rather than trust it.

    ``IDENTITY_LINK`` was defined for exactly this and had no caller until now;
    the alternative was overloading ``CONFIG_VALUE``, which would have described
    a directory fact as a policy setting.
    """
    total = len(accounts)

    return [
        Evidence(
            evidence_id=f"ev-{user.id}-{_SLUG}-{provider}-{account.account_id}",
            finding_id=finding_id,
            kind=EvidenceKind.IDENTITY_LINK,
            source=SourceSystem.IDP.value,
            timestamp=generated_at,
            description=(
                f"{provider} account {account.account_id} (login {account.login}, "
                f"status {account.status.value}) resolves to {user.username}, and is "
                f"one of {total} accounts this person holds with that provider."
            ),
            detail={
                "account_id": account.account_id,
                "provider": provider,
                "login": account.login,
                "email": account.email,
                "status": account.status.value,
                "mfa_enrolled": account.mfa_enrolled,
                "groups": list(account.groups),
                "canonical_account_id": canonical_id,
                # Recomputed here, never read from the identity: the engine owns
                # this judgement, and this row is where a reader can see it.
                "is_duplicate_of": (
                    None if account.account_id == canonical_id else canonical_id
                ),
            },
        )
        for account in accounts
    ]


# --------------------------------------------------------------------------- #
# The finding
# --------------------------------------------------------------------------- #


def _summarise(user: User, provider: str, accounts: Sequence[Identity]) -> str:
    """The deterministic statement of a duplicate-identity finding.

    It says what the directory contains and what follows from it -- that a record
    of this person's activity cannot be pinned to one account -- and then stops.
    It does not say which account is the mistake, because the engine cannot know:
    the account with the older-looking id may well be the one in use.

    Both account ids are named, or none. Naming only one would put a thumb on the
    scale the evidence does not support, and a reviewer skimming the summary
    would carry that bias into the review.
    """
    account_ids = ", ".join(account.account_id for account in accounts)

    return (
        f"{user.username} holds {len(accounts)} accounts in {provider} "
        f"({account_ids}), all resolving to the same person, so a record of what "
        "this person did cannot be attributed to a single account and neither "
        "account can be taken as the one in use. AccessLens does not change "
        "access; a reviewer decides whether both accounts are intended."
    )


def _duplicate_finding(
    user: User,
    provider: str,
    accounts: Sequence[Identity],
    settings: Settings,
    generated_at: datetime | None,
    rejections: Sequence[IngestRejection],
) -> Finding:
    """One finding for one (person, provider) pair.

    The provider is in the id because the finding is per directory: a person
    duplicated in Okta *and* in Google Workspace is two separate hygiene facts,
    and without the suffix the second would collide with the first in a dossier
    keyed by ``Finding.id``.
    """
    finding_id = f"fnd-{user.id}-{_SLUG}-{provider}"
    canonical_id = _canonical_account_id(accounts)

    return Finding(
        id=finding_id,
        user_id=user.id,
        type=FindingType.DUPLICATE_IDENTITY,
        severity=Severity.MEDIUM,
        status=FindingStatus.INVESTIGATION_REQUIRED,
        # Left at the default rather than computed: risk_level describes what the
        # *granted access* could do, which is Rules A and B's question. This rule
        # has measured no access, so it has no risk to report.
        risk_level=RiskLevel.UNKNOWN,
        summary=_summarise(user, provider, accounts),
        recommendation=Recommendation.MANUAL_REVIEW,
        evidence=_link_evidence(
            finding_id, user, provider, accounts, canonical_id, generated_at
        ),
        evidence_completeness=_completeness(user, accounts, generated_at, rejections),
        rules_triggered=[RULE_ID],
        # None, not a verdict: this rule reads no activity, so it has no
        # observation to report and must not appear to have made one.
        usage=None,
        created_at=settings.effective_analysis_as_of(),
    )


# --------------------------------------------------------------------------- #
# Entry points
# --------------------------------------------------------------------------- #


def evaluate_user(
    user: User,
    identities: Sequence[Identity],
    settings: Settings,
) -> list[Finding]:
    """This person's duplicate-identity findings, one per duplicated provider.

    The per-user entry point, and the only one that can be called without a
    dataset. It therefore cannot see two things that live on the dataset rather
    than on the person -- ``generated_at`` (D2's evidence anchor) and the ingest
    rejections (D6's completeness scope) -- so it reports every finding as
    PARTIAL with unanchored evidence. That is the honest answer to "here is a
    person and their accounts": nothing in the arguments states when the export
    was taken, and an evidence row with no timestamp is under-evidenced rather
    than timeless. :func:`detect_duplicate_identities` supplies both.
    """
    return [
        _duplicate_finding(
            user,
            provider,
            accounts,
            settings,
            generated_at=None,
            rejections=(),
        )
        for provider, accounts in _duplicate_groups(identities)
    ]


def detect_duplicate_identities(
    dataset: InMemoryDataset,
    settings: Settings,
) -> list[Finding]:
    """Run this rule over every person in the dataset.

    Deterministic order -- users by id, then provider within a person -- so two
    runs over identical facts produce identically ordered findings. This rule can
    return more than one finding for one person, which the other three cannot, so
    the ordering is part of the contract rather than an accident of iteration.

    The only work here beyond looping over :func:`evaluate_user` is supplying the
    two dataset-level facts that function cannot reach: the export's
    ``generated_at``, which anchors every evidence row, and the rejections that
    decide whether this person's directory evidence is complete.
    """
    findings: list[Finding] = []

    for user in sorted(dataset.users, key=lambda u: u.id):
        identities = dataset.identities_for(user.id)
        for provider, accounts in _duplicate_groups(identities):
            findings.append(
                _duplicate_finding(
                    user,
                    provider,
                    accounts,
                    settings,
                    generated_at=dataset.generated_at,
                    rejections=dataset.rejections,
                )
            )

    return findings
