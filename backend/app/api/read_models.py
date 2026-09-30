"""Stored rows, projected onto the API's response contracts.

Two routes report the same person: ``/api/personas`` lists everyone, and a
finding's dossier restates the one person that finding is about. They have to
agree. A dossier that disagreed with the persona list about someone's coverage
or their entitlements would be two answers to one question, and nothing would
fail -- so the projection lives here once and both routes call it, rather than
each route assembling its own version of the same facts.

**Where each half comes from is not an implementation detail.** People,
identities and entitlements come from the *database*, because that is what
proves ingestion persisted domain rows rather than the process happening to hold
parsed JSON in memory. Coverage comes from the assembled *dataset*, because
per-user coverage is derived -- it is the product of the manifest, that user's
entitlements and their rejections -- and persisting it would store a conclusion
that a later ingest could contradict.
"""

from __future__ import annotations

from collections.abc import Collection

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ingestion import InMemoryDataset
from app.models.entitlement import EntitlementRow
from app.models.identity import IdentityRow
from app.models.user import UserRow
from app.schemas.api import (
    ActivitySummary,
    EntitlementSummary,
    FindingSubject,
    IdentitySummary,
    PersonaSummary,
)

__all__ = ["build_personas", "find_persona", "finding_subject"]


def build_personas(
    session: Session,
    dataset: InMemoryDataset,
    *,
    only_user_ids: Collection[str] | None = None,
) -> list[PersonaSummary]:
    """Every ingested user as a :class:`PersonaSummary`, ordered by username.

    ``only_user_ids`` narrows the result without changing how it is built, so a
    caller asking about one person reads the same rows through the same code
    path as a caller asking about everyone. Two code paths would be two chances
    to disagree.
    """
    users = session.scalars(select(UserRow).order_by(UserRow.username)).all()

    identities: dict[str, list[IdentityRow]] = {}
    for row in session.scalars(select(IdentityRow).order_by(IdentityRow.account_id)):
        identities.setdefault(row.user_id, []).append(row)

    entitlements: dict[str, list[EntitlementRow]] = {}
    for row in session.scalars(
        select(EntitlementRow).order_by(EntitlementRow.source, EntitlementRow.role)
    ):
        entitlements.setdefault(row.user_id, []).append(row)

    return [
        PersonaSummary(
            id=user.id,
            username=user.username,
            name=user.name,
            department=user.department,
            employment_status=user.employment_status,
            termination_date=user.termination_date,
            identities=[
                IdentitySummary(
                    provider=row.provider,
                    account_id=row.account_id,
                    login=row.login,
                    status=row.status,
                    deactivated_at=row.deactivated_at,
                    deactivation_trigger=row.deactivation_trigger,
                    # Surfaced rather than hidden: a duplicated directory
                    # account is itself a review-relevant fact, and hiding it
                    # would make the identity count look cleaner than the truth.
                    is_duplicate_of=row.is_duplicate_of,
                )
                for row in identities.get(user.id, [])
            ],
            entitlements=[
                EntitlementSummary(
                    source=row.source,
                    role=row.role,
                    risk_level=row.risk_level,
                    protected_role=row.protected_role,
                    protection_reason=row.protection_reason,
                    protection_tags=list(row.protection_tags or []),
                    granted_at=row.granted_at,
                )
                for row in entitlements.get(user.id, [])
            ],
            activity=_activity_summary(dataset, user.id),
        )
        for user in users
        if only_user_ids is None or user.id in only_user_ids
    ]


def find_persona(
    session: Session, dataset: InMemoryDataset, user_id: str
) -> PersonaSummary | None:
    """One person, or ``None`` if the id is not a persisted user."""
    matches = build_personas(session, dataset, only_user_ids={user_id})
    return matches[0] if matches else None


def finding_subject(persona: PersonaSummary) -> FindingSubject:
    """The compact identity a queue row travels with.

    Derived from the same :class:`PersonaSummary` the dossier and
    ``/api/personas`` return, so a row's idea of who someone is cannot drift
    from the page that person's finding opens onto.
    """
    return FindingSubject(
        id=persona.id,
        username=persona.username,
        name=persona.name,
        department=persona.department,
        employment_status=persona.employment_status,
        termination_date=persona.termination_date,
    )


def _activity_summary(dataset: InMemoryDataset, user_id: str) -> ActivitySummary:
    """Project one user's activity slice onto the wire format.

    ``slice_for`` never returns ``None``; a user missing from the slice mapping
    comes back as ``NOT_QUERIED``, so a bug in the assembler surfaces here as
    "we cannot vouch for this" rather than as a clean-looking empty history.
    """
    slice_ = dataset.slice_for(user_id)
    return ActivitySummary(
        coverage=slice_.coverage,
        usage_observation=slice_.usage_observation,
        observed_event_count=slice_.observed_event_count,
        last_activity_at=slice_.last_activity_at,
        sources_queried=sorted(str(source) for source in slice_.sources_queried),
        sources_missing=sorted(str(source) for source in slice_.sources_missing),
        gaps=[
            f"{gap.source}: {gap.reason} -- {gap.detail}" for gap in slice_.gaps
        ],
    )
