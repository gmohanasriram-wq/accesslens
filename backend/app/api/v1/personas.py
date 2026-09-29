"""Ingested personas and their current access posture.

Read-only, and deliberately so: nothing in this API can change anyone's access.
Findings and recommendations arrive in Phase 2/3, and even then the blueprint
requires a human to approve any security-changing action -- so there is no
endpoint here, and will be none later, that revokes anything.
"""

from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import select

from app.api.deps import DatasetDep, SessionDep
from app.ingestion import InMemoryDataset
from app.models.entitlement import EntitlementRow
from app.models.identity import IdentityRow
from app.models.user import UserRow
from app.schemas.api import (
    ActivitySummary,
    EntitlementSummary,
    IdentitySummary,
    PersonaListResponse,
    PersonaSummary,
)

__all__ = ["router"]

router = APIRouter(tags=["personas"])


@router.get("/personas", response_model=PersonaListResponse)
def list_personas(session: SessionDep, dataset: DatasetDep) -> PersonaListResponse:
    """Every ingested user, with identities, entitlements and activity coverage.

    People, identities and entitlements come from the **database**, not from the
    fixture files: this is the surface that proves ingestion actually persisted
    domain rows, rather than the process happening to hold parsed JSON in memory.

    Coverage is the exception, and comes from the assembled dataset. Per-user
    coverage is *derived* -- it is the product of the manifest, this user's
    entitlements and their rejections -- so persisting it would store a
    conclusion that a later ingest could contradict. Phase 1 stores the manifest
    it derives from; the derivation stays in one place.
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

    personas = [
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
    ]

    return PersonaListResponse(
        count=len(personas),
        content_hash=dataset.content_hash,
        analysis_as_of=dataset.window[1],
        generated_at=dataset.generated_at,
        personas=personas,
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
