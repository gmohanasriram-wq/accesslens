"""Persistence for a normalized dataset.

Everything here is an **upsert keyed on the source's own natural key**, never a
blind insert. Two reasons, and the second is the one that bit:

1. Re-running ingestion must be a no-op. The blueprint's Phase 1 step 5 is
   "realistic fixture data" that will be edited repeatedly during development,
   and a re-ingest that duplicated every row would make utilisation ratios --
   which are counts -- silently wrong.

2. ``created_at`` must survive a re-ingest. ``Session.merge`` looks like the
   obvious tool, but a detached instance carrying ``created_at=None`` will
   happily overwrite the stored value with NULL, and ``updated_at``'s
   ``onupdate`` then fires on a row nothing actually changed. So rows are
   fetched, compared field by field, and written only if something differs. The
   return value distinguishes "inserted" from "updated" from "unchanged", which
   is what lets a test assert that a second identical ingest touched nothing.

No dialect-specific SQL: the lookups are plain ``SELECT``s, so these functions
behave identically on SQLite and PostgreSQL.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any, TypeVar

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.errors import IngestRejection
from app.models.activity import ActivityEventRow, SourceCoverageRow
from app.models.entitlement import EntitlementRow
from app.models.identity import IdentityRow
from app.models.ingest import IngestRejectionRow, IngestRunRow
from app.models.user import UserRow
from app.schemas.domain.activity import ActivityEvent
from app.schemas.domain.entitlement import Entitlement
from app.schemas.domain.identity import Identity
from app.schemas.domain.user import User
from app.schemas.ingest import IngestReport
from app.schemas.raw.activity import RawSourceCoverage

__all__ = [
    "upsert_users",
    "upsert_identities",
    "upsert_entitlements",
    "upsert_activity_events",
    "replace_source_coverage",
    "record_ingest_run",
    "record_rejections",
    "counts_by_table",
]

_RowT = TypeVar("_RowT")


def _find(
    session: Session, model: type[_RowT], natural_key: dict[str, Any]
) -> _RowT | None:
    """Fetch the row matching a natural key, or ``None``.

    Keyed on the source system's own identifiers rather than on a surrogate id,
    because the surrogate is local knowledge -- it changes between databases and
    cannot be reconstructed from the export.
    """
    stmt = select(model)
    for column, value in natural_key.items():
        stmt = stmt.where(getattr(model, column) == value)
    return session.scalars(stmt).first()


def _apply(row: Any, payload: dict[str, Any]) -> bool:
    """Copy changed fields onto a row. Returns whether anything differed.

    Comparing before assigning is what makes a repeat ingest a genuine no-op:
    assigning an equal value would still mark the row dirty and fire
    ``updated_at``'s ``onupdate``, so a test could not distinguish "we re-ran
    and nothing changed" from "we re-ran and rewrote everything".
    """
    changed = False
    for column, value in payload.items():
        if getattr(row, column) != value:
            setattr(row, column, value)
            changed = True
    return changed


def _upsert_many(
    session: Session,
    model: type[_RowT],
    payloads: Sequence[tuple[dict[str, Any], dict[str, Any]]],
) -> dict[str, int]:
    """Apply ``(natural_key, fields)`` pairs, returning what actually happened."""
    inserted = updated = unchanged = 0
    for natural_key, fields in payloads:
        existing = _find(session, model, natural_key)
        if existing is None:
            session.add(model(**natural_key, **fields))
            inserted += 1
        elif _apply(existing, fields):
            updated += 1
        else:
            unchanged += 1
    session.flush()
    return {"inserted": inserted, "updated": updated, "unchanged": unchanged}


# --------------------------------------------------------------------------- #
# Domain tables
# --------------------------------------------------------------------------- #


def upsert_users(session: Session, users: Iterable[User]) -> dict[str, int]:
    payloads = [
        (
            {"id": user.id},
            {
                "username": user.username,
                "name": user.name,
                "email": user.email,
                "department": user.department,
                "employment_status": str(user.employment_status),
                "termination_date": user.termination_date,
                "termination_reason": user.termination_reason,
                "manager_id": user.manager_id,
                "hire_date": user.hire_date,
                "source_updated_at": user.source_updated_at,
            },
        )
        for user in users
    ]
    return _upsert_many(session, UserRow, payloads)


def upsert_identities(session: Session, identities: Iterable[Identity]) -> dict[str, int]:
    payloads = [
        (
            {"provider": str(identity.provider), "account_id": identity.account_id},
            {
                "user_id": identity.user_id,
                "login": identity.login,
                "email": identity.email,
                "status": str(identity.status),
                "deactivated_at": identity.deactivated_at,
                "deactivation_trigger": identity.deactivation_trigger,
                "groups": list(identity.groups),
                "mfa_enrolled": identity.mfa_enrolled,
                "is_duplicate_of": identity.is_duplicate_of,
            },
        )
        for identity in identities
    ]
    return _upsert_many(session, IdentityRow, payloads)


def upsert_entitlements(
    session: Session, entitlements: Iterable[Entitlement]
) -> dict[str, int]:
    payloads = [
        (
            {
                "user_id": entitlement.user_id,
                "source": str(entitlement.source),
                "role": entitlement.role,
            },
            {
                "role_arn": entitlement.role_arn,
                "org": entitlement.org,
                "permissions": list(entitlement.permissions),
                "risk_level": str(entitlement.risk_level),
                "protected_role": entitlement.protected_role,
                "protection_reason": entitlement.protection_reason,
                "protection_tags": list(entitlement.protection_tags),
                "granted_at": entitlement.granted_at,
                "principal": entitlement.principal,
            },
        )
        for entitlement in entitlements
    ]
    return _upsert_many(session, EntitlementRow, payloads)


def upsert_activity_events(
    session: Session, events: Iterable[ActivityEvent]
) -> dict[str, int]:
    """Persist normalized events, keyed on the source-prefixed ``event_id``.

    The prefix matters here and not only upstream: ``event_id`` is the primary
    key, so a cross-source id collision would otherwise overwrite one system's
    evidence with another's.
    """
    payloads = [
        (
            {"event_id": event.event_id},
            {
                "timestamp": event.timestamp,
                "actor_id": event.actor_id,
                "source": str(event.source),
                "action": event.action,
                "resource": event.resource,
                "source_ip": event.source_ip,
                "credential_id": event.credential_id,
                "denied": event.denied,
                "raw_index": event.raw_index,
            },
        )
        for event in events
    ]
    return _upsert_many(session, ActivityEventRow, payloads)


# --------------------------------------------------------------------------- #
# Ingest bookkeeping
# --------------------------------------------------------------------------- #


def replace_source_coverage(
    session: Session, run_id: str, manifest: Iterable[RawSourceCoverage]
) -> int:
    """Store this run's coverage manifest.

    Replaced rather than upserted on ``(run_id, source)``: the manifest is one
    source system's statement about one window, so a later statement about the
    same window supersedes the earlier one. Keeping both would leave the reader
    to guess which of two contradictory declarations is current.
    """
    session.execute(
        delete(SourceCoverageRow).where(SourceCoverageRow.ingest_run_id == run_id)
    )

    rows = [
        SourceCoverageRow(
            ingest_run_id=run_id,
            source=str(entry.source),
            status=str(entry.status),
            window_start=entry.window_start,
            window_end=entry.window_end,
            record_count=entry.record_count,
            note=entry.note,
        )
        for entry in manifest
    ]
    session.add_all(rows)
    session.flush()
    return len(rows)


def record_rejections(
    session: Session, run_id: str, rejections: Iterable[IngestRejection]
) -> int:
    """Persist rejected records, replacing this run's previous set.

    Persisted rather than logged because a rejection is *evidence*: it is the
    reason a user's coverage is PARTIAL, and that reason has to still be
    readable when an auditor asks next quarter why a finding said "insufficient
    evidence".
    """
    session.execute(
        delete(IngestRejectionRow).where(IngestRejectionRow.ingest_run_id == run_id)
    )

    rows = [
        IngestRejectionRow(
            ingest_run_id=run_id,
            file=rejection.file,
            raw_index=rejection.raw_index,
            record_id=rejection.record_id,
            field_path=rejection.field_path,
            reason=rejection.reason,
            actor_hint=rejection.actor_hint,
            raw_value=_jsonable(rejection.raw_value),
        )
        for rejection in rejections
    ]
    session.add_all(rows)
    session.flush()
    return len(rows)


def record_ingest_run(session: Session, report: IngestReport) -> None:
    """Write the run's own audit row, upserted on ``run_id``."""
    existing = session.get(IngestRunRow, report.run_id)
    fields = {
        "status": str(report.status),
        "started_at": report.started_at,
        "finished_at": report.finished_at,
        "content_hash": report.content_hash,
        "counts": dict(report.counts),
    }
    if existing is None:
        session.add(IngestRunRow(run_id=report.run_id, **fields))
    else:
        _apply(existing, fields)
    session.flush()


def _jsonable(value: Any) -> Any:
    """Coerce a rejected value into something the JSON column can hold.

    A rejected value can be any JSON type *except* one that Pydantic failed to
    parse -- and it may be a ``datetime``, a ``ValidationError`` input, or a
    nested structure. Round-tripping through ``str`` is the honest fallback: the
    point of storing it is that a human can see what the upstream system
    actually sent.
    """
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    return str(value)


def counts_by_table(session: Session) -> dict[str, int]:
    """Row counts per domain table, for the ingest report and for tests."""
    models = {
        "users": UserRow,
        "identities": IdentityRow,
        "entitlements": EntitlementRow,
        "activity_events": ActivityEventRow,
        "source_coverage": SourceCoverageRow,
        "ingest_rejections": IngestRejectionRow,
    }
    return {
        name: session.scalar(select(func.count()).select_from(model)) or 0
        for name, model in models.items()
    }
