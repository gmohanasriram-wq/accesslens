"""SQLAlchemy base, and the UTC datetime column type.

:class:`UTCDateTime` exists because of a genuine SQLite trap. SQLite has no
native datetime type and does not store a UTC offset, so an aware datetime
written to a plain ``DateTime`` column comes back **naive**. For most
applications that is a nuisance. Here it is a correctness bug with a delayed
fuse: Rule D decides ghost access by comparing an HR termination time, an IdP
deactivation time and an activity timestamp, and comparing a naive value to an
aware one raises ``TypeError``. Without this type, that error would surface in
Phase 2 at analysis time -- far from the ingestion code that caused it.

So values are normalised to UTC on the way in and re-tagged as UTC on the way
out, and the round trip is lossless by construction.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, MetaData, TypeDecorator
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.core.time import ensure_utc, utcnow

__all__ = ["Base", "UTCDateTime", "metadata", "TimestampMixin"]

#: Explicit naming convention so that constraints get stable, predictable names
#: on every backend. Without it, an auto-named constraint on SQLite and the same
#: constraint on PostgreSQL differ, which makes migrations diverge later.
_NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

metadata = MetaData(naming_convention=_NAMING_CONVENTION)


class UTCDateTime(TypeDecorator):
    """A ``DateTime`` that always round-trips as timezone-aware UTC."""

    impl = DateTime
    cache_ok = True

    def load_dialect_impl(self, dialect):  # noqa: ANN001, ANN201 - SQLAlchemy hook
        # Ask for a timezone-aware column where the backend supports it
        # (PostgreSQL does; SQLite accepts the declaration and ignores it, which
        # is precisely why the bind/result processors below are required).
        return dialect.type_descriptor(DateTime(timezone=True))

    def process_bind_param(self, value: datetime | None, dialect):  # noqa: ANN001, ANN201
        if value is None:
            return None
        # Normalise before storage: this is what stops a +05:30 value from being
        # written as a local-looking wall time and read back as a different
        # instant.
        return ensure_utc(value)

    def process_result_value(self, value: datetime | None, dialect):  # noqa: ANN001, ANN201
        if value is None:
            return None
        if value.tzinfo is None:
            # SQLite path: we stored UTC, so re-attach UTC rather than guessing.
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class Base(DeclarativeBase):
    metadata = metadata


class TimestampMixin:
    """Adds bookkeeping columns recording when AccessLens saw a row.

    Distinct from the *source system's* timestamps, which are domain data. These
    say when the local copy was written, which is what makes an ingestion run
    auditable after the fact.

    ``onupdate`` fires only on a real UPDATE, so a re-ingest that is skipped
    because the inputs are unchanged leaves these values untouched -- which is
    what makes "re-running ingestion is a no-op" checkable.
    """

    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, default=utcnow, onupdate=utcnow
    )
