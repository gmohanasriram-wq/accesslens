"""Person table (HR-sourced)."""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import Date, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UTCDateTime

__all__ = ["UserRow"]


class UserRow(Base, TimestampMixin):
    __tablename__ = "users"

    #: Natural key from HR (``u_bob``). External systems supply the identifier,
    #: so this is not a generated surrogate -- it is what makes re-ingestion an
    #: upsert rather than a duplicate insert.
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(256))
    email: Mapped[str] = mapped_column(String(256), index=True)
    department: Mapped[str] = mapped_column(String(128))

    #: Stored as the enum's string value rather than a native DB enum: portable
    #: across SQLite and PostgreSQL, and legible in a database browser during a
    #: demo, which matters when the audience is auditing the data.
    employment_status: Mapped[str] = mapped_column(String(32), index=True)

    termination_date: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    termination_reason: Mapped[str | None] = mapped_column(String(256), nullable=True)
    manager_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    hire_date: Mapped[date | None] = mapped_column(Date, nullable=True)

    source_updated_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<UserRow {self.id} {self.username} {self.employment_status}>"
