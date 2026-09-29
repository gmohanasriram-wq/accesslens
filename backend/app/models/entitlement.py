"""Granted-access table."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UTCDateTime

__all__ = ["EntitlementRow"]


class EntitlementRow(Base, TimestampMixin):
    __tablename__ = "entitlements"
    __table_args__ = (
        UniqueConstraint(
            "user_id", "source", "role", name="uq_entitlements_user_source_role"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(String(64), ForeignKey("users.id"), index=True)

    source: Mapped[str] = mapped_column(String(32), index=True)
    role: Mapped[str] = mapped_column(String(256), index=True)
    role_arn: Mapped[str | None] = mapped_column(String(512), nullable=True)
    org: Mapped[str | None] = mapped_column(String(128), nullable=True)

    #: Raw permission strings as granted upstream, kept verbatim. Capabilities
    #: are derived from these at read time by ``core.capabilities`` rather than
    #: being stored, so that improving the mapping does not require a re-ingest.
    permissions: Mapped[list[str]] = mapped_column(JSON, default=list)

    risk_level: Mapped[str] = mapped_column(String(16), index=True)

    #: Rule C input. Explicitly stored rather than inferred from the role name.
    protected_role: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    protection_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)
    protection_tags: Mapped[list[str]] = mapped_column(JSON, default=list)

    granted_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    principal: Mapped[str] = mapped_column(String(512), default="")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<EntitlementRow {self.user_id} {self.source}:{self.role}>"
