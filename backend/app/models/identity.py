"""Directory account table (IdP-sourced)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UTCDateTime

__all__ = ["IdentityRow"]


class IdentityRow(Base, TimestampMixin):
    __tablename__ = "identities"
    __table_args__ = (
        # The provider's account id is the real key. ``login`` is deliberately
        # *not* unique: logins get reused, and two accounts legitimately sharing
        # one is the duplicate-identity case the blueprint asks us to detect.
        UniqueConstraint("provider", "account_id", name="uq_identities_provider_account"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id"), index=True
    )

    provider: Mapped[str] = mapped_column(String(32))
    account_id: Mapped[str] = mapped_column(String(128))
    login: Mapped[str] = mapped_column(String(256), index=True)
    email: Mapped[str | None] = mapped_column(String(256), nullable=True)
    status: Mapped[str] = mapped_column(String(32), index=True)

    #: Rule D's reference instant.
    deactivated_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    deactivation_trigger: Mapped[str | None] = mapped_column(String(64), nullable=True)

    groups: Mapped[list[str]] = mapped_column(JSON, default=list)
    mfa_enrolled: Mapped[bool] = mapped_column(Boolean, default=False)

    #: Account id treated as canonical when several resolve to one person.
    is_duplicate_of: Mapped[str | None] = mapped_column(String(128), nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<IdentityRow {self.provider}:{self.account_id} user={self.user_id}>"
