"""Finding and evidence tables.

These tables exist in Phase 1 but stay empty: they are written by the Phase 2
engine. They are created now so that the schema the engine writes into is fixed
alongside the contract it produces, rather than being invented at the same time
as the logic that fills it.

Note what is **absent**: there is no ``ai_explanation`` column and no
``decision`` column. Those belong to separate tables owned by Phases 3 and 4.
Keeping them off this table is what makes "the AI does not make the security
decision" a structural property of the database rather than a convention.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UTCDateTime

__all__ = ["FindingRow", "EvidenceRow"]


class FindingRow(Base, TimestampMixin):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(64), index=True)

    type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    risk_level: Mapped[str] = mapped_column(String(16), default="UNKNOWN")

    #: Deterministic text produced from a template by the engine.
    summary: Mapped[str] = mapped_column(Text)

    recommendation: Mapped[str] = mapped_column(String(64))

    #: COMPLETE / PARTIAL / MISSING -- how much of the evidence this conclusion
    #: should rest on actually exists.
    evidence_completeness: Mapped[str] = mapped_column(String(16), default="COMPLETE")

    #: Rule identifiers that fired, e.g. ``["RULE_B_LOW_USAGE_PRIVILEGED"]``.
    rules_triggered: Mapped[list[str]] = mapped_column(JSON, default=list)

    usage: Mapped[str | None] = mapped_column(String(16), nullable=True)

    #: The instant the analysis was performed for (not the wall clock at insert
    #: time) -- see ``Settings.analysis_as_of``.
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)

    evidence: Mapped[list["EvidenceRow"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", lazy="selectin"
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<FindingRow {self.id} {self.type} {self.user_id}>"


class EvidenceRow(Base, TimestampMixin):
    __tablename__ = "evidence"

    evidence_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    finding_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("findings.id"), index=True
    )

    kind: Mapped[str] = mapped_column(String(32), index=True)
    source: Mapped[str] = mapped_column(String(32))

    #: Null for kinds not anchored to an instant (COVERAGE_STATEMENT,
    #: CONFIG_VALUE) -- absence here means "not applicable", never "unknown".
    timestamp: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    event_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    description: Mapped[str] = mapped_column(Text)

    #: Rule-specific structured payload (thresholds applied, counts, window).
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    finding: Mapped[FindingRow] = relationship(back_populates="evidence")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<EvidenceRow {self.evidence_id} {self.kind}>"
