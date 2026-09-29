"""Telemetry tables: normalised events, and the coverage manifest."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UTCDateTime

__all__ = ["ActivityEventRow", "SourceCoverageRow"]


class ActivityEventRow(Base, TimestampMixin):
    __tablename__ = "activity_events"

    #: Source-prefixed natural key, e.g. ``gh_8f2a..`` or ``aws_1c9e..``.
    #: Natural rather than surrogate so that re-ingesting the same export is an
    #: upsert and cannot double-count usage.
    event_id: Mapped[str] = mapped_column(String(128), primary_key=True)

    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(String(64), index=True)
    source: Mapped[str] = mapped_column(String(32), index=True)
    action: Mapped[str] = mapped_column(String(128), index=True)
    resource: Mapped[str | None] = mapped_column(String(512), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    credential_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    #: Rule D counts only successful actions. A denied attempt proves the
    #: credential was still live, but reporting it as use would overstate the
    #: finding.
    denied: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    #: Position in the source export, retained so an auditor can locate the
    #: original line.
    raw_index: Mapped[int] = mapped_column(Integer, default=-1)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<ActivityEventRow {self.event_id} {self.actor_id} {self.action}>"


class SourceCoverageRow(Base, TimestampMixin):
    """One row of the coverage manifest: what we did and did not receive.

    This table is what makes "no activity observed" distinguishable from "no
    logs received". It is stored rather than derived because it is a statement
    by the *source system* about its own completeness -- an assertion AccessLens
    records and reasons about, not one it can compute.
    """

    __tablename__ = "source_coverage"
    __table_args__ = (
        UniqueConstraint("ingest_run_id", "source", name="uq_coverage_run_source"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    ingest_run_id: Mapped[str] = mapped_column(String(64), index=True)

    source: Mapped[str] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(String(16), index=True)

    window_start: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    window_end: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    #: The count the source *claims* to have sent. Cross-checked against the
    #: events actually parsed, so a truncated export cannot declare itself
    #: COMPLETE and pass unnoticed.
    record_count: Mapped[int] = mapped_column(Integer, default=0)

    note: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<SourceCoverageRow {self.source}={self.status}>"
