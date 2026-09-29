"""Bookkeeping for ingestion runs.

Keeping a history of runs -- rather than only the current state -- is what lets
the dossier answer "when did we last actually look?" and lets a re-ingest be
skipped when nothing changed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UTCDateTime

__all__ = ["IngestRunRow", "IngestRejectionRow"]


class IngestRunRow(Base, TimestampMixin):
    __tablename__ = "ingest_runs"

    run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    status: Mapped[str] = mapped_column(String(32), index=True)

    started_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    #: SHA-256 over the source files plus the analysis window. Identical hash
    #: means an identical dataset, which is the basis for skipping a re-run.
    content_hash: Mapped[str] = mapped_column(String(64), index=True)

    counts: Mapped[dict[str, int]] = mapped_column(JSON, default=dict)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<IngestRunRow {self.run_id} {self.status}>"


class IngestRejectionRow(Base, TimestampMixin):
    """A source record that was identified but not accepted.

    Persisted rather than only logged. A rejected record is evidence that a
    window is incomplete, and evidence has to be reviewable after the fact --
    a log line that scrolled past is not an audit trail.
    """

    __tablename__ = "ingest_rejections"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    ingest_run_id: Mapped[str] = mapped_column(String(64), index=True)

    file: Mapped[str] = mapped_column(String(128))
    raw_index: Mapped[int] = mapped_column(Integer, default=-1)

    #: The identity the record was about, when we could determine it. Null means
    #: the record could not be attributed to anyone -- which is why such a
    #: record is fatal to the run rather than merely rejected.
    record_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    field_path: Mapped[str | None] = mapped_column(String(256), nullable=True)
    reason: Mapped[str] = mapped_column(Text)

    #: The person the rejected record concerned, when it could be read off the
    #: raw record. This is what connects a rejection to a *user's* evidence
    #: quality -- without it a rejected record is a floating error message and
    #: nobody's coverage gets downgraded.
    actor_hint: Mapped[str | None] = mapped_column(String(256), nullable=True)

    #: The offending value, kept verbatim so the source export can be corrected.
    raw_value: Mapped[Any] = mapped_column(JSON, nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<IngestRejectionRow {self.file}[{self.raw_index}] {self.reason}>"
