"""The result of one ingestion run.

An ingestion run is not just "did it work". It carries the hash of the inputs it
consumed (so a finding can be tied to the exact fixture revision that produced
it), per-source counts, and every record that was identified but rejected.
"""

from __future__ import annotations

from pydantic import AwareDatetime, Field

from app.core.enums import IngestStatus
from app.core.errors import IngestRejection
from app.core.time import UTCModel

__all__ = ["IngestReport"]


class IngestReport(UTCModel):
    """Outcome of a single ingestion run."""

    run_id: str
    status: IngestStatus
    started_at: AwareDatetime
    finished_at: AwareDatetime | None = None

    #: SHA-256 over the source files plus the analysis window. Two runs with the
    #: same hash would produce the same dataset, which is what lets ingestion be
    #: skipped when nothing has changed.
    content_hash: str = ""

    #: Rows written per table, e.g. ``{"users": 9, "activity_events": 74}``.
    counts: dict[str, int] = Field(default_factory=dict)

    #: Records that were identified but not accepted. Non-empty means the run is
    #: ``SUCCEEDED_WITH_REJECTIONS`` and affected users have reduced coverage.
    rejections: list[IngestRejection] = Field(default_factory=list)

    #: Non-fatal observations worth surfacing (e.g. "source declared MISSING").
    warnings: list[str] = Field(default_factory=list)

    @property
    def total_rejected(self) -> int:
        return len(self.rejections)

    def rejection_summary(self) -> str:
        """One line per rejection, for logs and test failure output."""
        if not self.rejections:
            return "no rejected records"
        return "\n".join(f"  - {r}" for r in self.rejections)
