"""Error types for ingestion.

A fixture that fails to load must say *which file*, *which record*, and *which
field*. "Validation failed" is not an acceptable message in a system whose
whole premise is auditability: if a record could not be read, the reviewer has
to be able to see that it existed and why it was set aside.

Two distinct outcomes, and the distinction is load-bearing:

* :class:`IngestRejection` - a record we could identify but not accept. It is
  recorded, surfaced in the API, and downgrades the affected user's evidence
  coverage to PARTIAL. This is how "invalid timestamp" becomes "insufficient
  evidence" rather than a silently cleaner dataset.
* :class:`FatalIngestError` - we cannot even establish *who a record is about*.
  Without identity there is no one to downgrade coverage for, so continuing
  would drop evidence with no trace. This aborts the run instead.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

__all__ = [
    "AccessLensError",
    "FatalIngestError",
    "IngestRejection",
    "format_validation_error",
]


class AccessLensError(Exception):
    """Base class for all AccessLens errors."""


class FatalIngestError(AccessLensError):
    """Raised when a failure cannot be attributed to a specific record.

    Reserve this for conditions under which no honest dataset can be produced at
    all: the data directory is missing, no users could be read, or the coverage
    manifest does not declare every enabled source. Each of those would
    otherwise yield a dataset that *looks* clean -- an empty review population,
    or a source silently treated as complete -- and a security tool that reports
    "nothing wrong" when it is blind is worse than one that refuses to run.

    A failure that *can* be pinned on specific records does not come through
    here. Those are collected as :class:`IngestRejection` values and downgrade
    the affected user's coverage, so one unreadable record costs one user's
    certainty rather than the whole run.
    """


@dataclass(frozen=True, slots=True)
class IngestRejection:
    """One source record that was identified but not accepted.

    Kept as data rather than an exception so that a single bad record does not
    abort a run -- the other sources still load, and the affected identity's
    coverage is downgraded so its findings say "we could not fully see this"
    instead of implying a clean result.
    """

    file: str
    raw_index: int
    reason: str
    record_id: str | None = None
    field_path: str | None = None
    raw_value: Any = None

    #: Best-effort identity of the *person* the record concerned, read from
    #: whichever source-native field is present. The record failed validation,
    #: so this is a hint rather than a fact -- but it is the difference between
    #: "some activity log was unreadable" and "Bob's activity evidence is now
    #: incomplete". Without it, a rejected record would silently reduce a user's
    #: evidence quality with nobody to attribute it to, which is the same
    #: invisible-degradation failure this whole design exists to prevent.
    actor_hint: str | None = None

    #: The upstream telemetry source this record came from, when it could be
    #: read off the raw record. Used to reconcile a manifest's declared record
    #: count against what actually parsed: a shortfall explained by rejections
    #: is a per-record problem, while a shortfall nobody can explain means the
    #: whole export is truncated. Left ``None`` when it cannot be determined,
    #: which deliberately leaves the shortfall unexplained -- the safe direction.
    source: str | None = None

    def locator(self) -> str:
        """Human- and log-friendly position string, e.g. ``activity_logs.json[7]``."""
        where = f"{self.file}[{self.raw_index}]"
        if self.record_id is not None:
            where += f" (id={self.record_id!r})"
        if self.field_path:
            where += f".{self.field_path}"
        return where

    def __str__(self) -> str:  # pragma: no cover - convenience only
        return f"{self.locator()}: {self.reason}"


def format_validation_error(
    *,
    file: str,
    raw_index: int,
    record_id: str | None,
    error: ValidationError,
    actor_hint: str | None = None,
    source: str | None = None,
) -> list[IngestRejection]:
    """Turn a Pydantic ``ValidationError`` into one rejection per bad field.

    Pydantic reports errors for a whole model at once; collapsing them into a
    single string loses the per-field detail that makes a fixture fixable. One
    rejection per error keeps ``.locator()`` precise.
    """
    rejections: list[IngestRejection] = []
    for detail in error.errors():
        loc = detail.get("loc", ())
        field_path = ".".join(str(part) for part in loc) if loc else None
        rejections.append(
            IngestRejection(
                file=file,
                raw_index=raw_index,
                record_id=record_id,
                field_path=field_path,
                reason=detail.get("msg", "validation error"),
                raw_value=detail.get("input"),
                actor_hint=actor_hint,
                source=source,
            )
        )
    return rejections
