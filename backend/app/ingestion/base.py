"""Source loader abstraction.

Each loader stands in for a connector. In the prototype it reads a JSON file; in
production the same interface would call Workday, Okta, IAM and CloudTrail. That
is deliberate: swapping the fixture for a live integration should be a
substitution, not a rewrite.

Two failure modes, handled differently and on purpose:

* **A single bad record** is rejected and recorded. The rest of the file loads,
  and the affected user's evidence coverage is downgraded so their findings say
  "we could not fully see this" rather than implying a clean result.
* **A whole file failing** is recorded too, and does *not* stop the other
  sources. This matters more than it looks: the blueprint's "missing activity
  logs" scenario requires the other sources to load normally while one is
  absent. A pipeline that aborted on the first missing file could never express
  that scenario at all.

Neither case is silent.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, ValidationError

from app.core.enums import SourceSystem
from app.core.errors import IngestRejection, format_validation_error

__all__ = ["LoadResult", "JsonSourceLoader", "SourceLoader"]


@dataclass
class LoadResult:
    """Outcome of loading one source file.

    Immutable in spirit: everything a downstream stage needs is carried here
    rather than stashed on the loader, so a loader instance can be reused or
    shared without one load's state leaking into the next.
    """

    source: SourceSystem
    filename: str
    records: list[Any] = field(default_factory=list)
    rejections: list[IngestRejection] = field(default_factory=list)

    #: The parsed file, for loaders that need more than the record list -- the
    #: activity loader reads its coverage manifest from here. Kept on the result
    #: rather than on the loader so instances stay stateless between runs.
    envelope: dict[str, Any] | None = None

    #: The source's own statement about what it did and did not send. Populated
    #: only by the activity loader; empty for the others, and empty is treated
    #: as "no vouching possible" rather than as "everything is fine".
    coverage: list[Any] = field(default_factory=list)

    #: False when the file could not be read or parsed at all.
    file_ok: bool = True
    error: str | None = None

    @property
    def loaded_count(self) -> int:
        return len(self.records)

    def record_counts_by_source(self) -> dict[str, int]:
        """Parsed event count per ``source`` value.

        Cross-checked against each manifest entry's declared ``record_count``:
        a source claiming to have sent 400 events while 12 parsed is truncated,
        however it labels itself.
        """
        counts: dict[str, int] = {}
        for record in self.records:
            key = getattr(record, "source", None)
            if key is None:
                continue
            counts[str(key)] = counts.get(str(key), 0) + 1
        return counts


class SourceLoader(Protocol):
    """Reads one upstream system's export into validated raw records."""

    source: SourceSystem
    filename: str

    def load(self, data_dir: Path) -> LoadResult: ...


def _record_identifier(item: Any) -> str | None:
    """Best-effort identity for an unvalidated record, for error messages.

    Read defensively: the record failed validation precisely because it may not
    have the shape we expect, so every lookup is guarded.
    """
    if not isinstance(item, dict):
        return None
    for key in ("id", "account_id", "event_id", "eventID", "username"):
        value = item.get(key)
        if isinstance(value, str):
            return value
    return None


class JsonSourceLoader:
    """Base loader for the ``{"generated_at": ..., "<key>": [...]}`` envelope shape.

    Subclasses set :attr:`envelope_key` and :attr:`record_model`. Records are
    validated **one at a time** so that a single malformed entry becomes a
    rejection rather than a whole-file failure -- losing sixty good events
    because one has a truncated timestamp is precisely the kind of data loss
    that would make a low-usage finding wrong.
    """

    source: SourceSystem
    filename: str
    envelope_key: str
    record_model: type[BaseModel]

    def load(self, data_dir: Path) -> LoadResult:
        path = data_dir / self.filename

        if not path.exists():
            return self._file_failure(f"{self.filename} not found in {data_dir}")

        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            return self._file_failure(f"{self.filename} is not valid JSON: {exc}")

        if not isinstance(payload, dict):
            return self._file_failure(
                f"{self.filename} must contain a JSON object at the top level"
            )

        items = payload.get(self.envelope_key)
        if not isinstance(items, list):
            return self._file_failure(
                f"{self.filename} must contain a list at {self.envelope_key!r} "
                f"(found {type(items).__name__})"
            )

        records, rejections = self._validate_records(items)
        return LoadResult(
            source=self.source,
            filename=self.filename,
            records=records,
            rejections=rejections,
            envelope=payload,
        )

    def _file_failure(self, message: str) -> LoadResult:
        return LoadResult(
            source=self.source, filename=self.filename, file_ok=False, error=message
        )

    def _validate_records(
        self, items: list[Any]
    ) -> tuple[list[Any], list[IngestRejection]]:
        records: list[Any] = []
        rejections: list[IngestRejection] = []

        for index, item in enumerate(items):
            try:
                record = self._validate_one(item)
            except ValidationError as exc:
                rejections.extend(
                    format_validation_error(
                        file=self.filename,
                        raw_index=index,
                        record_id=_record_identifier(item),
                        error=exc,
                        actor_hint=self._actor_hint(item),
                        source=self._rejection_source(item),
                    )
                )
                continue
            # Inject the source position so any later error or stored row can
            # name the exact record it came from.
            records.append(record.model_copy(update={"raw_index": index}))

        return records, rejections

    def _validate_one(self, item: Any) -> BaseModel:
        """Validate a single record.

        Split out so a loader whose records are a discriminated union can swap
        in a ``TypeAdapter`` without duplicating the loop -- and, more
        importantly, without duplicating the rejection handling. The
        ``actor_hint`` plumbing in particular belongs in exactly one place.
        """
        return self.record_model.model_validate(item)

    def _actor_hint(self, item: Any) -> str | None:  # noqa: ARG002
        """Whose record is this, read defensively from an unvalidated dict.

        Overridden by loaders whose records carry an actor in a source-specific
        field. The default returns ``None`` -- for HR, IdP and entitlement
        exports the identifying field *is* the record id, which
        :func:`_record_identifier` already captures.
        """
        return None

    def _rejection_source(self, item: Any) -> str | None:  # noqa: ARG002
        """Which telemetry feed this record came from, when that is meaningful.

        ``None`` for every loader but the activity one. Only telemetry
        rejections participate in the manifest's declared-versus-parsed
        reconciliation, so inventing a source for the other three would put
        records into an arithmetic they have no part in.
        """
        return None
