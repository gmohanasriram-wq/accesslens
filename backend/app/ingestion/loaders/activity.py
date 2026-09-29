"""Loads the telemetry export, including its coverage manifest."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import TypeAdapter, ValidationError

from app.core.enums import SourceSystem
from app.core.errors import IngestRejection, format_validation_error
from app.ingestion.base import JsonSourceLoader, LoadResult
from app.schemas.raw.activity import RawActivityEvent, RawSourceCoverage

__all__ = ["ActivityLoader"]

#: A discriminated union needs a TypeAdapter rather than ``model_validate``.
_EVENT_ADAPTER: TypeAdapter[Any] = TypeAdapter(RawActivityEvent)


class ActivityLoader(JsonSourceLoader):
    """Reads ``data/activity_logs.json``.

    Differs from the other loaders in two ways, both because this file is an
    envelope rather than a bare list:

    * events are a *discriminated union* -- each record is validated against the
      variant named by its ``source`` field, so a malformed CloudTrail record
      fails as CloudTrail rather than as "some event";
    * the file carries a **coverage manifest**, the source systems' own
      statement about what they did and did not send. That manifest is what
      makes "no activity observed" distinguishable from "no logs received", so
      it is loaded with the same care as the events themselves.
    """

    source = SourceSystem.ACTIVITY
    filename = "activity_logs.json"
    envelope_key = "events"

    def load(self, data_dir: Path) -> LoadResult:
        result = super().load(data_dir)
        if result.file_ok and result.envelope is not None:
            coverage, manifest_rejections = self._parse_coverage(result.envelope)
            result.coverage = coverage
            # A malformed manifest entry is a rejection, not a shrug: dropping
            # it silently would erase the evidence that a source was missing.
            result.rejections.extend(manifest_rejections)
        return result

    def _validate_one(self, item: Any) -> Any:
        """Validate one event against the union variant its ``source`` names."""
        return _EVENT_ADAPTER.validate_python(item)

    def _actor_hint(self, item: Any) -> str | None:
        """Whose event was this, read from an unvalidated record.

        Worth the defensive lookup here in a way it is not for the other
        sources: an activity record is the *only* thing that can later prove a
        user's access was used, so a rejected one silently removes evidence.
        Naming the person turns "one activity record was unreadable" into
        "Ivan's activity evidence is incomplete", which is what lets his
        coverage be downgraded to PARTIAL instead of nothing being said at all.

        Each source names its actor differently, and the record failed
        validation precisely because it may not have the shape we expect --
        hence ``userIdentityArn`` (CloudTrail), ``actor`` (GitHub) and ``user``
        (proxy), all guarded.
        """
        if not isinstance(item, dict):
            return None
        for key in ("userIdentityArn", "actor", "user"):
            value = item.get(key)
            if isinstance(value, str) and value:
                return value
        return None

    def _rejection_source(self, item: Any) -> str | None:
        """Which feed the failed record claimed to come from.

        Read from the raw dict rather than from the validated model, because the
        model is precisely what failed to build. ``source`` is the discriminator,
        so it is the field most likely to be present even when the rest of the
        record is malformed -- and if it is missing too, we return ``None`` and
        the record stays in the *unexplained* remainder of the manifest
        reconciliation, which degrades coverage. That is the correct outcome for
        a record we cannot even place.
        """
        if not isinstance(item, dict):
            return None
        value = item.get("source")
        return value if isinstance(value, str) else None

    def _parse_coverage(
        self, envelope: dict[str, Any]
    ) -> tuple[list[RawSourceCoverage], list[IngestRejection]]:
        raw_manifest = envelope.get("coverage", [])
        if not isinstance(raw_manifest, list):
            return [], [
                IngestRejection(
                    file=self.filename,
                    raw_index=-1,
                    field_path="coverage",
                    reason="coverage manifest must be a list",
                    raw_value=raw_manifest,
                )
            ]

        parsed: list[RawSourceCoverage] = []
        rejections: list[IngestRejection] = []
        for index, entry in enumerate(raw_manifest):
            try:
                parsed.append(RawSourceCoverage.model_validate(entry))
            except ValidationError as exc:
                rejections.extend(
                    format_validation_error(
                        file=self.filename,
                        raw_index=index,
                        record_id=entry.get("source")
                        if isinstance(entry, dict)
                        else None,
                        error=exc,
                    )
                )
        return parsed, rejections
