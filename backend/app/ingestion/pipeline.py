"""The ingest pipeline: files in, ``InMemoryDataset`` plus an audit report out.

Five stages, in this order, for reasons that are not arbitrary:

1. **Load** each source independently. A missing file degrades that source only:
   the blueprint's "missing activity logs" scenario *requires* HR, IdP and
   entitlements to load normally while telemetry is absent, so an abort-on-first
   -failure pipeline could not express the scenario at all.
2. **Resolve** identities from the HR and IdP records that did load.
3. **Normalize** entitlements and events, which need that resolver.
4. **Assemble** per-user activity slices, gaps included.
5. **Persist** idempotently, then report.

Note what stage 1 does *not* do: it does not decide what anything means. Nothing
in this module knows what a finding is, and no rule from blueprint §8 lives here.
Ingestion establishes facts and their completeness; the Phase 2 engine draws
conclusions from them. Keeping that line bright is what lets the engine be
tested without a database, a file system, or this module.

The pipeline is deliberately runnable **with no database at all** (``session``
is optional). That is not a convenience: it is what makes the deterministic core
testable in memory, and it means a future connector can be validated without
first standing up storage.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.enums import Coverage, IngestStatus, SourceSystem
from app.core.errors import FatalIngestError, IngestRejection
from app.core.time import ensure_utc, utcnow
from app.ingestion import repository
from app.ingestion.base import LoadResult
from app.ingestion.dataset import InMemoryDataset
from app.ingestion.loaders import ALL_LOADERS
from app.ingestion.normalizer import (
    build_activity_slices,
    normalize_entitlements,
    normalize_events,
    normalize_identities,
    normalize_users,
)
from app.ingestion.resolution import IdentityResolver
from app.models.ingest import IngestRunRow
from app.schemas.ingest import IngestReport
from app.schemas.raw.activity import RawSourceCoverage

__all__ = ["IngestPipeline", "SOURCE_FILENAMES", "load_dataset"]


#: The files an ingest run consumes, in the order they are read. Named here
#: rather than discovered by globbing ``data/`` so that adding a file to the
#: directory cannot silently change what a run considers its inputs.
SOURCE_FILENAMES: tuple[str, ...] = (
    "users_hr.json",
    "idp_state.json",
    "entitlements.json",
    "activity_logs.json",
)


@dataclass
class _Loaded:
    """Everything stage 1 produced, kept together so stages 2-4 stay pure."""

    results: dict[SourceSystem, LoadResult]

    def records(self, source: SourceSystem) -> list[object]:
        result = self.results.get(source)
        return list(result.records) if result else []

    def all_rejections(self) -> list[IngestRejection]:
        collected: list[IngestRejection] = []
        for result in self.results.values():
            collected.extend(result.rejections)
        return collected

    def rejections_for(self, source: SourceSystem) -> list[IngestRejection]:
        """Rejections produced by *reading* one source's file.

        Stage 1 rejects records it cannot parse; stage 2 rejects records it
        parses but cannot attribute. Coverage arithmetic has to see both, which
        is why this exists separately from :meth:`all_rejections`.
        """
        result = self.results.get(source)
        return list(result.rejections) if result else []

    def coverage_manifest(self) -> list[RawSourceCoverage]:
        result = self.results.get(SourceSystem.ACTIVITY)
        if result is None:
            return []
        return [entry for entry in result.coverage if isinstance(entry, RawSourceCoverage)]

    def activity_loaded(self) -> bool:
        result = self.results.get(SourceSystem.ACTIVITY)
        return bool(result is not None and result.file_ok)

    def file_failures(self) -> list[str]:
        return [
            f"{result.filename}: {result.error}"
            for result in self.results.values()
            if not result.file_ok
        ]


class IngestPipeline:
    """Reads the fixture feeds and produces a normalized dataset."""

    def __init__(
        self,
        settings: Settings | None = None,
        data_dir: Path | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.data_dir = Path(data_dir or self.settings.data_dir)

    # -- stage 1 ----------------------------------------------------------- #

    def load_sources(self) -> _Loaded:
        """Read every source, independently of every other source."""
        if not self.data_dir.exists():
            raise FatalIngestError(
                f"data directory {self.data_dir} does not exist; there is no "
                "input to ingest"
            )

        results: dict[SourceSystem, LoadResult] = {}
        for loader in ALL_LOADERS():
            result = loader.load(self.data_dir)
            results[loader.source] = result
        return _Loaded(results=results)

    # -- stages 2-4 -------------------------------------------------------- #

    def _require_declared_coverage(self, loaded: _Loaded) -> None:
        """Every enabled source must be declared in the coverage manifest.

        A source that is simply absent from the manifest is the most dangerous
        shape of missing data, because it is indistinguishable from a source
        that had nothing to report. Forcing an explicit ``MISSING`` row means an
        operator (or a future connector) has to *state* that the data is absent,
        which is what turns "we could not see this" into a fact the engine can
        reason about.

        Skipped when the activity file failed to load: that case already
        produces ``NOT_QUERIED`` coverage, which is a different and more honest
        statement than a missing manifest row, and reporting it as a manifest
        problem would send someone to debug the wrong file.
        """
        if not loaded.activity_loaded():
            return

        declared = {entry.source for entry in loaded.coverage_manifest()}
        undeclared = [
            source
            for source in self.settings.enabled_activity_sources
            if source not in declared
        ]
        if undeclared:
            names = ", ".join(str(source) for source in undeclared)
            raise FatalIngestError(
                f"the coverage manifest does not declare {names}; every enabled "
                "source must state whether it delivered data, because an absent "
                "entry cannot be told apart from a source that had nothing to say"
            )

    def build_dataset(self, loaded: _Loaded) -> InMemoryDataset:
        """Normalize everything into one immutable dataset."""
        users = normalize_users(loaded.records(SourceSystem.HR))
        if not users:
            # Not a data-quality problem: with no people there is no review to
            # perform, and returning an empty dataset would render as "nobody
            # has a problem" -- the most dangerous possible failure mode for
            # this product.
            raise FatalIngestError(
                "no users were loaded from users_hr.json; an empty review "
                "population would be indistinguishable from a clean one"
            )

        pre_resolver = IdentityResolver(users, [])
        identities, identity_rejections = normalize_identities(
            loaded.records(SourceSystem.IDP), pre_resolver
        )

        # Rebuilt with the resolved identities so that logins and account ids
        # from the directory are usable when resolving entitlements and events.
        resolver = IdentityResolver(users, identities)

        entitlements, entitlement_rejections = normalize_entitlements(
            loaded.records(SourceSystem.ENTITLEMENT), resolver, self.settings
        )
        activity = normalize_events(loaded.records(SourceSystem.ACTIVITY), resolver)

        # Both kinds of activity rejection feed the coverage arithmetic: the
        # records the loader could not parse, and the records the normalizer
        # read but could not attribute to a person. ``_verdict_for_source``
        # subtracts rejections from the declared-versus-parsed shortfall, so
        # passing only one kind would leave the other looking like records that
        # simply vanished -- one malformed record would read as a truncated
        # export, degrading coverage for *every* user of that source and
        # destroying findings the data fully supports.
        activity_rejections = [
            *loaded.rejections_for(SourceSystem.ACTIVITY),
            *activity.rejections,
        ]

        self._require_declared_coverage(loaded)

        window = self.settings.window()
        slices = build_activity_slices(
            users=users,
            entitlements=entitlements,
            events=activity.events,
            manifest=loaded.coverage_manifest(),
            rejections=activity_rejections,
            resolver=resolver,
            settings=self.settings,
            window=window,
            activity_loaded=loaded.activity_loaded(),
        )

        content_hash = self.compute_content_hash()
        generated_at = self._generated_at(loaded)

        return InMemoryDataset(
            users=tuple(users),
            identities=tuple(identities),
            entitlements=tuple(entitlements),
            slices=slices,
            window=window,
            coverage_manifest=tuple(loaded.coverage_manifest()),
            rejections=tuple(
                [
                    # Loader rejections (all sources) + the activity
                    # normalizer's, which are stage-2 and so are not in
                    # ``all_rejections``.
                    *loaded.all_rejections(),
                    *identity_rejections,
                    *entitlement_rejections,
                    *activity.rejections,
                ]
            ),
            unattributable_actors=tuple(activity.unattributable),
            generated_at=generated_at,
            content_hash=content_hash,
        )

    # -- stage 5 ----------------------------------------------------------- #

    def run(
        self,
        session: Session | None = None,
        *,
        skip_if_unchanged: bool = True,
    ) -> tuple[IngestReport, InMemoryDataset]:
        """Run the pipeline, optionally persisting and optionally short-circuiting.

        The dataset is built even when persistence is skipped, so that callers
        always receive the facts alongside the report of how they were obtained.
        """
        run_id = uuid.uuid4().hex
        started_at = utcnow()
        content_hash = self.compute_content_hash()

        if session is not None and skip_if_unchanged:
            previous = self._previous_run_id(session, content_hash)
            if previous is not None:
                loaded = self.load_sources()
                dataset = self.build_dataset(loaded)
                report = IngestReport(
                    run_id=run_id,
                    status=IngestStatus.SKIPPED_UNCHANGED,
                    started_at=started_at,
                    finished_at=utcnow(),
                    content_hash=content_hash,
                    counts=repository.counts_by_table(session),
                    warnings=[
                        f"inputs unchanged since run {previous}; nothing was rewritten"
                    ],
                )
                return report, dataset

        loaded = self.load_sources()
        dataset = self.build_dataset(loaded)

        if session is not None:
            # Domain rows first, so the counts in the report describe what is
            # actually stored rather than what was about to be stored.
            self._persist_domain(session, dataset)

            # Coverage and rejection rows are written *before* the counts are
            # taken, and the run row is written last. ``record_ingest_run``
            # stores these counts as the run's permanent record of what it
            # wrote, so taking them any earlier had every run report zero
            # rejections and zero coverage rows -- an audit trail that
            # contradicts the two tables it is supposed to describe.
            repository.replace_source_coverage(
                session, run_id, dataset.coverage_manifest
            )
            repository.record_rejections(session, run_id, dataset.rejections)
            session.flush()
            counts = repository.counts_by_table(session)
        else:
            counts = self._in_memory_counts(dataset)

        warnings = self._warnings(dataset, loaded)
        status = (
            IngestStatus.SUCCEEDED_WITH_REJECTIONS
            if dataset.rejections
            else IngestStatus.SUCCEEDED
        )

        report = IngestReport(
            run_id=run_id,
            status=status,
            started_at=started_at,
            finished_at=utcnow(),
            content_hash=content_hash,
            counts=counts,
            rejections=list(dataset.rejections),
            warnings=warnings,
        )

        if session is not None:
            # One commit for domain, audit and run row together: a run row that
            # survived a rolled-back data write would claim evidence exists that
            # does not, and coverage rows are what a finding cites for
            # "we could not see this".
            repository.record_ingest_run(session, report)
            session.commit()

        return report, dataset

    # -- helpers ----------------------------------------------------------- #

    def compute_content_hash(self) -> str:
        """SHA-256 over the source files plus the analysis window.

        The window is included because the same files analyzed over a different
        lookback are not the same dataset -- Bob's events could be entirely
        inside one window and outside the next.
        """
        digest = hashlib.sha256()
        start, end = self.settings.window()
        digest.update(f"window:{start.isoformat()}:{end.isoformat()}".encode())
        for filename in SOURCE_FILENAMES:
            digest.update(f"\nfile:{filename}\n".encode())
            path = self.data_dir / filename
            try:
                digest.update(path.read_bytes())
            except OSError as exc:
                # A missing file is part of the content: two runs that are both
                # missing it are genuinely the same inputs, and a run that
                # gains the file is genuinely different.
                digest.update(f"<unreadable: {exc.__class__.__name__}>".encode())
        return digest.hexdigest()

    def _generated_at(self, loaded: _Loaded) -> datetime | None:
        """The sources' own ``generated_at``, when they agree.

        Only reported when every file that loaded states the same instant.
        Two sources disagreeing about when their export was produced is a real
        signal -- it means the review is joining facts from different moments --
        so the disagreement is surfaced as ``None`` rather than smoothed over by
        picking one arbitrarily.
        """
        stamps: set[datetime] = set()
        for result in loaded.results.values():
            if not result.file_ok or result.envelope is None:
                continue
            value = result.envelope.get("generated_at")
            if not isinstance(value, str):
                continue
            try:
                stamps.add(ensure_utc(datetime.fromisoformat(value)))
            except ValueError:
                # An unparseable header is a rejection-worthy problem, but it is
                # not worth failing the run over: nothing downstream reads it.
                continue
        if len(stamps) == 1:
            return next(iter(stamps))
        return None

    @staticmethod
    def _in_memory_counts(dataset: InMemoryDataset) -> dict[str, int]:
        return {
            "users": len(dataset.users),
            "identities": len(dataset.identities),
            "entitlements": len(dataset.entitlements),
            "activity_events": sum(len(s.events) for s in dataset.slices.values()),
            "source_coverage": len(dataset.coverage_manifest),
            "ingest_rejections": len(dataset.rejections),
        }

    def _warnings(self, dataset: InMemoryDataset, loaded: _Loaded) -> list[str]:
        warnings: list[str] = []

        for failure in loaded.file_failures():
            warnings.append(
                f"source file could not be read ({failure}); findings that "
                "depend on it will report insufficient evidence"
            )

        for entry in dataset.coverage_manifest:
            if entry.status is Coverage.MISSING:
                warnings.append(
                    f"{entry.source} declared MISSING for this window"
                    + (f": {entry.note}" if entry.note else "")
                )
            elif entry.status is Coverage.PARTIAL:
                warnings.append(
                    f"{entry.source} declared PARTIAL for this window"
                    + (f": {entry.note}" if entry.note else "")
                )

        if dataset.unattributable_actors:
            warnings.append(
                f"{len(dataset.unattributable_actors)} valid event(s) could not "
                "be attributed to a person (shared roles or service principals); "
                "they are recorded but degrade no individual's coverage"
            )

        return warnings

    def _persist_domain(self, session: Session, dataset: InMemoryDataset) -> None:
        """Upsert the domain tables. Idempotent; a repeat run writes nothing."""
        repository.upsert_users(session, dataset.users)
        repository.upsert_identities(session, dataset.identities)
        repository.upsert_entitlements(session, dataset.entitlements)
        repository.upsert_activity_events(
            session,
            [event for slice_ in dataset.slices.values() for event in slice_.events],
        )

    @staticmethod
    def _previous_run_id(session: Session, content_hash: str) -> str | None:
        """The most recent successful run over identical inputs, if any."""
        stmt = (
            select(IngestRunRow.run_id)
            .where(IngestRunRow.content_hash == content_hash)
            .where(IngestRunRow.status != str(IngestStatus.FAILED))
            .order_by(IngestRunRow.started_at.desc())
            .limit(1)
        )
        return session.scalars(stmt).first()


def load_dataset(settings: Settings | None = None) -> InMemoryDataset:
    """Convenience: load and normalize without touching a database."""
    pipeline = IngestPipeline(settings)
    _, dataset = pipeline.run(session=None)
    return dataset


def summarize_rejections(rejections: Sequence[IngestRejection]) -> str:
    """One line per rejection, for logs and for test failure output."""
    if not rejections:
        return "no rejected records"
    return "\n".join(f"  - {rejection}" for rejection in rejections)
