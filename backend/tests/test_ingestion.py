"""Persistence and idempotency: the pipeline's fifth stage, and its audit trail.

The pipeline is testable without a database by design, which means the database
path is the one that can rot unnoticed -- everything else would still be green.
So these tests are deliberately about what *survives*: that the rows written
agree with the dataset that produced them, that a second identical run changes
nothing, and that the evidence for an incomplete window is still there after the
process that discovered it has exited.

Expected values come from ``tests/fixtures/oracles/expected_findings.json``
rather than from the code, so a fixture edit that changes the arithmetic has to
be reconciled against the oracle instead of quietly redefining the baseline.
"""

from __future__ import annotations

import json

import pytest
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.enums import Coverage, IngestStatus, SourceSystem
from app.db import session_scope
from app.ingestion import IngestPipeline
from app.models.activity import SourceCoverageRow
from app.models.entitlement import EntitlementRow
from app.models.identity import IdentityRow
from app.models.ingest import IngestRejectionRow, IngestRunRow
from app.models.user import UserRow


def _rows(factory: sessionmaker[Session], model) -> list:
    with factory() as session:
        return list(session.scalars(select(model)).all())


# --------------------------------------------------------------------------- #
# What was written
# --------------------------------------------------------------------------- #


def test_persisted_counts_match_the_dataset_that_produced_them(ingesting) -> None:
    """The database holds exactly what ingestion says it holds.

    Checked against the in-memory dataset rather than against fixed numbers, so
    this catches a persistence bug (a dropped row, a duplicated upsert) without
    becoming a second, redundant oracle for the fixture contents.
    """
    factory, report, dataset = ingesting

    assert report.counts["users"] == len(dataset.users)
    assert report.counts["entitlements"] == len(dataset.entitlements)
    assert report.counts["activity_events"] == sum(
        len(s.events) for s in dataset.slices.values()
    )
    assert report.counts["ingest_rejections"] == len(dataset.rejections)

    # And the counts describe stored rows, not intended ones.
    assert len(_rows(factory, UserRow)) == len(dataset.users)
    assert len(_rows(factory, EntitlementRow)) == len(dataset.entitlements)
    assert len(_rows(factory, IdentityRow)) == sum(
        len(dataset.identities_for(user.id)) for user in dataset.users
    )


def test_dataset_level_expectations_hold(ingesting, oracle) -> None:
    """The oracle's whole-set arithmetic, asserted against the built dataset."""
    _, _, dataset = ingesting
    expected = oracle["dataset_level_expectations"]

    assert len(dataset.users) == expected["user_count"]
    assert len(dataset.entitlements) == expected["entitlement_count"]
    assert sorted(dataset.unattributable_actors) == expected["unattributable_actors"]

    missing = {
        str(entry.source)
        for entry in dataset.coverage_manifest
        if entry.status is Coverage.MISSING
    }
    assert sorted(missing) == expected["sources_declared_missing"]


def test_rejected_records_are_counted_per_file(ingesting, oracle) -> None:
    """Rejections are attributed to the file they came from.

    A single total would hide which export needs fixing, which is the only
    actionable fact about a rejected record.
    """
    _, _, dataset = ingesting
    expected = oracle["dataset_level_expectations"]["rejected_records"]

    by_file: dict[str, int] = {}
    for rejection in dataset.rejections:
        by_file[rejection.file] = by_file.get(rejection.file, 0) + 1

    assert by_file == expected, (
        f"rejections by file were {by_file}, oracle expects {expected}: "
        f"{dataset.rejections}"
    )


def test_every_rejection_is_persisted_and_locatable(ingesting) -> None:
    """A rejection that cannot be traced back to a record cannot be fixed.

    This is the reason rejections are a table rather than a log line: the run
    that discovered them is long gone by the time someone investigates.
    """
    factory, report, dataset = ingesting
    stored = _rows(factory, IngestRejectionRow)

    assert len(stored) == len(dataset.rejections) == report.total_rejected
    assert stored, "the fixture set is supposed to contain rejected records"

    for row in stored:
        assert row.file, "a rejection with no file names cannot be acted on"
        assert row.reason
        assert row.ingest_run_id == report.run_id


def test_an_unattributable_event_is_recorded_not_dropped(ingesting) -> None:
    """A valid event with no owner is a finding about the *dataset*.

    It must survive as evidence rather than being discarded for the convenience
    of having nobody to attach it to: "events happened that we cannot attribute"
    is exactly the kind of thing a reviewer needs to know. It degrades no
    individual's coverage, because it cannot be pinned on an individual.
    """
    factory, _, dataset = ingesting
    assert dataset.unattributable_actors, "expected the shared-role event"

    stored = _rows(factory, IngestRejectionRow)
    unattributable = [row for row in stored if row.field_path == "actor"]
    assert len(unattributable) == len(dataset.unattributable_actors)
    assert all(row.record_id for row in unattributable)


def test_coverage_manifest_is_persisted_one_row_per_enabled_source(
    ingesting, settings: Settings
) -> None:
    """Coverage is the evidence a finding cites for "we could not see this"."""
    factory, report, dataset = ingesting
    stored = _rows(factory, SourceCoverageRow)

    assert len(stored) == len(dataset.coverage_manifest)
    assert {row.source for row in stored} == {
        str(source) for source in settings.enabled_activity_sources
    }
    assert all(row.ingest_run_id == report.run_id for row in stored)

    # A MISSING source must be stored as MISSING, not omitted. An absent row is
    # indistinguishable from a source nobody asked about.
    proxy = next(row for row in stored if row.source == "proxy_zscaler")
    assert proxy.status == Coverage.MISSING.value
    assert proxy.note, "a MISSING source must say why"


def test_the_run_itself_is_recorded(ingesting) -> None:
    factory, report, _ = ingesting
    stored = _rows(factory, IngestRunRow)

    assert [row.run_id for row in stored] == [report.run_id]
    assert stored[0].content_hash == report.content_hash
    assert stored[0].counts == report.counts
    assert stored[0].status == IngestStatus.SUCCEEDED_WITH_REJECTIONS.value
    assert stored[0].started_at.tzinfo is not None


def test_duplicate_directory_account_is_persisted_as_a_duplicate(ingesting) -> None:
    """Henry's two Okta accounts must stay visible in storage.

    Resolving them to one person is correct -- they *are* one person -- but the
    duplication itself is a review-relevant fact about directory hygiene. Storing
    only the canonical account would make the directory look cleaner than it is.
    """
    factory, _, dataset = ingesting
    henry = next(u for u in dataset.users if u.username == "henry.okafor")

    identities = _rows(factory, IdentityRow)
    his = [row for row in identities if row.user_id == henry.id]
    assert len(his) == 2

    duplicates = [row for row in his if row.is_duplicate_of]
    assert duplicates, "neither account was marked as the duplicate"
    assert all(row.is_duplicate_of in {r.account_id for r in his} for row in duplicates)


# --------------------------------------------------------------------------- #
# Re-running changes nothing
# --------------------------------------------------------------------------- #


def test_second_identical_run_is_skipped_and_writes_nothing(
    ingesting, pipeline: IngestPipeline
) -> None:
    """Idempotency, which the whole review depends on.

    Utilisation ratios are counts. A re-ingest that inserted a second copy of
    every event would double everyone's observed activity and silently change
    every finding -- the worst kind of bug, because the numbers stay plausible.
    """
    factory, first, _ = ingesting

    with session_scope(factory) as session:
        second, _ = pipeline.run(session)

    assert second.status is IngestStatus.SKIPPED_UNCHANGED
    assert second.run_id != first.run_id
    assert first.run_id in second.warnings[0], "the run it skipped should be named"

    # Nothing rewritten: same counts, and still exactly one run row.
    assert second.counts == first.counts
    assert len(_rows(factory, IngestRunRow)) == 1
    assert len(_rows(factory, UserRow)) == first.counts["users"]


def test_content_hash_is_stable_for_identical_inputs(pipeline: IngestPipeline) -> None:
    assert pipeline.compute_content_hash() == pipeline.compute_content_hash()


def test_content_hash_changes_when_the_window_changes(settings: Settings) -> None:
    """The same files over a different lookback are not the same dataset.

    Without this, widening the window would leave the hash unchanged, the run
    would be skipped as "unchanged", and the review would silently keep the old
    window's conclusions.
    """
    narrow = IngestPipeline(settings)
    shifted = IngestPipeline(
        Settings(
            analysis_as_of=settings.analysis_as_of,
            database_url=settings.database_url,
            lookback_days=settings.lookback_days + 1,
            _env_file=None,  # type: ignore[call-arg]
        )
    )
    assert narrow.compute_content_hash() != shifted.compute_content_hash()


def test_a_changed_input_file_changes_the_hash(
    tmp_path, settings: Settings
) -> None:
    """Editing a fixture must invalidate the cache, or edits would be ignored."""
    import shutil

    from app.ingestion.pipeline import SOURCE_FILENAMES

    data_dir = tmp_path / "data"
    shutil.copytree(settings.data_dir, data_dir)
    baseline = IngestPipeline(settings, data_dir=data_dir).compute_content_hash()

    target = data_dir / SOURCE_FILENAMES[0]
    target.write_text(
        json.dumps({**json.loads(target.read_text(encoding="utf-8")), "extra": 1}),
        encoding="utf-8",
    )
    edited = IngestPipeline(settings, data_dir=data_dir).compute_content_hash()

    assert edited != baseline


def test_a_missing_file_is_part_of_the_hash(tmp_path, settings: Settings) -> None:
    """Two runs both missing the file are the same inputs; gaining it is not.

    Treated as unreadable content rather than an error, so a degraded window can
    still be cached as the degraded state it is.
    """
    import shutil

    from app.ingestion.pipeline import SOURCE_FILENAMES

    complete = tmp_path / "complete"
    degraded = tmp_path / "degraded"
    shutil.copytree(settings.data_dir, complete)
    shutil.copytree(settings.data_dir, degraded)
    (degraded / SOURCE_FILENAMES[-1]).unlink()

    complete_hash = IngestPipeline(settings, data_dir=complete).compute_content_hash()
    degraded_hash = IngestPipeline(settings, data_dir=degraded).compute_content_hash()
    assert complete_hash != degraded_hash

    # And stable: the same absence hashes the same twice.
    assert (
        degraded_hash
        == IngestPipeline(settings, data_dir=degraded).compute_content_hash()
    )


def test_run_without_a_session_still_builds_the_dataset(pipeline: IngestPipeline) -> None:
    """No database, still facts. This is what keeps the engine testable.

    The Phase 2 rules are supposed to run against loaded objects with no
    database in the loop, so ``run(session=None)`` must not be a stub.
    """
    report, dataset = pipeline.run(session=None)

    assert report.counts["users"] == len(dataset.users)
    assert report.counts["users"] > 0
    assert dataset.window[0].tzinfo is not None


def test_success_status_reflects_whether_anything_was_rejected(ingesting) -> None:
    """The fixture set has rejections, so the run must not claim a clean pass.

    A run that reported ``SUCCEEDED`` while having rejected records would tell an
    operator the review is complete when part of its evidence was discarded.
    """
    _, report, dataset = ingesting

    assert dataset.rejections, "the fixture set is supposed to contain rejections"
    assert report.status is IngestStatus.SUCCEEDED_WITH_REJECTIONS
