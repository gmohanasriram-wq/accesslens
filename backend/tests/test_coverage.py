"""The coverage model.

This is the module that matters most. Every other property of AccessLens rests
on the claim that "we looked and saw nothing" and "we never looked" are
different answers, and these tests are what make that claim checkable rather
than aspirational.

The oracle assertions here are Phase 1's: coverage and usage observation are
produced by ingestion and are true today. The `finding` blocks in the oracle
belong to Phase 2.
"""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.core.config import Settings
from app.core.enums import (
    ActivitySource,
    Coverage,
    EntitlementSource,
    GapReason,
    UsageObservation,
)
from app.core.errors import FatalIngestError
from app.ingestion import InMemoryDataset, IngestPipeline
from app.ingestion.normalizer import relevant_sources_for
from app.schemas.domain.activity import ActivityEvent, ActivitySlice

WINDOW = (
    datetime(2026, 7, 1, 6, 0, tzinfo=UTC),
    datetime(2026, 9, 29, 6, 0, tzinfo=UTC),
)


# --------------------------------------------------------------------------- #
# The gate itself
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("coverage", "expected"),
    [
        (Coverage.COMPLETE, UsageObservation.NONE_OBSERVED),
        (Coverage.PARTIAL, UsageObservation.UNKNOWN),
        (Coverage.MISSING, UsageObservation.UNKNOWN),
        (Coverage.NOT_QUERIED, UsageObservation.UNKNOWN),
    ],
)
def test_usage_observation_is_gated_on_coverage(
    coverage: Coverage, expected: UsageObservation
) -> None:
    """Only COMPLETE may produce a determinate verdict.

    Parametrised over every coverage state so that adding a state to the enum
    without deciding what it means for usage fails here rather than defaulting
    silently to something.
    """
    slice_ = ActivitySlice(
        user_id="u_x", window_start=WINDOW[0], window_end=WINDOW[1], coverage=coverage
    )
    assert slice_.usage_observation is expected


def test_events_do_not_override_incomplete_coverage() -> None:
    """A partial window full of events still yields UNKNOWN, not OBSERVED.

    The gate is symmetric on purpose. Erring only in the "no events" direction
    would still let an under-counted window be reported as well-evidenced
    activity, which is the same class of error pointed the other way.
    """
    slice_ = ActivitySlice(
        user_id="u_x",
        window_start=WINDOW[0],
        window_end=WINDOW[1],
        events=[
            ActivityEvent(
                event_id="e1",
                timestamp=datetime(2026, 8, 1, tzinfo=UTC),
                actor_id="u_x",
                source=ActivitySource.AWS_CLOUDTRAIL,
                action="s3:GetObject",
            )
        ],
        coverage=Coverage.PARTIAL,
    )
    assert slice_.observed_event_count == 1
    assert slice_.usage_observation is UsageObservation.UNKNOWN


def test_denied_events_are_not_usage() -> None:
    """A refused call proves the credential was live; it is not usage.

    Carol's post-deactivation AWS call is the fixture that needs this: counting
    it as successful activity would report a blocked attempt as ghost access and
    overstate the finding.
    """
    slice_ = ActivitySlice(
        user_id="u_x",
        window_start=WINDOW[0],
        window_end=WINDOW[1],
        events=[
            ActivityEvent(
                event_id="e1",
                timestamp=datetime(2026, 8, 1, tzinfo=UTC),
                actor_id="u_x",
                source=ActivitySource.AWS_CLOUDTRAIL,
                action="ec2:DescribeInstances",
                denied=True,
            )
        ],
        coverage=Coverage.COMPLETE,
    )
    assert len(slice_.events) == 1
    assert slice_.observed_event_count == 0
    assert slice_.usage_observation is UsageObservation.NONE_OBSERVED
    assert slice_.observed_capabilities == frozenset()


# --------------------------------------------------------------------------- #
# The fixture set's actual coverage -- the oracle
# --------------------------------------------------------------------------- #


def _source_status(slice_: ActivitySlice, source: ActivitySource) -> Coverage | None:
    """Reconstruct the per-source verdict from the slice's own fields.

    ``None`` means the source was not relevant to this user at all, which is a
    different answer from MISSING and is worth being able to assert.
    """
    if source in slice_.sources_missing:
        return Coverage.MISSING
    if any(gap.source is source for gap in slice_.gaps):
        return Coverage.PARTIAL
    if source in slice_.sources_queried:
        return Coverage.COMPLETE
    return None


def test_persona_coverage_matches_oracle(dataset: InMemoryDataset, oracle: dict) -> None:
    """Every persona's coverage, usage verdict and event count, as specified."""
    by_username = {user.username: user for user in dataset.users}
    failures: list[str] = []

    for persona in oracle["personas"]:
        user = by_username.get(persona["username"])
        assert user is not None, f"oracle names unknown user {persona['username']}"
        slice_ = dataset.slice_for(user.id)

        actual = {
            "overall_coverage": slice_.coverage.value,
            "usage_observation": slice_.usage_observation.value,
            "observed_event_count": slice_.observed_event_count,
        }
        expected = {
            "overall_coverage": persona["overall_coverage"],
            "usage_observation": persona["usage_observation"],
            "observed_event_count": persona["observed_event_count"],
        }
        for key, want in expected.items():
            if actual[key] != want:
                failures.append(
                    f"{persona['username']} [{persona['scenario']}]: {key} was "
                    f"{actual[key]!r}, oracle says {want!r}"
                )

        for name, want in persona.get("coverage", {}).items():
            got = _source_status(slice_, ActivitySource(name))
            if got is None or got.value != want:
                failures.append(
                    f"{persona['username']}: source {name} was "
                    f"{got.value if got else 'NOT RELEVANT'}, oracle says {want}"
                )

        # Observed capabilities, where the oracle names them. Compared as sets
        # because capability order is not a property of anything.
        if "observed_capabilities" in persona:
            got = sorted(c.value for c in slice_.observed_capabilities)
            if got != sorted(persona["observed_capabilities"]):
                failures.append(
                    f"{persona['username']}: capabilities were {got}, oracle says "
                    f"{sorted(persona['observed_capabilities'])}"
                )

        for reason in persona.get("expected_gap_reasons", []):
            if reason not in {g.reason.value for g in slice_.gaps}:
                failures.append(
                    f"{persona['username']}: expected gap {reason}, has "
                    f"{[g.reason.value for g in slice_.gaps]}"
                )

    assert not failures, "coverage oracle mismatches:\n  " + "\n  ".join(failures)


def test_every_fixture_user_has_a_slice(dataset: InMemoryDataset) -> None:
    """No user may be missing from the slice mapping.

    `slice_for` falls back to NOT_QUERIED rather than None, so a gap here shows
    up as every user being unmeasurable rather than as a crash -- visible, but
    worth asserting directly so the assembler cannot quietly stop running.
    """
    for user in dataset.users:
        assert user.id in dataset.slices, f"{user.username} has no activity slice"


def test_unknown_user_is_treated_as_unmeasured(dataset: InMemoryDataset) -> None:
    """A user the assembler never saw is unmeasurable, never "no activity"."""
    slice_ = dataset.slice_for("u_does_not_exist")
    assert slice_ is not None
    assert slice_.coverage is Coverage.NOT_QUERIED
    assert slice_.usage_observation is UsageObservation.UNKNOWN


# --------------------------------------------------------------------------- #
# The arithmetic that decides COMPLETE vs truncated
# --------------------------------------------------------------------------- #


def test_declared_counts_reconcile_for_complete_sources(
    dataset: InMemoryDataset, oracle: dict
) -> None:
    """Declared = parsed + rejected, for every source claiming COMPLETE.

    This is the assertion that caught a real bug: when only *normalizer*
    rejections were subtracted from a declared-versus-parsed shortfall, one
    malformed CloudTrail record made the whole export look truncated and marked
    every AWS user PARTIAL. The findings the data supports survived only because
    loader rejections count toward the reconciliation too.
    """
    expectations = oracle["dataset_level_expectations"]

    for source, declared, parsed in (
        (
            ActivitySource.AWS_CLOUDTRAIL,
            expectations["aws_declared_records"],
            expectations["aws_parsed_records"],
        ),
        (
            ActivitySource.GITHUB_AUDIT,
            expectations["github_declared_records"],
            expectations["github_parsed_records"],
        ),
    ):
        parsed_actual = sum(
            1 for s in dataset.slices.values() for e in s.events if e.source is source
        )
        assert parsed_actual == parsed, f"{source} parsed count drifted"

        rejected = sum(1 for r in dataset.rejections if r.source == str(source))
        assert declared - parsed_actual - rejected == 0, (
            f"{source} declares {declared} records but {parsed_actual} parsed and "
            f"{rejected} were rejected, leaving "
            f"{declared - parsed_actual - rejected} unexplained -- the export "
            "would read as truncated"
        )


def test_one_bad_record_does_not_truncate_the_whole_source(
    dataset: InMemoryDataset,
) -> None:
    """Users of a source with a single rejected record stay COMPLETE.

    Ivan is the exception and proves the rule is not vacuous: his gap is
    RECORDS_REJECTED, attributed to *him* because the rejected record's actor
    hint resolves to his account. Everyone else on CloudTrail is untouched.
    """
    unaffected = [
        user
        for user in dataset.users
        if user.username != "ivan.petrov"
        and ActivitySource.AWS_CLOUDTRAIL in dataset.slice_for(user.id).sources_queried
    ]
    assert unaffected, "expected some users to be observing CloudTrail"

    for user in unaffected:
        slice_ = dataset.slice_for(user.id)
        assert GapReason.WINDOW_TRUNCATED not in {g.reason for g in slice_.gaps}, (
            f"{user.username} was degraded by a truncated export that did not happen"
        )
        assert slice_.coverage is Coverage.COMPLETE, (
            f"{user.username} should be COMPLETE, got {slice_.coverage}"
        )


def test_rejected_record_is_attributed_to_the_affected_user(
    dataset: InMemoryDataset,
) -> None:
    """The rejected record lowers Ivan's coverage, and only Ivan's."""
    ivan = next(u for u in dataset.users if u.username == "ivan.petrov")
    slice_ = dataset.slice_for(ivan.id)

    assert slice_.coverage is Coverage.PARTIAL
    assert slice_.usage_observation is UsageObservation.UNKNOWN
    assert GapReason.RECORDS_REJECTED in {g.reason for g in slice_.gaps}

    rejected = [r for r in dataset.rejections if r.record_id == "evt-aws-0028"]
    assert len(rejected) == 1
    assert rejected[0].source == str(ActivitySource.AWS_CLOUDTRAIL)


def test_unattributable_event_does_not_degrade_anyone(
    dataset: InMemoryDataset,
) -> None:
    """An event with no owner is a dataset caveat, not a user's coverage gap.

    The bare-role CloudTrail record resolves to nobody, so it cannot be charged
    to a person. It is still carried on the dataset so the reconciliation can
    account for it -- and it must not appear as a gap on any user's slice.
    """
    assert dataset.unattributable_actors == (
        "arn:aws:iam::123456789012:role/PlatformAdmin",
    )

    for slice_ in dataset.slices.values():
        assert GapReason.IDENTITY_UNMAPPED not in {g.reason for g in slice_.gaps}, (
            "an ownerless event was charged to a user"
        )


# --------------------------------------------------------------------------- #
# Global degradation -- the negative control for per-user scoping
# --------------------------------------------------------------------------- #


def _copy_fixtures(tmp_path: Path, settings: Settings) -> Path:
    """The real fixture set, in a directory the test may edit.

    Copied from ``settings.data_dir`` rather than from a freshly constructed
    ``Settings()``, so the source is the same hermetic, ``.env``-free value the
    other fixtures use. A test that read the developer's ``.env`` for its input
    path would not be testing what CI tests.
    """
    destination = tmp_path / "data"
    shutil.copytree(settings.data_dir, destination)
    return destination


def test_globally_truncated_source_degrades_every_user_of_that_source(
    tmp_path: Path, settings: Settings
) -> None:
    """A genuinely truncated export must still degrade everyone who relies on it.

    The counterpart to `test_one_bad_record_does_not_truncate_the_whole_source`.
    That test shows per-user scoping is not over-eager; this one shows it is not
    toothless.

    Built by editing a copy of the real fixture file rather than by constructing
    slices directly, so the assertion runs through the real loader, the real
    manifest check and the real assembler. A test that bypassed them would prove
    only that `_verdict_for_source` can subtract.
    """
    data_dir = _copy_fixtures(tmp_path, settings)
    activity_path = data_dir / "activity_logs.json"
    payload = json.loads(activity_path.read_text(encoding="utf-8"))

    # Inflate one source's declared count with no rejections to explain the
    # difference -- the signature of an export truncated in transit.
    for entry in payload["coverage"]:
        if entry["source"] == str(ActivitySource.AWS_CLOUDTRAIL):
            entry["record_count"] += 25
    activity_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    pipeline = IngestPipeline(settings, data_dir=data_dir)
    dataset = pipeline.build_dataset(pipeline.load_sources())

    aws_users = [
        user
        for user in dataset.users
        if ActivitySource.AWS_CLOUDTRAIL in dataset.slice_for(user.id).sources_queried
    ]
    assert aws_users, "expected CloudTrail users"

    for user in aws_users:
        slice_ = dataset.slice_for(user.id)
        assert slice_.coverage is Coverage.PARTIAL, (
            f"{user.username} should be degraded by a truncated export, got "
            f"{slice_.coverage}"
        )
        assert slice_.usage_observation is UsageObservation.UNKNOWN, (
            f"{user.username} reached a determinate verdict on a truncated export"
        )
        assert GapReason.WINDOW_TRUNCATED in {g.reason for g in slice_.gaps}

    # And a user who does not rely on CloudTrail keeps her own verdict: one
    # source's outage is not evidence about someone it could never have watched.
    gina = next(u for u in dataset.users if u.username == "gina.patel")
    assert dataset.slice_for(gina.id).coverage is Coverage.MISSING


def test_relevance_scoping_ignores_sources_a_user_cannot_touch(
    dataset: InMemoryDataset,
) -> None:
    """A user is only measured against sources that could observe them.

    Gina has no AWS or GitHub access, so a CloudTrail outage is not a hole in
    *her* evidence. Without this, one degraded source would mark every persona
    INSUFFICIENT_EVIDENCE and the other blueprint scenarios could never be
    exhibited.
    """
    gina = next(u for u in dataset.users if u.username == "gina.patel")
    slice_ = dataset.slice_for(gina.id)

    assert slice_.sources_missing == frozenset({ActivitySource.PROXY_ZSCALER})
    assert ActivitySource.AWS_CLOUDTRAIL not in slice_.sources_missing
    assert [g.reason for g in slice_.gaps] == [GapReason.SOURCE_MISSING]


def test_relevant_sources_is_a_union_of_access_and_observation() -> None:
    """Observation alone makes a source relevant, whatever the entitlements say.

    Otherwise a missing entitlement record could shrink someone's coverage to
    nothing -- the same failure as treating absent evidence as safe, arriving
    through a different door.
    """
    observed = frozenset({ActivitySource.GITHUB_AUDIT})
    relevant = relevant_sources_for("u_nobody", [], observed)
    assert relevant == observed

    class _ApplicationEntitlement:
        user_id = "u_x"
        source = EntitlementSource.APPLICATION

    relevant = relevant_sources_for("u_x", [_ApplicationEntitlement()], frozenset())
    assert relevant == frozenset({ActivitySource.PROXY_ZSCALER})


# --------------------------------------------------------------------------- #
# Failures of the file and of the manifest as a whole
# --------------------------------------------------------------------------- #


def test_missing_activity_file_yields_not_queried_not_missing(
    tmp_path: Path, settings: Settings
) -> None:
    """A file we never read is NOT_QUERIED, not MISSING.

    "The source says it sent nothing" and "we never opened the export" are
    different statements, and the evidence has to keep them apart. The rest of
    the sources still load: the blueprint's missing-logs scenario needs HR, IdP
    and entitlements intact.
    """
    data_dir = _copy_fixtures(tmp_path, settings)
    (data_dir / "activity_logs.json").unlink()

    pipeline = IngestPipeline(settings, data_dir=data_dir)
    dataset = pipeline.build_dataset(pipeline.load_sources())

    assert dataset.users, "the other sources must still load"
    assert dataset.coverage_manifest == ()

    for user in dataset.users:
        slice_ = dataset.slice_for(user.id)
        assert slice_.coverage is Coverage.NOT_QUERIED
        assert slice_.usage_observation is UsageObservation.UNKNOWN
        assert slice_.gaps, "an unqueried slice must still say so"
        assert all(g.reason is GapReason.SOURCE_NOT_QUERIED for g in slice_.gaps)


def test_manifest_omitting_an_enabled_source_is_fatal(
    tmp_path: Path, settings: Settings
) -> None:
    """A source absent from the manifest stops the run.

    An absent entry cannot be told apart from a source that had nothing to say,
    which is the most dangerous shape missing data can take. Removing the row is
    the check that the guard is enforced rather than merely documented.
    """
    data_dir = _copy_fixtures(tmp_path, settings)
    activity_path = data_dir / "activity_logs.json"
    payload = json.loads(activity_path.read_text(encoding="utf-8"))
    payload["coverage"] = [
        entry
        for entry in payload["coverage"]
        if entry["source"] != str(ActivitySource.PROXY_ZSCALER)
    ]
    activity_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    pipeline = IngestPipeline(settings, data_dir=data_dir)
    with pytest.raises(FatalIngestError, match="proxy_zscaler"):
        pipeline.build_dataset(pipeline.load_sources())
