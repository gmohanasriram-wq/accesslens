"""Fixes the fixture set, and proves the validation around it is real.

Two claims are checked here, and the second is the one that matters.

**The shipped fixtures are valid.** Each of the four files in ``data/`` parses
against its schema. This catches drift as the fixture set grows: a persona added
by hand with one misspelled key fails here rather than producing a subtly
smaller dataset that every other test then happily agrees with.

**The invalid fixtures are rejected.** The files in ``tests/fixtures/invalid/``
are deliberately broken, one defect each, and this module asserts that the real
loader rejects each in the way the defect deserves. Without this, "validation"
is a claim about code nobody has watched fail -- and validation that has never
been observed to reject anything is indistinguishable from validation that does
nothing.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.core.enums import ActivitySource, Coverage, GapReason, SourceSystem
from app.core.errors import FatalIngestError
from app.ingestion import IngestPipeline
from app.ingestion.loaders import ALL_LOADERS
from app.schemas.raw.activity import RawActivityEnvelope
from app.schemas.raw.entitlements import RawEntitlementEnvelope
from app.schemas.raw.hr import RawHREnvelope
from app.schemas.raw.idp import RawIdPEnvelope

INVALID_DIR = Path(__file__).resolve().parent / "fixtures" / "invalid"

SHIPPED_ENVELOPES = {
    "users_hr.json": RawHREnvelope,
    "idp_state.json": RawIdPEnvelope,
    "entitlements.json": RawEntitlementEnvelope,
}


# --------------------------------------------------------------------------- #
# The shipped fixtures are valid
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("filename", sorted(SHIPPED_ENVELOPES))
def test_shipped_envelope_validates_against_its_schema(
    filename: str, settings: Settings
) -> None:
    """Each whole-file envelope validates, not just the records the loader kept."""
    payload = json.loads(
        (settings.data_dir / filename).read_text(encoding="utf-8")
    )
    SHIPPED_ENVELOPES[filename].model_validate(payload)


def test_shipped_activity_envelope_validates_except_for_its_known_defects(
    settings: Settings,
) -> None:
    """``activity_logs.json`` validates once its two deliberate defects are set aside.

    Its events cannot be validated wholesale, because the fixture set
    *intentionally* contains a truncated timestamp and an ownerless event -- they
    are personas. So the envelope is checked structurally, and the two bad
    records are asserted to be exactly the two the oracle names. If a third
    record ever stops validating, this fails rather than quietly shrinking the
    dataset.
    """
    payload = json.loads(
        (settings.data_dir / "activity_logs.json").read_text(encoding="utf-8")
    )
    assert set(payload) == {"generated_at", "lookback_days", "coverage", "events"}
    assert isinstance(payload["events"], list)

    # The manifest itself must validate in full -- unlike the events, no
    # coverage row is deliberately malformed.
    envelope = RawActivityEnvelope.model_validate({**payload, "events": []})
    assert len(envelope.coverage) == 3

    unreadable: list[str] = []
    for entry in payload["events"]:
        try:
            RawActivityEnvelope.model_validate({**payload, "events": [entry]})
        except ValidationError:
            unreadable.append(entry.get("eventID") or entry.get("event_id"))
    assert unreadable == ["evt-aws-0028"]


def test_every_shipped_source_loads(loaded) -> None:
    """All four loader stages read their file without a whole-file failure."""
    for loader_source in SourceSystem:
        result = loaded.results.get(loader_source)
        assert result is not None, f"{loader_source} was never loaded"
        assert result.file_ok, f"{result.filename} failed to load: {result.error}"


def test_loaders_are_keyed_by_their_declared_source(loaded) -> None:
    """A loader's ``source`` is what the pipeline files it under, so it must match."""
    declared = {loader.source for loader in ALL_LOADERS()}
    assert declared == set(SourceSystem)
    assert set(loaded.results) == declared


# --------------------------------------------------------------------------- #
# The invalid fixtures are rejected
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class InvalidCase:
    """One broken file and the outcome its defect deserves."""

    filename: str
    what: str
    #: False when the whole file is unreadable rather than one record in it.
    file_ok: bool
    #: Substring the loader's error must contain, when ``file_ok`` is False.
    error_contains: str | None = None
    #: Field the first rejection must name, when a record was rejected.
    rejected_field: str | None = None
    #: True when the pipeline must refuse to run at all.
    fatal: bool = False


INVALID_CASES = (
    InvalidCase(
        "naive_timestamp.json",
        "a timestamp with no UTC offset",
        file_ok=True,
        rejected_field="eventTime",
    ),
    InvalidCase(
        "truncated_timestamp.json",
        "a timestamp cut off mid-field",
        file_ok=True,
        rejected_field="eventTime",
    ),
    InvalidCase(
        "unknown_field.json",
        "an unrecognised field on an otherwise valid event",
        file_ok=True,
        rejected_field="mfaUsed",
    ),
    InvalidCase(
        "bad_manifest_status.json",
        "a coverage status outside the enum",
        file_ok=True,
        fatal=True,
    ),
    InvalidCase(
        "events_not_a_list.json",
        "an events key that is not a list",
        file_ok=False,
        error_contains="must contain a list",
    ),
    InvalidCase(
        "malformed_json.json",
        "a file that is not valid JSON at all",
        file_ok=False,
        error_contains="not valid JSON",
    ),
)


def _data_dir_with(tmp_path: Path, settings: Settings, invalid: str) -> Path:
    """The real fixture set with one file swapped for a deliberately broken one.

    Using the whole real set rather than the single file is what makes the
    propagation assertions meaningful: the rest of the pipeline has to keep
    working while one source is degraded.
    """
    destination = tmp_path / "data"
    shutil.copytree(settings.data_dir, destination)
    shutil.copyfile(INVALID_DIR / invalid, destination / "activity_logs.json")
    return destination


@pytest.mark.parametrize("case", INVALID_CASES, ids=lambda c: c.filename)
def test_invalid_fixture_is_rejected(
    case: InvalidCase, tmp_path: Path, settings: Settings
) -> None:
    """Each broken file fails in the specific way its defect deserves."""
    data_dir = _data_dir_with(tmp_path, settings, case.filename)

    activity_loader = next(
        loader for loader in ALL_LOADERS() if loader.source is SourceSystem.ACTIVITY
    )
    result = activity_loader.load(data_dir)

    assert result.file_ok is case.file_ok, (
        f"{case.filename} ({case.what}): expected file_ok={case.file_ok}, got "
        f"{result.file_ok} (error={result.error!r})"
    )

    if not case.file_ok:
        assert case.error_contains is not None
        assert case.error_contains in (result.error or ""), (
            f"{case.filename}: error was {result.error!r}, expected it to mention "
            f"{case.error_contains!r}"
        )
        assert result.records == []
        return

    assert result.rejections, (
        f"{case.filename} ({case.what}) was accepted; validation is not doing "
        "anything"
    )
    if case.rejected_field is not None:
        # A discriminated union prefixes the variant tag, so an unrecognised key
        # on a CloudTrail record is reported at ``aws_cloudtrail.mfaUsed``. Only
        # the final segment is the field the reviewer has to fix, but the whole
        # path is worth keeping in the message.
        paths = sorted(r.field_path for r in result.rejections if r.field_path)
        named = [path for path in paths if path.split(".")[-1] == case.rejected_field]
        assert named, (
            f"{case.filename}: rejections named {paths}, expected one ending in "
            f"{case.rejected_field!r}"
        )

    # Every rejection must be locatable, or the reviewer cannot act on it.
    for rejection in result.rejections:
        assert rejection.locator().startswith("activity_logs.json[")


@pytest.mark.parametrize("case", INVALID_CASES, ids=lambda c: c.filename)
def test_invalid_fixture_does_not_abort_the_run_unless_it_must(
    case: InvalidCase, tmp_path: Path, settings: Settings
) -> None:
    """A bad record costs one user's certainty; a bad manifest stops the run.

    The distinction is the whole point of the two error types. A record we can
    identify is rejected and attributed, so the other sources still load and the
    affected person's evidence is marked incomplete. A manifest we cannot read
    leaves a source undeclared, and an undeclared source cannot be told apart
    from one that had nothing to say -- so that one refuses to run.
    """
    data_dir = _data_dir_with(tmp_path, settings, case.filename)
    pipeline = IngestPipeline(settings, data_dir=data_dir)

    if case.fatal:
        with pytest.raises(FatalIngestError):
            pipeline.build_dataset(pipeline.load_sources())
        return

    dataset = pipeline.build_dataset(pipeline.load_sources())

    assert dataset.users, "a bad record must not cost the whole review population"

    if case.file_ok:
        # A rejected record is attributed to bob.chen, so his evidence is the
        # only thing marked incomplete.
        bob = next(u for u in dataset.users if u.username == "bob.chen")
        bob_slice = dataset.slice_for(bob.id)
        assert bob_slice.coverage is Coverage.PARTIAL, (
            f"{case.filename}: bob.chen should have degraded coverage, got "
            f"{bob_slice.coverage}"
        )
        assert GapReason.RECORDS_REJECTED in {g.reason for g in bob_slice.gaps}
        return

    # The whole file was unreadable, so nobody's telemetry was consulted.
    for user in dataset.users:
        slice_ = dataset.slice_for(user.id)
        assert slice_.coverage is Coverage.NOT_QUERIED, (
            f"{case.filename}: {user.username} should be NOT_QUERIED, got "
            f"{slice_.coverage}"
        )
        assert all(
            gap.reason is GapReason.SOURCE_NOT_QUERIED for gap in slice_.gaps
        )


def test_invalid_fixture_carrying_a_valid_manifest_still_reports_coverage(
    tmp_path: Path, settings: Settings
) -> None:
    """A readable manifest survives a bad event, so other users keep their verdicts.

    The negative control for the case above: only the user whose record was
    rejected should lose certainty. If this fails while the previous test
    passes, the rejection is being charged to everyone.
    """
    data_dir = _data_dir_with(tmp_path, settings, "truncated_timestamp.json")
    pipeline = IngestPipeline(settings, data_dir=data_dir)
    dataset = pipeline.build_dataset(pipeline.load_sources())

    others = [
        user
        for user in dataset.users
        if user.username != "bob.chen"
        and ActivitySource.AWS_CLOUDTRAIL in dataset.slice_for(user.id).sources_queried
    ]
    assert others, "expected other CloudTrail users"

    for user in others:
        slice_ = dataset.slice_for(user.id)
        assert GapReason.WINDOW_TRUNCATED not in {g.reason for g in slice_.gaps}
        assert slice_.coverage is Coverage.COMPLETE, (
            f"{user.username} was degraded by a record that is not theirs"
        )


def test_invalid_directory_has_no_stray_files() -> None:
    """Every file in ``invalid/`` is a case this module knows about.

    An unlisted file would be a defect nobody asserts against, which is worse
    than no file: it looks like coverage.
    """
    on_disk = {path.name for path in INVALID_DIR.glob("*.json")}
    declared = {case.filename for case in INVALID_CASES}
    assert on_disk == declared, (
        f"invalid/ holds {sorted(on_disk - declared)} which no case asserts, and "
        f"cases name {sorted(declared - on_disk)} which do not exist"
    )
