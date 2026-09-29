"""The schema contracts, and the two invariants they encode.

Most of this module is ordinary Pydantic behaviour checks. Two of them are not
ordinary, and they are the reason the module exists:

* :func:`test_recommendation_enum_cannot_express_revocation` -- the
  no-auto-revocation rule is enforced by the type system, not by reviewer
  discipline, and this is the test that keeps it that way.
* The datetime group -- a naive timestamp must be rejected at the boundary,
  because Rule D is an ordering comparison over timestamps from four different
  systems and a silent timezone assumption produces a confidently wrong finding.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import AwareDatetime, TypeAdapter, ValidationError

from app.core.enums import (
    ActivitySource,
    Capability,
    Coverage,
    EvidenceKind,
    FindingType,
    Recommendation,
    Severity,
    UsageObservation,
)
from app.core.errors import IngestRejection
from app.core.time import UTCModel, ensure_utc
from app.schemas.domain.activity import ActivityEvent, CoverageGap

DATETIME_ADAPTER = TypeAdapter(AwareDatetime)


# --------------------------------------------------------------------------- #
# The no-auto-revocation invariant
# --------------------------------------------------------------------------- #


def test_recommendation_enum_cannot_express_revocation() -> None:
    """No ``Recommendation`` member may instruct a change to anyone's access.

    This is the highest-value test in the repository and it is deliberately
    blunt. AccessLens is human-controlled: it may suggest that a human *review*
    or *downscope with approval*, and it may never tell anyone to revoke,
    disable, remove or delete access. Encoding that as an enum with no such
    member means a Phase 4 AI layer cannot express revocation using this
    contract, however it is prompted.

    Checked by substring over the member names rather than by asserting a fixed
    list, so *adding* a revoke-like member fails here. A frozen list would only
    catch removals from the list, which is the direction that does not matter.
    """
    forbidden = ("revoke", "remove", "disable", "delete", "terminate", "suspend")
    offenders = [
        member.name
        for member in Recommendation
        if any(word in member.name.lower() for word in forbidden)
    ]
    assert not offenders, (
        f"Recommendation gained {offenders}; AccessLens never changes access and "
        "the enum is how that is enforced rather than remembered"
    )

    # And the positive claim: the members that do exist only ever point at a
    # human. Every one of them must name a person's action, not the system's.
    assert set(Recommendation) == {
        Recommendation.MANUAL_REVIEW,
        Recommendation.SUGGEST_DOWNSCOPE_MANUAL_APPROVAL,
        Recommendation.NO_ACTION_DOCUMENT_JUSTIFICATION,
        Recommendation.INVESTIGATE_GHOST_ACCESS,
        Recommendation.GATHER_MORE_EVIDENCE,
    }


def test_recommendation_and_decision_are_separate_types() -> None:
    """The system suggests; a human decides. The two must not share a field.

    If a recommendation could hold ``APPROVED``, then a suggestion would be
    indistinguishable from a decision, and the approval step would be
    representable without anyone approving anything.
    """
    from app.core.enums import RecommendationDecision

    assert not (set(Recommendation) & set(RecommendationDecision))


# --------------------------------------------------------------------------- #
# Datetime discipline
# --------------------------------------------------------------------------- #


def test_naive_datetime_is_rejected_by_the_annotation() -> None:
    """A bare ``AwareDatetime`` annotation refuses a naive value."""
    with pytest.raises(ValidationError):
        DATETIME_ADAPTER.validate_python("2026-09-20T14:30:00")


def test_aware_datetime_is_accepted() -> None:
    parsed = DATETIME_ADAPTER.validate_python("2026-09-20T14:30:00Z")
    assert parsed == datetime(2026, 9, 20, 14, 30, tzinfo=UTC)


def test_naive_datetime_is_rejected_on_a_domain_model() -> None:
    """The rejection happens on the model, before any rule code can run."""
    with pytest.raises(ValidationError):
        ActivityEvent(
            event_id="e1",
            timestamp="2026-09-20T14:30:00",  # type: ignore[arg-type]
            actor_id="u_x",
            source=ActivitySource.AWS_CLOUDTRAIL,
            action="s3:GetObject",
        )


def test_offsets_are_normalised_to_utc() -> None:
    """A non-UTC offset is rewritten, not preserved.

    Rule D compares values from four systems. If one of them stored ``+05:30``
    and another stored the same instant as ``Z``, an equality or ordering check
    would depend on which representation happened to be used.
    """
    event = ActivityEvent(
        event_id="e1",
        timestamp="2026-09-20T20:00:00+05:30",  # type: ignore[arg-type]
        actor_id="u_x",
        source=ActivitySource.AWS_CLOUDTRAIL,
        action="s3:GetObject",
    )
    assert event.timestamp == datetime(2026, 9, 20, 14, 30, tzinfo=UTC)
    assert event.timestamp.utcoffset() == timedelta(0)


def test_ensure_utc_refuses_to_guess() -> None:
    """``ensure_utc`` raises on a naive value rather than assuming UTC.

    Assuming is the dangerous option: it turns an unmeasured identity into a
    confident finding. Raise, and let the caller decide.
    """
    with pytest.raises(ValueError, match="naive datetime rejected"):
        ensure_utc(datetime(2026, 9, 20, 14, 30))

    converted = ensure_utc(
        datetime(2026, 9, 20, 20, 0, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    )
    assert converted == datetime(2026, 9, 20, 14, 30, tzinfo=UTC)


# --------------------------------------------------------------------------- #
# Strictness
# --------------------------------------------------------------------------- #


def test_unknown_keys_are_rejected_not_ignored() -> None:
    """``extra="forbid"`` on every domain model.

    A dropped field is indistinguishable from a field that was never sent, and
    in an audit those are different answers.
    """
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        CoverageGap(
            source=ActivitySource.AWS_CLOUDTRAIL,
            reason="SOURCE_MISSING",  # type: ignore[arg-type]
            detail="test",
            severity="HIGH",  # type: ignore[call-arg]
        )


def test_coverage_gap_requires_a_detail() -> None:
    """Every gap must be explainable to a reviewer.

    A gap with no detail would let a finding say "evidence is incomplete"
    without being able to say what is missing or why -- which is the kind of
    unexplained caution a reviewer learns to ignore.
    """
    with pytest.raises(ValidationError):
        CoverageGap(
            source=ActivitySource.AWS_CLOUDTRAIL,
            reason="SOURCE_MISSING",  # type: ignore[arg-type]
        )


# --------------------------------------------------------------------------- #
# Serialisation, because the API and the oracles are both JSON
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("enum_type", [Coverage, UsageObservation, Severity, FindingType, EvidenceKind])
def test_enums_serialise_as_plain_strings(enum_type: type) -> None:
    """``StrEnum`` values round-trip as JSON strings, not as enum objects.

    The oracles are JSON files and the API is JSON, so an enum that serialised
    as ``"Coverage.MISSING"`` would make both unreadable to anything that is not
    this codebase.
    """
    for member in enum_type:
        assert member.value == str(member)
        assert member.value == member.value.upper() or member.value.islower()


def test_utc_model_dumps_as_iso8601_utc() -> None:
    event = ActivityEvent(
        event_id="e1",
        timestamp=datetime(2026, 9, 20, 14, 30, tzinfo=UTC),
        actor_id="u_x",
        source=ActivitySource.GITHUB_AUDIT,
        action="repo.clone",
    )
    dumped = event.model_dump(mode="json")
    assert dumped["timestamp"] == "2026-09-20T14:30:00Z"
    assert dumped["source"] == "github_audit"


def test_activity_event_capabilities_are_derived_not_stored() -> None:
    """``capabilities`` is computed from the action, so it cannot drift.

    Storing it would create a second source of truth for what an action means,
    and the two would eventually disagree.
    """
    event = ActivityEvent(
        event_id="e1",
        timestamp=datetime(2026, 9, 20, 14, 30, tzinfo=UTC),
        actor_id="u_x",
        source=ActivitySource.AWS_CLOUDTRAIL,
        action="s3:GetObject",
    )
    assert event.capabilities == frozenset({Capability.S3_READ})
    assert "capabilities" not in event.model_dump()


def test_unknown_action_yields_the_unknown_capability_not_an_empty_set() -> None:
    """An action we cannot classify is visible, not silently weightless.

    An empty set would shrink a user's observed activity and make their access
    look more idle than it is -- a false positive produced by a vocabulary gap.
    """
    event = ActivityEvent(
        event_id="e1",
        timestamp=datetime(2026, 9, 20, 14, 30, tzinfo=UTC),
        actor_id="u_x",
        source=ActivitySource.AWS_CLOUDTRAIL,
        action="qldb:PartiQLSelect",
    )
    assert event.capabilities == frozenset({Capability.UNKNOWN})


def test_utcmodel_is_the_shared_base() -> None:
    assert issubclass(ActivityEvent, UTCModel)
    assert ActivityEvent.model_config["extra"] == "forbid"


def test_ingest_rejection_locator_names_file_index_and_field() -> None:
    """A rejection nobody can locate is a rejection nobody can fix."""
    rejection = IngestRejection(
        file="activity_logs.json",
        raw_index=27,
        record_id="evt-aws-0028",
        field_path="eventTime",
        reason="Input should be a valid datetime",
        raw_value="2026-09-20T14:3",
        actor_hint="arn:aws:iam::123456789012:user/ivan.petrov",
    )
    assert rejection.locator() == (
        "activity_logs.json[27] (id='evt-aws-0028').eventTime"
    )
    assert "Input should be a valid datetime" in str(rejection)
