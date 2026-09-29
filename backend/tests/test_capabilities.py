"""The action/permission vocabulary, and the two ways it can lie.

Rule A's utilisation ratio is a set comparison, and a set comparison is only as
honest as the vocabulary underneath it. The vocabulary can lie in either
direction, and both directions are tested here:

* **By omission on the observed side.** An action AccessLens cannot classify,
  silently dropped, shrinks the numerator and makes an active person look idle.
  That is a false accusation produced by a missing dictionary entry, so it is
  the more dangerous of the two.
* **By omission on the granted side.** A permission it cannot classify,
  silently dropped, shrinks the denominator and makes excessive privilege look
  proportionate.

The fixture guards below are the ones that matter day to day: they assert that
nothing in ``data/*.json`` reaches either fallback, so the vocabulary cannot
drift away from the data without a test going red.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from app.core.capabilities import (
    ACTION_TO_CAPABILITIES,
    POLICY_TO_CAPABILITIES,
    capabilities_for_actions,
    capabilities_for_permissions,
    classify_permission,
)
from app.core.config import Settings
from app.core.enums import ActivitySource, Capability, Coverage
from app.schemas.domain.activity import ActivityEvent, ActivitySlice

UNKNOWN = frozenset({Capability.UNKNOWN})


# --------------------------------------------------------------------------- #
# The fixture set stays inside the vocabulary
# --------------------------------------------------------------------------- #


def _fixture_actions(settings: Settings) -> set[str]:
    """Every action string appearing in the shipped activity export.

    Read from the raw JSON rather than from loaded domain objects, so this
    check covers records the loader may go on to reject -- a misspelled action
    on an otherwise-broken record is still a vocabulary gap worth knowing about.
    """
    payload = json.loads(
        (settings.data_dir / "activity_logs.json").read_text(encoding="utf-8")
    )
    return {
        record.get("eventName") or record.get("action") for record in payload["events"]
    }


def _fixture_permissions(settings: Settings) -> set[str]:
    """Every *permission* string in the shipped entitlements export.

    Only ``permissions``, never ``role``. A role name is a label the granting
    system chose (``DataPortalAdmin``); it is deliberately not part of the
    classification vocabulary, because the capability a grant confers is
    defined by the permissions inside it. Adding role names here would test a
    question the code never asks.
    """
    payload = json.loads(
        (settings.data_dir / "entitlements.json").read_text(encoding="utf-8")
    )
    return {
        permission
        for entitlement in payload["entitlements"]
        for permission in entitlement.get("permissions", [])
    }


def test_every_fixture_action_is_in_the_vocabulary(settings: Settings) -> None:
    """No shipped action falls through to ``UNKNOWN``.

    This is the guard the module docstring promises. It is what turns "we think
    we understand the data" into something checkable: a fixture author who
    invents ``s3:GetBucketAcl`` and forgets the mapping finds out here, rather
    than shipping a persona whose utilisation ratio is quietly wrong.
    """
    actions = _fixture_actions(settings)
    assert actions, "the activity fixture has no events; this guard proves nothing"

    unmapped = sorted(
        action for action in actions if capabilities_for_actions([action]) == UNKNOWN
    )
    assert not unmapped, (
        f"{unmapped} appear in data/activity_logs.json but are absent from "
        "ACTION_TO_CAPABILITIES. Every observed action must map to a real "
        "capability, or the utilisation ratio silently understates usage."
    )


def test_every_fixture_permission_is_in_the_vocabulary(settings: Settings) -> None:
    """No shipped granted permission falls through to ``UNKNOWN``."""
    permissions = _fixture_permissions(settings)
    assert permissions, "the entitlements fixture grants nothing; this guard proves nothing"

    unmapped = sorted(p for p in permissions if classify_permission(p) == UNKNOWN)
    assert not unmapped, (
        f"{unmapped} are granted in data/entitlements.json but classify as "
        "UNKNOWN. An unclassifiable grant shrinks the denominator and makes "
        "privilege look proportionate when it is not."
    )


# --------------------------------------------------------------------------- #
# The table's own invariants
# --------------------------------------------------------------------------- #


def test_only_deliberate_no_ops_map_to_the_empty_set() -> None:
    """An empty mapping must be a decision, never a typo.

    ``sts:GetCallerIdentity`` confers nothing by design -- it reports who you
    already are. If someone later adds an action and forgets its capabilities,
    the entry looks identical to that deliberate no-op, so this pins the exact
    set and makes any new empty entry a conscious edit.
    """
    empty = sorted(
        action for action, caps in ACTION_TO_CAPABILITIES.items() if not caps
    )
    assert empty == ["sts:GetCallerIdentity"]


def test_the_table_never_maps_an_action_to_unknown() -> None:
    """``UNKNOWN`` is reserved for the fallback and must not be a mapping value.

    Mapping an action *to* UNKNOWN would mean "we know this action exists and we
    do not know what it does", which is a contradiction the fallback already
    expresses. Storing it as data would also make the fixture guard above
    unable to tell a real gap from a deliberate entry.
    """
    offenders = sorted(
        action
        for action, caps in ACTION_TO_CAPABILITIES.items()
        if Capability.UNKNOWN in caps
    )
    assert not offenders
    assert not any(Capability.UNKNOWN in caps for caps in POLICY_TO_CAPABILITIES.values())


# --------------------------------------------------------------------------- #
# The two sides behave symmetrically
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("value", ["qldb:PartiQLSelect", "repo.force_push", "made.up:Action"])
def test_an_unclassifiable_value_is_visible_on_both_sides(value: str) -> None:
    """The same unknown string yields ``{UNKNOWN}`` whether granted or observed.

    The asymmetry this replaces was not a neutral default. An unclassifiable
    *permission* shrank the denominator, and an unclassifiable *action* shrank
    the numerator -- a ratio moved by a missing dictionary entry in either
    direction, with nothing recording that it had happened.
    """
    assert classify_permission(value) == UNKNOWN
    assert capabilities_for_actions([value]) == UNKNOWN


def test_known_no_op_is_distinguishable_from_unknown_action() -> None:
    """The distinction the empty set used to destroy.

    Both of these once returned ``frozenset()``, so no consumer could tell a
    person who did something we understand to be harmless from a person who did
    something we failed to understand. Those are different facts, and a reviewer
    reading "no observed capability" deserves to know which one they have.
    """
    no_op = capabilities_for_actions(["sts:GetCallerIdentity"])
    unknown = capabilities_for_actions(["qldb:PartiQLSelect"])

    assert no_op == frozenset()
    assert unknown == UNKNOWN
    assert no_op != unknown


def test_capabilities_union_across_actions() -> None:
    assert capabilities_for_actions(["s3:GetObject", "ec2:DescribeInstances"]) == frozenset(
        {Capability.S3_READ, Capability.EC2_READ}
    )


def test_wildcard_expands_from_the_action_table() -> None:
    """``s3:*`` is derived, so it cannot go stale as actions are added."""
    expected = frozenset().union(
        *(caps for action, caps in ACTION_TO_CAPABILITIES.items() if action.startswith("s3:"))
    )
    assert classify_permission("s3:*") == expected
    assert Capability.S3_READ in classify_permission("s3:*")

    # A wildcard over a prefix with no actions is a gap, not a silent nothing.
    assert classify_permission("qldb:*") == UNKNOWN


def test_bare_star_grants_every_capability() -> None:
    assert classify_permission("*") == frozenset(Capability)


def test_managed_policy_names_classify_by_name() -> None:
    """``AdministratorAccess`` resolves directly rather than via its actions."""
    caps = classify_permission("AdministratorAccess")
    assert Capability.IAM_WRITE in caps
    assert Capability.S3_DELETE in caps
    assert Capability.UNKNOWN not in caps


def test_permissions_union_across_a_grant_list() -> None:
    assert capabilities_for_permissions(["s3:GetObject", "repo:admin"]) == frozenset(
        {Capability.S3_READ, Capability.REPO_READ, Capability.REPO_WRITE, Capability.REPO_ADMIN}
    )


# --------------------------------------------------------------------------- #
# The consequence: a vocabulary gap must not manufacture a low-usage finding
# --------------------------------------------------------------------------- #


def _slice_with(*actions: str, denied: bool = False) -> ActivitySlice:
    return ActivitySlice(
        user_id="u_test",
        window_start=datetime(2026, 7, 1, 6, 0, tzinfo=UTC),
        window_end=datetime(2026, 9, 29, 6, 0, tzinfo=UTC),
        sources_queried=frozenset({ActivitySource.AWS_CLOUDTRAIL}),
        coverage=Coverage.COMPLETE,
        events=[
            ActivityEvent(
                event_id=f"e{index}",
                timestamp=datetime(2026, 9, 20, 14, 30, tzinfo=UTC),
                actor_id="u_test",
                source=ActivitySource.AWS_CLOUDTRAIL,
                action=action,
                denied=denied,
            )
            for index, action in enumerate(actions)
        ],
    )


def test_unclassifiable_activity_does_not_look_idle() -> None:
    """Rule 6, made concrete at the level Phase 2 will actually read.

    Phase 2 compares ``observed_capabilities`` against the granted set to reach
    a utilisation verdict. If an unclassifiable action contributed nothing, this
    slice would present exactly like a user who did nothing at all -- and a
    high-privilege account that looks idle is a finding *against* someone. The
    slice still shows activity happened, and it says plainly that we could not
    name what it achieved.
    """
    slice_ = _slice_with("qldb:PartiQLSelect", "qldb:PartiQLDelete")

    assert slice_.observed_event_count == 2
    assert slice_.observed_capabilities == UNKNOWN
    assert slice_.coverage is Coverage.COMPLETE


def test_a_genuine_no_op_activity_slice_is_still_possible() -> None:
    """The other side of the distinction: real nothing, stated as nothing."""
    slice_ = _slice_with("sts:GetCallerIdentity")

    assert slice_.observed_event_count == 1
    assert slice_.observed_capabilities == frozenset()


def test_denied_attempts_contribute_no_capability() -> None:
    """A blocked call is evidence a credential is live, not evidence of use.

    So an unclassifiable *denied* attempt must not put UNKNOWN into the observed
    set either -- the exclusion happens on ``denied``, not on whether the action
    is understood.
    """
    slice_ = _slice_with("qldb:PartiQLSelect", denied=True)

    assert slice_.observed_event_count == 0
    assert slice_.observed_capabilities == frozenset()
