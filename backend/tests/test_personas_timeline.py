"""The fixture timeline, and the pairs of personas that must not be conflated.

These tests assert **facts about the data**, not security conclusions. Rule D
-- "was there activity after deactivation?" -- is Phase 2's, and implementing it
here would mean testing a reimplementation of the engine rather than the data
the engine will read. What is checked instead is the structure the rule depends
on: that the four instants of Carol's story are present, correctly ordered, and
attributed to the right person, and that the personas which look identical to a
naive rule are genuinely distinguishable in the data.

Every fixture set has personas that fail in pairs. Those pairs are the point:

* **Carol vs Frank** -- both terminated, both disabled. Only one has activity
  afterwards. A rule keyed on "has activity in the window" fires on both.
* **Gina vs Alice** -- both have zero events. Only one of them was actually
  watched. A rule keyed on the event count cannot tell them apart, and will call
  the unobserved one clean.
"""

from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import TypeAdapter

from app.core.enums import Coverage, UsageObservation
from app.ingestion import InMemoryDataset

AWARE = TypeAdapter(datetime)


def _user(dataset: InMemoryDataset, username: str):
    found = next((u for u in dataset.users if u.username == username), None)
    assert found is not None, f"{username} is missing from the fixture set"
    return found


def _deactivation(dataset: InMemoryDataset, username: str) -> datetime:
    """When the directory says this person's account was switched off.

    The latest such instant across their accounts: a person with two accounts is
    only deprovisioned once the last one is closed.
    """
    user = _user(dataset, username)
    stamps = [
        identity.deactivated_at
        for identity in dataset.identities_for(user.id)
        if identity.deactivated_at is not None
    ]
    assert stamps, f"{username} has no deactivated identity"
    return max(stamps)


def _post_deactivation_successes(dataset: InMemoryDataset, username: str) -> list:
    """Successful events strictly after deactivation -- measured, not judged."""
    user = _user(dataset, username)
    cutoff = _deactivation(dataset, username)
    return [
        event
        for event in dataset.slice_for(user.id).successful_events
        if event.timestamp > cutoff
    ]


# --------------------------------------------------------------------------- #
# Carol: the interlocking timeline
# --------------------------------------------------------------------------- #


def test_carols_four_timeline_instants_are_present_and_ordered(
    dataset: InMemoryDataset, oracle: dict
) -> None:
    """The evidence must render as an exact sequence, because that *is* the finding.

    A ghost-access dossier is four facts in order -- HR terminated them, the
    directory was switched off, a credential was still trying, and then it
    succeeded. If any instant were wrong or out of order the story would be
    wrong, even though every individual field still looked plausible.
    """
    carol = _user(dataset, "carol.diaz")
    expected = next(
        row for row in oracle["personas"] if row["user_id"] == carol.id
    )["timeline"]

    assert carol.termination_date == AWARE.validate_python(expected[0]["at"])
    deactivated = _deactivation(dataset, "carol.diaz")
    assert deactivated == AWARE.validate_python(expected[1]["at"])

    # The third instant is the denied AWS call: a credential that still worked
    # enough to be refused rather than rejected outright.
    denied = [
        event
        for event in dataset.slice_for(carol.id).events
        if event.denied
    ]
    assert len(denied) == 1
    assert denied[0].timestamp == AWARE.validate_python(expected[2]["at"])

    # The fourth is the first *successful* activity after deactivation.
    post = _post_deactivation_successes(dataset, "carol.diaz")
    assert post, "carol.diaz has no post-deactivation activity; the fixture is wrong"
    assert post[0].timestamp == AWARE.validate_python(expected[3]["at"])

    # And the whole sequence is monotonic.
    assert (
        carol.termination_date
        < deactivated
        < denied[0].timestamp
        < post[0].timestamp
    )


def test_carol_activity_counts_match_the_oracle(
    dataset: InMemoryDataset, oracle: dict
) -> None:
    """Six successful and one denied -- the split Rule D depends on.

    The denied call proves her credential was live without counting as use of
    the entitlement. Reporting it as use would overstate the severity; dropping
    it would lose the evidence that the credential survived deprovisioning.
    """
    carol = _user(dataset, "carol.diaz")
    expected = next(row for row in oracle["personas"] if row["user_id"] == carol.id)
    slice_ = dataset.slice_for(carol.id)

    assert slice_.observed_event_count == expected["observed_event_count"] == 6
    assert len(slice_.events) == 7
    assert len([e for e in slice_.events if e.denied]) == expected["denied_event_count"] == 1
    assert (
        len(_post_deactivation_successes(dataset, "carol.diaz"))
        == expected["post_deactivation_successful_events"]
        == 3
    )


def test_carols_post_deactivation_activity_is_her_github_credential(
    dataset: InMemoryDataset,
) -> None:
    """The story has to be actionable: which credential survived, and where.

    "Access is still live" is not actionable. "This GitHub token still works
    even though the Okta account was disabled" is -- it names the thing to
    revoke.
    """
    post = _post_deactivation_successes(dataset, "carol.diaz")

    assert all(event.credential_id for event in post), (
        "a post-deactivation event with no credential cannot be acted on"
    )
    assert {str(event.source) for event in post} == {"github_audit"}


# --------------------------------------------------------------------------- #
# Carol vs Frank: the pair a naive rule conflates
# --------------------------------------------------------------------------- #


def test_frank_is_the_negative_control_for_ghost_access(
    dataset: InMemoryDataset, oracle: dict
) -> None:
    """Terminated and disabled, with nothing afterwards.

    His last activity is the day *before* termination. A rule that fires on
    "terminated AND has activity in the window" produces a false CRITICAL here,
    which is why he exists.
    """
    frank = _user(dataset, "frank.moreau")
    assert frank.is_terminated
    assert _deactivation(dataset, "frank.moreau") > frank.termination_date

    slice_ = dataset.slice_for(frank.id)
    assert slice_.observed_event_count == 5, "he was active -- just not afterwards"
    assert slice_.last_activity_at is not None
    assert slice_.last_activity_at < frank.termination_date
    assert _post_deactivation_successes(dataset, "frank.moreau") == []


def test_carol_and_frank_differ_only_in_the_thing_that_matters(
    dataset: InMemoryDataset,
) -> None:
    """Same shape, opposite conclusion -- so the distinguishing field is real."""
    for username in ("carol.diaz", "frank.moreau"):
        assert _user(dataset, username).is_terminated

    assert _post_deactivation_successes(dataset, "carol.diaz")
    assert not _post_deactivation_successes(dataset, "frank.moreau")


# --------------------------------------------------------------------------- #
# Gina vs Alice: same count, opposite meaning
# --------------------------------------------------------------------------- #


def test_gina_and_alice_have_identical_event_counts_and_opposite_verdicts(
    dataset: InMemoryDataset,
) -> None:
    """The sharpest test of "missing evidence is not safe" in the fixture set.

    Both have zero events. Alice's zero is a *fact* -- her telemetry arrived and
    was complete, so we can prove she did not use the role. Gina's zero is a
    *hole* -- the only source that could have observed her never delivered. Any
    implementation that branches on the event count reports Gina as clean.
    """
    alice = dataset.slice_for(_user(dataset, "alice.nguyen").id)
    gina = dataset.slice_for(_user(dataset, "gina.patel").id)

    assert alice.observed_event_count == gina.observed_event_count == 0

    assert alice.coverage is Coverage.COMPLETE
    assert alice.usage_observation is UsageObservation.NONE_OBSERVED

    assert gina.coverage is Coverage.MISSING
    assert gina.usage_observation is UsageObservation.UNKNOWN


def test_gina_is_missing_because_her_only_source_never_arrived(
    dataset: InMemoryDataset,
) -> None:
    """Her relevant source is the proxy, and the proxy export was not delivered.

    This is also what the relevance scoping buys: she is not degraded by
    CloudTrail's state, because she holds no AWS entitlement and CloudTrail
    could never have observed her.
    """
    gina = _user(dataset, "gina.patel")
    slice_ = dataset.slice_for(gina.id)

    assert slice_.sources_missing, "her unobservable source must be named"
    assert slice_.observed_capabilities == frozenset()
    assert all(gap.detail for gap in slice_.gaps), (
        "a gap a reviewer cannot read is a gap they will ignore"
    )


def test_alice_is_protected_despite_the_most_idle_account_in_the_set(
    dataset: InMemoryDataset,
) -> None:
    """Twelve granted capabilities, none used, and nothing should be removed.

    The entitlement carries the organisational decision explicitly rather than
    leaving it to be inferred from the role's name, because "is this break-glass"
    is a policy judgement the reviewer's organisation already made.
    """
    alice = _user(dataset, "alice.nguyen")
    grants = dataset.entitlements_for(alice.id)

    assert grants
    protected = [grant for grant in grants if grant.protected_role]
    assert protected, "alice.nguyen's break-glass role is not marked protected"
    assert all(grant.protection_reason for grant in protected)


@pytest.mark.parametrize(
    "username", ["bob.chen", "alice.nguyen", "carol.diaz", "dave.okonkwo", "erin.walsh",
                 "frank.moreau", "gina.patel", "ivan.petrov", "henry.okafor"]
)
def test_every_persona_has_a_slice_and_a_verdict(
    username: str, dataset: InMemoryDataset
) -> None:
    """No persona may be missing from the analysis.

    A user absent from the slice mapping would render as NOT_QUERIED rather than
    crashing, so without this the omissible failure mode is a silent one.
    """
    user = _user(dataset, username)
    slice_ = dataset.slice_for(user.id)

    assert slice_.user_id == user.id
    assert slice_.coverage is not Coverage.NOT_QUERIED
