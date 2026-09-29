"""Normalised activity, and the evidence-quality model that qualifies it.

The single most important structure in AccessLens is not the event -- it is
:class:`ActivitySlice`, which carries an event list *together with an account of
how much we are missing*.

Why that matters. An access review that stores a bare list of events can only
express two states, "events exist" and "events is empty", and it will read the
second as "this person does nothing". That is wrong in at least four different
ways:

1. We queried every source and the user genuinely did nothing.  -> no usage
2. A source was never ingested, so we never looked.              -> unknown
3. A source was queried but its export covers only part of the window. -> partial
4. Events existed but some were rejected as unparseable.         -> partial

Only case 1 licenses the conclusion "no usage observed". Cases 2-4 license
nothing at all, and a system that cannot tell them apart will confidently clear
people it never actually looked at. Blueprint §16 requires both the
"missing activity logs -> insufficient evidence" and the
"invalid timestamp -> validation error / insufficient evidence" rows, and
neither is expressible without this structure.

The guard is enforced in :attr:`ActivitySlice.usage_observation`: a
determinate observation is returned **only** when coverage is COMPLETE.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import AwareDatetime, Field

from app.core.capabilities import capabilities_for_actions
from app.core.enums import (
    ActivitySource,
    Capability,
    Coverage,
    GapReason,
    UsageObservation,
)
from app.core.time import UTCModel

__all__ = ["ActivityEvent", "CoverageGap", "ActivitySlice"]


class ActivityEvent(UTCModel):
    """A normalised telemetry event (blueprint §6).

    Every source's wire format collapses into this, so the engine never needs to
    know whether an action arrived from CloudTrail, GitHub or a proxy.
    """

    event_id: str
    timestamp: AwareDatetime
    actor_id: str
    source: ActivitySource
    action: str
    resource: str | None = None
    source_ip: str | None = None
    credential_id: str | None = None

    #: The source recorded this attempt as denied. Rule D must count only
    #: *successful* activity: a blocked call after deactivation shows the
    #: credential was still live, but reporting it as successful use would
    #: overstate severity. Kept as data so the rule can make that call.
    denied: bool = False

    #: Position in the source file, retained for audit traceability.
    raw_index: int = -1

    @property
    def capabilities(self) -> frozenset[Capability]:
        """What this action achieved, in the shared vocabulary."""
        return capabilities_for_actions([self.action])


class CoverageGap(UTCModel):
    """A known hole in the evidence, with a stated reason.

    A gap is never inferred from an absence -- it is recorded when something
    specific went wrong (a source declared MISSING, a window truncated, records
    rejected). Every gap carries a reason and a human-readable detail so the
    resulting finding can explain itself rather than simply asserting caution.
    """

    source: ActivitySource
    reason: GapReason
    window_start: AwareDatetime | None = None
    window_end: AwareDatetime | None = None
    affected_record_count: int = 0
    detail: str


class ActivitySlice(UTCModel):
    """Everything known about one identity's activity -- including what is not known.

    Deliberately per-user rather than global: coverage is a per-identity
    property. A truncated CloudTrail export affects only the users whose events
    would have come from it, and Erin's finding must differ from Bob's for that
    reason alone.
    """

    user_id: str
    window_start: AwareDatetime
    window_end: AwareDatetime

    events: list[ActivityEvent] = Field(default_factory=list)

    #: Sources we actually looked at, and sources we know we did not.
    sources_queried: frozenset[ActivitySource] = frozenset()
    sources_missing: frozenset[ActivitySource] = frozenset()

    gaps: list[CoverageGap] = Field(default_factory=list)

    #: The summary verdict over the above.
    coverage: Coverage = Coverage.NOT_QUERIED

    @property
    def is_observable(self) -> bool:
        """True only when the window can be vouched for in full."""
        return self.coverage is Coverage.COMPLETE

    @property
    def successful_events(self) -> tuple[ActivityEvent, ...]:
        """Events that actually succeeded, oldest first.

        Denied attempts are excluded from usage accounting: they are evidence
        that a credential was live, not evidence that the entitlement was used.
        """
        return tuple(
            sorted(
                (e for e in self.events if not e.denied),
                key=lambda e: (e.timestamp, e.event_id),
            )
        )

    @property
    def observed_event_count(self) -> int:
        return len(self.successful_events)

    @property
    def observed_capabilities(self) -> frozenset[Capability]:
        """Union of capabilities exercised by successful events."""
        observed: set[Capability] = set()
        for event in self.successful_events:
            observed |= event.capabilities
        return frozenset(observed)

    @property
    def last_activity_at(self) -> datetime | None:
        """Timestamp of the most recent *successful* event, if any."""
        events = self.successful_events
        return events[-1].timestamp if events else None

    @property
    def usage_observation(self) -> UsageObservation:
        """The coverage-gated verdict on whether usage was observed.

        THE INVARIANT, stated once and enforced here rather than trusted to
        every future caller:

            A determinate answer (NONE_OBSERVED or OBSERVED) is returned only
            when coverage is COMPLETE. Every other coverage value yields
            UNKNOWN, regardless of how many or how few events are present.

        This is what makes "missing evidence is not safe" a property of the data
        model instead of a rule each Phase 2 detector has to remember. A rule
        that branches on ``== NONE_OBSERVED`` cannot accidentally match an
        unmeasured user, because an unmeasured user is never NONE_OBSERVED.

        Note the symmetry this buys: PARTIAL coverage also cannot yield
        OBSERVED, so an under-counted window cannot be mistaken for a
        well-evidenced low-usage case either. Erring in only one direction
        would still allow false accusations of low usage.
        """
        if self.coverage is not Coverage.COMPLETE:
            return UsageObservation.UNKNOWN
        if self.observed_event_count == 0:
            return UsageObservation.NONE_OBSERVED
        return UsageObservation.OBSERVED
