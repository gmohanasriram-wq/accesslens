"""Datetime discipline.

AccessLens compares timestamps that came from four different systems: an HR
termination time, an IdP deactivation time, and activity timestamps from AWS,
GitHub and a proxy. Rule D (ghost access) is nothing more than an ordering
question over those values -- "did a *successful* action happen after the
account was disabled?".

If any of those values is naive (no ``tzinfo``), or silently misinterpreted as
local time, the comparison either raises ``TypeError`` at analysis time or --
worse -- quietly returns the wrong answer and produces a security finding that
is confidently incorrect. So the rule for this codebase is:

    Every datetime in the domain layer is timezone-aware and normalised to UTC.
    Naive datetimes are rejected at the point of parsing, not later.

Enforced in three places:

1. **Annotation** - fields are typed ``AwareDatetime``, so Pydantic rejects a
   naive value during validation, before any custom code runs.
2. **Normalisation** - :class:`UTCModel` rewrites any accepted offset to UTC, so
   ``+05:30`` input cannot leak into a comparison.
3. **Storage** - ``models.base.UTCDateTime`` re-attaches UTC on the way out of
   SQLite, which does not persist offsets natively.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, field_validator

__all__ = ["UTC", "utcnow", "ensure_utc", "UTCModel"]


def utcnow() -> datetime:
    """Current time, timezone-aware, in UTC.

    Prefer ``Settings.analysis_as_of`` over this anywhere in analysis code. The
    fixture set and the Phase 2 oracles are anchored to a fixed "today"; a
    stray call to the wall clock makes results depend on when the tests ran.
    See ``tests/test_datetime_discipline.py``.
    """
    return datetime.now(UTC)


def ensure_utc(value: datetime) -> datetime:
    """Return ``value`` as a UTC-aware datetime, or raise if it is naive.

    Raising rather than assuming UTC is the point. Guessing that a naive
    timestamp means UTC is exactly the kind of silent assumption that turns an
    unmeasured identity into a confident finding.
    """
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(
            "naive datetime rejected: AccessLens requires timezone-aware timestamps "
            f"(got {value!r}); use an explicit offset such as '2026-09-25T10:00:00Z'"
        )
    return value.astimezone(UTC)


class UTCModel(BaseModel):
    """Base for every domain model.

    Two behaviours, both deliberate:

    * ``extra="forbid"`` - an unrecognised field is an error, not a silently
      ignored key. Fixture typos and upstream schema drift must fail loudly;
      a dropped field is indistinguishable from a field that was never there,
      and "we never received it" vs "we ignored it" are different answers in an
      audit.
    * ``_normalise_datetimes`` - every ``datetime`` on every subclass is
      rewritten to UTC after validation, so callers never need to think about
      the offset a source system happened to send.
    """

    model_config = ConfigDict(extra="forbid")

    @field_validator("*", mode="after")
    @classmethod
    def _normalise_datetimes(cls, value: object) -> object:
        return ensure_utc(value) if isinstance(value, datetime) else value
