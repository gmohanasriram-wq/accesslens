"""The database round trip, which is where timezone discipline actually breaks.

The schema tests prove a naive datetime is refused at the *boundary*. This
module proves the other half: that a datetime which has been through storage
comes back just as aware as it went in.

That is not a formality. SQLite has no native datetime type and does not store a
UTC offset, so an aware value written to a plain ``DateTime`` column returns
**naive**. Rule D decides ghost access by comparing an HR termination time, an
IdP deactivation time and an activity timestamp -- and comparing a naive value
to an aware one raises ``TypeError``. The failure would appear in Phase 2, at
analysis time, far from the ingestion code that caused it: a fuse lit in Phase 1
and burning in Phase 2. ``UTCDateTime`` is what defuses it, and these tests are
what stop someone removing it as redundant.

Each test deliberately reads back through a **fresh session**. Re-reading in the
session that wrote the row would return the cached Python object and pass even
with the type decorator deleted -- a green test proving nothing.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.time import ensure_utc, utcnow
from app.db import build_engine, build_session_factory, create_all
from app.models.activity import ActivityEventRow


@pytest.fixture
def engine(settings: Settings) -> Engine:
    """A real database, because the bug lives in the driver, not in the model."""
    built = build_engine(settings)
    create_all(built)
    yield built
    built.dispose()


@pytest.fixture
def sessions(engine: Engine) -> sessionmaker[Session]:
    return build_session_factory(engine)


def _write_event(sessions: sessionmaker[Session], when: datetime) -> None:
    with sessions() as session:
        session.add(
            ActivityEventRow(
                event_id="evt-roundtrip",
                timestamp=when,
                actor_id="u_test",
                source="aws_cloudtrail",
                action="s3:GetObject",
            )
        )
        session.commit()


def _read_event(sessions: sessionmaker[Session]) -> datetime:
    with sessions() as session:
        row = session.get(ActivityEventRow, "evt-roundtrip")
        assert row is not None
        return row.timestamp


def test_stored_datetime_comes_back_aware(sessions: sessionmaker[Session]) -> None:
    """The whole point: storage must not strip the offset."""
    _write_event(sessions, datetime(2026, 8, 15, 9, 12, tzinfo=UTC))
    stored = _read_event(sessions)

    assert stored.tzinfo is not None, (
        "a naive datetime came back from storage; Rule D compares this value "
        "against domain datetimes and would raise TypeError"
    )
    assert stored == datetime(2026, 8, 15, 9, 12, tzinfo=UTC)
    assert stored.utcoffset() == timedelta(0)


def test_stored_datetime_is_comparable_to_a_fresh_domain_value(
    sessions: sessionmaker[Session],
) -> None:
    """The exact operation Rule D performs, on a value that has been stored.

    Ordering, not just equality: a ghost-access decision is "did activity happen
    *after* deactivation", which is a ``>`` between a value read from the
    database and one held in memory.
    """
    termination = datetime(2026, 8, 14, 17, 0, tzinfo=UTC)
    _write_event(sessions, datetime(2026, 8, 19, 2, 41, 33, tzinfo=UTC))

    stored = _read_event(sessions)
    assert stored > termination  # TypeError here if the offset were lost


def test_a_non_utc_offset_is_normalised_by_storage(
    sessions: sessionmaker[Session],
) -> None:
    """Storing ``+05:30`` must not store a local-looking wall time.

    If it did, the same instant written from two systems would read back as two
    different instants, and the first system to send a non-UTC offset would
    silently shift every timeline it appears in.
    """
    _write_event(sessions, datetime(2026, 9, 20, 20, 0, tzinfo=timezone(timedelta(hours=5, minutes=30))))
    stored = _read_event(sessions)

    assert stored == datetime(2026, 9, 20, 14, 30, tzinfo=UTC)
    assert stored.utcoffset() == timedelta(0)


def test_a_naive_value_already_in_storage_is_re_tagged_utc(
    engine: Engine, sessions: sessionmaker[Session]
) -> None:
    """The adversarial case: a row that storage holds with no offset at all.

    Rows can arrive without going through the ORM -- a hand-written INSERT, a
    restored dump, a future migration. Those genuinely have no offset on disk,
    and the decorator's job is then to assume the UTC that ingestion guaranteed,
    rather than to hand a naive value to the engine.
    """
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO activity_events "
                "(event_id, timestamp, actor_id, source, action, denied, raw_index, "
                " created_at, updated_at) "
                "VALUES (:e, :t, :a, :s, :act, 0, -1, :t, :t)"
            ),
            {
                "e": "evt-naive",
                "t": "2026-08-15 09:12:00.000000",  # no offset, as SQLite writes it
                "a": "u_test",
                "s": "aws_cloudtrail",
                "act": "s3:GetObject",
            },
        )

    with sessions() as session:
        row = session.get(ActivityEventRow, "evt-naive")
        assert row is not None
        stored = row.timestamp

    assert stored.tzinfo is not None
    assert stored == datetime(2026, 8, 15, 9, 12, tzinfo=UTC)


def test_ingested_rows_keep_their_instants_through_the_real_pipeline(
    ingesting,
) -> None:
    """End to end: the timestamps the fixture states are the ones that come back.

    Carol's interlocking timeline is the reason this matters. Her finding is an
    ordered sequence of four instants across three systems, so a rounding or an
    offset shift anywhere in the round trip changes the story the evidence tells.
    """
    factory, _, dataset = ingesting
    carol = next(u for u in dataset.users if u.username == "carol.diaz")
    expected = {
        event.event_id: event.timestamp
        for event in dataset.slice_for(carol.id).events
    }
    assert expected, "carol.diaz has no events; this check would pass vacuously"

    with factory() as session:
        from sqlalchemy import select

        rows = session.scalars(
            select(ActivityEventRow).where(ActivityEventRow.actor_id == carol.id)
        ).all()
        assert rows
        assert {row.event_id: row.timestamp for row in rows} == expected


# --------------------------------------------------------------------------- #
# The helpers themselves
# --------------------------------------------------------------------------- #


def test_utcnow_is_aware_and_utc() -> None:
    """The clock used for audit columns, not for analysis."""
    now = utcnow()
    assert now.tzinfo is not None
    assert now.utcoffset() == timedelta(0)


def test_ensure_utc_converts_rather_than_replacing() -> None:
    """A non-UTC aware value is *converted*; only a naive one is rejected.

    Replacing the tzinfo instead of converting is the classic way to shift an
    instant by hours while every value still looks timezone-aware.
    """
    converted = ensure_utc(
        datetime(2026, 9, 20, 20, 0, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    )
    assert converted == datetime(2026, 9, 20, 14, 30, tzinfo=UTC)

    with pytest.raises(ValueError, match="naive datetime rejected"):
        ensure_utc(datetime(2026, 9, 20, 14, 30))
