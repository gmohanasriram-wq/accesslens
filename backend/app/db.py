"""Database engine and session management.

The URL is configuration, not code. Every model uses portable SQLAlchemy types
(``String``, ``Integer``, ``Boolean``, ``JSON``, and the ``UTCDateTime``
decorator), so moving from the default SQLite file to PostgreSQL is a
``DATABASE_URL`` change with no model edits.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings
from app.models.base import Base

__all__ = ["build_engine", "build_session_factory", "create_all", "session_scope"]


def build_engine(settings: Settings | None = None, *, url: str | None = None) -> Engine:
    """Create an engine for the configured database.

    ``check_same_thread=False`` is required for SQLite under FastAPI: the
    development server serves requests from a thread pool, and the default
    SQLite driver refuses cross-thread connection use. Sessions are still
    request-scoped, so connections are not shared concurrently.
    """
    settings = settings or get_settings()
    database_url = url or settings.database_url
    is_sqlite = database_url.startswith("sqlite")

    engine = create_engine(
        database_url,
        echo=settings.debug,
        connect_args={"check_same_thread": False} if is_sqlite else {},
        future=True,
    )

    if is_sqlite:
        _enable_sqlite_foreign_keys(engine)

    return engine


def _enable_sqlite_foreign_keys(engine: Engine) -> None:
    """Turn on FK enforcement for SQLite.

    SQLite ignores foreign keys unless asked, which would let an ingested event
    reference a user that does not exist and pass silently -- exactly the kind
    of dangling reference that makes a finding unattributable.
    """

    @event.listens_for(engine, "connect")
    def _set_pragma(dbapi_connection, connection_record):  # noqa: ANN001, ARG001
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def build_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


def create_all(engine: Engine) -> None:
    """Create any missing tables.

    Sufficient for a prototype with no migration history to preserve. A
    long-lived deployment would use Alembic; adding it now would be tooling
    without a migration to manage.
    """
    Base.metadata.create_all(engine)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """Transactional session scope: commit on success, roll back on error."""
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
