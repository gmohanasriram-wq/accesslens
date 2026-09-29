"""Request-scoped dependencies.

The engine, the settings and the database are all reached through here rather
than imported directly by a route, so a test can substitute any of them without
patching module globals.

The ingest outcome is stored on ``app.state`` rather than re-derived per request
in two parts, for two different reasons:

* the dataset is expensive to assemble and must not be rebuilt per request;
* a *failed* ingest is stored too, rather than being re-raised. If startup
  aborted on a bad fixture the process would die and the operator would have no
  way to ask what was wrong -- ``/api/health`` can report it only because the
  failure is kept as data.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.ingestion import InMemoryDataset
from app.schemas.ingest import IngestReport

__all__ = [
    "AppState",
    "get_app_state",
    "get_settings",
    "get_session",
    "require_dataset",
    "SessionDep",
    "SettingsDep",
    "DatasetDep",
]


@dataclass
class AppState:
    """Everything the lifespan assembled, in one place."""

    settings: Settings
    engine: Engine
    session_factory: sessionmaker[Session]

    #: None when ingest failed; ``ingest_error`` then says why. Exactly one of
    #: the two is set, so a reader cannot see a dataset and an error at once.
    dataset: InMemoryDataset | None = None
    report: IngestReport | None = None
    ingest_error: str | None = None


def get_app_state(request: Request) -> AppState:
    state = getattr(request.app.state, "accesslens", None)
    if state is None:  # pragma: no cover - only on a misconfigured lifespan
        raise RuntimeError(
            "application state is missing; the lifespan did not run, so the "
            "database and dataset were never initialised"
        )
    return state


def get_settings(state: Annotated[AppState, Depends(get_app_state)]) -> Settings:
    return state.settings


def get_session(
    state: Annotated[AppState, Depends(get_app_state)],
) -> Iterator[Session]:
    """A read-only session per request.

    No commit: Phase 1 exposes no write endpoints, and leaving a commit out means
    a future write route has to opt in explicitly rather than inheriting a
    silent flush.
    """
    session = state.session_factory()
    try:
        yield session
    finally:
        session.close()


def require_dataset(
    state: Annotated[AppState, Depends(get_app_state)],
) -> InMemoryDataset:
    """The assembled dataset, or 503 explaining why there isn't one.

    503 rather than 500: the request is well-formed and the server is running,
    but a dependency -- the fixture inputs -- is not available, which is exactly
    what 503 means and what makes the distinction visible to a client.
    """
    if state.dataset is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=state.ingest_error or "the dataset is not available",
        )
    return state.dataset


def check_database(engine: Engine) -> str:
    """Round-trip a trivial query so "connected" means actually connected."""
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        return f"unavailable: {type(exc).__name__}"
    return "ok"


SessionDep = Annotated[Session, Depends(get_session)]
SettingsDep = Annotated[Settings, Depends(get_settings)]
DatasetDep = Annotated[InMemoryDataset, Depends(require_dataset)]
StateDep = Annotated[AppState, Depends(get_app_state)]
