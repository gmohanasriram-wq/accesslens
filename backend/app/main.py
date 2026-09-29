"""FastAPI application factory.

The lifespan does three things, in this order: create any missing tables, run
ingestion, and record the outcome on ``app.state``. Ordering matters -- ingest
writes domain rows, so the tables have to exist first.

A failed ingest does **not** abort startup. That is a deliberate choice rather
than leniency: if the process died on a bad fixture, the only way to find out
what was wrong would be to read the crash trace, and ``/api/health`` could not
answer at all. Keeping the failure as data means the running service can explain
itself -- health reports ``degraded`` with the reason, and the analysis routes
return 503 -- while the process stays up to be asked. What it must never do is
start *successfully* and serve an empty review as though it were a clean one, so
``dataset`` stays ``None`` and every route that needs it refuses to answer.

Ingestion runs once, here, rather than per request: the review is over a fixed
window (``Settings.analysis_as_of``), so rebuilding the dataset per request
would produce identical results at N times the cost.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.deps import AppState
from app.api.v1.router import api_router
from app.core.config import Settings, get_settings
from app.core.errors import AccessLensError
from app.db import build_engine, build_session_factory, create_all, session_scope
from app.ingestion import IngestPipeline

__all__ = ["create_app", "app"]

logger = logging.getLogger("accesslens")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application. Accepts injected settings so tests can pin them."""
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        engine = build_engine(settings)
        create_all(engine)

        state = AppState(
            settings=settings,
            engine=engine,
            session_factory=build_session_factory(engine),
        )
        try:
            with session_scope(state.session_factory) as session:
                report, dataset = IngestPipeline(settings).run(session)
        except AccessLensError as exc:
            # Expected failure modes (missing fixtures, no users, an undeclared
            # coverage source) are reported through the API rather than raised.
            state.ingest_error = str(exc)
            logger.error("ingestion failed: %s", exc)
        except Exception as exc:  # noqa: BLE001 - must not kill startup
            state.ingest_error = f"{type(exc).__name__}: {exc}"
            logger.exception("ingestion failed unexpectedly")
        else:
            state.report = report
            state.dataset = dataset
            logger.info(
                "ingested %d users (%s, %d rejections)",
                len(dataset.users),
                report.status.value,
                len(report.rejections),
            )

        application.state.accesslens = state
        try:
            yield
        finally:
            engine.dispose()

    application = FastAPI(
        title=f"{settings.app_name} API",
        version=settings.app_version,
        summary=(
            "Telemetry-informed access review. Deterministic findings, and no "
            "automatic revocation: a human approves every security-changing action."
        ),
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=True,
        allow_methods=["GET"],
        allow_headers=["*"],
    )

    application.include_router(api_router, prefix=settings.api_prefix)
    return application


app = create_app()
