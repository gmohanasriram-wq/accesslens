"""Health and readiness."""

from __future__ import annotations

from fastapi import APIRouter, Response, status

from app.api.deps import StateDep, check_database
from app.core.enums import IngestStatus
from app.schemas.api import HealthResponse

__all__ = ["router"]

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health(state: StateDep, response: Response) -> HealthResponse:
    """Report whether the process can actually serve an access review.

    Deliberately not a bare ``{"status": "ok"}``. Liveness is the least
    interesting fact here: a process can be up, answer this route, and still be
    incapable of reviewing anyone because the database is unreachable or the
    dataset never loaded. Both are reported, and either one makes this route
    return 503, so an orchestrator's readiness probe fails for the right reason
    instead of passing while the analysis surface is blind.
    """
    settings = state.settings
    database = check_database(state.engine)

    healthy = database == "ok" and state.dataset is not None
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    if state.dataset is None:
        state_label = "unavailable"
    elif state.report is not None:
        state_label = state.report.status.value
    else:  # pragma: no cover - report is always set alongside a dataset
        state_label = IngestStatus.SUCCEEDED.value

    return HealthResponse(
        status="ok" if healthy else "degraded",
        app=settings.app_name,
        version=settings.app_version,
        environment=settings.environment,
        database=database,
        users_loaded=len(state.dataset.users) if state.dataset else 0,
        ingest_status=state_label,
        content_hash=state.dataset.content_hash if state.dataset else None,
        rejections=len(state.dataset.rejections) if state.dataset else 0,
        detail=state.ingest_error,
    )
