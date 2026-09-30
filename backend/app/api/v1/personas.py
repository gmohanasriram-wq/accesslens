"""Ingested personas and their current access posture.

Read-only, and deliberately so: nothing in this API can change anyone's access.
Even now that findings are served, nothing here recommends or performs a
revocation -- a human approves every security-changing action -- so there is no
endpoint here, and will be none later, that revokes anything.

The projection itself lives in :mod:`app.api.read_models`, because a finding's
dossier restates one of these people and the two views must not be able to
disagree.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.deps import DatasetDep, SessionDep
from app.api.read_models import build_personas
from app.schemas.api import PersonaListResponse

__all__ = ["router"]

router = APIRouter(tags=["personas"])


@router.get("/personas", response_model=PersonaListResponse)
def list_personas(session: SessionDep, dataset: DatasetDep) -> PersonaListResponse:
    """Every ingested user, with identities, entitlements and activity coverage."""
    personas = build_personas(session, dataset)

    return PersonaListResponse(
        count=len(personas),
        content_hash=dataset.content_hash,
        analysis_as_of=dataset.window[1],
        generated_at=dataset.generated_at,
        personas=personas,
    )
