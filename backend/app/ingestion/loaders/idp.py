"""Loads the identity-provider export."""

from __future__ import annotations

from app.core.enums import SourceSystem
from app.ingestion.base import JsonSourceLoader
from app.schemas.raw.idp import RawIdPIdentity

__all__ = ["IdPLoader"]


class IdPLoader(JsonSourceLoader):
    """Reads ``data/idp_state.json`` (Okta-shaped)."""

    source = SourceSystem.IDP
    filename = "idp_state.json"
    envelope_key = "identities"
    record_model = RawIdPIdentity
