"""Loads the granted-access export."""

from __future__ import annotations

from app.core.enums import SourceSystem
from app.ingestion.base import JsonSourceLoader
from app.schemas.raw.entitlements import RawEntitlement

__all__ = ["EntitlementLoader"]


class EntitlementLoader(JsonSourceLoader):
    """Reads ``data/entitlements.json``.

    A single file stands in for several systems (IAM, GitHub, the finance
    application); the ``source`` field on each record says which. One file keeps
    the fixture set small without flattening the distinction.
    """

    source = SourceSystem.ENTITLEMENT
    filename = "entitlements.json"
    envelope_key = "entitlements"
    record_model = RawEntitlement
