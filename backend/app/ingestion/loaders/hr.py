"""Loads the HR / workforce export."""

from __future__ import annotations

from app.core.enums import SourceSystem
from app.ingestion.base import JsonSourceLoader
from app.schemas.raw.hr import RawHRUser

__all__ = ["HRLoader"]


class HRLoader(JsonSourceLoader):
    """Reads ``data/users_hr.json``.

    In production this would be a Workday report or an HRIS sync. The loader
    shape is the same either way.
    """

    source = SourceSystem.HR
    filename = "users_hr.json"
    envelope_key = "users"
    record_model = RawHRUser
