"""Normalised person record."""

from __future__ import annotations

from datetime import date

from pydantic import AwareDatetime

from app.core.enums import EmploymentStatus
from app.core.time import UTCModel

__all__ = ["User"]


class User(UTCModel):
    """A person, as HR knows them.

    Distinct from :class:`~app.schemas.domain.identity.Identity` on purpose: a
    person can hold several directory accounts, and the relationship between
    "is employed" and "has a live account" is exactly where ghost access lives.
    """

    id: str
    username: str
    name: str
    email: str
    department: str
    employment_status: EmploymentStatus

    #: When employment ended. Rule D's reference point on the HR side.
    termination_date: AwareDatetime | None = None
    termination_reason: str | None = None

    manager_id: str | None = None
    hire_date: date | None = None
    source_updated_at: AwareDatetime

    @property
    def is_terminated(self) -> bool:
        return self.employment_status is EmploymentStatus.TERMINATED
