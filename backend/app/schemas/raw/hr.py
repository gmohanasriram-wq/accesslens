"""Raw HR / workforce data -- the Workday-style system of record.

This source owns two facts nothing else can supply: whether someone is still
employed, and *when* that stopped being true. Rule D compares the termination
timestamp against IdP deactivation and downstream activity, so a missing or
fuzzy value here weakens ghost-access detection at its root.
"""

from __future__ import annotations

from datetime import date

from pydantic import AwareDatetime

from app.core.enums import EmploymentStatus
from app.core.time import UTCModel

__all__ = ["RawHRUser", "RawHREnvelope"]


class RawHRUser(UTCModel):
    id: str
    username: str
    name: str
    email: str
    department: str
    employment_status: EmploymentStatus

    #: Set when ``employment_status`` is TERMINATED. Left optional because HR
    #: sometimes reports the status before the timestamp lands; the normalizer
    #: records that gap rather than inventing a time.
    termination_date: AwareDatetime | None = None
    termination_reason: str | None = None
    manager_id: str | None = None
    hire_date: date | None = None

    #: When HR last changed this record -- distinguishes "still employed" from
    #: "no update received", which matters when HR data itself looks stale.
    source_updated_at: AwareDatetime

    raw_index: int = -1


class RawHREnvelope(UTCModel):
    """The shape of ``data/users_hr.json``.

    ``source_system`` names the upstream system of record the export came from.
    It is declared here because the fixture files carry it and
    :class:`~app.core.time.UTCModel` forbids undeclared keys -- an envelope whose
    own provenance field fails validation against the model documenting it is a
    schema that is wrong about the file it describes. Optional because not every
    export states one, and a system that omits it has simply not said, which is
    different from having said nothing useful.
    """

    generated_at: AwareDatetime
    source_system: str | None = None
    users: list[RawHRUser]
