"""One loader per upstream system, in the order they are applied."""

from app.ingestion.loaders.activity import ActivityLoader
from app.ingestion.loaders.entitlements import EntitlementLoader
from app.ingestion.loaders.hr import HRLoader
from app.ingestion.loaders.idp import IdPLoader

__all__ = ["ActivityLoader", "EntitlementLoader", "HRLoader", "IdPLoader", "ALL_LOADERS"]


def ALL_LOADERS() -> list[object]:
    """Fresh loader instances for a run.

    A function rather than a module-level list so that no run can share mutable
    loader state with another.
    """
    return [HRLoader(), IdPLoader(), EntitlementLoader(), ActivityLoader()]
