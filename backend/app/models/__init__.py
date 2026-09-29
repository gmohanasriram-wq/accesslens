"""SQLAlchemy ORM tables.

Importing this package registers every table on ``Base.metadata``, which is what
``create_all`` needs. Keep the imports below even though they look unused.
"""

from app.models.base import Base, TimestampMixin, UTCDateTime, metadata
from app.models.activity import ActivityEventRow, SourceCoverageRow
from app.models.entitlement import EntitlementRow
from app.models.finding import EvidenceRow, FindingRow
from app.models.identity import IdentityRow
from app.models.ingest import IngestRejectionRow, IngestRunRow
from app.models.user import UserRow

__all__ = [
    "ActivityEventRow",
    "Base",
    "EntitlementRow",
    "EvidenceRow",
    "FindingRow",
    "IdentityRow",
    "IngestRejectionRow",
    "IngestRunRow",
    "SourceCoverageRow",
    "TimestampMixin",
    "UTCDateTime",
    "UserRow",
    "metadata",
]
