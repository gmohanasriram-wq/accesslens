"""Normalised granted access -- the "what do they have" side of the review."""

from __future__ import annotations

from pydantic import AwareDatetime

from app.core.capabilities import capabilities_for_permissions
from app.core.enums import Capability, EntitlementSource, RiskLevel
from app.core.time import UTCModel

__all__ = ["Entitlement"]


class Entitlement(UTCModel):
    """One grant: a role held by a person, in one system.

    :attr:`protected_role` is what stops Rule B from recommending that a
    disaster-recovery role be trimmed for inactivity. Break-glass access is
    *supposed* to be unused -- that is the entire design of it -- so an
    inactivity signal that cannot tell "unused" from "unnecessary" would
    recommend dismantling exactly the access an organisation most needs to keep.
    """

    user_id: str
    source: EntitlementSource
    role: str
    role_arn: str | None = None
    org: str | None = None

    #: Raw permission strings as granted upstream, retained verbatim so an
    #: auditor can trace back to the source system's own record.
    permissions: list[str] = []

    risk_level: RiskLevel = RiskLevel.UNKNOWN

    protected_role: bool = False
    protection_reason: str | None = None
    protection_tags: list[str] = []

    granted_at: AwareDatetime | None = None

    #: Source-native principal identifier, kept for traceability.
    principal: str = ""

    @property
    def capabilities(self) -> frozenset[Capability]:
        """The capability set this grant confers -- Rule A's denominator."""
        return capabilities_for_permissions(self.permissions)

    @property
    def key(self) -> tuple[str, EntitlementSource, str]:
        """Natural key: a person holds a given role once per system."""
        return (self.user_id, self.source, self.role)

    @property
    def is_high_risk(self) -> bool:
        return self.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
