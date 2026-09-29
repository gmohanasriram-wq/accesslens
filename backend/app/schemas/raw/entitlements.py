"""Raw granted access -- AWS IAM policies, GitHub org roles, application roles.

This is the "what access do they have" side of the product, and the denominator
of Rule A's utilisation ratio.

``protected_role`` is carried on the record rather than inferred, because
break-glass classification is an organisational policy decision. Inferring it
from the role's *name* alone would be fragile: a role called
``dr-operator`` in one company is disaster recovery and in another is
"daily reports". The name patterns in ``Settings`` exist only as a *fallback*
for records that arrive without an explicit flag, and the fixture set marks all
protected roles explicitly so the fallback is never load-bearing in the demo.
"""

from __future__ import annotations

from pydantic import AwareDatetime

from app.core.enums import EntitlementSource, RiskLevel
from app.core.time import UTCModel

__all__ = ["RawEntitlement", "RawEntitlementEnvelope"]


class RawEntitlement(UTCModel):
    #: Source-native identity: an IAM ARN, a GitHub login, or an email.
    principal: str
    source: EntitlementSource
    role: str
    role_arn: str | None = None
    org: str | None = None

    #: Consequence of misuse, not likelihood of misuse. Assigned by whoever
    #: granted the access and carried through unchanged.
    risk_level: RiskLevel = RiskLevel.UNKNOWN

    #: Rule C's input. ``True`` suppresses low-usage pruning recommendations.
    protected_role: bool = False
    protection_reason: str | None = None
    protection_tags: list[str] = []

    #: Specific granted permissions. Managed policies are also given by name
    #: (``AdministratorAccess``); ``core.capabilities`` resolves both.
    permissions: list[str] = []

    granted_at: AwareDatetime | None = None

    raw_index: int = -1


class RawEntitlementEnvelope(UTCModel):
    """The shape of ``data/entitlements.json``.

    ``source_system`` names where the grants came from. Unlike the other three
    exports this one is a *join* across several systems, which is why the
    fixture set states it as ``"aws_iam+github_org+app_catalog"`` rather than a
    single product name -- and why the per-record ``source`` field is what
    actually routes each grant, not this header.
    """

    generated_at: AwareDatetime
    source_system: str | None = None
    entitlements: list[RawEntitlement]
