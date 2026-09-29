"""Normalised directory account."""

from __future__ import annotations

from pydantic import AwareDatetime

from app.core.enums import IdentityProvider, IdentityStatus
from app.core.time import UTCModel

__all__ = ["Identity"]


class Identity(UTCModel):
    """An account in an identity provider, joined to a person.

    ``user_id`` is the *result* of the normalizer's identity resolution, not
    something the provider supplies. When resolution is ambiguous the identity
    is still recorded -- flagged via ``is_duplicate_of`` -- because an
    unresolvable join is a finding in its own right (blueprint §16, "Duplicate
    identity -> Investigation required"), not a record to discard.
    """

    user_id: str
    provider: IdentityProvider

    #: The provider's immutable key for the account.
    account_id: str
    login: str
    email: str | None = None
    status: IdentityStatus

    #: When the account was disabled. Rule D compares downstream activity
    #: against this instant, so it must be a real UTC value or absent --
    #: never approximated.
    deactivated_at: AwareDatetime | None = None
    deactivation_trigger: str | None = None

    groups: list[str] = []
    mfa_enrolled: bool = False

    #: Set when more than one account resolves to the same person. Holds the
    #: ``account_id`` treated as canonical.
    is_duplicate_of: str | None = None

    @property
    def key(self) -> tuple[IdentityProvider, str]:
        """Natural key: ``(provider, account_id)``.

        Not ``login`` -- logins are reused and reassigned, and two accounts may
        legitimately share one.
        """
        return (self.provider, self.account_id)

    @property
    def is_deactivated(self) -> bool:
        return self.status in (IdentityStatus.DISABLED, IdentityStatus.DEPROVISIONED)
