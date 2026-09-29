"""Raw identity-provider state -- the Okta-style account directory.

Note the deliberate absence of an AccessLens ``user_id``. Okta does not know
about our internal identifiers; it knows logins and account ids. Joining those
to a person is the normalizer's job, and modelling it honestly here is what
lets a mis-join surface as ``IDENTITY_UNMAPPED`` coverage rather than as a
silently misattributed finding.
"""

from __future__ import annotations

from pydantic import AwareDatetime

from app.core.enums import IdentityProvider, IdentityStatus
from app.core.time import UTCModel

__all__ = ["RawIdPIdentity", "RawIdPEnvelope"]


class RawIdPIdentity(UTCModel):
    """One directory account.

    ``account_id`` is the provider's own immutable key, so two accounts may
    share a ``login`` -- which is exactly the duplicate-identity case in
    blueprint §16. Keeping ``(provider, account_id)`` as the identity here, and
    ``login`` as a non-unique attribute, is what makes that detectable instead
    of invisible.
    """

    account_id: str
    provider: IdentityProvider
    login: str
    email: str | None = None
    status: IdentityStatus

    #: Set when the account was disabled/deprovisioned. This is the reference
    #: point Rule D measures downstream activity against.
    deactivated_at: AwareDatetime | None = None
    deactivation_trigger: str | None = None

    groups: list[str] = []
    mfa_enrolled: bool = False

    raw_index: int = -1


class RawIdPEnvelope(UTCModel):
    """The shape of ``data/idp_state.json``.

    ``source_system`` names the directory the export came from (``okta`` in the
    fixture set). Declared rather than ignored because ``UTCModel`` forbids
    undeclared keys, so without it the file cannot be validated against the
    model that documents it.
    """

    generated_at: AwareDatetime
    source_system: str | None = None
    identities: list[RawIdPIdentity]
