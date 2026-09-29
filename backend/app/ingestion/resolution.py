"""Mapping source-native identifiers onto AccessLens users.

No upstream system knows our user ids. CloudTrail emits IAM ARNs, GitHub emits
logins, the proxy emits email addresses, and HR emits usernames. Joining all of
those to one person is a real step that can genuinely fail, and the blueprint
asks the right question about it in §10: *"is the identity mapping reliable?"*

This module answers honestly. A resolution failure does not drop the event and
does not guess. The caller records an ``IDENTITY_UNMAPPED`` coverage gap for the
affected source, which downgrades that user's evidence quality -- so the system
says "we could not attribute some activity" instead of quietly analysing a
subset as though it were the whole.

One deliberate design choice: matching is case-insensitive on email and login
(those are case-insensitive in practice) but case-sensitive on usernames and
account ids, which are not.
"""

from __future__ import annotations

from collections.abc import Iterable

from app.schemas.domain.identity import Identity
from app.schemas.domain.user import User

__all__ = ["IdentityResolver", "parse_aws_arn_identity"]


def parse_aws_arn_identity(arn: str) -> str | None:
    """Extract the human-ish identifier from an IAM/STS ARN.

    Handles the two shapes that actually appear in CloudTrail:

    * ``arn:aws:iam::123456789012:user/bob.chen`` -> ``bob.chen``
    * ``arn:aws:iam::123456789012:assumed-role/PlatformAdmin/bob.chen``
      -> ``bob.chen`` (the session name, which for a human login is the username)

    A role ARN with no session name (``:role/PlatformAdmin``) yields ``None``:
    there is no person in it to attribute activity to, and inventing one would
    be exactly the unreliable mapping this module exists to avoid.
    """
    if not arn.startswith("arn:"):
        return None

    parts = arn.split(":", 5)
    if len(parts) < 6:
        return None
    resource = parts[5]

    if resource.startswith("user/"):
        name = resource[len("user/") :]
        return name or None

    if resource.startswith("assumed-role/"):
        segments = resource.split("/")
        # ["assumed-role", "<RoleName>", "<SessionName>"]
        if len(segments) >= 3 and segments[2]:
            return segments[2]
        return None

    return None


class IdentityResolver:
    """Resolves upstream identifiers to AccessLens user ids.

    Built from HR users plus IdP identities, so it knows the usernames, emails,
    logins and account ids that legitimately belong to each person.
    """

    def __init__(self, users: Iterable[User], identities: Iterable[Identity]) -> None:
        self._by_username: dict[str, str] = {}
        self._by_email: dict[str, str] = {}
        self._by_login: dict[str, str] = {}
        self._by_account_id: dict[str, str] = {}

        #: Identifiers that matched more than one person. Recorded rather than
        #: silently resolved to whichever came first -- an ambiguous join is
        #: itself a finding (blueprint §16, duplicate identity).
        self.ambiguous: dict[str, set[str]] = {}

        for user in users:
            self._register_exact(self._by_username, user.username, user.id)
            self._register_ci(self._by_email, user.email, user.id)

        for identity in identities:
            self._register_ci(self._by_login, identity.login, identity.user_id)
            if identity.email:
                self._register_ci(self._by_email, identity.email, identity.user_id)
            self._register_exact(self._by_account_id, identity.account_id, identity.user_id)

    @staticmethod
    def _register_exact(index: dict[str, str], key: str, user_id: str) -> None:
        index.setdefault(key, user_id)

    def _register_ci(self, index: dict[str, str], key: str, user_id: str) -> None:
        normalised = key.strip().lower()
        existing = index.get(normalised)
        if existing is None:
            index[normalised] = user_id
        elif existing != user_id:
            # Two people claim the same identifier. Keep the first and record
            # the collision; the duplicate-identity rule reports it.
            self.ambiguous.setdefault(normalised, {existing, user_id})

    def resolve(self, identifier: str | None) -> str | None:
        """Resolve any supported identifier form, or return ``None``.

        Tried in order of decreasing specificity: exact username, exact account
        id, then case-insensitive email and login.
        """
        if not identifier:
            return None
        candidate = identifier.strip()

        if candidate in self._by_username:
            return self._by_username[candidate]
        if candidate in self._by_account_id:
            return self._by_account_id[candidate]

        lowered = candidate.lower()
        if lowered in self._by_email:
            return self._by_email[lowered]
        if lowered in self._by_login:
            return self._by_login[lowered]

        return None

    def resolve_principal(self, principal: str | None) -> str | None:
        """Resolve an entitlement principal, which may be an ARN or a login."""
        if not principal:
            return None
        direct = self.resolve(principal)
        if direct is not None:
            return direct
        if principal.startswith("arn:"):
            return self.resolve(parse_aws_arn_identity(principal))
        return None

    def resolve_activity_actor(self, actor: str | None) -> str | None:
        """Resolve an activity actor, which may be an ARN or a login."""
        return self.resolve_principal(actor)

    @property
    def known_user_ids(self) -> set[str]:
        return set(self._by_username.values())
