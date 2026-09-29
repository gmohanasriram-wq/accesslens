"""The normalized dataset: everything the security engine is allowed to see.

One object, assembled once per ingest, handed to the Phase 2 engine as a pure
value. This is the boundary that makes "detection logic is deterministic and
independently testable" true rather than aspirational: the engine receives
domain objects and returns findings, with no database session, no HTTP client
and no clock in reach. A rule cannot depend on what happens to be in a table
when the only thing it is given is this.

**Immutable on purpose.** Every collection here is a tuple or a read-only
mapping, and the container is frozen. The engine is a pure function, so nothing
downstream has a legitimate reason to mutate its input -- and a rule that
accidentally reordered ``slices`` while iterating would produce findings that
differ between runs over identical data, which is exactly the non-determinism
the blueprint's Rule A-D design exists to rule out.

Two hashes are carried, and they answer different questions:

``content_hash``
    SHA-256 over the *raw input files* plus the analysis window. Answers "are
    these the same inputs as last time?", which is what lets a re-ingest be
    skipped.

``dataset_fingerprint()``
    SHA-256 over the *normalized* content. Answers "is this the same dataset?",
    which is what a finding cites so it can be tied to an exact revision of the
    facts even after the raw files have been replaced.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime
from functools import cached_property
from types import MappingProxyType

from app.core.errors import IngestRejection
from app.schemas.domain.activity import ActivitySlice, CoverageGap
from app.schemas.domain.entitlement import Entitlement
from app.schemas.domain.identity import Identity
from app.schemas.domain.user import User
from app.schemas.raw.activity import RawSourceCoverage

__all__ = ["InMemoryDataset"]


#: Not ``slots=True``: the index below is a ``cached_property``, which needs an
#: instance ``__dict__`` to cache into. Freezing still prevents assignment, so
#: immutability is unaffected.
@dataclass(frozen=True)
class InMemoryDataset:
    """A complete, immutable snapshot of the normalized facts."""

    users: tuple[User, ...]
    identities: tuple[Identity, ...]
    entitlements: tuple[Entitlement, ...]

    #: Per-user activity, *including* the coverage gaps that qualify it. There
    #: is deliberately no way to get at the events without the gaps: a caller
    #: holding an ``ActivitySlice`` is holding both, so it cannot accidentally
    #: reason about usage without also being able to see how much was missing.
    slices: Mapping[str, ActivitySlice]

    window: tuple[datetime, datetime]

    #: What each source declared about its own completeness.
    coverage_manifest: tuple[RawSourceCoverage, ...]

    #: Records that were read but not accepted, and events that were read but
    #: could not be attributed to anyone. Both are carried into the engine so a
    #: finding can cite the evidence it is missing, not merely the evidence it
    #: has.
    rejections: tuple[IngestRejection, ...]
    unattributable_actors: tuple[str, ...]

    #: The source files' ``generated_at``, so a reader can tell how stale the
    #: underlying exports are independently of when ingest ran.
    generated_at: datetime | None = None

    content_hash: str = ""

    # -- lookups ---------------------------------------------------------- #

    def user(self, user_id: str) -> User | None:
        return self._users_by_id.get(user_id)

    def entitlements_for(self, user_id: str) -> tuple[Entitlement, ...]:
        return tuple(e for e in self.entitlements if e.user_id == user_id)

    def identities_for(self, user_id: str) -> tuple[Identity, ...]:
        return tuple(i for i in self.identities if i.user_id == user_id)

    def slice_for(self, user_id: str) -> ActivitySlice:
        """This user's activity slice, or an empty un-queried one.

        Never returns ``None``. A user with no slice is a bug in the assembler,
        and returning a ``NOT_QUERIED`` slice makes that bug show up as
        "insufficient evidence" -- a visible, wrong-in-the-safe-direction answer
        -- rather than as an ``AttributeError`` deep inside a rule, or worse, as
        a ``None`` that a rule treats as "no activity".
        """
        existing = self.slices.get(user_id)
        if existing is not None:
            return existing
        return ActivitySlice(
            user_id=user_id,
            window_start=self.window[0],
            window_end=self.window[1],
        )

    def __iter__(self) -> Iterator[User]:
        return iter(self.users)

    def __len__(self) -> int:
        return len(self.users)

    # -- derived ---------------------------------------------------------- #

    @cached_property
    def _users_by_id(self) -> Mapping[str, User]:
        return MappingProxyType({u.id: u for u in self.users})

    @property
    def has_rejections(self) -> bool:
        return bool(self.rejections)

    def dataset_fingerprint(self) -> str:
        """Stable SHA-256 over the normalized content.

        Built from a canonical JSON projection rather than ``repr`` so that the
        value is stable across processes and Python versions. Everything is
        sorted, so two datasets assembled in different orders hash identically
        -- order is an artifact of ingestion, not a property of the facts.
        """
        digest = hashlib.sha256()
        digest.update(
            json.dumps(
                {
                    "users": sorted(
                        (u.model_dump(mode="json") for u in self.users),
                        key=lambda d: d["id"],
                    ),
                    "identities": sorted(
                        (i.model_dump(mode="json") for i in self.identities),
                        key=lambda d: (d["provider"], d["account_id"]),
                    ),
                    "entitlements": sorted(
                        (e.model_dump(mode="json") for e in self.entitlements),
                        key=lambda d: (d["user_id"], d["source"], d["role"]),
                    ),
                    "activity": sorted(
                        (
                            {
                                "user_id": slice_.user_id,
                                "coverage": str(slice_.coverage),
                                "gaps": [
                                    g.model_dump(mode="json")
                                    for g in sorted(slice_.gaps, key=_gap_sort_key)
                                ],
                                "events": sorted(
                                    (
                                        e.model_dump(mode="json")
                                        for e in slice_.events
                                    ),
                                    key=lambda d: d["event_id"],
                                ),
                            }
                            for slice_ in self.slices.values()
                        ),
                        key=lambda d: d["user_id"],
                    ),
                    "window": [d.isoformat() for d in self.window],
                },
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            ).encode("utf-8")
        )
        return digest.hexdigest()


def _gap_sort_key(gap: CoverageGap) -> tuple[str, str, str]:
    """Total ordering for gaps, so the fingerprint cannot depend on list order."""
    return (str(gap.source), str(gap.reason), gap.detail)
