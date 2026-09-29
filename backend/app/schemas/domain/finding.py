"""The finding and evidence contracts.

These are frozen in Phase 1, before any detection logic exists, for three
reasons:

1. **Oracles need a type.** The Phase 2 engine is developed test-first against
   the expected outcomes in ``tests/fixtures/oracles/``. If the type and the
   expectation were written in the same commit, a wrong expectation could
   quietly become the contract. Freezing the type first makes the oracle a
   genuine constraint.

2. **A finding is a data contract, not a detector.** Phase 2 still chooses every
   threshold and every predicate; nothing here constrains that.

3. **The AI boundary needs a structural home.** ``Finding`` is produced only by
   the deterministic engine. ``ai_explanation`` and ``human_decision`` are
   deliberately *not* fields on it -- they attach separately in Phases 3 and 4.
   That makes "AI never makes the security decision" a fact about the type
   system rather than a rule someone has to keep remembering.
"""

from __future__ import annotations

from typing import Any

from pydantic import AwareDatetime, Field, field_validator

from app.core.enums import (
    EvidenceCompleteness,
    EvidenceKind,
    FindingStatus,
    FindingType,
    Recommendation,
    RiskLevel,
    Severity,
    UsageObservation,
)
from app.core.time import UTCModel

__all__ = ["Evidence", "Finding", "FORBIDDEN_CONCLUSION_PHRASES"]


#: Language a deterministic finding must never use.
#:
#: The blueprint's principle "unused ≠ unnecessary" is easy to state and easy to
#: violate by accident -- a summary template that slips in "this access is
#: unnecessary" would assert a business judgement that the evidence cannot
#: support. AccessLens observed that a permission was *not used*; it did not
#: establish that it is *not needed*. Enforcing this where findings are
#: constructed means the distinction cannot erode through a well-meaning
#: wording change in Phase 2 or Phase 4.
#: Phrases are matched as substrings against the lowercased summary, so they are
#: deliberately narrow. Bare "revoke" is *not* listed: a ghost-access summary
#: must be able to state the factual finding that a credential was **not
#: revoked** when the account was disabled, and that sentence contains the
#: substring. Only prescriptive forms are rejected.
FORBIDDEN_CONCLUSION_PHRASES: tuple[str, ...] = (
    "unnecessary",
    "no longer needed",
    "not needed",
    "safe to remove",
    "safe to delete",
    "should be revoked",
    "must be revoked",
    "automatically revoke",
)


class Evidence(UTCModel):
    """One attributable fact supporting a finding."""

    evidence_id: str
    finding_id: str | None = None
    kind: EvidenceKind

    #: Originating system, as a plain string so it can name an
    #: ``ActivitySource``, an ``EntitlementSource`` or a ``SourceSystem``.
    source: str

    #: ``None`` only for kinds that are not anchored to a moment
    #: (``COVERAGE_STATEMENT``, ``CONFIG_VALUE``).
    timestamp: AwareDatetime | None = None
    event_id: str | None = None

    #: Deterministic, human-readable description. Never model-generated: an
    #: auditor has to be able to reproduce this text from the evidence alone.
    description: str

    #: Structured, rule-specific payload (thresholds applied, counts, window).
    #: Opaque on purpose, so Phase 2 can record what it needs without a schema
    #: change.
    detail: dict[str, Any] = Field(default_factory=dict)


class Finding(UTCModel):
    """A conclusion a human should review, with the evidence behind it."""

    id: str
    user_id: str
    type: FindingType
    severity: Severity
    status: FindingStatus
    risk_level: RiskLevel = RiskLevel.UNKNOWN

    #: Deterministic summary produced by the engine from a template.
    summary: str

    #: What AccessLens suggests. Never an automatic action -- see
    #: :class:`~app.core.enums.Recommendation`.
    recommendation: Recommendation

    evidence: list[Evidence] = Field(default_factory=list)

    #: How much of the evidence this conclusion *should* rest on actually
    #: exists. A finding can be real and still be under-evidenced; surfacing
    #: that keeps a reviewer from treating a partial picture as complete.
    evidence_completeness: EvidenceCompleteness = EvidenceCompleteness.COMPLETE

    #: Rule identifiers, e.g. ``["RULE_B_LOW_USAGE_PRIVILEGED"]``. Named so the
    #: dossier can cite the specific control that fired.
    rules_triggered: list[str] = Field(default_factory=list)

    usage: UsageObservation | None = None

    created_at: AwareDatetime

    @field_validator("summary")
    @classmethod
    def _reject_unsupported_conclusions(cls, value: str) -> str:
        """Reject summaries that assert more than the evidence supports."""
        lowered = value.lower()
        for phrase in FORBIDDEN_CONCLUSION_PHRASES:
            if phrase in lowered:
                raise ValueError(
                    f"finding summary asserts an unsupported conclusion ({phrase!r}); "
                    "AccessLens may report that access was not observed in use, but "
                    "must not claim it is unnecessary or safe to remove. "
                    f"Got: {value!r}"
                )
        return value

    @property
    def evidence_ids(self) -> list[str]:
        return [e.evidence_id for e in self.evidence]
