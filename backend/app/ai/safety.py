"""Output safety enforcement and denylist guardrails for Phase 4.

Every generated investigation result must pass these checks before being displayed
to a human reviewer or returned via the API.
"""

from __future__ import annotations

import re
from typing import Sequence

from app.ai.packet import InvestigationPacket
from app.ai.schemas import StructuredInvestigationResult
from app.core.enums import Coverage, EvidenceCompleteness

__all__ = ["SafetyViolationError", "validate_investigation_safety"]


class SafetyViolationError(ValueError):
    """Raised when an investigation result violates safety invariants or the denylist."""

    pass


# Forbidden prescriptive conclusion phrases
_FORBIDDEN_NECESSITY_PHRASES: tuple[str, ...] = (
    "unnecessary",
    "no longer needed",
    "not needed",
    "safe to remove",
    "safe to delete",
    "is necessary",
    "is essential",
)

# Regex patterns matching imperative revocation or removal directives
_REVOCATION_DIRECTIVE_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"\brevoke\b", re.IGNORECASE),
    re.compile(r"\bremove access\b", re.IGNORECASE),
    re.compile(r"\bdisable (?:account|user|identity)\b", re.IGNORECASE),
    re.compile(r"\bdelete credential\b", re.IGNORECASE),
    re.compile(r"\bdeprovision immediately\b", re.IGNORECASE),
    re.compile(r"\bshould be revoked\b", re.IGNORECASE),
    re.compile(r"\bmust be revoked\b", re.IGNORECASE),
)

# Safe exceptions where "revoked" is part of a factual retrospective description
_ALLOWED_FACTUAL_REVOCATION: tuple[str, ...] = (
    "was not revoked",
    "had not been revoked",
    "failed to revoke",
    "token was not revoked",
    "credential was not revoked",
    "not revoked at",
)

# Severity regrading patterns
_SEVERITY_REGRADE_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"\bseverity should be\b", re.IGNORECASE),
    re.compile(r"\bregrade(?:d)? to\b", re.IGNORECASE),
    re.compile(r"\bupgrade(?:d)? to (?:critical|high|medium|low|info)\b", re.IGNORECASE),
    re.compile(r"\bdowngrade(?:d)? to (?:critical|high|medium|low|info)\b", re.IGNORECASE),
    re.compile(r"\bshould be regraded\b", re.IGNORECASE),
)

# Definitive usage assertions that are forbidden when coverage is incomplete
_DEFINITIVE_USAGE_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"\bhas not used any\b", re.IGNORECASE),
    re.compile(r"\bdid not use\b", re.IGNORECASE),
    re.compile(r"\bzero events recorded\b", re.IGNORECASE),
    re.compile(r"\bnever used\b", re.IGNORECASE),
    re.compile(r"\bno activity\b", re.IGNORECASE),
    re.compile(r"\bno unused access\b", re.IGNORECASE),
)


def _collect_all_text_blocks(result: StructuredInvestigationResult) -> list[str]:
    """Gather all free-text fields in the result to be scanned by safety filters."""
    blocks: list[str] = [result.factual_summary]
    blocks.extend(result.uncertainty_and_contradictions)
    blocks.extend(result.missing_or_unverified_evidence)
    blocks.extend(result.evidence_vs_inference.verified_facts)
    blocks.extend(result.evidence_vs_inference.inferences)
    blocks.extend(result.adversarial_questions)
    blocks.extend(result.investigation_next_steps)
    for cite in result.supporting_evidence:
        blocks.append(cite.relevance)
    return blocks


def validate_investigation_safety(
    result: StructuredInvestigationResult, packet: InvestigationPacket
) -> None:
    """Validate that the investigation result satisfies all safety invariants.

    Raises SafetyViolationError if:
    1. Any revocation or removal directive is present.
    2. Any claim that access is "unnecessary" or "necessary" is present.
    3. Any severity or risk re-grading is attempted.
    4. Any definitive usage conclusion is made when telemetry coverage is incomplete.
    5. Any evidence citation references an unknown or hallucinated evidence ID.
    """
    text_blocks = _collect_all_text_blocks(result)

    # 1. Check for revocation/removal directives
    for text in text_blocks:
        lowered = text.lower()
        for pattern in _REVOCATION_DIRECTIVE_PATTERNS:
            if pattern.search(text):
                # Check if it is a permitted factual description in ghost access
                if any(allowed in lowered for allowed in _ALLOWED_FACTUAL_REVOCATION):
                    continue
                raise SafetyViolationError(
                    f"Output contains forbidden revocation or removal directive: {text!r}. "
                    "AccessLens never prescribes revocation; a human decides."
                )

    # 2. Check for necessity assertions
    for text in text_blocks:
        lowered = text.lower()
        for phrase in _FORBIDDEN_NECESSITY_PHRASES:
            if phrase in lowered:
                raise SafetyViolationError(
                    f"Output asserts an unsupported necessity conclusion ({phrase!r}): {text!r}. "
                    "Necessity is a business owner's judgement, not an AI inference."
                )

    # 3. Check for severity / risk regrading
    for text in text_blocks:
        for pattern in _SEVERITY_REGRADE_PATTERNS:
            if pattern.search(text):
                raise SafetyViolationError(
                    f"Output attempts to regrade deterministic severity: {text!r}. "
                    f"The finding severity is {packet.finding.severity} and must not be altered."
                )

    # 4. Check for coverage integrity
    is_coverage_incomplete = (
        packet.subject.activity.coverage != Coverage.COMPLETE
        or packet.finding.evidence_completeness != EvidenceCompleteness.COMPLETE
    )
    if is_coverage_incomplete:
        for text in text_blocks:
            for pattern in _DEFINITIVE_USAGE_PATTERNS:
                if pattern.search(text):
                    raise SafetyViolationError(
                        f"Output makes definitive usage assertions while coverage is incomplete: {text!r}. "
                        "When coverage is PARTIAL or MISSING, missing evidence must remain uncertainty."
                    )

    # 5. Check for hallucinated evidence citations
    valid_ids = packet.valid_evidence_ids
    for citation in result.supporting_evidence:
        if citation.evidence_id not in valid_ids:
            raise SafetyViolationError(
                f"Cited evidence_id {citation.evidence_id!r} is not in packet valid evidence IDs. "
                "The AI must never invent evidence."
            )
