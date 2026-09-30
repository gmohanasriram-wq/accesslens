"""Pydantic schemas for the AI Investigation Layer.

These models define the structured forensic output contract for Phase 4.
The AI layer never creates or alters security findings; it produces structured
explanations, separates verified facts from inferences, and drafts adversarial
questions for a human reviewer.
"""

from __future__ import annotations

from enum import StrEnum
from pydantic import AwareDatetime, Field
from app.core.time import UTCModel

__all__ = [
    "InvestigationStatus",
    "EvidenceCitation",
    "FactVsInference",
    "StructuredInvestigationResult",
]


class InvestigationStatus(StrEnum):
    """Lifecycle state of an investigation analysis."""

    COMPLETED = "COMPLETED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    ERROR = "ERROR"


class EvidenceCitation(UTCModel):
    """Direct reference to a deterministic Evidence exhibit."""

    evidence_id: str = Field(description="Exact ID of the cited Evidence item")
    relevance: str = Field(
        description="Explanation of how this exhibit supports or challenges the finding"
    )


class FactVsInference(UTCModel):
    """Explicit separation of ground truth from model inferences."""

    verified_facts: list[str] = Field(
        default_factory=list,
        description="Direct observations drawn strictly from the provided exhibits",
    )
    inferences: list[str] = Field(
        default_factory=list,
        description="Analytical deductions or hypotheses drawn from the facts",
    )


class StructuredInvestigationResult(UTCModel):
    """The structured forensic dossier drafted by the AI investigator."""

    finding_id: str
    user_id: str
    status: InvestigationStatus

    # Core Narrative
    factual_summary: str = Field(
        description="Plain-English explanation of what was observed without prescriptive directives"
    )

    # Evidence Assessment
    supporting_evidence: list[EvidenceCitation] = Field(
        default_factory=list,
        description="Exhibits that support the finding",
    )
    uncertainty_and_contradictions: list[str] = Field(
        default_factory=list,
        description="Observations that contradict assumptions or introduce ambiguity",
    )
    missing_or_unverified_evidence: list[str] = Field(
        default_factory=list,
        description="Logs, feeds, or time ranges that were not available or incomplete",
    )

    # Boundary Discipline
    evidence_vs_inference: FactVsInference = Field(
        description="Explicit separation of verified facts from speculative inferences"
    )

    # Human Reviewer Enablement
    adversarial_questions: list[str] = Field(
        default_factory=list,
        description="Challenging questions a reviewer/auditor should ask before deciding",
    )
    investigation_next_steps: list[str] = Field(
        default_factory=list,
        description="Non-mutating investigative actions (queries, owner interviews, log checks)",
    )

    # Provenance
    provider_info: str = Field(
        description="Identifier of the provider/model that generated this result"
    )
    generated_at: AwareDatetime
