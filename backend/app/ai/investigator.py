"""Coordinator for the AI investigation layer.

Orchestrates packet processing, provider invocation, and safety validation.
"""

from __future__ import annotations

import logging

from app.ai.packet import InvestigationPacket
from app.ai.provider import LLMProvider, MockLLMProvider
from app.ai.safety import validate_investigation_safety
from app.ai.schemas import (
    FactVsInference,
    InvestigationStatus,
    StructuredInvestigationResult,
)

logger = logging.getLogger(__name__)

__all__ = ["investigate_finding"]


def investigate_finding(
    packet: InvestigationPacket,
    provider: LLMProvider | None = None,
) -> StructuredInvestigationResult:
    """Run an AI investigation for a finding packet.

    Executes the provider, validates safety invariants, and returns a
    StructuredInvestigationResult. Network, model or parse failures return
    a graceful ERROR status result rather than raising unhandled exceptions.
    """
    if provider is None:
        provider = MockLLMProvider()

    try:
        result = provider.investigate(packet)
        validate_investigation_safety(result, packet)
        return result
    except Exception as exc:
        logger.warning(
            "Investigation failed for finding %s: %s", packet.finding.id, exc
        )
        return StructuredInvestigationResult(
            finding_id=packet.finding.id,
            user_id=packet.finding.user_id,
            status=InvestigationStatus.ERROR,
            factual_summary=f"Investigation failed to complete: {exc}",
            supporting_evidence=[],
            uncertainty_and_contradictions=[
                f"Investigation provider exception: {exc}"
            ],
            missing_or_unverified_evidence=[],
            evidence_vs_inference=FactVsInference(
                verified_facts=[], inferences=[]
            ),
            adversarial_questions=[],
            investigation_next_steps=[
                "Check AI provider health and configuration.",
                "Review deterministic exhibits directly in the dossier.",
            ],
            provider_info="error-fallback",
            generated_at=packet.analysis_as_of,
        )
