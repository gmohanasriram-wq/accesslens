"""Coordinator for the AI investigation layer.

Orchestrates packet processing, provider invocation, and safety validation.
"""

from __future__ import annotations

import logging

from app.ai.packet import InvestigationPacket
from app.ai.provider import LLMProvider, MockLLMProvider, get_provider
from app.ai.safety import validate_chat_safety, validate_investigation_safety
from app.ai.schemas import (
    ChatMessage,
    FactVsInference,
    InvestigationChatResponse,
    InvestigationStatus,
    StructuredInvestigationResult,
)
from app.core.config import Settings

logger = logging.getLogger(__name__)

__all__ = ["investigate_finding", "investigate_chat"]


def investigate_finding(
    packet: InvestigationPacket,
    provider: LLMProvider | None = None,
    settings: Settings | None = None,
) -> StructuredInvestigationResult:
    """Run an AI investigation for a finding packet.

    Executes the provider, validates safety invariants, and returns a
    StructuredInvestigationResult. Network, model or parse failures return
    a graceful ERROR status result rather than raising unhandled exceptions.
    """
    if provider is None:
        provider = get_provider(settings=settings)

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


def investigate_chat(
    packet: InvestigationPacket,
    message: str,
    history: list[ChatMessage],
    provider: LLMProvider | None = None,
    settings: Settings | None = None,
) -> InvestigationChatResponse:
    """Run an interactive chat turn for a finding packet.

    Executes the provider, validates safety invariants, and returns an
    InvestigationChatResponse. If NVIDIA times out, errors, or fails,
    it falls back deterministically to MockLLMProvider with an explicit
    fallback indicator rather than failing.
    """
    if provider is None:
        provider = get_provider(settings=settings)

    try:
        result = provider.chat(packet, message, history)
    except Exception as exc:
        logger.warning(
            "Primary chat provider (%s) failed for finding %s: %s; falling back to deterministic local engine",
            type(provider).__name__,
            packet.finding.id,
            exc,
        )
        fallback_provider = MockLLMProvider()
        result = fallback_provider.chat(packet, message, history)
        result.is_fallback = True
        result.provider_info = "fallback:deterministic-mock"

    try:
        validate_chat_safety(result.reply, result.citations, packet)
    except Exception as safety_exc:
        logger.warning(
            "Chat safety validation caught an invariant violation: %s. Sanitizing response.",
            safety_exc,
        )
        fallback_provider = MockLLMProvider()
        result = fallback_provider.chat(packet, message, history)
        result.is_fallback = True
        result.provider_info = "fallback:deterministic-mock (safety-sanitized)"

    return result

