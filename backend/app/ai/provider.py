"""Model-agnostic provider interface and deterministic mock provider for Phase 4.

This module provides the abstract interface for LLM backends (Gemini, DeepSeek,
Claude, OpenAI) and a deterministic MockLLMProvider for tests and offline execution.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from app.ai.packet import InvestigationPacket
from app.ai.schemas import (
    EvidenceCitation,
    FactVsInference,
    InvestigationStatus,
    StructuredInvestigationResult,
)
from app.core.enums import Coverage, FindingType

__all__ = ["LLMProvider", "MockLLMProvider", "generate_deterministic_mock_result"]


class LLMProvider(ABC):
    """Abstract interface for AI investigation backends."""

    @abstractmethod
    def investigate(self, packet: InvestigationPacket) -> StructuredInvestigationResult:
        """Analyze an investigation packet and produce a structured result."""
        pass


def generate_deterministic_mock_result(
    packet: InvestigationPacket,
) -> StructuredInvestigationResult:
    """Synthesize a deterministic, safe, schema-compliant investigation result."""
    finding = packet.finding
    subject = packet.subject

    # Citations from valid evidence attached to the finding
    citations = [
        EvidenceCitation(
            evidence_id=e.evidence_id,
            relevance=f"Supports analysis of {e.kind.value} from {e.source}.",
        )
        for e in finding.evidence[:5]
    ]

    # Handle Incomplete Coverage (Gina, Ivan)
    if subject.activity.coverage != Coverage.COMPLETE:
        missing_sources = subject.activity.sources_missing or ["telemetry logs"]
        gaps = subject.activity.gaps or ["Telemetry window truncated or source missing."]
        return StructuredInvestigationResult(
            finding_id=finding.id,
            user_id=finding.user_id,
            status=InvestigationStatus.INSUFFICIENT_EVIDENCE,
            factual_summary=(
                f"Activity telemetry coverage is incomplete for {subject.name} "
                f"({subject.activity.coverage.value}). No conclusion regarding access utilization "
                "can be reached from available data."
            ),
            supporting_evidence=citations,
            uncertainty_and_contradictions=[
                f"Coverage is {subject.activity.coverage.value}; absence of events cannot be treated as non-usage."
            ],
            missing_or_unverified_evidence=gaps + [f"Missing feed: {s}" for s in missing_sources],
            evidence_vs_inference=FactVsInference(
                verified_facts=[
                    f"Telemetry coverage is {subject.activity.coverage.value}.",
                    f"Observed event count is {subject.activity.observed_event_count}.",
                ],
                inferences=[
                    "Telemetry gap precludes evaluating actual permission utilization."
                ],
            ),
            adversarial_questions=[
                "Why was telemetry for this source not delivered to the audit collector?",
                "Can proxy or application access logs be retrieved from secondary log archives?",
            ],
            investigation_next_steps=[
                "Gather missing telemetry feeds from infrastructure owners.",
                "Verify log collection pipeline health for this identity.",
            ],
            provider_info="deterministic-mock-v1",
            generated_at=packet.analysis_as_of,
        )

    # Handle Ghost Access (Carol)
    if finding.type == FindingType.GHOST_ACCESS:
        return StructuredInvestigationResult(
            finding_id=finding.id,
            user_id=finding.user_id,
            status=InvestigationStatus.COMPLETED,
            factual_summary=(
                f"Employment for {subject.name} was terminated and IdP account disabled. "
                "Downstream credential activity was subsequently recorded using a token "
                "that was not revoked at deactivation."
            ),
            supporting_evidence=citations,
            uncertainty_and_contradictions=[
                "Downstream service activity continued after central account was disabled."
            ],
            missing_or_unverified_evidence=[],
            evidence_vs_inference=FactVsInference(
                verified_facts=[
                    f"Termination date recorded as {subject.termination_date}.",
                    "Downstream activity occurred after deactivation timestamp.",
                ],
                inferences=[
                    "Downstream token or key appears to have persisted after identity provider deactivation."
                ],
            ),
            adversarial_questions=[
                "Was this downstream token generated through a self-service personal access mechanism?",
                "Are automated deprovisioning hooks in place for this downstream application?",
            ],
            investigation_next_steps=[
                "Audit all personal access tokens and SSH keys associated with this account.",
                "Confirm whether the post-termination activity was performed by a human or an automated script.",
            ],
            provider_info="deterministic-mock-v1",
            generated_at=packet.analysis_as_of,
        )

    # Handle Protected Break-Glass (Alice)
    if finding.type == FindingType.PROTECTED_BREAK_GLASS:
        return StructuredInvestigationResult(
            finding_id=finding.id,
            user_id=finding.user_id,
            status=InvestigationStatus.COMPLETED,
            factual_summary=(
                f"{subject.name} holds an emergency/break-glass role with complete telemetry coverage "
                "and zero observed events. Inactivity is the intended operational state for emergency access."
            ),
            supporting_evidence=citations,
            uncertainty_and_contradictions=[
                "Zero usage is expected for emergency break-glass roles; lack of activity does not imply lack of need."
            ],
            missing_or_unverified_evidence=[],
            evidence_vs_inference=FactVsInference(
                verified_facts=[
                    "Grant is tagged as emergency/break-glass protected.",
                    "Telemetry coverage is COMPLETE with zero observed events.",
                ],
                inferences=[
                    "Absence of routine activity indicates the emergency role has not been misused for daily tasks."
                ],
            ),
            adversarial_questions=[
                "When was this emergency role last exercised in a scheduled disaster recovery drill?",
                "Is the emergency access notification alert tested on a recurring schedule?",
            ],
            investigation_next_steps=[
                "Review justification documentation with the incident response team lead.",
                "Verify that emergency alert webhooks are active.",
            ],
            provider_info="deterministic-mock-v1",
            generated_at=packet.analysis_as_of,
        )

    # Handle High Privilege / Low Usage (Bob) and Rarely Used Privileged (Erin)
    return StructuredInvestigationResult(
        finding_id=finding.id,
        user_id=finding.user_id,
        status=InvestigationStatus.COMPLETED,
        factual_summary=(
            f"{subject.name} holds high-privilege entitlements. "
            f"Observed telemetry within the lookback window indicates low utilization "
            f"({subject.activity.observed_event_count} events observed)."
        ),
        supporting_evidence=citations,
        uncertainty_and_contradictions=[
            "Telemetry reflects observed activity during this window; periodic or emergency duties may occur outside it."
        ],
        missing_or_unverified_evidence=[],
        evidence_vs_inference=FactVsInference(
            verified_facts=[
                f"Observed {subject.activity.observed_event_count} activity events with COMPLETE coverage.",
                f"Granted access includes roles: {', '.join(e.role for e in subject.entitlements)}.",
            ],
            inferences=[
                "Observed routine work utilized a subset of the granted capabilities."
            ],
        ),
        adversarial_questions=[
            "Are unexercised high-risk permissions required for emergency, quarterly, or disaster-recovery tasks?",
            "Can routine duties be satisfied by a more tightly scoped policy without operational impact?",
        ],
        investigation_next_steps=[
            "Interview the user and their manager to review required permissions.",
            "Inspect historical ticketing logs to verify whether administrative capabilities were required in past incidents.",
        ],
        provider_info="deterministic-mock-v1",
        generated_at=packet.analysis_as_of,
    )


class MockLLMProvider(LLMProvider):
    """Deterministic, offline mock provider for testing and local execution."""

    def __init__(
        self, responses: dict[str, StructuredInvestigationResult] | None = None
    ) -> None:
        self._responses = responses or {}

    def register_response(
        self, finding_id: str, result: StructuredInvestigationResult
    ) -> None:
        self._responses[finding_id] = result

    def investigate(self, packet: InvestigationPacket) -> StructuredInvestigationResult:
        if packet.finding.id in self._responses:
            return self._responses[packet.finding.id]
        return generate_deterministic_mock_result(packet)
