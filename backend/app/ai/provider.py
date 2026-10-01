"""Model-agnostic provider interface and deterministic mock provider for Phase 4.

This module provides the abstract interface for LLM backends (Gemini, DeepSeek,
Claude, OpenAI) and a deterministic MockLLMProvider for tests and offline execution.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Any

from app.ai.packet import InvestigationPacket
from app.ai.schemas import (
    ChatMessage,
    EvidenceCitation,
    FactVsInference,
    InvestigationChatResponse,
    InvestigationStatus,
    StructuredInvestigationResult,
)
from app.core.enums import Coverage, FindingType

__all__ = [
    "LLMProvider",
    "MockLLMProvider",
    "generate_deterministic_mock_result",
    "generate_deterministic_mock_chat",
    "get_provider",
]


class LLMProvider(ABC):
    """Abstract interface for AI investigation backends."""

    @abstractmethod
    def investigate(self, packet: InvestigationPacket) -> StructuredInvestigationResult:
        """Analyze an investigation packet and produce a structured result."""
        pass

    def chat(
        self,
        packet: InvestigationPacket,
        message: str,
        history: list[ChatMessage],
    ) -> InvestigationChatResponse:
        """Conduct an interactive investigation turn grounded in the packet facts.

        Subclasses that support conversational investigation implement this.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} does not implement chat()"
        )


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

    def chat(
        self,
        packet: InvestigationPacket,
        message: str,
        history: list[ChatMessage],
    ) -> InvestigationChatResponse:
        return generate_deterministic_mock_chat(packet, message, history)


_KNOWN_PERSONAS: dict[str, tuple[str, str]] = {
    "alice": ("Alice Nguyen", "u_alice"),
    "bob": ("Bob Chen", "u_bob"),
    "carol": ("Carol Diaz", "u_carol"),
    "dave": ("Dave Okonkwo", "u_dave"),
    "erin": ("Erin Walsh", "u_erin"),
    "frank": ("Frank Moreau", "u_frank"),
    "gina": ("Gina Patel", "u_gina"),
    "henry": ("Henry Okafor", "u_henry"),
    "ivan": ("Ivan Petrov", "u_ivan"),
}


def _detect_cross_person_inquiry(
    q: str,
    subject_id: str,
    subject_name: str,
) -> tuple[str, str] | None:
    """Return (other_name, other_id) if query refers to another persona, else None."""
    subj_name_lower = subject_name.lower()
    for key, (full_name, user_id) in _KNOWN_PERSONAS.items():
        pattern = rf"\b(?:{key}|{re.escape(full_name.lower())})\b"
        if re.search(pattern, q):
            if user_id != subject_id and key not in subj_name_lower:
                return (full_name, user_id)
    return None


def _is_remediation_inquiry(q: str) -> bool:
    """Check if query asks whether to revoke, remove access, or execute automated remediation."""
    if any(p in q for p in ("was not revoked", "not revoked", "had not been revoked", "why was", "why were")):
        return False
    if re.search(r"\b(?:should (?:i|we)|can (?:i|we)|do (?:i|we))\s+(?:revoke|remove|delete|disable|deprovision|alter)\b", q):
        return True
    if re.search(r"\b(?:revoke|revoking|deprovision immediately)\b", q):
        return True
    if re.search(r"\b(?:remove access|delete credential)\b", q):
        return True
    return False


def generate_deterministic_mock_chat(
    packet: InvestigationPacket,
    message: str,
    history: list[ChatMessage],
) -> InvestigationChatResponse:
    """Generate a persona-grounded, safety-checked deterministic mock chat reply."""
    finding = packet.finding
    subject = packet.subject
    q = message.lower().strip()

    # 1. Off-topic filter
    off_topic_patterns = [
        "python",
        "president",
        "joke",
        "capital of",
        "recipe",
        "weather",
        "who won",
        "song",
        "poem",
        "movie",
        "sports",
    ]
    if any(p in q for p in off_topic_patterns):
        return InvestigationChatResponse(
            finding_id=finding.id,
            reply=(
                "I am the AccessLens Trial Lawyer Assistant and can only answer questions "
                "regarding this finding, the identity, and supporting telemetry exhibits."
            ),
            citations=[],
            suggested_followups=[
                "Why was this finding raised?",
                "What evidence was attached to this finding?",
            ],
            provider_info="deterministic-mock-v1",
            is_fallback=False,
            generated_at=packet.analysis_as_of,
        )

    # 2. Cross-person inquiry filter
    cross_person = _detect_cross_person_inquiry(q, subject.id, subject.name)
    if cross_person:
        other_name, _ = cross_person
        return InvestigationChatResponse(
            finding_id=finding.id,
            reply=(
                f"This investigation is scoped strictly to finding {finding.id} and persona {subject.name}. "
                f"To investigate questions regarding {other_name}'s access or findings, please navigate to {other_name}'s finding dossier."
            ),
            citations=[],
            suggested_followups=[
                "Why was this finding raised?",
                "What exhibits support this finding?",
                "Could this access be legitimate?",
            ],
            provider_info="deterministic-mock-v1",
            is_fallback=False,
            generated_at=packet.analysis_as_of,
        )

    # 3. Remediation / Revocation inquiry filter
    if _is_remediation_inquiry(q):
        citations = [
            EvidenceCitation(evidence_id=e.evidence_id, relevance=e.description)
            for e in finding.evidence[:3]
            if e.evidence_id in packet.valid_evidence_ids
        ]
        reply = (
            "AccessLens is an investigative and evidence-grounding platform; AccessLens does not alter permissions automatically, "
            "and automated credential alteration or access modification is strictly prohibited. Remediation and downscoping "
            "decisions require attested human authorization by an assigned reviewer. For this finding, a reviewer should inspect "
            "the supporting telemetry exhibits and determine whether credential downscoping or deprovisioning is appropriate "
            "according to organizational policy."
        )
        return InvestigationChatResponse(
            finding_id=finding.id,
            reply=reply,
            citations=citations,
            suggested_followups=[
                "What exhibits support this finding?",
                "Could this access be legitimate?",
            ],
            provider_info="deterministic-mock-v1",
            is_fallback=False,
            generated_at=packet.analysis_as_of,
        )

    # 4. Incomplete Coverage (Gina Patel / Ivan Petrov)
    if (
        subject.activity.coverage != Coverage.COMPLETE
        or subject.username == "gina.patel"
        or "gina" in subject.name.lower()
    ):
        citations = [
            EvidenceCitation(evidence_id=e.evidence_id, relevance=e.description)
            for e in finding.evidence
            if e.evidence_id in packet.valid_evidence_ids
            and ("proxy" in e.evidence_id.lower() or "gap" in e.evidence_id.lower())
        ]
        reply = (
            f"Telemetry coverage for {subject.name} is incomplete ({subject.activity.coverage.value}). "
            "Specifically, proxy telemetry (proxy_zscaler) was never delivered (SOURCE_MISSING). "
            "The available evidence is insufficient to evaluate access utilization or reach conclusions. "
            "AccessLens does not infer non-usage from missing logs; telemetry collection health must be resolved first."
        )
        return InvestigationChatResponse(
            finding_id=finding.id,
            reply=reply,
            citations=citations,
            suggested_followups=[
                "Why was proxy telemetry not delivered to the audit collector?",
                "Can proxy logs be retrieved from secondary log archives?",
                "What applications does Gina have access to?",
            ],
            provider_info="deterministic-mock-v1",
            is_fallback=False,
            generated_at=packet.analysis_as_of,
        )

    # 5. Carol Diaz (Ghost Access)
    if (
        subject.username == "carol.diaz"
        or "carol" in subject.name.lower()
        or finding.type == FindingType.GHOST_ACCESS
    ):
        # 5a. Repository inquiry
        if re.search(r"\b(?:repositor(?:y|ies)|repo(?:s)?|codebase)\b", q):
            citations = [
                EvidenceCitation(evidence_id=e.evidence_id, relevance=e.description)
                for e in finding.evidence
                if e.evidence_id in packet.valid_evidence_ids
                and "gh" in e.evidence_id.lower()
            ]
            reply = (
                "Post-deactivation telemetry indicates access to two repositories: northwind/site and northwind/internal. "
                "Specifically, on 2026-08-19 (02:41 UTC), repo.clone was performed on northwind/site; on 2026-08-27 (23:05 UTC), "
                "git.push was executed on northwind/site; and on 2026-09-11 (04:18 UTC), repo.access occurred on northwind/internal. "
                "All three actions were authenticated using personal access token ghp_carol_legacy, which was not revoked at deactivation."
            )
            return InvestigationChatResponse(
                finding_id=finding.id,
                reply=reply,
                citations=citations,
                suggested_followups=[
                    "Are other personal tokens active for this persona?",
                    "Why was GitHub access not linked to central Okta SCIM deprovisioning?",
                    "What happened after Carol's Okta account was disabled?",
                ],
                provider_info="deterministic-mock-v1",
                is_fallback=False,
                generated_at=packet.analysis_as_of,
            )

        # 5b. Active tokens inquiry
        if re.search(r"\b(?:token(?:s)?|pat(?:s)?|ssh key(?:s)?)\b", q):
            citations = [
                EvidenceCitation(evidence_id=e.evidence_id, relevance=e.description)
                for e in finding.evidence
                if e.evidence_id in packet.valid_evidence_ids
                and "gh" in e.evidence_id.lower()
            ]
            reply = (
                "Observed telemetry records active use of credential ghp_carol_legacy across three post-deactivation GitHub audit "
                "events between 2026-08-19 and 2026-09-11. However, telemetry logs only record credentials that generate traffic; "
                "they are insufficient to confirm whether additional personal access tokens, OAuth applications, or SSH keys remain active. "
                "To determine complete credential status, an out-of-band audit of the organization's GitHub token inventory and SSH key registry is required."
            )
            return InvestigationChatResponse(
                finding_id=finding.id,
                reply=reply,
                citations=citations,
                suggested_followups=[
                    "Which repository was accessed after deactivation?",
                    "What happened after Carol's Okta account was disabled?",
                    "Why was GitHub access not linked to central Okta SCIM deprovisioning?",
                ],
                provider_info="deterministic-mock-v1",
                is_fallback=False,
                generated_at=packet.analysis_as_of,
            )

        # 5c. Timeline / What happened after deactivation
        if re.search(r"\b(?:what happened|after (?:okta|deactivation|termination)|timeline|chronology|sequence|post[- ]deactivation|github actions)\b", q):
            citations = [
                EvidenceCitation(evidence_id=e.evidence_id, relevance=e.description)
                for e in finding.evidence
                if e.evidence_id in packet.valid_evidence_ids
            ]
            reply = (
                f"HR records confirm {subject.name}'s employment was terminated on 2026-08-14, and their primary "
                "Okta identity account was disabled on 2026-08-15 09:12 UTC. Subsequently, on 2026-08-16 07:30 UTC, "
                "an AWS EC2 request using credential AKIACAROLKEY was denied. However, on 2026-08-19 02:41 UTC, "
                "2026-08-27 23:05 UTC, and 2026-09-11 04:18 UTC, three GitHub audit events (repo.clone, git.push, and repo.access) "
                "succeeded using personal access token ghp_carol_legacy, which was not revoked at deactivation."
            )
            return InvestigationChatResponse(
                finding_id=finding.id,
                reply=reply,
                citations=citations,
                suggested_followups=[
                    "Which repository was accessed after deactivation?",
                    "Are other personal tokens active for this persona?",
                    "Why was GitHub access not linked to central Okta SCIM deprovisioning?",
                ],
                provider_info="deterministic-mock-v1",
                is_fallback=False,
                generated_at=packet.analysis_as_of,
            )

        # 5d. Default Carol reply
        citations = [
            EvidenceCitation(evidence_id=e.evidence_id, relevance=e.description)
            for e in finding.evidence
            if e.evidence_id in packet.valid_evidence_ids
        ]
        reply = (
            f"HR records confirm {subject.name}'s employment was terminated on 2026-08-14, and their primary "
            "Okta identity account was disabled on 2026-08-15 09:12 UTC. However, on 2026-08-19, three GitHub audit "
            "events (git clone and push actions) were successfully executed using a personal access token that was "
            "not revoked at deactivation. AccessLens does not alter accounts automatically; a reviewer must determine "
            "remediation actions for the orphan credential."
        )
        return InvestigationChatResponse(
            finding_id=finding.id,
            reply=reply,
            citations=citations,
            suggested_followups=[
                "Which repository was accessed after deactivation?",
                "Why was GitHub access not linked to central Okta SCIM deprovisioning?",
                "Are other personal tokens active for this persona?",
            ],
            provider_info="deterministic-mock-v1",
            is_fallback=False,
            generated_at=packet.analysis_as_of,
        )

    # 6. Bob Chen (High Privilege Low Usage)
    if (
        subject.username == "bob.chen"
        or "bob" in subject.name.lower()
        or finding.type == FindingType.HIGH_PRIVILEGE_LOW_USAGE
    ):
        # 6a. Permissions used / Capabilities exercised
        if re.search(r"\b(?:capabilit(?:y|ies)|permission(?:s)?|actually use(?:d)?|exercised|actions|what did bob actually use)\b", q):
            citations = [
                EvidenceCitation(evidence_id=e.evidence_id, relevance=e.description)
                for e in finding.evidence
                if e.evidence_id in packet.valid_evidence_ids
                and "aws_evt" in e.evidence_id.lower()
            ]
            if not citations:
                citations = [
                    EvidenceCitation(evidence_id=e.evidence_id, relevance=e.description)
                    for e in finding.evidence[:2]
                    if e.evidence_id in packet.valid_evidence_ids
                ]
            reply = (
                "Across 4 recorded CloudTrail events in the lookback window, Bob Chen exercised only 2 distinct "
                "capabilities out of the 13 granted by AWS AdministratorAccess: S3_READ (via s3:ListBucket on 2026-07-08 "
                "and s3:GetObject on 2026-08-14) and EC2_READ (via ec2:DescribeInstances on 2026-09-02). A fourth event, "
                "sts:GetCallerIdentity on 2026-09-21, does not exercise a privileged capability. The remaining 11 "
                "administrative capabilities (such as IAM write, KMS write, and EC2 write) were not exercised."
            )
            return InvestigationChatResponse(
                finding_id=finding.id,
                reply=reply,
                citations=citations,
                suggested_followups=[
                    "Could this access be legitimate?",
                    "What evidence supports AdministratorAccess overprivilege?",
                    "Can Bob's permissions be safely downscoped to S3 and EC2 read?",
                ],
                provider_info="deterministic-mock-v1",
                is_fallback=False,
                generated_at=packet.analysis_as_of,
            )

        # 6b. Legitimacy / Business justification inquiry
        if re.search(r"\b(?:legitimate|legitimacy|justification|business need|valid reason|why might)\b", q):
            citations = [
                EvidenceCitation(evidence_id=e.evidence_id, relevance=e.description)
                for e in finding.evidence
                if e.evidence_id in packet.valid_evidence_ids
                and ("grant" in e.evidence_id.lower() or "coverage" in e.evidence_id.lower() or "utilization" in e.evidence_id.lower())
            ]
            if not citations:
                citations = [
                    EvidenceCitation(evidence_id=e.evidence_id, relevance=e.description)
                    for e in finding.evidence[:2]
                    if e.evidence_id in packet.valid_evidence_ids
                ]
            reply = (
                "AccessLens evaluates telemetry utilization against mathematical thresholds (0.25 observed ratio), "
                "not business justification. Broad administrative access may have legitimate operational reasons "
                "not reflected in routine telemetry—such as emergency standby duties, quarterly disaster recovery drills, "
                "or architectural maintenance. However, confirming operational legitimacy requires a human reviewer "
                "to consult the user's manager and review change management records; AccessLens does not make subjective "
                "policy assertions."
            )
            return InvestigationChatResponse(
                finding_id=finding.id,
                reply=reply,
                citations=citations,
                suggested_followups=[
                    "What specific AWS capabilities did Bob actually use?",
                    "What evidence supports AdministratorAccess overprivilege?",
                    "Can Bob's permissions be safely downscoped to S3 and EC2 read?",
                ],
                provider_info="deterministic-mock-v1",
                is_fallback=False,
                generated_at=packet.analysis_as_of,
            )

        # 6c. Evidence supports / Exhibits inquiry
        if re.search(r"\b(?:what evidence supports|evidence supports|what exhibits|exhibits support|evidence exists)\b", q):
            citations = [
                EvidenceCitation(evidence_id=e.evidence_id, relevance=e.description)
                for e in finding.evidence
                if e.evidence_id in packet.valid_evidence_ids
            ]
            reply = (
                "Bob Chen's finding is supported by 8 recorded exhibits: (1) Grant exhibit confirming AWS AdministratorAccess "
                "confers 13 capabilities; (2-5) Four CloudTrail activity events recording s3:ListBucket, s3:GetObject, "
                "ec2:DescribeInstances, and sts:GetCallerIdentity; (6) Complete telemetry coverage manifest over 2026-07-01 "
                "to 2026-09-29; (7) Rule A configuration thresholds (0.25 utilization ratio, min 3 events); and (8) Utilization "
                "calculation establishing that 2 of 13 capabilities were exercised (0.154 ratio)."
            )
            return InvestigationChatResponse(
                finding_id=finding.id,
                reply=reply,
                citations=citations,
                suggested_followups=[
                    "What specific AWS capabilities did Bob actually use?",
                    "Could this access be legitimate?",
                    "Can Bob's permissions be safely downscoped to S3 and EC2 read?",
                ],
                provider_info="deterministic-mock-v1",
                is_fallback=False,
                generated_at=packet.analysis_as_of,
            )

        # 6d. Default Bob reply (AdministratorAccess, 13 capabilities, 2 capabilities, 0.154 ratio)
        citations = [
            EvidenceCitation(evidence_id=e.evidence_id, relevance=e.description)
            for e in finding.evidence
            if e.evidence_id in packet.valid_evidence_ids
            and ("aws" in e.evidence_id.lower() or "read" in e.description.lower())
        ]
        if not citations:
            citations = [
                EvidenceCitation(evidence_id=e.evidence_id, relevance=e.description)
                for e in finding.evidence[:2]
                if e.evidence_id in packet.valid_evidence_ids
            ]

        reply = (
            f"{subject.name} holds the AWS AdministratorAccess entitlement, which grants 13 capabilities. "
            "Telemetry recorded across 4 CloudTrail events reveals only 2 capabilities were actually exercised "
            "(S3_READ and EC2_READ). The observed privilege utilization ratio is 0.154 (2 / 13), falling below "
            "the 0.25 threshold defined by Rule A. AccessLens does not alter permissions automatically; a human "
            "reviewer should review the finding and consider downscoping permissions to the observed read actions."
        )
        return InvestigationChatResponse(
            finding_id=finding.id,
            reply=reply,
            citations=citations,
            suggested_followups=[
                "What specific AWS capabilities did Bob actually use?",
                "Can Bob's permissions be safely downscoped to S3 and EC2 read?",
                "What is Bob's role in the organization?",
            ],
            provider_info="deterministic-mock-v1",
            is_fallback=False,
            generated_at=packet.analysis_as_of,
        )

    # 7. Alice Nguyen (Protected Break-glass)
    if subject.username == "alice.nguyen" or "alice" in subject.name.lower():
        citations = [
            EvidenceCitation(evidence_id=e.evidence_id, relevance=e.description)
            for e in finding.evidence
            if e.evidence_id in packet.valid_evidence_ids
        ]
        reply = (
            f"{subject.name} holds the AWS_EMERGENCY_ADMIN role, which is an emergency break-glass credential. "
            "Under Rule C, break-glass roles are exempt from standard dormancy rules because they are deliberately "
            "held unused so they remain available during identity provider failures. AccessLens flags the observation "
            "without prescribing credential alteration."
        )
        return InvestigationChatResponse(
            finding_id=finding.id,
            reply=reply,
            citations=citations,
            suggested_followups=[
                "What is the justification for the emergency break-glass exemption?",
                "When was this break-glass role last tested?",
            ],
            provider_info="deterministic-mock-v1",
            is_fallback=False,
            generated_at=packet.analysis_as_of,
        )

    # 8. General Fallback
    citations = [
        EvidenceCitation(evidence_id=e.evidence_id, relevance=e.description)
        for e in finding.evidence[:3]
        if e.evidence_id in packet.valid_evidence_ids
    ]
    reply = (
        f"Finding {finding.id} ({finding.type.value}) for {subject.name} was evaluated by the AccessLens engine. "
        f"Summary: {finding.summary}. There are {len(finding.evidence)} attached exhibits supporting this analysis. "
        "A human reviewer decides appropriate next steps based on the recorded exhibits."
    )
    return InvestigationChatResponse(
        finding_id=finding.id,
        reply=reply,
        citations=citations,
        suggested_followups=[
            "What controls fired on this finding?",
            "What exhibits were recorded?",
            "What next steps are suggested?",
        ],
        provider_info="deterministic-mock-v1",
        is_fallback=False,
        generated_at=packet.analysis_as_of,
    )
def get_provider(
    settings_or_name: Any = None,
    settings: Any = None,
) -> LLMProvider:
    """Return the configured LLMProvider instance.

    Defaults to MockLLMProvider for offline deterministic execution and test suites.
    Returns NvidiaLLMProvider if requested via provider name 'nvidia' or
    when settings.ai_provider == 'nvidia'.
    """
    from app.core.config import Settings, get_settings

    if isinstance(settings_or_name, Settings):
        resolved_settings = settings_or_name
        resolved_name = None
    elif isinstance(settings_or_name, str):
        resolved_settings = settings or get_settings()
        resolved_name = settings_or_name
    else:
        resolved_settings = settings or get_settings()
        resolved_name = None

    active_provider = resolved_name or resolved_settings.ai_provider
    if active_provider == "nvidia":
        from app.ai.nvidia_provider import NvidiaLLMProvider

        return NvidiaLLMProvider(settings=resolved_settings)

    return MockLLMProvider()

