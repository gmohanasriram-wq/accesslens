"""NVIDIA Nemotron 3 Super hosted LLM provider for Phase 4.

Connects AccessLens to NVIDIA hosted inference (https://integrate.api.nvidia.com/v1)
using the Nemotron-3 Super model (nvidia/nemotron-3-super-120b-a12b).

Conforms strictly to the existing LLMProvider interface, taking an immutable
InvestigationPacket and returning a StructuredInvestigationResult.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import httpx

from app.ai.packet import InvestigationPacket
from app.ai.provider import LLMProvider
from app.ai.schemas import (
    ChatMessage,
    EvidenceCitation,
    FactVsInference,
    InvestigationChatResponse,
    InvestigationStatus,
    StructuredInvestigationResult,
)
from app.core.config import Settings, get_settings
from app.core.enums import Coverage

logger = logging.getLogger(__name__)

__all__ = [
    "NvidiaLLMProvider",
    "NEMOTRON_SYSTEM_PROMPT",
    "NEMOTRON_CHAT_SYSTEM_PROMPT",
]

NEMOTRON_CHAT_SYSTEM_PROMPT = """You are the AI Trial Lawyer Assistant for AccessLens.

AccessLens is a telemetry-informed access review and deprovisioning forensics system.

The deterministic AccessLens security engine has already produced the finding and collected evidence.

You are interacting with a human security reviewer who is examining a specific finding.

Rules:
1. Answer the reviewer's questions strictly using the information supplied in the InvestigationPacket and its evidence exhibits.
2. Never invent facts, events, timestamps, identities, permissions, or evidence exhibits.
3. Cite only evidence IDs actually present in the InvestigationPacket's valid evidence IDs.
4. Never evaluate access necessity. Never use the words "unnecessary", "necessary", "not needed", "no longer needed", "safe to remove", or "safe to delete". Describe observed usage versus granted permissions purely factually.
5. Never instruct the reviewer to revoke, remove, disable, delete, or terminate access, and never use imperative words like "revoke", "remove access", or "deprovision". Access modifications are strictly human-owned decisions.
6. If telemetry coverage is incomplete (PARTIAL or MISSING), explicitly state that available evidence is insufficient to conclude whether access was used or unused. Never claim an identity has "no activity" or was "clean" when coverage is incomplete.
7. Refuse all off-topic, creative writing, coding, or unrelated queries. Politely state that you can only investigate the current finding and identity.
8. Maintain a professional, objective, courtroom-ready tone.

Your output must be a single valid JSON object strictly matching this schema:
{
  "reply": "string (markdown formatted explanation addressing the user's question)",
  "citations": [
    {
      "evidence_id": "string (must match an exhibit ID from the packet)",
      "relevance": "string (brief explanation of how this exhibit supports the answer)"
    }
  ],
  "suggested_followups": [
    "string (1-3 relevant follow-up investigative questions the reviewer could ask)"
  ]
}
Return only JSON without markdown formatting, introductory text, or code block markers.
"""

NEMOTRON_SYSTEM_PROMPT = """You are the AI investigation assistant for AccessLens.

AccessLens is a telemetry-informed access review and deprovisioning forensics system.

The deterministic AccessLens security engine has already produced the finding.

Your responsibility is ONLY to investigate and explain the supplied finding and evidence.

You are NOT the source of truth for the security finding.

The supplied finding, severity, risk level, evidence IDs, timestamps, identities, and coverage information are authoritative.

Rules:

1. Use only information supplied in the InvestigationPacket and its evidence.
2. Never invent facts, events, timestamps, identities, permissions, or evidence.
3. Never invent or modify evidence IDs.
4. Cite only evidence IDs actually supplied in the packet.
5. Never change the finding type.
6. Never change severity.
7. Never change risk level.
8. Never evaluate access necessity. Never use the words "unnecessary", "necessary", "not needed", "no longer needed", "safe to remove", or "safe to delete". Describe observed usage versus granted permissions purely factually.
9. Never instruct the reviewer to revoke, remove, disable, delete, or terminate access, and never use words like "revoke", "remove access", or "deprovision". Access modifications are strictly human-owned decisions.
10. If telemetry coverage is incomplete, explicitly state that the available evidence is insufficient for a definitive negative-usage conclusion.
11. Clearly separate verified facts from inference.
12. Identify uncertainty and contradictions.
13. Ask adversarial questions that could challenge the initial interpretation.
14. Provide investigative next steps focused on collecting or verifying evidence.
15. Do not pretend to have access to systems outside the supplied packet.
16. Do not claim that you performed an external investigation.
17. Do not make compliance claims unless they are explicitly supported by supplied evidence.
18. Prefer precise, evidence-grounded language over speculation.

Your output must be a single valid JSON object strictly matching this schema:
{
  "finding_id": string,
  "user_id": string,
  "status": "COMPLETED" or "INSUFFICIENT_EVIDENCE",
  "factual_summary": string,
  "supporting_evidence": [
    {
      "evidence_id": string,
      "relevance": string
    }
  ],
  "uncertainty_and_contradictions": [string],
  "missing_or_unverified_evidence": [string],
  "evidence_vs_inference": {
    "verified_facts": [string],
    "inferences": [string]
  },
  "adversarial_questions": [string],
  "investigation_next_steps": [string],
  "provider_info": string,
  "generated_at": string
}
Return only JSON without markdown formatting or introductory text.
"""


def _clean_json_text(text: str) -> str:
    """Extract raw JSON text if enclosed in markdown code fences."""
    cleaned = text.strip()
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", cleaned)
    if match:
        return match.group(1).strip()
    return cleaned


class NvidiaLLMProvider(LLMProvider):
    """NVIDIA Nemotron 3 Super hosted API provider.

    Executes structured forensic investigations against the NVIDIA NIM cloud API.
    """

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
        timeout: float | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.api_key = api_key or self.settings.nvidia_api_key
        self.model = model or self.settings.nvidia_model
        self.base_url = (base_url or self.settings.nvidia_base_url).rstrip("/")
        self.timeout = timeout or self.settings.nvidia_timeout_seconds
        self._client = client

    def _build_user_prompt(self, packet: InvestigationPacket) -> str:
        """Serialize the InvestigationPacket into a structured context string."""
        context: dict[str, Any] = {
            "packet_id": packet.packet_id,
            "finding": packet.finding.model_dump(mode="json"),
            "subject": packet.subject.model_dump(mode="json"),
            "analysis_as_of": packet.analysis_as_of.isoformat(),
            "window_start": packet.window_start.isoformat(),
            "window_end": packet.window_end.isoformat(),
            "dataset_fingerprint": packet.dataset_fingerprint,
            "valid_evidence_ids": sorted(packet.valid_evidence_ids),
        }
        return (
            "Investigate the following deterministic finding and evidence packet. "
            "Return a structured forensic analysis strictly matching the requested JSON schema:\n\n"
            + json.dumps(context, indent=2)
        )

    def _parse_and_validate_response(
        self, raw_text: str, packet: InvestigationPacket
    ) -> StructuredInvestigationResult:
        """Parse raw model output into a valid StructuredInvestigationResult."""
        cleaned_json = _clean_json_text(raw_text)
        try:
            data = json.loads(cleaned_json)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Model output is not valid JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise ValueError("Model output JSON must be an object/dict")

        # Grounding invariants: enforce packet IDs
        data["finding_id"] = packet.finding.id
        data["user_id"] = packet.finding.user_id
        data["provider_info"] = f"nvidia/{self.model}"
        data["generated_at"] = packet.analysis_as_of.isoformat()

        # Coverage discipline: incomplete coverage must reflect INSUFFICIENT_EVIDENCE
        if packet.subject.activity.coverage != Coverage.COMPLETE:
            data["status"] = InvestigationStatus.INSUFFICIENT_EVIDENCE.value

        # Filter supporting evidence to only IDs present in packet
        valid_ids = packet.valid_evidence_ids
        raw_citations = data.get("supporting_evidence", [])
        filtered_citations: list[dict[str, Any]] = []
        if isinstance(raw_citations, list):
            for cite in raw_citations:
                if isinstance(cite, dict) and cite.get("evidence_id") in valid_ids:
                    filtered_citations.append(cite)
        data["supporting_evidence"] = filtered_citations

        # Ensure evidence_vs_inference structure
        evi = data.get("evidence_vs_inference")
        if not isinstance(evi, dict):
            data["evidence_vs_inference"] = {"verified_facts": [], "inferences": []}

        try:
            return StructuredInvestigationResult.model_validate(data)
        except Exception as exc:
            raise ValueError(
                f"Model response failed schema validation: {exc}"
            ) from exc

    def investigate(self, packet: InvestigationPacket) -> StructuredInvestigationResult:
        """Execute an investigation call to NVIDIA Nemotron 3 Super."""
        if not self.api_key:
            raise RuntimeError(
                "NVIDIA_API_KEY is not configured. Set the NVIDIA_API_KEY environment variable "
                "or update .env to use the NVIDIA Nemotron provider."
            )

        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        user_prompt = self._build_user_prompt(packet)
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": NEMOTRON_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
            "top_p": 0.7,
            "max_tokens": 4096,
            "response_format": {"type": "json_object"},
        }

        try:
            if self._client is not None:
                response = self._client.post(
                    url, headers=headers, json=payload, timeout=self.timeout
                )
            else:
                with httpx.Client(timeout=self.timeout) as client:
                    response = client.post(url, headers=headers, json=payload)
        except httpx.TimeoutException as exc:
            raise RuntimeError(
                f"NVIDIA API request timed out after {self.timeout}s"
            ) from exc
        except httpx.RequestError as exc:
            raise RuntimeError(
                f"NVIDIA API network connection error: {type(exc).__name__}"
            ) from exc

        if response.status_code == 401:
            raise RuntimeError(
                "NVIDIA API authentication failed: invalid or unauthorized API key (HTTP 401)"
            )
        if response.status_code == 429:
            raise RuntimeError(
                "NVIDIA API rate limit exceeded: too many requests (HTTP 429)"
            )
        if response.status_code >= 400:
            raise RuntimeError(
                f"NVIDIA API request failed with HTTP status {response.status_code}"
            )

        try:
            resp_data = response.json()
            content = resp_data["choices"][0]["message"]["content"]
        except Exception as exc:
            raise ValueError(
                f"Invalid response envelope received from NVIDIA API: {exc}"
            ) from exc

        return self._parse_and_validate_response(content, packet)

    def _parse_and_validate_chat_response(
        self, raw_text: str, packet: InvestigationPacket
    ) -> InvestigationChatResponse:
        """Parse raw model output into a valid InvestigationChatResponse."""
        cleaned_json = _clean_json_text(raw_text)
        try:
            data = json.loads(cleaned_json)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Model chat output is not valid JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise ValueError("Model chat output JSON must be an object/dict")

        reply = data.get("reply", "")
        if not reply or not isinstance(reply, str):
            reply = "Analysis completed. Review the exhibits and finding details in the dossier."

        # Filter citations to only valid evidence IDs
        valid_ids = packet.valid_evidence_ids
        raw_citations = data.get("citations", [])
        filtered_citations: list[EvidenceCitation] = []
        if isinstance(raw_citations, list):
            for cite in raw_citations:
                if isinstance(cite, dict) and cite.get("evidence_id") in valid_ids:
                    filtered_citations.append(
                        EvidenceCitation(
                            evidence_id=cite["evidence_id"],
                            relevance=cite.get("relevance", "Supporting exhibit."),
                        )
                    )

        raw_followups = data.get("suggested_followups", [])
        followups = [str(f) for f in raw_followups if isinstance(f, str)][:3]

        return InvestigationChatResponse(
            finding_id=packet.finding.id,
            reply=reply,
            citations=filtered_citations,
            suggested_followups=followups,
            provider_info=f"nvidia/{self.model}",
            is_fallback=False,
            generated_at=packet.analysis_as_of,
        )

    def chat(
        self,
        packet: InvestigationPacket,
        message: str,
        history: list[ChatMessage],
    ) -> InvestigationChatResponse:
        """Execute a conversational investigation query against NVIDIA Nemotron 3 Super."""
        if not self.api_key:
            raise RuntimeError(
                "NVIDIA_API_KEY is not configured. Set the NVIDIA_API_KEY environment variable "
                "or update .env to use the NVIDIA Nemotron provider."
            )

        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        # Build messages payload
        packet_context = {
            "packet_id": packet.packet_id,
            "finding": packet.finding.model_dump(mode="json"),
            "subject": packet.subject.model_dump(mode="json"),
            "analysis_as_of": packet.analysis_as_of.isoformat(),
            "window_start": packet.window_start.isoformat(),
            "window_end": packet.window_end.isoformat(),
            "valid_evidence_ids": sorted(packet.valid_evidence_ids),
        }

        messages: list[dict[str, str]] = [
            {
                "role": "system",
                "content": (
                    f"{NEMOTRON_CHAT_SYSTEM_PROMPT}\n\n"
                    f"AUTHORITATIVE INVESTIGATION PACKET CONTEXT:\n"
                    f"{json.dumps(packet_context, indent=2)}"
                ),
            }
        ]

        # Append recent history (capped at 6 messages)
        recent_history = history[-6:] if history else []
        for turn in recent_history:
            messages.append({"role": turn.role, "content": turn.content})

        # Append current user question
        messages.append({"role": "user", "content": message})

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.2,
            "top_p": 0.7,
            "max_tokens": 2048,
            "response_format": {"type": "json_object"},
        }

        try:
            if self._client is not None:
                response = self._client.post(
                    url, headers=headers, json=payload, timeout=self.timeout
                )
            else:
                with httpx.Client(timeout=self.timeout) as client:
                    response = client.post(url, headers=headers, json=payload)
        except httpx.TimeoutException as exc:
            raise RuntimeError(
                f"NVIDIA API request timed out after {self.timeout}s"
            ) from exc
        except httpx.RequestError as exc:
            raise RuntimeError(
                f"NVIDIA API network connection error: {type(exc).__name__}"
            ) from exc

        if response.status_code == 401:
            raise RuntimeError(
                "NVIDIA API authentication failed: invalid or unauthorized API key (HTTP 401)"
            )
        if response.status_code == 429:
            raise RuntimeError(
                "NVIDIA API rate limit exceeded: too many requests (HTTP 429)"
            )
        if response.status_code >= 400:
            raise RuntimeError(
                f"NVIDIA API request failed with HTTP status {response.status_code}"
            )

        try:
            resp_data = response.json()
            content = resp_data["choices"][0]["message"]["content"]
        except Exception as exc:
            raise ValueError(
                f"Invalid response envelope received from NVIDIA API: {exc}"
            ) from exc

        return self._parse_and_validate_chat_response(content, packet)


