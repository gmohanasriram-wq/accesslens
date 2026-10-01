"""RED tests for Phase 4: AI Investigation Layer.

These tests define the contract for the model-agnostic AI investigation layer
before any implementation is written. They must fail initially for the intended
reasons (ImportError / missing routes / unimplemented schemas).

The tests verify:
1. InvestigationPacket construction from verified engine/ingest facts only.
2. StructuredInvestigationResult Pydantic schema validation.
3. Provider-agnostic interface and deterministic MockLLMProvider.
4. Output safety denylist enforcement:
   - Rejection of revocation / removal directives.
   - Rejection of necessity claims ("unnecessary" / "safe to remove").
   - Rejection of severity / risk regrading.
   - Rejection of definitive usage conclusions when coverage is not COMPLETE.
   - Rejection of hallucinated / invented evidence IDs.
5. Provider failure resilience (graceful fallback to ERROR status without crashing).
6. Read-only API route invariants (GET only, no write paths, 404 on missing finding).
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.config import Settings
from app.core.enums import Coverage, Severity
from app.engine import analyze
from app.ingestion import InMemoryDataset
from app.api.read_models import find_persona

# These imports define the Phase 4 contract
from app.ai import (
    EvidenceCitation,
    FactVsInference,
    InvestigationPacket,
    InvestigationStatus,
    LLMProvider,
    MockLLMProvider,
    NvidiaLLMProvider,
    SafetyViolationError,
    StructuredInvestigationResult,
    build_investigation_packet,
    get_provider,
    investigate_finding,
    validate_investigation_safety,
)


# --------------------------------------------------------------------------- #
# Helpers & Fixtures
# --------------------------------------------------------------------------- #


def _get_subject(user_id: str, dataset: InMemoryDataset, settings: Settings) -> PersonaSummary:
    from app.db import build_engine, build_session_factory, create_all, session_scope
    from app.ingestion import IngestPipeline
    engine = build_engine(settings)
    create_all(engine)
    factory = build_session_factory(engine)
    pipeline = IngestPipeline(settings)
    try:
        with session_scope(factory) as session:
            pipeline.run(session)
            persona = find_persona(session, dataset, user_id)
            assert persona is not None
            return persona
    finally:
        engine.dispose()


def _get_bob_finding_and_subject(dataset: InMemoryDataset, settings: Settings):
    findings = analyze(dataset, settings)
    bob_finding = next(f for f in findings if f.user_id == "u_bob")
    subject = _get_subject("u_bob", dataset, settings)
    return bob_finding, subject


def _get_gina_finding_and_subject(dataset: InMemoryDataset, settings: Settings):
    findings = analyze(dataset, settings)
    gina_finding = next(f for f in findings if f.user_id == "u_gina")
    subject = _get_subject("u_gina", dataset, settings)
    return gina_finding, subject


# --------------------------------------------------------------------------- #
# 1. Packet Construction & Fact Boundary
# --------------------------------------------------------------------------- #


def test_packet_construction_from_dossier_facts_only(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """The packet must bundle only facts established by AccessLens."""
    finding, subject = _get_bob_finding_and_subject(dataset, settings)

    packet = build_investigation_packet(finding, subject, dataset, settings)

    assert isinstance(packet, InvestigationPacket)
    assert packet.finding.id == finding.id
    assert packet.finding.user_id == "u_bob"
    assert packet.subject.id == "u_bob"
    assert packet.subject.activity.coverage == Coverage.COMPLETE
    assert packet.window_start == dataset.window[0]
    assert packet.window_end == dataset.window[1]
    assert packet.analysis_as_of == dataset.window[1]
    assert packet.dataset_fingerprint == dataset.dataset_fingerprint()
    assert packet.valid_evidence_ids == {e.evidence_id for e in finding.evidence}


# --------------------------------------------------------------------------- #
# 2. StructuredInvestigationResult Schema Validation
# --------------------------------------------------------------------------- #


def test_structured_investigation_result_schema_validation(
    analysis_as_of: datetime,
) -> None:
    """The result must strictly validate required sections and types."""
    valid_payload = {
        "finding_id": "fnd-u_bob-rule-a-aws",
        "user_id": "u_bob",
        "status": "COMPLETED",
        "factual_summary": "Observed 4 AWS CloudTrail events covering S3_READ and EC2_READ.",
        "supporting_evidence": [
            {
                "evidence_id": "ev_test_1",
                "relevance": "Shows read-only S3 activity during the 90-day window.",
            }
        ],
        "uncertainty_and_contradictions": [],
        "missing_or_unverified_evidence": [],
        "evidence_vs_inference": {
            "verified_facts": ["Bob exercised 2 of 13 granted capabilities."],
            "inferences": ["Role permissions may be broader than day-to-day requirements."],
        },
        "adversarial_questions": [
            "Are write capabilities needed for scheduled or quarterly maintenance?"
        ],
        "investigation_next_steps": [
            "Review ticket history with Bob's manager for emergency write requirements."
        ],
        "provider_info": "mock-test-provider",
        "generated_at": analysis_as_of,
    }

    result = StructuredInvestigationResult.model_validate(valid_payload)
    assert result.status == InvestigationStatus.COMPLETED
    assert len(result.supporting_evidence) == 1
    assert result.supporting_evidence[0].evidence_id == "ev_test_1"

    # Missing mandatory section must fail validation
    invalid_payload = valid_payload.copy()
    del invalid_payload["evidence_vs_inference"]
    with pytest.raises(ValidationError):
        StructuredInvestigationResult.model_validate(invalid_payload)


# --------------------------------------------------------------------------- #
# 3. Provider Interface & Deterministic Mock
# --------------------------------------------------------------------------- #


def test_mock_provider_deterministic_behavior(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """MockLLMProvider must implement LLMProvider and return reproducible output."""
    finding, subject = _get_bob_finding_and_subject(dataset, settings)
    packet = build_investigation_packet(finding, subject, dataset, settings)

    provider: LLMProvider = MockLLMProvider()
    result1 = provider.investigate(packet)
    result2 = provider.investigate(packet)

    assert isinstance(result1, StructuredInvestigationResult)
    assert result1.finding_id == packet.finding.id
    assert result1.user_id == packet.finding.user_id
    assert result1.model_dump() == result2.model_dump()


# --------------------------------------------------------------------------- #
# 4. Safety Denylist & Guardrail Enforcement
# --------------------------------------------------------------------------- #


def test_safety_rejects_revocation_directives(
    dataset: InMemoryDataset, settings: Settings, analysis_as_of: datetime
) -> None:
    """The safety validator must reject any revocation or access-removal command."""
    finding, subject = _get_bob_finding_and_subject(dataset, settings)
    packet = build_investigation_packet(finding, subject, dataset, settings)

    bad_result = StructuredInvestigationResult(
        finding_id=finding.id,
        user_id=finding.user_id,
        status=InvestigationStatus.COMPLETED,
        factual_summary="Bob does not use admin access.",
        supporting_evidence=[],
        uncertainty_and_contradictions=[],
        missing_or_unverified_evidence=[],
        evidence_vs_inference=FactVsInference(
            verified_facts=[], inferences=[]
        ),
        adversarial_questions=[],
        investigation_next_steps=[
            "Revoke Bob's AdministratorAccess policy immediately."
        ],
        provider_info="mock-test",
        generated_at=analysis_as_of,
    )

    with pytest.raises(SafetyViolationError, match="revocation or removal"):
        validate_investigation_safety(bad_result, packet)


def test_safety_rejects_necessity_assertion(
    dataset: InMemoryDataset, settings: Settings, analysis_as_of: datetime
) -> None:
    """The safety validator must reject assertions that access is 'unnecessary'."""
    finding, subject = _get_bob_finding_and_subject(dataset, settings)
    packet = build_investigation_packet(finding, subject, dataset, settings)

    bad_result = StructuredInvestigationResult(
        finding_id=finding.id,
        user_id=finding.user_id,
        status=InvestigationStatus.COMPLETED,
        factual_summary="Bob's admin role is completely unnecessary and safe to remove.",
        supporting_evidence=[],
        uncertainty_and_contradictions=[],
        missing_or_unverified_evidence=[],
        evidence_vs_inference=FactVsInference(
            verified_facts=[], inferences=[]
        ),
        adversarial_questions=[],
        investigation_next_steps=["Ask manager."],
        provider_info="mock-test",
        generated_at=analysis_as_of,
    )

    with pytest.raises(SafetyViolationError, match="unnecessary|safe to remove"):
        validate_investigation_safety(bad_result, packet)


def test_safety_rejects_regraded_severity(
    dataset: InMemoryDataset, settings: Settings, analysis_as_of: datetime
) -> None:
    """The safety validator must reject attempts to change finding severity."""
    finding, subject = _get_bob_finding_and_subject(dataset, settings)
    assert finding.severity == Severity.HIGH
    packet = build_investigation_packet(finding, subject, dataset, settings)

    bad_result = StructuredInvestigationResult(
        finding_id=finding.id,
        user_id=finding.user_id,
        status=InvestigationStatus.COMPLETED,
        factual_summary="This finding should be regraded to CRITICAL severity.",
        supporting_evidence=[],
        uncertainty_and_contradictions=[],
        missing_or_unverified_evidence=[],
        evidence_vs_inference=FactVsInference(
            verified_facts=[], inferences=[]
        ),
        adversarial_questions=[],
        investigation_next_steps=["Ask manager."],
        provider_info="mock-test",
        generated_at=analysis_as_of,
    )

    with pytest.raises(SafetyViolationError, match="severity"):
        validate_investigation_safety(bad_result, packet)


def test_safety_rejects_definitive_usage_on_missing_coverage(
    dataset: InMemoryDataset, settings: Settings, analysis_as_of: datetime
) -> None:
    """Definitive usage claims must be rejected when coverage is not COMPLETE."""
    finding, subject = _get_gina_finding_and_subject(dataset, settings)
    assert subject.activity.coverage == Coverage.MISSING
    packet = build_investigation_packet(finding, subject, dataset, settings)

    # Gina's telemetry was never delivered; claiming she did not use access is unsafe
    unsafe_result = StructuredInvestigationResult(
        finding_id=finding.id,
        user_id=finding.user_id,
        status=InvestigationStatus.COMPLETED,
        factual_summary="Gina has not used any of her permissions during the window.",
        supporting_evidence=[],
        uncertainty_and_contradictions=[],
        missing_or_unverified_evidence=[],
        evidence_vs_inference=FactVsInference(
            verified_facts=["Zero events recorded."], inferences=[]
        ),
        adversarial_questions=[],
        investigation_next_steps=["Gather logs."],
        provider_info="mock-test",
        generated_at=analysis_as_of,
    )

    with pytest.raises(SafetyViolationError, match="coverage"):
        validate_investigation_safety(unsafe_result, packet)


def test_safety_rejects_hallucinated_evidence_id(
    dataset: InMemoryDataset, settings: Settings, analysis_as_of: datetime
) -> None:
    """Every cited evidence ID must exist in the packet's valid evidence set."""
    finding, subject = _get_bob_finding_and_subject(dataset, settings)
    packet = build_investigation_packet(finding, subject, dataset, settings)

    bad_result = StructuredInvestigationResult(
        finding_id=finding.id,
        user_id=finding.user_id,
        status=InvestigationStatus.COMPLETED,
        factual_summary="Observed read activity.",
        supporting_evidence=[
            EvidenceCitation(
                evidence_id="ev_invented_ghost_log_999",
                relevance="Asserts nonexistent event occurred.",
            )
        ],
        uncertainty_and_contradictions=[],
        missing_or_unverified_evidence=[],
        evidence_vs_inference=FactVsInference(
            verified_facts=[], inferences=[]
        ),
        adversarial_questions=[],
        investigation_next_steps=["Check logs."],
        provider_info="mock-test",
        generated_at=analysis_as_of,
    )

    with pytest.raises(SafetyViolationError, match="ev_invented_ghost_log_999"):
        validate_investigation_safety(bad_result, packet)


# --------------------------------------------------------------------------- #
# 5. Failure Resilience & Graceful Fallback
# --------------------------------------------------------------------------- #


class BrokenProvider(LLMProvider):
    def investigate(self, packet: InvestigationPacket) -> StructuredInvestigationResult:
        raise RuntimeError("Provider connection timeout: upstream LLM unreachable")


def test_provider_failure_returns_graceful_error_status(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """Provider network/model exceptions must return ERROR status, not crash."""
    finding, subject = _get_bob_finding_and_subject(dataset, settings)
    packet = build_investigation_packet(finding, subject, dataset, settings)

    result = investigate_finding(packet, provider=BrokenProvider())

    assert isinstance(result, StructuredInvestigationResult)
    assert result.status == InvestigationStatus.ERROR
    assert any("upstream LLM unreachable" in u for u in result.uncertainty_and_contradictions)


# --------------------------------------------------------------------------- #
# 6. Read-Only API Endpoint
# --------------------------------------------------------------------------- #


def test_investigation_endpoint_is_strictly_read_only(client: TestClient) -> None:
    """The investigation endpoint must be GET only, never a mutating route."""
    bob_finding_id = "fnd-u_bob-rule-a"

    # GET must succeed and return the structured investigation
    get_res = client.get(f"/api/analysis/findings/{bob_finding_id}/investigation")
    assert get_res.status_code == 200
    data = get_res.json()
    assert data["finding_id"] == bob_finding_id
    assert "factual_summary" in data
    assert "evidence_vs_inference" in data

    # 404 for unknown finding ID
    assert client.get("/api/analysis/findings/fnd-nonexistent/investigation").status_code == 404

    # POST, PUT, DELETE must be rejected (405 Method Not Allowed)
    assert client.post(f"/api/analysis/findings/{bob_finding_id}/investigation").status_code == 405
    assert client.put(f"/api/analysis/findings/{bob_finding_id}/investigation").status_code == 405
    assert client.delete(f"/api/analysis/findings/{bob_finding_id}/investigation").status_code == 405


# --------------------------------------------------------------------------- #
# 7. NVIDIA Provider Tests (Unit / Mocked HTTP)
# --------------------------------------------------------------------------- #


def _make_nvidia_response_payload(
    finding_id: str,
    user_id: str,
    valid_evidence_id: str,
    *,
    status: str = "COMPLETED",
    include_extra_evidence: bool = False,
) -> dict:
    supporting = [{"evidence_id": valid_evidence_id, "relevance": "Direct match"}]
    if include_extra_evidence:
        supporting.append({"evidence_id": "ev_invented_ghost_999", "relevance": "Hallucinated"})

    inner_content = {
        "finding_id": finding_id,
        "user_id": user_id,
        "status": status,
        "factual_summary": "Investigated identity telemetry and access grant.",
        "supporting_evidence": supporting,
        "uncertainty_and_contradictions": ["No contradiction noted."],
        "missing_or_unverified_evidence": [],
        "evidence_vs_inference": {
            "verified_facts": ["Telemetry log event recorded."],
            "inferences": ["Access grant exercised intermittently."],
        },
        "adversarial_questions": ["Is write access necessary for emergency failover?"],
        "investigation_next_steps": ["Verify ticketing system records."],
        "provider_info": "nemotron-test",
        "generated_at": "2026-09-29T06:00:00Z",
    }
    return {
        "id": "chatcmpl-test-123",
        "object": "chat.completion",
        "created": 1727589600,
        "model": "nvidia/nemotron-3-super-120b-a12b",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": json.dumps(inner_content),
                },
                "finish_reason": "stop",
            }
        ],
    }


def test_nvidia_provider_missing_key_behavior(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """Missing API key must raise RuntimeError and fallback gracefully via investigate_finding."""
    finding, subject = _get_bob_finding_and_subject(dataset, settings)
    packet = build_investigation_packet(finding, subject, dataset, settings)

    no_key_settings = Settings(nvidia_api_key=None)
    provider = NvidiaLLMProvider(settings=no_key_settings, api_key=None)

    # Calling provider.investigate directly without key raises RuntimeError
    with pytest.raises(RuntimeError, match="NVIDIA_API_KEY is not configured"):
        provider.investigate(packet)

    # Calling via investigate_finding catches it and returns ERROR status
    result = investigate_finding(packet, provider=provider)
    assert result.status == InvestigationStatus.ERROR
    assert "NVIDIA_API_KEY is not configured" in result.factual_summary


def test_nvidia_provider_successful_response_parsing(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """Successful NVIDIA API response must parse into a valid StructuredInvestigationResult."""
    finding, subject = _get_bob_finding_and_subject(dataset, settings)
    packet = build_investigation_packet(finding, subject, dataset, settings)
    first_evidence_id = sorted(packet.valid_evidence_ids)[0]

    api_payload = _make_nvidia_response_payload(finding.id, finding.user_id, first_evidence_id)

    def mock_handler(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://integrate.api.nvidia.com/v1/chat/completions"
        assert request.headers["Authorization"] == "Bearer test-key-12345"
        body = json.loads(request.content.decode("utf-8"))
        assert body["model"] == "nvidia/nemotron-3-super-120b-a12b"
        return httpx.Response(200, json=api_payload)

    client = httpx.Client(transport=httpx.MockTransport(mock_handler))
    provider = NvidiaLLMProvider(api_key="test-key-12345", client=client)

    result = provider.investigate(packet)
    assert isinstance(result, StructuredInvestigationResult)
    assert result.finding_id == finding.id
    assert result.user_id == finding.user_id
    assert result.status == InvestigationStatus.COMPLETED
    assert len(result.supporting_evidence) == 1
    assert result.supporting_evidence[0].evidence_id == first_evidence_id
    assert "nvidia/nemotron-3-super-120b-a12b" in result.provider_info
    # Safety validator must also accept the valid result
    validate_investigation_safety(result, packet)


def test_nvidia_provider_handles_markdown_code_fences(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """Provider must strip markdown code fences from model response."""
    finding, subject = _get_bob_finding_and_subject(dataset, settings)
    packet = build_investigation_packet(finding, subject, dataset, settings)
    first_evidence_id = sorted(packet.valid_evidence_ids)[0]

    raw_dict = _make_nvidia_response_payload(finding.id, finding.user_id, first_evidence_id)
    # Wrap content in markdown code block
    fenced_content = f"```json\n{raw_dict['choices'][0]['message']['content']}\n```"
    raw_dict["choices"][0]["message"]["content"] = fenced_content

    client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, json=raw_dict)))
    provider = NvidiaLLMProvider(api_key="test-key", client=client)

    result = provider.investigate(packet)
    assert result.status == InvestigationStatus.COMPLETED
    assert result.finding_id == finding.id


def test_nvidia_provider_http_401_error(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """HTTP 401 must raise a sanitized authentication error without leaking keys."""
    finding, subject = _get_bob_finding_and_subject(dataset, settings)
    packet = build_investigation_packet(finding, subject, dataset, settings)

    client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(401, json={"error": "Unauthorized"})))
    provider = NvidiaLLMProvider(api_key="secret-api-key", client=client)

    with pytest.raises(RuntimeError, match="authentication failed: invalid or unauthorized API key"):
        provider.investigate(packet)

    result = investigate_finding(packet, provider=provider)
    assert result.status == InvestigationStatus.ERROR
    assert "secret-api-key" not in result.factual_summary


def test_nvidia_provider_http_429_rate_limit(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """HTTP 429 must raise rate limit error and return ERROR status gracefully."""
    finding, subject = _get_bob_finding_and_subject(dataset, settings)
    packet = build_investigation_packet(finding, subject, dataset, settings)

    client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(429, json={"error": "Rate limit exceeded"})))
    provider = NvidiaLLMProvider(api_key="test-key", client=client)

    with pytest.raises(RuntimeError, match="rate limit exceeded"):
        provider.investigate(packet)

    result = investigate_finding(packet, provider=provider)
    assert result.status == InvestigationStatus.ERROR


def test_nvidia_provider_http_500_server_error(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """HTTP 500 must raise request failed error and return ERROR status gracefully."""
    finding, subject = _get_bob_finding_and_subject(dataset, settings)
    packet = build_investigation_packet(finding, subject, dataset, settings)

    client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(500, text="Internal Server Error")))
    provider = NvidiaLLMProvider(api_key="test-key", client=client)

    with pytest.raises(RuntimeError, match="failed with HTTP status 500"):
        provider.investigate(packet)

    result = investigate_finding(packet, provider=provider)
    assert result.status == InvestigationStatus.ERROR


def test_nvidia_provider_network_timeout(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """Network timeout must raise clean timeout exception and return ERROR status."""
    finding, subject = _get_bob_finding_and_subject(dataset, settings)
    packet = build_investigation_packet(finding, subject, dataset, settings)

    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("Read timed out after 30s")

    client = httpx.Client(transport=httpx.MockTransport(timeout_handler))
    provider = NvidiaLLMProvider(api_key="test-key", timeout=30.0, client=client)

    with pytest.raises(RuntimeError, match="timed out"):
        provider.investigate(packet)

    result = investigate_finding(packet, provider=provider)
    assert result.status == InvestigationStatus.ERROR


def test_nvidia_provider_malformed_json_response(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """Malformed non-JSON output must raise ValueError and return ERROR status."""
    finding, subject = _get_bob_finding_and_subject(dataset, settings)
    packet = build_investigation_packet(finding, subject, dataset, settings)

    malformed_resp = {
        "choices": [{"message": {"content": "Sorry, I cannot produce JSON right now."}}]
    }
    client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, json=malformed_resp)))
    provider = NvidiaLLMProvider(api_key="test-key", client=client)

    with pytest.raises(ValueError, match="not valid JSON"):
        provider.investigate(packet)

    result = investigate_finding(packet, provider=provider)
    assert result.status == InvestigationStatus.ERROR


def test_nvidia_provider_filters_hallucinated_evidence_ids(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """Provider must filter out evidence IDs not present in the packet."""
    finding, subject = _get_bob_finding_and_subject(dataset, settings)
    packet = build_investigation_packet(finding, subject, dataset, settings)
    first_evidence_id = sorted(packet.valid_evidence_ids)[0]

    api_payload = _make_nvidia_response_payload(
        finding.id, finding.user_id, first_evidence_id, include_extra_evidence=True
    )
    client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, json=api_payload)))
    provider = NvidiaLLMProvider(api_key="test-key", client=client)

    result = provider.investigate(packet)
    # The hallucinated ID 'ev_invented_ghost_999' must have been stripped
    assert len(result.supporting_evidence) == 1
    assert result.supporting_evidence[0].evidence_id == first_evidence_id
    assert all(c.evidence_id in packet.valid_evidence_ids for c in result.supporting_evidence)


def test_nvidia_provider_enforces_insufficient_evidence_on_incomplete_telemetry(
    dataset: InMemoryDataset, settings: Settings
) -> None:
    """Provider must enforce INSUFFICIENT_EVIDENCE when subject coverage is incomplete."""
    finding, subject = _get_gina_finding_and_subject(dataset, settings)
    assert subject.activity.coverage == Coverage.MISSING
    packet = build_investigation_packet(finding, subject, dataset, settings)

    # Model returned COMPLETED despite missing telemetry
    api_payload = _make_nvidia_response_payload(
        finding.id, finding.user_id, "ev_dummy", status="COMPLETED"
    )
    client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, json=api_payload)))
    provider = NvidiaLLMProvider(api_key="test-key", client=client)

    result = provider.investigate(packet)
    # Provider must enforce INSUFFICIENT_EVIDENCE
    assert result.status == InvestigationStatus.INSUFFICIENT_EVIDENCE


# --------------------------------------------------------------------------- #
# 8. Provider Factory & Configuration Invariants
# --------------------------------------------------------------------------- #


def test_provider_factory_selection() -> None:
    """Factory must return MockLLMProvider by default and NvidiaLLMProvider when configured."""
    # Hermetic default settings -> MockLLMProvider
    hermetic_default = Settings(_env_file=None)
    assert isinstance(get_provider(hermetic_default), MockLLMProvider)

    # Explicit settings with mock
    mock_settings = Settings(ai_provider="mock", _env_file=None)
    assert isinstance(get_provider(mock_settings), MockLLMProvider)

    # Explicit settings with nvidia
    nvidia_settings = Settings(ai_provider="nvidia", nvidia_api_key="test-nv-key", _env_file=None)
    nv_p = get_provider(nvidia_settings)
    assert isinstance(nv_p, NvidiaLLMProvider)
    assert nv_p.api_key == "test-nv-key"

    # Explicit provider_name override
    assert isinstance(get_provider("nvidia"), NvidiaLLMProvider)
    assert isinstance(get_provider("mock"), MockLLMProvider)


# --------------------------------------------------------------------------- #
# 9. Live Integration Test (Conditional)
# --------------------------------------------------------------------------- #


def _is_live_nvidia_configured() -> bool:
    """Check whether live NVIDIA Nemotron testing is configured via env or .env."""
    from app.core.config import get_settings

    try:
        s = get_settings()
        has_key = bool(
            os.getenv("NVIDIA_API_KEY")
            or os.getenv("ACCESSLENS_NVIDIA_API_KEY")
            or s.nvidia_api_key
        )
        provider = (
            os.getenv("ACCESSLENS_AI_PROVIDER")
            or os.getenv("AI_PROVIDER")
            or s.ai_provider
        )
        return has_key and (provider == "nvidia")
    except Exception:
        return False


@pytest.mark.skipif(
    not _is_live_nvidia_configured(),
    reason="Requires valid NVIDIA_API_KEY and ACCESSLENS_AI_PROVIDER=nvidia to run live cloud inference.",
)
def test_live_nvidia_integration(dataset: InMemoryDataset) -> None:
    """Live integration test against NVIDIA Nemotron 3 Super hosted API.

    Executes only if NVIDIA_API_KEY is configured and AI_PROVIDER is set to nvidia.
    """
    from app.core.config import get_settings

    live_settings = get_settings()
    finding, subject = _get_bob_finding_and_subject(dataset, live_settings)
    packet = build_investigation_packet(finding, subject, dataset, live_settings)

    provider = get_provider(live_settings)
    assert isinstance(provider, NvidiaLLMProvider)

    result = provider.investigate(packet)

    assert isinstance(result, StructuredInvestigationResult)
    assert result.finding_id == finding.id
    assert result.user_id == finding.user_id
    assert result.status in (InvestigationStatus.COMPLETED, InvestigationStatus.INSUFFICIENT_EVIDENCE)
    assert len(result.factual_summary) > 0
    assert len(result.evidence_vs_inference.verified_facts) > 0

    # Ensure result passes all safety invariants
    validate_investigation_safety(result, packet)


