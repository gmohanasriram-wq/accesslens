"""Tests for the Phase 4 Contextual AI Review Chatbot ("AI Trial Lawyer Chat").

Verifies:
1. Bob Chen privilege utilization inquiry (AdministratorAccess vs 2 observed read capabilities).
2. Carol Diaz ghost access inquiry (Okta disable timeline vs post-deactivation GitHub actions).
3. Gina Patel incomplete coverage inquiry (missing proxy telemetry; strictly no clean claims).
4. Safety validation (no revocation directives, no necessity claims, grounded citations only).
5. Off-topic prompt refusal.
6. Graceful fallback on NVIDIA timeout/error with explicit fallback badge.
7. API integration via GET /api/analysis/findings/{finding_id}/investigation?q=...
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.ai import (
    ChatMessage,
    EvidenceCitation,
    InvestigationChatResponse,
    InvestigationPacket,
    SafetyViolationError,
    StructuredInvestigationResult,
    build_investigation_packet,
    investigate_chat,
    validate_chat_safety,
)
from app.api.read_models import find_persona
from app.core.config import Settings
from app.core.enums import Coverage, FindingType
from app.db import build_engine, build_session_factory, create_all, session_scope
from app.engine import analyze
from app.ingestion import InMemoryDataset, IngestPipeline
from app.schemas.api import PersonaSummary


def _get_subject(user_id: str, dataset: InMemoryDataset, settings: Settings) -> PersonaSummary:
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


@pytest.fixture
def bob_packet(dataset: InMemoryDataset, settings: Settings):
    findings = analyze(dataset, settings)
    bob_finding = next(f for f in findings if f.user_id == "u_bob" and f.type == FindingType.HIGH_PRIVILEGE_LOW_USAGE)
    subject = _get_subject("u_bob", dataset, settings)
    return build_investigation_packet(bob_finding, subject, dataset, settings)


@pytest.fixture
def carol_packet(dataset: InMemoryDataset, settings: Settings):
    findings = analyze(dataset, settings)
    carol_finding = next(f for f in findings if f.user_id == "u_carol" and f.type == FindingType.GHOST_ACCESS)
    subject = _get_subject("u_carol", dataset, settings)
    return build_investigation_packet(carol_finding, subject, dataset, settings)


@pytest.fixture
def alice_packet(dataset: InMemoryDataset, settings: Settings):
    findings = analyze(dataset, settings)
    alice_finding = next(f for f in findings if f.user_id == "u_alice")
    subject = _get_subject("u_alice", dataset, settings)
    return build_investigation_packet(alice_finding, subject, dataset, settings)


@pytest.fixture
def gina_packet(dataset: InMemoryDataset, settings: Settings):
    findings = analyze(dataset, settings)
    gina_finding = next(f for f in findings if f.user_id == "u_gina")
    subject = _get_subject("u_gina", dataset, settings)
    return build_investigation_packet(gina_finding, subject, dataset, settings)


def test_chat_bob_privilege_utilization(bob_packet, settings):
    """Bob inquiries must cite AdministratorAccess, 13 capabilities, 2 observed capabilities, and valid exhibits."""
    res = investigate_chat(
        bob_packet,
        message="Why was Bob flagged for AdministratorAccess?",
        history=[],
        settings=settings,
    )
    assert isinstance(res, InvestigationChatResponse)
    assert res.finding_id == bob_packet.finding.id
    assert "AdministratorAccess" in res.reply
    assert "13" in res.reply
    assert "2" in res.reply
    assert "0.154" in res.reply
    assert res.provider_info == "deterministic-mock-v1"
    assert res.is_fallback is False

    # Check evidence citations
    assert len(res.citations) > 0
    for cit in res.citations:
        assert cit.evidence_id in bob_packet.valid_evidence_ids


def test_chat_carol_ghost_access_timeline(carol_packet, settings):
    """Carol inquiries must cite termination, Okta disable on 2026-08-15, and GitHub activity on 2026-08-19."""
    res = investigate_chat(
        carol_packet,
        message="What happened after Carol's Okta account was disabled?",
        history=[],
        settings=settings,
    )
    assert isinstance(res, InvestigationChatResponse)
    assert "2026-08-15" in res.reply
    assert "2026-08-19" in res.reply
    assert "GitHub" in res.reply
    assert len(res.citations) > 0
    for cit in res.citations:
        assert cit.evidence_id in carol_packet.valid_evidence_ids


def test_chat_gina_incomplete_coverage(gina_packet, settings):
    """Gina inquiries must reflect missing proxy telemetry and make NO clean or unused claims."""
    res = investigate_chat(
        gina_packet,
        message="Did Gina use her application access?",
        history=[],
        settings=settings,
    )
    assert isinstance(res, InvestigationChatResponse)
    assert "proxy_zscaler" in res.reply or "SOURCE_MISSING" in res.reply or "incomplete" in res.reply
    assert "insufficient" in res.reply.lower()

    # Safety: must not say clean, unused, or never used
    reply_lower = res.reply.lower()
    assert "clean" not in reply_lower
    assert "never used" not in reply_lower


def test_chat_safety_rejection_of_revocation(bob_packet):
    """validate_chat_safety must raise on imperative revocation commands."""
    citations = [EvidenceCitation(evidence_id=next(iter(bob_packet.valid_evidence_ids)), relevance="exhibit")]
    with pytest.raises(SafetyViolationError, match="revocation or removal directive"):
        validate_chat_safety("You should revoke Bob's AWS AdministratorAccess immediately.", citations, bob_packet)


def test_chat_safety_rejection_of_necessity(bob_packet):
    """validate_chat_safety must raise on necessity claims."""
    citations = [EvidenceCitation(evidence_id=next(iter(bob_packet.valid_evidence_ids)), relevance="exhibit")]
    with pytest.raises(SafetyViolationError, match="necessity conclusion"):
        validate_chat_safety("This access is unnecessary for Bob's role.", citations, bob_packet)


def test_chat_safety_rejection_of_invalid_citation(bob_packet):
    """validate_chat_safety must raise if an ungrounded citation ID is provided."""
    citations = [EvidenceCitation(evidence_id="hallucinated-exhibit-id", relevance="fake")]
    with pytest.raises(SafetyViolationError, match="not in packet valid evidence IDs"):
        validate_chat_safety("Bob used S3 read permissions.", citations, bob_packet)


def test_chat_off_topic_refusal(bob_packet, settings):
    """Off-topic queries must receive a polite refusal without hallucinations."""
    res = investigate_chat(
        bob_packet,
        message="Write a python script to calculate fibonacci numbers",
        history=[],
        settings=settings,
    )
    assert "AccessLens Trial Lawyer Assistant" in res.reply
    assert "can only answer questions regarding this finding" in res.reply
    assert len(res.citations) == 0


def test_chat_fallback_on_nvidia_error(bob_packet):
    """When NVIDIA provider fails, investigate_chat must fall back to Mock with explicit fallback badge."""
    settings = Settings(ai_provider="nvidia")

    with patch("app.ai.investigator.get_provider") as mock_get_provider:
        nvidia_mock = MagicMock()
        nvidia_mock.chat.side_effect = TimeoutError("NVIDIA API timed out")
        mock_get_provider.return_value = nvidia_mock

        res = investigate_chat(
            bob_packet,
            message="Why was Bob flagged?",
            history=[],
            settings=settings,
        )

        assert isinstance(res, InvestigationChatResponse)
        assert res.is_fallback is True
        assert res.provider_info == "fallback:deterministic-mock"
        assert "AdministratorAccess" in res.reply


def test_chat_api_get_investigation_without_q(client: TestClient):
    """GET /api/analysis/findings/{id}/investigation without q returns StructuredInvestigationResult."""
    analysis_res = client.get("/api/analysis")
    assert analysis_res.status_code == 200
    findings = analysis_res.json()["findings"]
    bob_finding = next(f for f in findings if f["user_id"] == "u_bob")

    res = client.get(f"/api/analysis/findings/{bob_finding['id']}/investigation")
    assert res.status_code == 200
    data = res.json()
    assert "factual_summary" in data
    assert "evidence_vs_inference" in data
    assert "adversarial_questions" in data
    assert data["status"] == "COMPLETED"


def test_chat_api_get_investigation_with_q(client: TestClient):
    """GET /api/analysis/findings/{id}/investigation with q returns InvestigationChatResponse."""
    analysis_res = client.get("/api/analysis")
    findings = analysis_res.json()["findings"]
    bob_finding = next(f for f in findings if f["user_id"] == "u_bob")

    res = client.get(
        f"/api/analysis/findings/{bob_finding['id']}/investigation",
        params={"q": "Why was Bob flagged for AdministratorAccess?"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "reply" in data
    assert "citations" in data
    assert "provider_info" in data
    assert data["is_fallback"] is False
    assert "AdministratorAccess" in data["reply"]


def test_chat_api_with_history(client: TestClient):
    """GET /api/analysis/findings/{id}/investigation accepts valid JSON history."""
    analysis_res = client.get("/api/analysis")
    findings = analysis_res.json()["findings"]
    carol_finding = next(f for f in findings if f["user_id"] == "u_carol")

    history = [
        {"role": "user", "content": "What is this finding about?"},
        {"role": "assistant", "content": "This finding reports ghost access for Carol Diaz."},
    ]
    res = client.get(
        f"/api/analysis/findings/{carol_finding['id']}/investigation",
        params={
            "q": "What happened after Carol's Okta account was disabled?",
            "history": json.dumps(history),
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert "GitHub" in data["reply"]


def test_chat_api_404_on_unknown_finding(client: TestClient):
    """GET /api/analysis/findings/fnd-nonexistent/investigation returns 404."""
    res = client.get("/api/analysis/findings/fnd-nonexistent/investigation", params={"q": "hello"})
    assert res.status_code == 404


def test_chat_carol_repository_inquiry(carol_packet, settings):
    """Inquiry on repositories accessed by Carol must identify northwind/site and northwind/internal."""
    res = investigate_chat(
        carol_packet,
        message="Which repository was accessed after deactivation?",
        history=[],
        settings=settings,
    )
    assert isinstance(res, InvestigationChatResponse)
    assert "northwind/site" in res.reply
    assert "northwind/internal" in res.reply
    assert "ghp_carol_legacy" in res.reply
    assert len(res.citations) > 0
    for cit in res.citations:
        assert cit.evidence_id in carol_packet.valid_evidence_ids


def test_chat_carol_active_tokens_inquiry(carol_packet, settings):
    """Inquiry on Carol's active tokens must note telemetry limits and recommend token inventory audit."""
    res = investigate_chat(
        carol_packet,
        message="Are other personal tokens active for this persona?",
        history=[],
        settings=settings,
    )
    assert isinstance(res, InvestigationChatResponse)
    assert "ghp_carol_legacy" in res.reply
    assert "insufficient" in res.reply.lower() or "audit" in res.reply.lower()
    assert len(res.citations) > 0
    for cit in res.citations:
        assert cit.evidence_id in carol_packet.valid_evidence_ids


def test_chat_bob_permissions_used_inquiry(bob_packet, settings):
    """Inquiry on permissions used by Bob must detail S3_READ and EC2_READ vs 13 granted capabilities."""
    res = investigate_chat(
        bob_packet,
        message="What permissions did Bob actually use?",
        history=[],
        settings=settings,
    )
    assert isinstance(res, InvestigationChatResponse)
    assert "S3_READ" in res.reply
    assert "EC2_READ" in res.reply
    assert "13" in res.reply
    assert len(res.citations) > 0
    for cit in res.citations:
        assert cit.evidence_id in bob_packet.valid_evidence_ids


def test_chat_bob_legitimacy_inquiry(bob_packet, settings):
    """Inquiry on legitimacy must explain telemetry vs business need and require manager interview."""
    res = investigate_chat(
        bob_packet,
        message="Could this access be legitimate?",
        history=[],
        settings=settings,
    )
    assert isinstance(res, InvestigationChatResponse)
    assert "manager" in res.reply.lower()
    assert "telemetry" in res.reply.lower()
    assert len(res.citations) > 0
    for cit in res.citations:
        assert cit.evidence_id in bob_packet.valid_evidence_ids


def test_chat_bob_evidence_supports_inquiry(bob_packet, settings):
    """Inquiry on evidence supporting AdministratorAccess must list exhibits."""
    res = investigate_chat(
        bob_packet,
        message="What evidence supports AdministratorAccess overprivilege?",
        history=[],
        settings=settings,
    )
    assert isinstance(res, InvestigationChatResponse)
    assert "exhibits" in res.reply.lower() or "supported by" in res.reply.lower()
    assert len(res.citations) > 0
    for cit in res.citations:
        assert cit.evidence_id in bob_packet.valid_evidence_ids


def test_chat_cross_person_refusal_on_alice(alice_packet, settings):
    """Asking about Bob on Alice's finding must state investigation is scoped to Alice and refuse."""
    res = investigate_chat(
        alice_packet,
        message="Why was Bob Chen flagged?",
        history=[],
        settings=settings,
    )
    assert isinstance(res, InvestigationChatResponse)
    assert "scoped strictly to finding" in res.reply
    assert "Alice Nguyen" in res.reply
    assert "Bob Chen" in res.reply
    assert len(res.citations) == 0


def test_chat_cross_person_refusal_on_carol(carol_packet, settings):
    """Asking about Bob on Carol's finding must state investigation is scoped to Carol."""
    res = investigate_chat(
        carol_packet,
        message="Why was Bob flagged?",
        history=[],
        settings=settings,
    )
    assert isinstance(res, InvestigationChatResponse)
    assert "scoped strictly to finding" in res.reply
    assert "Carol Diaz" in res.reply
    assert "Bob Chen" in res.reply
    assert len(res.citations) == 0


def test_chat_remediation_human_in_loop(bob_packet, settings):
    """Inquiry asking whether to revoke access must explain AccessLens does not alter permissions automatically."""
    res = investigate_chat(
        bob_packet,
        message="Should I revoke Bob's access right now?",
        history=[],
        settings=settings,
    )
    assert isinstance(res, InvestigationChatResponse)
    assert "AccessLens does not alter permissions automatically" in res.reply
    assert "reviewer" in res.reply.lower()
