"""The findings surface: the review queue and the auditor dossier.

Until this module existed, ``analyze()`` was called by tests and by nothing else
-- the whole product was a Python function, and no reviewer could see a finding.
These two routes are the whole of the gap, and they are deliberately thin.

**Nothing here decides anything.** Both routes call ``analyze()`` and project its
output; neither reaches for a rule module, re-derives a threshold, or re-sorts a
list. ``analyze()`` is the source of truth for what the findings are and what
order they come in, and an API that formed its own opinion would be a second
implementation of the security model -- in a language the tests do not cover,
disagreeing eventually and silently.

**Nothing here writes anything.** Findings are a pure function of an immutable
dataset, so persisting them would create a second copy that can go stale the
moment the fixtures change, and a reader of that table would have no way to tell
which revision of the facts it was computed from. The ``finding`` and
``evidence`` tables have existed since Phase 1 and stay empty on purpose; a test
asserts it.

**The dossier restates the person rather than inventing a shape for them.** Its
``subject`` is the same :class:`~app.schemas.api.PersonaSummary` that
``/api/personas`` returns, built by the same projection, so the two views cannot
disagree about who someone is or how much of the window we can vouch for.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from app.ai import (
    StructuredInvestigationResult,
    build_investigation_packet,
    investigate_finding,
)
from app.api.deps import DatasetDep, SessionDep, SettingsDep
from app.api.read_models import build_personas, find_persona, finding_subject
from app.engine import analyze
from app.schemas.api import (
    AnalysisResponse,
    FindingDossierResponse,
    FindingSummary,
    PersonaSummary,
)
from app.schemas.domain.finding import Finding

__all__ = ["router"]

router = APIRouter(tags=["analysis"])


def _summarise(
    finding: Finding, subject: PersonaSummary
) -> FindingSummary:
    """One queue row: the finding minus its payload, plus its subject.

    ``evidence`` is excluded and ``evidence_count`` takes its place. The list is
    a queue and the dossier is the record; carrying sixty evidence rows in the
    queue would make the list's contract depend on the detail's.
    """
    return FindingSummary(
        **finding.model_dump(exclude={"evidence"}),
        evidence_count=len(finding.evidence),
        subject=finding_subject(subject),
    )


@router.get("/analysis", response_model=AnalysisResponse)
def get_analysis(
    session: SessionDep, dataset: DatasetDep, settings: SettingsDep
) -> AnalysisResponse:
    """Every finding ``analyze()`` produced, in ``analyze()``'s own order.

    The order is not re-sorted. ``analyze()`` went to the trouble of defining a
    total order -- user-major, severity-descending -- as presentation policy,
    precisely so that one person's two findings stay adjacent and are not read
    as two people's problems. A route that grouped or re-sorted would discard
    that decision without anything failing.
    """
    findings = analyze(dataset, settings)
    personas = {persona.id: persona for persona in build_personas(session, dataset)}

    return AnalysisResponse(
        content_hash=dataset.content_hash,
        dataset_fingerprint=dataset.dataset_fingerprint(),
        analysis_as_of=dataset.window[1],
        window_start=dataset.window[0],
        window_end=dataset.window[1],
        rejections=len(dataset.rejections),
        findings=[_summarise(finding, _subject(personas, finding)) for finding in findings],
    )


@router.get(
    "/analysis/findings/{finding_id}",
    response_model=FindingDossierResponse,
)
def get_finding(
    finding_id: str,
    session: SessionDep,
    dataset: DatasetDep,
    settings: SettingsDep,
) -> FindingDossierResponse:
    """One finding, its exhibits, the person it is about, and their other findings.

    404 for an unknown id rather than an empty dossier. "There is no such
    record" and "this person has nothing to report" are different claims, and a
    client cannot tell them apart from a payload that looks the same.
    """
    findings = analyze(dataset, settings)
    finding = next((f for f in findings if f.id == finding_id), None)
    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"no finding with id {finding_id!r}",
        )

    subject = find_persona(session, dataset, finding.user_id)
    if subject is None:  # pragma: no cover - the dataset and the table agree
        raise _unknown_subject(finding)

    # The sweep is already ordered user-major, so filtering preserves it: the
    # person's other findings arrive worst-first, which is how they are read.
    related = [
        _summarise(other, subject)
        for other in findings
        if other.user_id == finding.user_id and other.id != finding.id
    ]

    return FindingDossierResponse(
        finding=finding,
        subject=subject,
        related_findings=related,
    )


@router.get(
    "/analysis/findings/{finding_id}/investigation",
    response_model=StructuredInvestigationResult,
)
def get_finding_investigation(
    finding_id: str,
    session: SessionDep,
    dataset: DatasetDep,
    settings: SettingsDep,
) -> StructuredInvestigationResult:
    """One finding's AI forensic investigation dossier.

    Deterministic and provider-agnostic. Produces structured forensic analysis,
    separating verified facts from inferences and drafting reviewer questions.
    404 for an unknown id.
    """
    findings = analyze(dataset, settings)
    finding = next((f for f in findings if f.id == finding_id), None)
    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"no finding with id {finding_id!r}",
        )

    subject = find_persona(session, dataset, finding.user_id)
    if subject is None:  # pragma: no cover - the dataset and the table agree
        raise _unknown_subject(finding)

    packet = build_investigation_packet(finding, subject, dataset, settings)
    return investigate_finding(packet)


def _subject(
    personas: dict[str, PersonaSummary], finding: Finding
) -> PersonaSummary:
    """The person a queue row is about.

    A finding naming a user who is not a persisted user would mean the engine
    and the ingest disagree about who exists -- a bug, not a result -- so it
    raises rather than rendering a row with nobody's name on it.
    """
    persona = personas.get(finding.user_id)
    if persona is None:  # pragma: no cover - the dataset and the table agree
        raise _unknown_subject(finding)
    return persona


def _unknown_subject(finding: Finding) -> RuntimeError:
    return RuntimeError(
        f"finding {finding.id!r} is about {finding.user_id!r}, which is not a "
        "persisted user; the engine and the ingest disagree about who exists"
    )
