"""Investigation packet construction.

The InvestigationPacket is the sole, immutable bundle of facts supplied to the
AI investigator. It contains only information established by ingestion and the
deterministic engine.
"""

from __future__ import annotations

from pydantic import AwareDatetime, Field

from app.core.config import Settings
from app.core.time import UTCModel
from app.ingestion import InMemoryDataset
from app.schemas.api import PersonaSummary
from app.schemas.domain.finding import Finding

__all__ = ["InvestigationPacket", "build_investigation_packet"]


class InvestigationPacket(UTCModel):
    """Immutable bundle of facts supplied to the AI investigator.

    Contains ONLY facts already established by AccessLens. It holds no external
    web data, unverified assumptions, or prompt injections.
    """

    packet_id: str = Field(description="Unique packet ID, e.g. pkt-fnd-u_bob-rule-a")
    finding: Finding = Field(description="The deterministic finding under investigation")
    subject: PersonaSummary = Field(
        description="The persona's verified identity, entitlements, and coverage"
    )

    # Provenance and Temporal Context
    analysis_as_of: AwareDatetime = Field(description="Anchor instant of the analysis run")
    window_start: AwareDatetime = Field(description="Start of the lookback window")
    window_end: AwareDatetime = Field(description="End of the lookback window")
    dataset_fingerprint: str = Field(
        description="Cryptographic fingerprint of the normalized dataset"
    )

    @property
    def valid_evidence_ids(self) -> set[str]:
        """Set of all valid evidence IDs attached to this finding."""
        return {e.evidence_id for e in self.finding.evidence}


def build_investigation_packet(
    finding: Finding,
    subject: PersonaSummary,
    dataset: InMemoryDataset,
    settings: Settings,
) -> InvestigationPacket:
    """Construct an InvestigationPacket from verified finding and persona context."""
    return InvestigationPacket(
        packet_id=f"pkt-{finding.id}",
        finding=finding,
        subject=subject,
        analysis_as_of=dataset.window[1],
        window_start=dataset.window[0],
        window_end=dataset.window[1],
        dataset_fingerprint=dataset.dataset_fingerprint(),
    )
