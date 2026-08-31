"""Threat intelligence — the one entry point the orchestrator calls.

Indicator normalization/hashing (`indicators`), the repository call that
persists and correlates them (`correlation`), campaign clustering
(`correlation` for indicator-based, `campaigns` for the deferred embedding
path), and domain reputation (`reputation`, built but not yet wired — see its
module docstring) all live under this package. `analyze()` is the seam
`packages/domain/investigations/orchestrator.py`'s threat_intel stage calls;
everything else is an implementation detail behind it.
"""

from __future__ import annotations

from packages.domain.threat_intel.repository import ThreatIndicatorRepository
from packages.shared.schemas.entities import ExtractedEntity
from packages.shared.schemas.report import ThreatIntelMatch
from packages.shared.schemas.signals import RiskSignal
from packages.threat_intel.correlation import correlate

__all__ = ["analyze", "ThreatIndicatorRepository"]


async def analyze(
    repository: ThreatIndicatorRepository, *, investigation_id: str, entities: tuple[ExtractedEntity, ...]
) -> tuple[tuple[ThreatIntelMatch, ...], tuple[RiskSignal, ...]]:
    return await correlate(repository, investigation_id=investigation_id, entities=entities)
