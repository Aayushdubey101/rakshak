"""Cross-investigation indicator correlation.

Every indicator this investigation produced is checked against every prior
investigation's occurrences of the same `(kind, value_hash)`
(`ThreatIndicatorRepository.correlate`, `packages/shared/db/repositories.py`).
A hit becomes both a `RiskSignal` (real evidence for fusion — task.md phase 9:
"they are evidence, not decoration") and a `ThreatIntelMatch` (the report-facing
"this resembles an existing scam campaign" line).
"""

from __future__ import annotations

from packages.domain.risk.fusion import attach_weight
from packages.domain.threat_intel.repository import ThreatIndicatorRepository
from packages.shared.schemas.entities import ExtractedEntity
from packages.shared.schemas.report import ThreatIntelMatch
from packages.shared.schemas.signals import RiskSignal, SignalSource
from packages.threat_intel.indicators import indicators_from_entities

CORRELATION_SOURCE = "threat_intel.correlation"


async def correlate(
    repository: ThreatIndicatorRepository, *, investigation_id: str, entities: tuple[ExtractedEntity, ...]
) -> tuple[tuple[ThreatIntelMatch, ...], tuple[RiskSignal, ...]]:
    """Persists this investigation's indicators and returns every match found
    against prior investigations, plus one `RiskSignal` per indicator that
    correlated. An indicator with no prior occurrence still gets recorded
    (via `repository.correlate`) so a *future* investigation can match
    against it — correlation is symmetric, just not simultaneous."""
    matches: list[ThreatIntelMatch] = []
    signals: list[RiskSignal] = []

    for indicator in indicators_from_entities(entities):
        prior = await repository.correlate(
            investigation_id=investigation_id,
            kind=indicator.kind.value,
            value=indicator.value,
            normalized=indicator.normalized,
            value_hash=indicator.value_hash,
        )
        if not prior:
            continue

        campaign_id = prior[0].campaign_id
        matches.append(ThreatIntelMatch(
            indicator=indicator.value,
            kind=indicator.kind,
            source=CORRELATION_SOURCE,
            confidence=min(0.6 + 0.1 * len(prior), 0.95),
            first_seen=prior[0].first_seen,
            campaign_id=campaign_id,
        ))
        signals.append(attach_weight(RiskSignal(
            source=SignalSource.THREAT_INTEL,
            score=min(0.6 + 0.1 * len(prior), 1.0),
            label=f"shared_indicator:{indicator.kind.value}",
            confidence=min(0.6 + 0.1 * len(prior), 0.95),
            model_id="rakshak.threat_intel.correlation.v1",
        )))

    return tuple(matches), tuple(signals)
