"""Repository interfaces for cross-investigation threat intelligence. Same
boundary as every other `packages/domain/*/repository.py`: domain code
depends on these Protocols, never on an ORM session. SQLAlchemy
implementations live in `packages/shared/db/repositories.py`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Protocol


@dataclass(frozen=True)
class CorrelationMatch:
    """One prior investigation that produced the same indicator."""

    investigation_id: str
    value: str
    first_seen: datetime
    campaign_id: Optional[str]


class ThreatIndicatorRepository(Protocol):
    """Persists one investigation's occurrence of a normalized indicator and
    reports every *other* investigation that has produced the same one.

    A shared indicator across two investigations is what "correlation" means
    here (task.md phase 9's done-when). The first investigation to produce an
    indicator has nothing to correlate against; the second call for the same
    `(kind, value_hash)` is what creates the `scam_campaigns` row both link to.
    """

    async def correlate(
        self, *, investigation_id: str, kind: str, value: str, normalized: str, value_hash: str
    ) -> tuple[CorrelationMatch, ...]: ...


@dataclass(frozen=True)
class DomainReputation:
    domain: str
    reputation_score: float
    is_repeat: bool


class DomainReputationRepository(Protocol):
    """Aggregates `packages/ml/url`'s lexical score for a domain across every
    investigation that has mentioned it, into the `domains` table's running
    `reputation_score` — Rakshak's own local reputation history."""

    async def record_sighting(self, domain: str, lexical_score: float) -> DomainReputation: ...
