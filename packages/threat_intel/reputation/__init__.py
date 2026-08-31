"""Domain reputation.

Two sources feed a domain's reputation, and either can be absent:

1. **Local history** — `DomainReputationRepository.record_sighting` aggregates
   `packages/ml/url`'s lexical score for a domain across every investigation
   that has mentioned it, into the `domains` table's `reputation_score`
   (exponential moving average, so a domain that keeps re-triggering lexical
   red flags trends risky, and one that mostly scores clean trends down).
   This is real and requires no external service or API key.
2. **External provider** — `ReputationProvider.lookup`. No credential means
   `None` (absent, not zero), same rule the LLM providers follow
   (`packages/llm/gateway/base.py`): nothing raises `NotImplementedError`,
   nothing degrades a report because a paid lookup wasn't configured. No such
   provider is wired to a live API in this environment; `NullReputationProvider`
   is the default and only implementation.

Not called from the orchestrator: doing so needs `packages/ml/url`'s lexical
score in scope at the URL-observation level, which the orchestrator doesn't
compute yet (`packages/ml/url` isn't wired into `detector.analyze()` either —
a phase 8 gap this phase doesn't reopen). `score()` is built and unit-tested
against a fake repository so wiring it later is one call site, not new logic.
"""

from __future__ import annotations

from typing import Protocol

from packages.domain.risk.fusion import attach_weight
from packages.domain.threat_intel.repository import DomainReputationRepository
from packages.shared.schemas.signals import RiskSignal, SignalSource

REPUTATION_MODEL_ID = "rakshak.domain_reputation.v1"


class ReputationProvider(Protocol):
    async def lookup(self, domain: str) -> float | None: ...


class NullReputationProvider:
    async def lookup(self, domain: str) -> float | None:
        return None


async def score(
    domain: str,
    *,
    lexical_score: float,
    repository: DomainReputationRepository,
    provider: ReputationProvider = NullReputationProvider(),
) -> RiskSignal | None:
    """`None` when neither source has an opinion — an unseen, unscored domain
    is absent evidence, not a clean bill of health."""
    external = await provider.lookup(domain)
    reputation = await repository.record_sighting(domain, lexical_score)
    combined = reputation.reputation_score if external is None else max(reputation.reputation_score, external)

    if combined <= 0:
        return None

    signal = RiskSignal(
        source=SignalSource.THREAT_INTEL,
        score=min(combined, 1.0),
        label=f"domain_reputation:{domain}",
        confidence=0.6 if reputation.is_repeat else 0.4,
        model_id=REPUTATION_MODEL_ID,
    )
    return attach_weight(signal)
