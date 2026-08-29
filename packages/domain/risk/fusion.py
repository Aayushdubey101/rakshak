"""Risk fusion — combines `RiskSignal`s from every layer into one score.

Replaces the hardcoded 0.5/0.3/0.2 blend `detector.analyze()` used to compute
inline. Two things changed on purpose:

1. Weights are configuration (`Settings.FUSION_WEIGHT_*`), not literals.
2. A signal that never ran (model disabled, no LLM provider configured) is
   **absent from the list**, not present-with-score-zero. `fuse()` divides by
   the weight of only the signals actually present, so an unconfigured layer
   doesn't silently discount the layers that did run — a lite-mode
   deployment (pattern signal only) can still reach full confidence when the
   pattern signal itself is confident, instead of being permanently capped
   at its configured weight fraction of 1.0. This was a real defect (#6 in
   `work.md`'s Phase 0 table): lite-mode confidence was always pattern
   confidence × its weight, an artificial ceiling, not a reasoned score.

`fuse()` itself never reads config — it only reads `signal.weight`, which the
caller must have already set from the config at *creation* time (see
`packages/ml/*`'s wrappers). That's what makes fusion a pure function of
stored evidence: re-fusing an investigation's `risk_assessments` rows months
later reproduces the same number even if the configured weights have since
changed. This is `RiskSignal.weight`'s documented purpose
(packages/shared/schemas/signals.py).
"""

from __future__ import annotations

from dataclasses import dataclass

from packages.shared.config.settings import get_settings
from packages.shared.schemas.signals import RiskSignal, SignalSource


@dataclass(frozen=True)
class FusionWeights:
    weights: dict[SignalSource, float]

    def weight_for(self, source: SignalSource) -> float:
        return self.weights.get(source, 0.0)


# Same relative ratio as the code this replaces (pattern 0.5, ml 0.3, llm 0.2)
# so the only *intentional* behavior change is renormalization, not also a
# silent reweighing of the layers that already existed.
DEFAULT_WEIGHTS = FusionWeights({
    SignalSource.PATTERN: 0.5,
    SignalSource.ML_TEXT: 0.3,
    SignalSource.LLM: 0.2,
    SignalSource.ML_VISION: 0.3,
    SignalSource.ML_URL: 0.3,
    SignalSource.THREAT_INTEL: 0.4,
})


def weights_from_settings() -> FusionWeights:
    settings = get_settings()
    return FusionWeights({
        SignalSource.PATTERN: settings.FUSION_WEIGHT_PATTERN,
        SignalSource.ML_TEXT: settings.FUSION_WEIGHT_ML_TEXT,
        SignalSource.LLM: settings.FUSION_WEIGHT_LLM,
        SignalSource.ML_VISION: settings.FUSION_WEIGHT_ML_VISION,
        SignalSource.ML_URL: settings.FUSION_WEIGHT_ML_URL,
        SignalSource.THREAT_INTEL: settings.FUSION_WEIGHT_THREAT_INTEL,
    })


def attach_weight(signal: RiskSignal, weights: FusionWeights | None = None) -> RiskSignal:
    """Stamps the current configured weight for `signal.source` onto a
    freshly created signal. Call this once, when a signal is produced —
    never inside `fuse()`."""
    weights = weights or weights_from_settings()
    return signal.model_copy(update={"weight": weights.weight_for(signal.source)})


@dataclass(frozen=True)
class FusionResult:
    risk_score: float  # 0..1
    contributing_sources: tuple[SignalSource, ...]
    signals: tuple[RiskSignal, ...]


def fuse(signals: list[RiskSignal]) -> FusionResult:
    """Weighted average of `score`, over only the signals present, using
    each signal's own `.weight` (already stamped by `attach_weight`).
    Zero signals, or all zero-weighted, yields zero risk rather than
    raising — an investigation with every layer disabled is still a valid,
    if maximally degraded, report."""
    contributing = [s for s in signals if s.weight > 0]
    total_weight = sum(s.weight for s in contributing)

    if not contributing or total_weight == 0:
        return FusionResult(risk_score=0.0, contributing_sources=(), signals=tuple(signals))

    risk_score = sum(s.score * s.weight for s in contributing) / total_weight
    return FusionResult(
        risk_score=round(risk_score, 3),
        contributing_sources=tuple(s.source for s in contributing),
        signals=tuple(signals),
    )
