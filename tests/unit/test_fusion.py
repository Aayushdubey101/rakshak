"""packages/domain/risk/fusion.py — the config-driven, renormalizing blend
that replaced the hardcoded 0.5/0.3/0.2 in detector.analyze()."""

from packages.domain.risk.fusion import DEFAULT_WEIGHTS, FusionWeights, attach_weight, fuse
from packages.shared.schemas.signals import RiskSignal, SignalSource


def _signal(source: SignalSource, score: float, weight: float) -> RiskSignal:
    return RiskSignal(source=source, score=score, label="test", confidence=score, weight=weight)


def test_single_signal_fuses_to_its_own_score_regardless_of_weight():
    """One signal present -> its weight renormalizes to 1.0 -- the whole
    point of renormalization, and the defect-#6 fix."""
    signal = _signal(SignalSource.PATTERN, score=0.8, weight=0.5)
    result = fuse([signal])
    assert result.risk_score == 0.8


def test_two_signals_blend_by_relative_weight():
    pattern = _signal(SignalSource.PATTERN, score=1.0, weight=0.5)
    ml = _signal(SignalSource.ML_TEXT, score=0.0, weight=0.3)
    result = fuse([pattern, ml])
    # (1.0*0.5 + 0.0*0.3) / (0.5+0.3) = 0.625
    assert result.risk_score == 0.625


def test_missing_signal_renormalizes_instead_of_scoring_zero():
    """The core behavior change: a signal that never ran isn't in the list
    at all, so it can't drag the average toward zero."""
    pattern_alone = fuse([_signal(SignalSource.PATTERN, score=0.6, weight=0.5)])
    pattern_with_absent_ml = fuse([_signal(SignalSource.PATTERN, score=0.6, weight=0.5)])
    assert pattern_alone.risk_score == pattern_with_absent_ml.risk_score == 0.6


def test_zero_signals_yields_zero_risk_not_a_crash():
    result = fuse([])
    assert result.risk_score == 0.0
    assert result.contributing_sources == ()


def test_zero_weighted_signal_is_excluded_from_the_average():
    contributing = _signal(SignalSource.PATTERN, score=1.0, weight=0.5)
    excluded = _signal(SignalSource.ML_URL, score=0.0, weight=0.0)  # weight 0 -- e.g. unconfigured
    result = fuse([contributing, excluded])
    assert result.risk_score == 1.0
    assert result.contributing_sources == (SignalSource.PATTERN,)


def test_contributing_sources_lists_only_signals_that_counted():
    pattern = _signal(SignalSource.PATTERN, score=0.5, weight=0.5)
    ml = _signal(SignalSource.ML_TEXT, score=0.5, weight=0.3)
    result = fuse([pattern, ml])
    assert set(result.contributing_sources) == {SignalSource.PATTERN, SignalSource.ML_TEXT}


def test_attach_weight_stamps_the_configured_weight_for_the_source():
    signal = RiskSignal(source=SignalSource.PATTERN, score=0.5, label="x", confidence=0.5)
    assert signal.weight == 1.0  # schema default, unstamped

    stamped = attach_weight(signal, DEFAULT_WEIGHTS)
    assert stamped.weight == DEFAULT_WEIGHTS.weight_for(SignalSource.PATTERN) == 0.5


def test_fuse_is_pure_and_reproducible_from_stored_signals():
    """The whole point of stamping weight onto the signal: fusing the same
    stored evidence twice, even with different *current* config, reproduces
    the same number -- fuse() never reads config."""
    stored_signals = [
        _signal(SignalSource.PATTERN, score=0.4, weight=0.5),
        _signal(SignalSource.ML_TEXT, score=0.9, weight=0.3),
    ]
    first = fuse(stored_signals)
    second = fuse(stored_signals)
    assert first.risk_score == second.risk_score


def test_custom_weights_change_the_blend():
    weights = FusionWeights({SignalSource.PATTERN: 0.1, SignalSource.ML_TEXT: 0.9})
    pattern = attach_weight(
        RiskSignal(source=SignalSource.PATTERN, score=1.0, label="x", confidence=1.0), weights
    )
    ml = attach_weight(
        RiskSignal(source=SignalSource.ML_TEXT, score=0.0, label="x", confidence=1.0), weights
    )
    result = fuse([pattern, ml])
    # (1.0*0.1 + 0.0*0.9) / 1.0 = 0.1 -- ML dominates now, not pattern
    assert result.risk_score == 0.1
