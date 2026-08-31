"""Phase 3: the LLM cannot silently lower a deterministic verdict.

Rule 5 of the architecture, as executable policy. Raising risk is free;
lowering it needs an explicit reason, and the reason is returned so it can be
logged and audited.
"""

import pytest

from packages.llm.policies.evidence_override import (
    DEFAULT_POLICY,
    EvidenceVerdict,
    LLMOpinion,
    OverridePolicy,
    resolve_llm_opinion,
)
from packages.shared.schemas import Verdict


def _evidence(verdict=Verdict.SCAM, score=90, confidence=0.9, deterministic=True):
    return EvidenceVerdict(verdict, score, confidence, deterministic)


def test_no_opinion_leaves_evidence_untouched():
    decision = resolve_llm_opinion(_evidence(), None)
    assert (decision.verdict, decision.risk_score, decision.overridden) == (
        Verdict.SCAM, 90, False,
    )
    assert decision.reason == "no llm opinion"


def test_llm_may_always_raise_risk():
    evidence = _evidence(Verdict.SUSPICIOUS, 40, 0.9)
    decision = resolve_llm_opinion(
        evidence, LLMOpinion(Verdict.SCAM, 95, confidence=0.3, rationale="knows this campaign")
    )
    assert (decision.verdict, decision.risk_score, decision.overridden) == (
        Verdict.SCAM, 95, True,
    )
    assert "raised risk" in decision.reason


def test_raising_never_lowers_the_score():
    """Higher-rank verdict carrying a smaller number must not regress the score."""
    evidence = _evidence(Verdict.SUSPICIOUS, 70, 0.9)
    decision = resolve_llm_opinion(evidence, LLMOpinion(Verdict.SCAM, 55, confidence=0.9))
    assert (decision.verdict, decision.risk_score) == (Verdict.SCAM, 70)


def test_high_confidence_evidence_cannot_be_lowered():
    decision = resolve_llm_opinion(
        _evidence(Verdict.SCAM, 90, 0.85),
        LLMOpinion(Verdict.LIKELY_SAFE, 5, confidence=0.99, rationale="looks fine to me"),
    )
    assert (decision.verdict, decision.risk_score, decision.overridden) == (
        Verdict.SCAM, 90, False,
    )
    assert decision.reason.startswith("blocked: deterministic evidence")


def test_low_confidence_evidence_may_be_lowered_by_a_confident_llm():
    decision = resolve_llm_opinion(
        _evidence(Verdict.SUSPICIOUS, 45, 0.30),
        LLMOpinion(Verdict.LIKELY_SAFE, 10, confidence=0.95, rationale="quote from a news article"),
    )
    assert (decision.verdict, decision.risk_score, decision.overridden) == (
        Verdict.LIKELY_SAFE, 10, True,
    )
    assert "permitted" in decision.reason and "news article" in decision.reason


def test_an_unsure_llm_may_not_lower_anything():
    decision = resolve_llm_opinion(
        _evidence(Verdict.SUSPICIOUS, 45, 0.30),
        LLMOpinion(Verdict.LIKELY_SAFE, 10, confidence=0.5),
    )
    assert decision.overridden is False
    assert decision.reason.startswith("blocked: llm confidence")


def test_non_deterministic_evidence_is_not_protected():
    """Only deterministic evidence gets the confidence shield."""
    decision = resolve_llm_opinion(
        _evidence(Verdict.SCAM, 80, 0.95, deterministic=False),
        LLMOpinion(Verdict.SUSPICIOUS, 40, confidence=0.9),
    )
    assert (decision.verdict, decision.overridden) == (Verdict.SUSPICIOUS, True)


def test_agreement_is_not_an_override():
    decision = resolve_llm_opinion(
        _evidence(Verdict.SCAM, 90, 0.9), LLMOpinion(Verdict.SCAM, 90, confidence=0.9)
    )
    assert (decision.overridden, decision.reason) == (False, "llm agreed with evidence")


@pytest.mark.parametrize("threshold", [0.0, 1.0])
def test_policy_thresholds_are_configurable(threshold):
    policy = OverridePolicy(protected_confidence=threshold, min_llm_confidence=0.0)
    decision = resolve_llm_opinion(
        _evidence(Verdict.SCAM, 90, 0.5),
        LLMOpinion(Verdict.LIKELY_SAFE, 5, confidence=0.6),
        policy=policy,
    )
    # Evidence confidence 0.5 is protected only when the bar sits at or below it.
    assert decision.overridden is (threshold > 0.5)


def test_default_policy_values():
    assert (DEFAULT_POLICY.protected_confidence, DEFAULT_POLICY.min_llm_confidence) == (0.60, 0.80)


def test_decision_renders_for_the_audit_log():
    assert str(resolve_llm_opinion(_evidence(), None)) == "scam/90 (no llm opinion)"
