"""Evidence-override policy.

The LLM explains, enriches, and correlates evidence. It cannot silently
invalidate a deterministic high-confidence security verdict. Raising risk is
always allowed — a model spotting what the rules missed is the point. Lowering
risk is allowed only under an explicit rule, and every decision carries the
reason that permitted or blocked it, so it is auditable rather than implicit.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from packages.shared.schemas import Verdict

logger = logging.getLogger("uvicorn")

# Verdicts ordered by how much risk they assert.
_RANK: dict[Verdict, int] = {
    Verdict.UNKNOWN: 0,
    Verdict.LIKELY_SAFE: 1,
    Verdict.SUSPICIOUS: 2,
    Verdict.SCAM: 3,
}


@dataclass(frozen=True)
class OverridePolicy:
    """When deterministic evidence may be softened by a model."""

    # Evidence at or above this confidence is high-confidence and cannot be
    # lowered by the LLM at all.
    protected_confidence: float = 0.60
    # The LLM must be at least this confident before it may lower anything.
    min_llm_confidence: float = 0.80


DEFAULT_POLICY = OverridePolicy()


@dataclass(frozen=True)
class EvidenceVerdict:
    """What rules, ML, and threat intel concluded, before any model spoke."""

    verdict: Verdict
    risk_score: int
    confidence: float
    deterministic: bool = True


@dataclass(frozen=True)
class LLMOpinion:
    verdict: Verdict
    risk_score: int
    confidence: float
    rationale: str = ""


@dataclass(frozen=True)
class OverrideDecision:
    verdict: Verdict
    risk_score: int
    overridden: bool
    reason: str

    def __str__(self) -> str:  # what lands in the audit log
        return f"{self.verdict.value}/{self.risk_score} ({self.reason})"


def resolve_llm_opinion(
    evidence: EvidenceVerdict,
    llm: LLMOpinion | None,
    *,
    policy: OverridePolicy = DEFAULT_POLICY,
) -> OverrideDecision:
    """Combine deterministic evidence with a model's opinion, safely."""
    if llm is None:
        return OverrideDecision(evidence.verdict, evidence.risk_score, False, "no llm opinion")

    raises_risk = _RANK[llm.verdict] > _RANK[evidence.verdict] or (
        llm.verdict == evidence.verdict and llm.risk_score > evidence.risk_score
    )
    if raises_risk:
        return OverrideDecision(
            llm.verdict,
            max(llm.risk_score, evidence.risk_score),
            True,
            "llm raised risk (always permitted)",
        )

    lowers_risk = _RANK[llm.verdict] < _RANK[evidence.verdict] or (
        llm.verdict == evidence.verdict and llm.risk_score < evidence.risk_score
    )
    if not lowers_risk:
        return OverrideDecision(
            evidence.verdict, evidence.risk_score, False, "llm agreed with evidence"
        )

    if evidence.deterministic and evidence.confidence >= policy.protected_confidence:
        reason = (
            f"blocked: deterministic evidence at {evidence.confidence:.2f} "
            f"confidence cannot be lowered by the llm"
        )
        logger.warning(f"🛡️ evidence override {reason}")
        return OverrideDecision(evidence.verdict, evidence.risk_score, False, reason)

    if llm.confidence < policy.min_llm_confidence:
        reason = (
            f"blocked: llm confidence {llm.confidence:.2f} below "
            f"{policy.min_llm_confidence:.2f} required to lower risk"
        )
        logger.info(f"🛡️ evidence override {reason}")
        return OverrideDecision(evidence.verdict, evidence.risk_score, False, reason)

    reason = (
        f"permitted: low-confidence evidence ({evidence.confidence:.2f}) lowered by llm "
        f"at {llm.confidence:.2f}"
        + (f" — {llm.rationale}" if llm.rationale else "")
    )
    logger.info(f"🛡️ evidence override {reason}")
    return OverrideDecision(llm.verdict, llm.risk_score, True, reason)
