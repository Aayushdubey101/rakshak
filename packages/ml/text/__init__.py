"""Text ML signal — spam/scam classification via the existing HF pipelines
(`packages/ml/inference/hf.py`). Nothing here talks to `transformers`
directly; this module is the `MLSignal`-shaped adapter in front of it.

`asyncio.to_thread` around every call is the fix for defect #7 (`work.md`
Phase 0 table): `transformers` pipelines are synchronous and CPU-bound, and
calling `hf.detect_spam()` directly from `detector.analyze()` (an async
function, on the request-handling event loop) blocked every other in-flight
request for the duration of inference. This module is now the only place
`hf.detect_spam`/`classify_scam_type` get called from detection, so the fix
lives in exactly one place.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from packages.domain.risk.fusion import attach_weight
from packages.ml.inference import hf
from packages.ml.model_registry import TEXT_SEMANTIC_MODEL, TEXT_SPAM_MODEL, TEXT_SUPERVISED_MODEL
from packages.ml.text import semantic as _semantic
from packages.ml.text import supervised as _supervised
from packages.shared.schemas.signals import RiskSignal, SignalSource


async def score(text: str, **_context) -> RiskSignal | None:
    """None when no spam-classification model is loaded (lite mode, or the
    model failed to load) — absent, not a zero-score opinion."""
    if not hf.MODELS_AVAILABLE or not hf.spam_classifier:
        return None

    result = await asyncio.to_thread(hf.detect_spam, text)
    if result["label"] not in ("spam", "ham"):
        return None  # "unknown"/"error" -- the model didn't produce an opinion

    risk_score = result["score"] if result["label"] == "spam" else 0.0
    signal = RiskSignal(
        source=SignalSource.ML_TEXT,
        score=risk_score,
        label=result["label"],
        confidence=result["score"],
        model_id=TEXT_SPAM_MODEL.id,
    )
    return attach_weight(signal)


async def score_supervised(text: str, **_context) -> RiskSignal | None:
    """The scikit-learn TF-IDF+logistic-regression classifier
    (packages/ml/text/supervised.py) -- unlike `score()` above, this runs
    unconditionally (no DEPLOYMENT_MODE/HF_LITE_MODE gate, no torch/transformers
    dependency). Still returns `None`, not a zero-score opinion, if the
    artifact hasn't been trained yet (`scripts/train_supervised_classifier.py`).

    Reuses `SignalSource.ML_TEXT` (the same source `score()`'s HF spam model
    would use) -- both are "the ML text opinion"; nothing in this deployment
    runs both at once today (HF is inert in lite mode), so this doesn't yet
    double-count in fusion. Revisit if a deployment ever runs both."""
    prediction = await asyncio.to_thread(_supervised.predict, text)
    if prediction is None:
        return None

    risk_score = 0.0 if prediction.label == "benign" else prediction.confidence
    signal = RiskSignal(
        source=SignalSource.ML_TEXT,
        score=risk_score,
        label=prediction.label,
        confidence=prediction.confidence,
        model_id=TEXT_SUPERVISED_MODEL.id,
    )
    return attach_weight(signal)


# Margin below which the semantic classifier's top1/top2 gap is treated as
# "ambiguous between classes" -- spec item 19: weak semantic similarity must
# not be forced into a specific category (bank_impersonation, mfa_code_theft,
# ...) without real separation between the winning class and the runner-up.
_SEMANTIC_TYPE_MARGIN_FLOOR = 0.15


@dataclass(frozen=True)
class SemanticResult:
    """Everything detector.py needs from one MiniLM inference call -- kept
    as one call (not score_semantic() + a separate raw-prediction fetch)
    because encode() is the expensive part; a second call would re-embed the
    same text for no reason."""

    signal: RiskSignal | None  # fusion contribution, or None if unavailable/benign-scored
    label: str | None  # raw predicted label, independent of evidence gating below
    evidence: dict | None  # spec item 16, gated by margin per item 19 (None if ambiguous/benign/unavailable)


async def score_semantic(text: str, **_context) -> SemanticResult:
    """The sentence-transformers/all-MiniLM-L6-v2 + LogisticRegression
    classifier (packages/ml/text/semantic.py) -- same "runs unconditionally
    once its artifact exists, None-not-zero when it doesn't" contract as
    score_supervised() above, just embeddings instead of TF-IDF.

    Reuses SignalSource.ML_TEXT, same as score() and score_supervised() --
    all three are "the ML text opinion"; fusion.fuse() renormalizes over
    whichever of them actually ran, so running two or three at once doesn't
    silently discount the other layers (see fusion.py's docstring)."""
    prediction = await asyncio.to_thread(_semantic.predict, text)
    if prediction is None:
        return SemanticResult(signal=None, label=None, evidence=None)

    risk_score = 0.0 if prediction.label == "benign" else prediction.confidence
    signal = attach_weight(RiskSignal(
        source=SignalSource.ML_TEXT,
        score=risk_score,
        label=prediction.label,
        confidence=prediction.confidence,
        model_id=TEXT_SEMANTIC_MODEL.id,
    ))

    evidence = None
    if prediction.label != "benign" and prediction.margin >= _SEMANTIC_TYPE_MARGIN_FLOOR:
        if prediction.confidence >= 0.75:
            confidence_level = "high"
        elif prediction.confidence >= 0.45:
            confidence_level = "medium"
        else:
            confidence_level = "low"
        evidence = {
            "source": "semantic_model",
            "signal": prediction.label.upper(),
            "confidence_level": confidence_level,
        }

    return SemanticResult(signal=signal, label=prediction.label, evidence=evidence)


async def classify_type(text: str, labels: list[str]) -> dict | None:
    """Zero-shot scam-type classification. Returns the raw top label/score —
    callers decide whether to trust it (`detector.py` already gates this on
    the spam signal being confident first); not itself an `MLSignal`,
    since a scam *type* isn't a risk score."""
    if not hf.MODELS_AVAILABLE or not hf.scam_type_classifier:
        return None

    result = await asyncio.to_thread(hf.classify_scam_type, text, labels)
    if result["top_label"] in ("unknown", "error"):
        return None
    return result
