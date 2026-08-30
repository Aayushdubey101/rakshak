"""The supervised text classifier -- the ML path that actually runs.

Unlike `packages/ml/inference/hf.py` (gated behind `DEPLOYMENT_MODE=full` +
a `torch`/`transformers` install this environment doesn't have), this is
TF-IDF + logistic regression via scikit-learn, a small core dependency with
no GPU/heavy download. It loads its artifact lazily and returns `None` (not
a zero-score opinion) if `scripts/train_supervised_classifier.py` hasn't
been run yet -- same "absent, not a silent zero" convention `packages/ml/text/score()`
already uses for the HF spam model.

Trained on 90 hand-written examples across 9 classes
(ml-models/evaluation/dev_train_set.json) -- small enough that this should be
read as an experimental signal, not a production classifier. See
docs/ml/phase8-evaluation.md for the actual generalization numbers, measured
on a disjoint unseen set this module was never trained or tuned against.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_ARTIFACT_PATH = Path(__file__).parent.parent.parent.parent / "ml-models" / "trained" / "supervised_classifier.joblib"

_pipeline = None
_load_attempted = False


@dataclass(frozen=True)
class SupervisedPrediction:
    label: str
    confidence: float  # predict_proba of the winning label
    proba: dict[str, float]  # full class -> probability distribution


def _load():
    global _pipeline, _load_attempted
    if _load_attempted:
        return _pipeline
    _load_attempted = True
    if not _ARTIFACT_PATH.exists():
        return None
    import joblib

    _pipeline = joblib.load(_ARTIFACT_PATH)
    return _pipeline


def predict(text: str) -> Optional[SupervisedPrediction]:
    """None when the artifact hasn't been trained (run
    scripts/train_supervised_classifier.py) -- absent, not a benign opinion."""
    pipeline = _load()
    if pipeline is None:
        return None

    proba_row = pipeline.predict_proba([text])[0]
    classes = pipeline.classes_
    proba = {cls: float(p) for cls, p in zip(classes, proba_row)}
    label = max(proba, key=proba.get)
    return SupervisedPrediction(label=label, confidence=proba[label], proba=proba)
