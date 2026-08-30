"""Semantic text classifier -- sentence-transformers/all-MiniLM-L6-v2
embeddings + LogisticRegression (Phase 10).

packages/ml/text/supervised.py (TF-IDF + char n-grams) and
packages/domain/risk/behavioral_signals.py (regex) both pattern-match
surface vocabulary -- neither has ever seen "OTP" and "six digits" as
related. This module embeds *meaning* instead: the documented next step in
docs/ml/phase8-evaluation.md's Phase 9 conclusion ("this architecture
pattern-matches vocabulary, at whatever scale... closing this gap for real
most likely needs an actual semantic/embedding representation").

Two artifacts load lazily and independently, same "absent, not a stub"
contract packages/ml/text/supervised.py already uses:
  1. the MiniLM encoder itself (sentence-transformers, `semantic` extra --
     see pyproject.toml -- downloaded/cached by the library on first use)
  2. the trained classifier head (scripts/train_minilm_classifier.py's
     output, ml-models/trained/minilm_classifier.joblib)

Not fine-tuned: MiniLM is frozen, used purely as a sentence encoder. The
classifier head is the only trained piece here, same shape as
supervised.py's TF-IDF+LogisticRegression pipeline, so the two are a fair
architecture comparison (scripts/train_and_compare_models.py's sibling for
this candidate is scripts/train_minilm_classifier.py).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

ENCODER_MODEL_ID = "sentence-transformers/all-MiniLM-L6-v2"
EMBEDDING_DIMENSION = 384

_ARTIFACT_PATH = (
    Path(__file__).parent.parent.parent.parent / "ml-models" / "trained" / "minilm_classifier.joblib"
)

_encoder = None
_encoder_load_attempted = False
_classifier = None
_classifier_load_attempted = False


@dataclass(frozen=True)
class SemanticPrediction:
    label: str
    confidence: float  # predict_proba of the winning label
    proba: dict[str, float]  # full class -> probability distribution
    margin: float  # top1 - top2 proba; low margin == ambiguous between classes


def _load_encoder():
    global _encoder, _encoder_load_attempted
    if _encoder_load_attempted:
        return _encoder
    _encoder_load_attempted = True
    try:
        from sentence_transformers import SentenceTransformer
    except ImportError:
        return None
    _encoder = SentenceTransformer(ENCODER_MODEL_ID)
    return _encoder


def _load_classifier():
    global _classifier, _classifier_load_attempted
    if _classifier_load_attempted:
        return _classifier
    _classifier_load_attempted = True
    if not _ARTIFACT_PATH.exists():
        return None
    import joblib

    _classifier = joblib.load(_ARTIFACT_PATH)
    return _classifier


def available() -> bool:
    """True only when both the encoder library and a trained classifier head
    are present. Callers use this instead of duplicating the two-artifact
    check (encode() succeeding says nothing about the classifier)."""
    return _load_encoder() is not None and _load_classifier() is not None


def encode(texts: list[str], *, batch_size: int = 32, normalize_embeddings: bool = True):
    """Batch sentence embeddings, shape (len(texts), 384). None -- not an
    empty array -- when sentence-transformers isn't installed, so "didn't
    run" is never confused with "ran on zero texts"."""
    encoder = _load_encoder()
    if encoder is None:
        return None
    if not texts:
        import numpy as np

        return np.empty((0, EMBEDDING_DIMENSION))
    return encoder.encode(list(texts), batch_size=batch_size, normalize_embeddings=normalize_embeddings)


def predict_batch(texts: list[str]) -> list[Optional[SemanticPrediction]]:
    """Batch inference: one encode() call for every text (the point of
    batching), not a Python loop calling predict() per text. Returns a list
    the same length as `texts` -- all-None when the model/classifier isn't
    available, so callers can always zip(texts, predict_batch(texts))."""
    if not texts:
        return []
    if not available():
        return [None] * len(texts)

    embeddings = encode(texts)
    classifier = _load_classifier()
    proba_matrix = classifier.predict_proba(embeddings)
    classes = classifier.classes_

    predictions: list[Optional[SemanticPrediction]] = []
    for row in proba_matrix:
        proba = {cls: float(p) for cls, p in zip(classes, row)}
        sorted_probs = sorted(proba.values(), reverse=True)
        label = max(proba, key=proba.get)
        margin = sorted_probs[0] - (sorted_probs[1] if len(sorted_probs) > 1 else 0.0)
        predictions.append(SemanticPrediction(label=label, confidence=proba[label], proba=proba, margin=margin))
    return predictions


def predict(text: str) -> Optional[SemanticPrediction]:
    """Single-text convenience wrapper -- same shape as
    packages/ml/text/supervised.py's predict(), used by the per-message
    detector.py call site. None when the artifact hasn't been trained yet
    (run scripts/train_minilm_classifier.py) or sentence-transformers isn't
    installed (run `uv sync --extra semantic`) -- absent, not a benign
    opinion."""
    return predict_batch([text])[0]


class SemanticClassifier:
    """Object-shaped interface (task spec's requested `encode`/`predict`/
    `predict_proba`) around the module-level lazy singletons above. The
    module functions are what detector.py and the eval/training scripts
    actually call; this class exists for callers that want an instance."""

    def encode(self, texts: list[str], *, batch_size: int = 32, normalize_embeddings: bool = True):
        return encode(texts, batch_size=batch_size, normalize_embeddings=normalize_embeddings)

    def predict(self, texts: list[str]) -> list[Optional[SemanticPrediction]]:
        return predict_batch(texts)

    def predict_proba(self, texts: list[str]) -> list[Optional[dict[str, float]]]:
        return [p.proba if p is not None else None for p in predict_batch(texts)]
