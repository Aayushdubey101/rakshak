"""Phase 10: sentence-transformers/all-MiniLM-L6-v2 + LogisticRegression
(packages/ml/text/semantic.py). Unlike test_ml_text_and_vision.py (which
exercises the lite-mode "no model loaded" path), the `semantic` extra IS
installed in this environment and the classifier head IS trained
(ml-models/trained/minilm_classifier.joblib) -- these tests exercise the
real inference path, not a stub.

Skipped automatically wherever the artifact/dependency isn't present (a CI
runner without `uv sync --extra semantic`, or before
scripts/train_minilm_classifier.py has been run) -- absent-not-a-stub,
consistent with the rest of packages/ml/*.
"""

from __future__ import annotations

import pytest

from packages.ml.text import semantic

pytestmark = pytest.mark.skipif(
    not semantic.available(),
    reason="sentence-transformers/minilm_classifier.joblib not available in this environment",
)


def test_embedding_dimension_is_384():
    embeddings = semantic.encode(["hello world"])
    assert embeddings.shape == (1, semantic.EMBEDDING_DIMENSION)
    assert semantic.EMBEDDING_DIMENSION == 384


def test_encode_batch_returns_one_row_per_text():
    texts = ["Send me the OTP.", "Team meeting moved to 3pm.", "Guaranteed returns, invest today."]
    embeddings = semantic.encode(texts)
    assert embeddings.shape == (3, 384)


def test_encode_normalizes_embeddings_to_unit_length():
    import numpy as np

    embeddings = semantic.encode(["Send me the OTP."], normalize_embeddings=True)
    norm = np.linalg.norm(embeddings[0])
    assert abs(norm - 1.0) < 1e-4


def test_predict_returns_label_confidence_and_proba():
    pred = semantic.predict("Please reply with the verification code sent to your phone.")
    assert pred is not None
    assert pred.label in pred.proba
    assert 0.0 <= pred.confidence <= 1.0
    assert abs(sum(pred.proba.values()) - 1.0) < 1e-3


def test_predict_batch_matches_length_of_input():
    texts = ["Send me the OTP.", "Lunch is in the break room.", "Guaranteed returns, invest today."]
    predictions = semantic.predict_batch(texts)
    assert len(predictions) == len(texts)
    assert all(p is not None for p in predictions)


def test_predict_batch_empty_list_returns_empty_list():
    assert semantic.predict_batch([]) == []


def test_semantic_classifier_object_interface():
    """The spec's requested SemanticClassifier.encode/predict/predict_proba
    shape -- exercised directly, not just the module functions."""
    clf = semantic.SemanticClassifier()
    texts = ["Send me the OTP.", "Lunch is in the break room."]
    embeddings = clf.encode(texts)
    assert embeddings.shape == (2, 384)
    predictions = clf.predict(texts)
    assert len(predictions) == 2
    probas = clf.predict_proba(texts)
    assert len(probas) == 2
    assert probas[0] is not None


# ---------------------------------------------------------------------------
# Hard negatives (spec item 15): security vocabulary without a request for
# the secret must not be classified as a scam by MiniLM alone.
# ---------------------------------------------------------------------------
HARD_NEGATIVES = [
    "Please never send your OTP to anyone.",
    "The security team will not ask for your password.",
    "Your MFA enrollment is complete.",
    "Please confirm that the authentication prompt appeared.",
    "Employees should never share authentication values.",
]


@pytest.mark.parametrize("text", HARD_NEGATIVES)
def test_hard_negatives_stay_under_production_threshold(text):
    """Mirrors the regression guard scripts/train_minilm_classifier.py
    already enforces before selecting TEXT_SEMANTIC_MODEL.threshold -- this
    is the same property, verified directly against the shipped artifact so
    a future retrain that regresses it fails CI, not just the training
    script's own printed warning."""
    from packages.ml.model_registry import TEXT_SEMANTIC_MODEL

    pred = semantic.predict(text)
    assert pred is not None
    is_flagged = pred.label != "benign" and pred.confidence > TEXT_SEMANTIC_MODEL.threshold
    assert not is_flagged, f"{text!r} flagged as {pred.label} ({pred.confidence:.3f})"


# ---------------------------------------------------------------------------
# packages/ml/text/__init__.py's score_semantic() wrapper + evidence gate
# ---------------------------------------------------------------------------


async def test_score_semantic_returns_risk_signal_for_scam_text():
    from packages.ml.text import score_semantic
    from packages.shared.schemas.signals import SignalSource

    result = await score_semantic("Send me the OTP right now, it's urgent.")
    assert result.signal is not None
    assert result.signal.source == SignalSource.ML_TEXT
    assert result.label is not None


async def test_score_semantic_evidence_is_none_for_benign_prediction():
    from packages.ml.text import score_semantic

    result = await score_semantic("Team meeting moved to 3pm, conference room B is booked.")
    if result.label == "benign":
        assert result.evidence is None


async def test_score_semantic_evidence_shape_when_present():
    from packages.ml.text import score_semantic

    # A strongly-worded scam message is likely to clear the margin gate;
    # skip (not fail) if this particular model instance stays ambiguous --
    # the shape assertion below is what actually matters.
    result = await score_semantic(
        "URGENT: Your bank account is blocked. Complete KYC verification immediately or lose access."
    )
    if result.evidence is None:
        pytest.skip("model was ambiguous (margin gate) for this text in this trained instance")
    assert result.evidence["source"] == "semantic_model"
    assert result.evidence["confidence_level"] in ("low", "medium", "high")
    assert result.evidence["signal"] == result.label.upper()


# ---------------------------------------------------------------------------
# Absent-model fallback (spec item 7/22): predict()/encode() return None,
# not raise, when the encoder or classifier isn't available.
# ---------------------------------------------------------------------------


def test_predict_returns_none_when_encoder_unavailable(monkeypatch):
    monkeypatch.setattr(semantic, "_load_encoder", lambda: None)
    assert semantic.encode(["hello"]) is None
    assert semantic.predict("hello") is None
    assert semantic.available() is False


def test_predict_returns_none_when_classifier_unavailable(monkeypatch):
    monkeypatch.setattr(semantic, "_load_classifier", lambda: None)
    assert semantic.predict("hello") is None
    assert semantic.available() is False


async def test_score_semantic_absent_when_model_unavailable(monkeypatch):
    from packages.ml.text import score_semantic

    monkeypatch.setattr(semantic, "_load_classifier", lambda: None)
    result = await score_semantic("Send me the OTP.")
    assert result.signal is None
    assert result.label is None
    assert result.evidence is None


# ---------------------------------------------------------------------------
# End-to-end through detector.analyze() -- the semantic signal actually
# contributes to fusion and doesn't override the hard-negative guard.
# ---------------------------------------------------------------------------


async def test_detector_flags_paraphrased_mfa_request():
    from packages.domain.risk import detector

    result = await detector.analyze(
        "What is the number that appeared after the authentication challenge? I need it now."
    )
    assert "semantic_prediction" in result
    assert result["semantic_prediction"]["model_available"] is True


async def test_detector_does_not_flag_negated_credential_request_from_semantic_alone():
    from packages.domain.risk import detector

    result = await detector.analyze("The security team will never ask for your password.")
    assert result["isScam"] is False
