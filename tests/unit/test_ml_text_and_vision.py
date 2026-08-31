"""packages/ml/text (lite-mode path) and packages/ml/vision (not-yet-implemented
stub). Real-model paths (MODELS_AVAILABLE=True) aren't exercised here — no
torch/transformers installed in this environment; see
docs/ml/phase8-evaluation.md.
"""

from packages.ml import text as ml_text
from packages.ml import vision as ml_vision


async def test_text_score_is_none_when_no_model_is_loaded():
    """tests/conftest.py sets HF_LITE_MODE=true -- hf.MODELS_AVAILABLE is
    False for the whole suite, so this is the lite-mode path for real."""
    signal = await ml_text.score("send money now")
    assert signal is None


async def test_text_classify_type_is_none_when_no_model_is_loaded():
    result = await ml_text.classify_type("send money now", labels=["lottery", "job scam"])
    assert result is None


async def test_vision_score_is_always_none():
    """Documented not-yet-implemented -- absent, not a fake zero score."""
    signal = await ml_vision.score(b"fake-image-bytes")
    assert signal is None
