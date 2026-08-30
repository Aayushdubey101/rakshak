"""Model id, version, and decision thresholds — in one place, in config-shaped
data, not as literals scattered through detection code.

The models loaded here (`packages/ml/inference/hf.py`) were already chosen
before this phase; this registry doesn't select between candidates, because
no benchmark has run in this environment to justify picking one over
another. `task.md`'s "no model family is hard-coded until evaluation
justifies it" is honored by keeping the id/version/threshold *configurable*
and by `scripts/eval_detection.py` existing and running against the current
baseline (see `docs/ml/phase8-evaluation.md`) — swapping a model is changing
one `ModelDescriptor`, not editing detection logic.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ModelDescriptor:
    id: str
    version: str
    threshold: float = 0.5


TEXT_SPAM_MODEL = ModelDescriptor(
    id="mrm8488/bert-tiny-finetuned-sms-spam-detection", version="1", threshold=0.8
)
# Was "microsoft/deberta-v3-small" -- a bare pretrained backbone with no
# NLI/entailment fine-tuning, verified against HF's own zero-shot-classification
# pipeline requirements (an entailment-tuned checkpoint). Transformers attaches
# a randomly-initialized classification head to a model like that, producing
# meaningless probabilities regardless of input. Corrected to a checkpoint
# actually trained for zero-shot NLI (MoritzLaurer/deberta-v3-base-zeroshot-v1,
# a maintained, widely-used zero-shot model). Still gated behind
# DEPLOYMENT_MODE=full + `uv sync --extra ml` (torch/transformers) -- not
# installed or benchmarked in this environment. TEXT_SUPERVISED_MODEL below is
# the ML path that actually runs today, in lite mode, with no heavy install.
TEXT_ZERO_SHOT_MODEL = ModelDescriptor(
    id="MoritzLaurer/deberta-v3-base-zeroshot-v1", version="1", threshold=0.5
)
# FeatureUnion(word TF-IDF 1-2gram, char_wb TF-IDF 3-5gram) + logistic
# regression, trained by scripts/select_production_model.py on
# ml-models/evaluation/dev_train_set_v2.json (1321 examples, 9 classes --
# phase 9's expansion of the original 90-example set). scikit-learn is a core
# dependency (small, no GPU/heavy download), so this runs unconditionally --
# not gated by DEPLOYMENT_MODE/HF_LITE_MODE the way the HF pipelines are.
# Threshold 0.65 was chosen by scripts/select_production_model.py's sweep,
# with a hard floor: the threshold must clear every text
# tests/unit/test_scam_regression.py / test_char_detection.py assert is
# benign, not just threshold_validation_set.json's own FPR. An earlier pass
# picked 0.30 from validation-set numbers alone (P=1.0/R=1.0 there) and it
# let the ML signal alone flag a real regression case ("To set up MFA, open
# the authenticator app and scan the QR code...", confidence 0.645) as
# mfa_code_theft -- threshold_validation_set.json is drawn from the same
# templates as training, so it has no out-of-distribution "instructional"
# benign phrasing like that to catch the problem. See
# ml-models/trained/supervised_classifier.metadata.json's regression_guard
# section and docs/ml/phase8-evaluation.md's Phase 9 section.
TEXT_SUPERVISED_MODEL = ModelDescriptor(
    id="rakshak.supervised_tfidf_logreg.v2", version="2", threshold=0.65
)
# Phase 10: sentence-transformers/all-MiniLM-L6-v2 embeddings (384-dim) +
# LogisticRegression (packages/ml/text/semantic.py), trained by
# scripts/train_minilm_classifier.py on the same dev_train_set_v2.json as
# TEXT_SUPERVISED_MODEL above. Threshold 0.5 came from that script's sweep
# against threshold_validation_set.json (same top1-framing + regression-
# guard-floor selection process TEXT_SUPERVISED_MODEL's 0.65 went through):
# the measured floor was 0.483 (the exact confidence
# "To set up MFA, open the authenticator app and scan the QR code shown on
# your account security page." scored -- same regression case that broke
# the supervised classifier's first threshold pick in Phase 9), and 0.5 is
# the lowest swept value above that floor, giving the best F1 (0.966) among
# safe thresholds on threshold_validation_set.json. See
# ml-models/trained/minilm_classifier.metadata.json for the full sweep and
# docs/ml/phase10-semantic-evaluation.md for the frozen-set numbers this
# threshold was NOT tuned against.
TEXT_SEMANTIC_MODEL = ModelDescriptor(
    id="rakshak.minilm_logreg.v1", version="1", threshold=0.5
)
PATTERN_RULESET = ModelDescriptor(id="rakshak.risk_signals.v1", version="1", threshold=0.30)
URL_LEXICAL_RULESET = ModelDescriptor(id="rakshak.url_lexical.v1", version="1", threshold=0.5)


async def record_model_run(
    repository, *, investigation_id: str, stage: str, model: ModelDescriptor, duration_ms: int
) -> None:
    """Every inference that runs through this registry writes one
    `model_runs` row (phase 7's table) — the audit trail an evaluation
    script or a later incident review reads, not application logs."""
    await repository.record_model_run(
        investigation_id=investigation_id, stage=stage,
        model_id=model.id, version=model.version, duration_ms=duration_ms,
    )
