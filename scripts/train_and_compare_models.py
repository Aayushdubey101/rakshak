"""Phase 9 step 4/5/9: compare lightweight model configs, pick production model.

    uv run python scripts/train_and_compare_models.py

Trains each config on ml-models/evaluation/dev_train_set_v2.json, evaluates on
ml-models/evaluation/threshold_validation_set.json ONLY (never the frozen
unseen set). Decision rule matches production (packages/ml/text/supervised.py
+ detector.py): predicted label = argmax proba; is_scam = label != "benign"
and proba[label] > threshold (fixed at 0.5 here for a fair head-to-head; step
6 sweeps the threshold separately for whichever config wins here).

Semantic-layer note (spec item 5): gensim + a pretrained GloVe vector set was
the first option considered for paraphrase generalization. Rejected without
installing it: this same session already saw `uv add scikit-learn joblib`
(both far lighter than gensim + a 66MB vector download) stall for 7+ minutes
in this environment and require killing the process. Adding a heavier,
network-fetched dependency on unproven install reliability, for a benefit
that's a hypothesis until measured, isn't the lightweight-first path the
spec's own guardrail asks for. Char n-gram TF-IDF is the fallback the spec
explicitly allows: zero new dependencies (scikit-learn already core), no
network fetch at train or inference time, and it captures *morphological*
similarity (shared substrings across inflections/typos) that word-level
TF-IDF misses -- it does NOT capture true lexical-semantic similarity
("OTP" vs "six digits" share no character trigrams), which is disclosed
plainly in docs/ml/phase8-evaluation.md's Phase 9 section as the known
ceiling of this choice.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import joblib
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.svm import LinearSVC

ROOT = Path(__file__).parent.parent
EVAL_DIR = ROOT / "ml-models" / "evaluation"
TRAIN_PATH = EVAL_DIR / "dev_train_set_v2.json"
VAL_PATH = EVAL_DIR / "threshold_validation_set.json"
ARTIFACT_DIR = ROOT / "ml-models" / "trained"

DEFAULT_THRESHOLD = 0.5


def _load(path: Path) -> tuple[list[str], list[str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    texts = [ex["text"] for ex in data["examples"]]
    labels = [ex["label"] for ex in data["examples"]]
    return texts, labels


def _build_pipelines() -> dict[str, Pipeline]:
    word_tfidf = TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True)
    char_tfidf = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True)
    combined = FeatureUnion([("word", word_tfidf), ("char", char_tfidf)])

    return {
        "word_tfidf_logreg": Pipeline([
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True)),
            ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", C=1.0)),
        ]),
        "word_tfidf_linearsvc": Pipeline([
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True)),
            ("clf", CalibratedClassifierCV(
                LinearSVC(class_weight="balanced", C=1.0), method="sigmoid", cv=3
            )),
        ]),
        "char_ngram_logreg": Pipeline([
            ("tfidf", char_tfidf),
            ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", C=1.0)),
        ]),
        "word_plus_char_logreg": Pipeline([
            ("features", combined),
            ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", C=0.5)),
        ]),
    }


def _predict_decision(pipeline: Pipeline, text: str, threshold: float) -> tuple[bool, str, float]:
    proba_row = pipeline.predict_proba([text])[0]
    classes = pipeline.classes_
    proba = dict(zip(classes, proba_row))
    label = max(proba, key=proba.get)
    confidence = proba[label]
    is_scam = label != "benign" and confidence > threshold
    return is_scam, label, confidence


def _confusion(preds: list[bool], actuals: list[bool]) -> dict:
    tp = fp = tn = fn = 0
    for p, a in zip(preds, actuals):
        if p and a:
            tp += 1
        elif p and not a:
            fp += 1
        elif not p and not a:
            tn += 1
        else:
            fn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
        "fpr": round(fpr, 3), "fnr": round(fnr, 3),
    }


def main() -> None:
    train_texts, train_labels = _load(TRAIN_PATH)
    val_texts, val_labels = _load(VAL_PATH)
    val_actual_scam = [lbl != "benign" for lbl in val_labels]

    pipelines = _build_pipelines()
    results = []

    for name, pipeline in pipelines.items():
        t0 = time.perf_counter()
        pipeline.fit(train_texts, train_labels)
        train_seconds = time.perf_counter() - t0

        preds, pred_labels = [], []
        latencies_ms = []
        for text in val_texts:
            started = time.perf_counter()
            is_scam, label, _confidence = _predict_decision(pipeline, text, DEFAULT_THRESHOLD)
            latencies_ms.append((time.perf_counter() - started) * 1000)
            preds.append(is_scam)
            pred_labels.append(label)

        latencies_ms.sort()
        p50 = latencies_ms[len(latencies_ms) // 2]
        p95 = latencies_ms[int(len(latencies_ms) * 0.95)]

        type_correct = sum(
            1 for pl, al, a in zip(pred_labels, val_labels, val_actual_scam)
            if a and pl == al
        )
        type_total = sum(val_actual_scam)

        tmp_path = ARTIFACT_DIR / f"_tmp_{name}.joblib"
        ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(pipeline, tmp_path)
        size_kb = tmp_path.stat().st_size / 1024
        tmp_path.unlink()

        metrics = _confusion(preds, val_actual_scam)
        results.append({
            "model": name,
            **metrics,
            "scam_type_exact_match": round(type_correct / type_total, 3) if type_total else 0.0,
            "latency_ms_p50": round(p50, 3),
            "latency_ms_p95": round(p95, 3),
            "train_seconds": round(train_seconds, 2),
            "artifact_kb": round(size_kb, 1),
        })

    print(f"n_train={len(train_texts)} n_val={len(val_texts)} threshold={DEFAULT_THRESHOLD}\n")
    header = f"{'model':<24}{'prec':>7}{'rec':>7}{'f1':>7}{'fpr':>7}{'fnr':>7}{'type_acc':>10}{'p50ms':>8}{'p95ms':>8}{'KB':>8}"
    print(header)
    for r in results:
        print(
            f"{r['model']:<24}{r['precision']:>7}{r['recall']:>7}{r['f1']:>7}{r['fpr']:>7}{r['fnr']:>7}"
            f"{r['scam_type_exact_match']:>10}{r['latency_ms_p50']:>8}{r['latency_ms_p95']:>8}{r['artifact_kb']:>8}"
        )

    (EVAL_DIR / "phase9_model_comparison.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nWrote {EVAL_DIR / 'phase9_model_comparison.json'}")


if __name__ == "__main__":
    main()
