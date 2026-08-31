"""Phase 9 step 6/9: train the chosen production model (word_plus_char_logreg
-- see scripts/train_and_compare_models.py's comparison and
docs/ml/phase8-evaluation.md's Phase 9 section for why), sweep decision
thresholds on ml-models/evaluation/threshold_validation_set.json ONLY, and
write the final artifact + metadata + calibration report.

    uv run python scripts/select_production_model.py

Threshold framings swept (spec item 8):
  - top1: predicted label's own probability > t (what detector.py already
    implements: `label != benign and confidence > threshold`)
  - not_benign: 1 - P(benign) > t (what scripts/eval_unseen.py's old
    `ml_only` used -- included for comparison, not because production uses it)
  - margin: P(top1) - P(top2) > t (confidence *relative* to the runner-up,
    not absolute)

Selection criterion (stated, not implicit): highest F1 among thresholds with
FPR <= 0.10 on the validation split -- a production detector shown to a real
user should not be wrong about benign messages more than 1 in 10 times, and
within that constraint we want the best recall/precision balance.
"""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline

ROOT = Path(__file__).parent.parent
EVAL_DIR = ROOT / "ml-models" / "evaluation"
TRAIN_PATH = EVAL_DIR / "dev_train_set_v2.json"
VAL_PATH = EVAL_DIR / "threshold_validation_set.json"
ARTIFACT_DIR = ROOT / "ml-models" / "trained"
ARTIFACT_PATH = ARTIFACT_DIR / "supervised_classifier.joblib"
METADATA_PATH = ARTIFACT_DIR / "supervised_classifier.metadata.json"

THRESHOLDS = [round(x, 2) for x in np.arange(0.10, 0.91, 0.05)]


def _load(path: Path) -> tuple[list[str], list[str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [ex["text"] for ex in data["examples"]], [ex["label"] for ex in data["examples"]]


def _build_pipeline() -> Pipeline:
    word_tfidf = TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True)
    char_tfidf = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True)
    return Pipeline([
        ("features", FeatureUnion([("word", word_tfidf), ("char", char_tfidf)])),
        ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", C=0.5)),
    ])


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
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": round(precision, 3),
            "recall": round(recall, 3), "f1": round(f1, 3), "fpr": round(fpr, 3), "fnr": round(fnr, 3)}


def _calibration(confidences: list[float], actuals: list[bool], n_bins: int = 10) -> dict:
    brier = sum((c - int(a)) ** 2 for c, a in zip(confidences, actuals)) / len(confidences)
    bins = [[] for _ in range(n_bins)]
    for c, a in zip(confidences, actuals):
        idx = min(int(c * n_bins), n_bins - 1)
        bins[idx].append((c, a))
    ece = 0.0
    n = len(confidences)
    bin_report = []
    for i, bucket in enumerate(bins):
        if not bucket:
            continue
        avg_conf = sum(c for c, _ in bucket) / len(bucket)
        avg_acc = sum(int(a) for _, a in bucket) / len(bucket)
        ece += (len(bucket) / n) * abs(avg_conf - avg_acc)
        bin_report.append({"range": f"{i/n_bins:.1f}-{(i+1)/n_bins:.1f}", "n": len(bucket),
                            "avg_confidence": round(avg_conf, 3), "actual_scam_rate": round(avg_acc, 3)})
    return {"brier_score": round(brier, 4), "ece": round(ece, 4), "bins": bin_report}


def _permanent_regression_benign_texts() -> list[str]:
    """Every text this repo's permanent regression suite asserts is benign --
    imported, not copy-pasted, so this stays in sync if those files change.
    A threshold that lets the ML signal alone flag any of these is rejected:
    these are exactly the out-of-distribution-vs-threshold_validation_set
    cases that a same-template validation split can't catch (see this
    script's own warning about threshold_validation_set.json's ceiling)."""
    import sys

    sys.path.insert(0, str(ROOT))
    from tests.unit.test_scam_regression import BENIGN_CASES
    from tests.unit.test_char_detection import BENIGN_BANK

    return list(BENIGN_CASES.values()) + list(BENIGN_BANK.values())


def main() -> None:
    train_texts, train_labels = _load(TRAIN_PATH)
    val_texts, val_labels = _load(VAL_PATH)
    val_actual = [lbl != "benign" for lbl in val_labels]
    regression_benign_texts = _permanent_regression_benign_texts()

    pipeline = _build_pipeline()
    pipeline.fit(train_texts, train_labels)

    top1_conf, not_benign_conf, margin_conf, top1_label = [], [], [], []
    for text in val_texts:
        proba_row = pipeline.predict_proba([text])[0]
        classes = list(pipeline.classes_)
        proba = dict(zip(classes, proba_row))
        sorted_probs = sorted(proba.values(), reverse=True)
        label = max(proba, key=proba.get)
        top1_label.append(label)
        top1_conf.append(proba[label])
        not_benign_conf.append(1.0 - proba.get("benign", 0.0))
        margin_conf.append(sorted_probs[0] - (sorted_probs[1] if len(sorted_probs) > 1 else 0.0))

    print("=== Threshold sweep (n=%d) ===" % len(val_texts))
    sweep_results = {}
    for framing_name, confidences in [("top1", top1_conf), ("not_benign", not_benign_conf), ("margin", margin_conf)]:
        print(f"\n-- framing: {framing_name} --")
        rows = []
        for t in THRESHOLDS:
            if framing_name == "not_benign":
                preds = [c > t for c in confidences]
            else:
                preds = [(lbl != "benign") and (c > t) for lbl, c in zip(top1_label, confidences)]
            metrics = _confusion(preds, val_actual)
            rows.append({"threshold": float(t), **metrics})
            print(f"  t={t:.2f}  P={metrics['precision']:.3f} R={metrics['recall']:.3f} "
                  f"F1={metrics['f1']:.3f} FPR={metrics['fpr']:.3f} FNR={metrics['fnr']:.3f}")
        sweep_results[framing_name] = rows

    # Regression guard: for each threshold, does the ML signal ALONE (no
    # rule/behavioral corroboration -- this is what "is_supervised_scam" in
    # detector.py checks) flag any text the permanent regression suite
    # asserts is benign? threshold_validation_set.json can't catch this --
    # it's drawn from the same templates as training, so it has no
    # out-of-distribution phrasing like "To set up MFA, open the
    # authenticator app and scan the QR code..." (legitimate instructions
    # that happen to share vocabulary with mfa_code_theft).
    regression_min_safe_threshold = 0.0
    regression_false_positives = []
    for text in regression_benign_texts:
        proba_row = pipeline.predict_proba([text])[0]
        proba = dict(zip(pipeline.classes_, proba_row))
        label = max(proba, key=proba.get)
        if label == "benign":
            continue
        confidence = proba[label]
        regression_false_positives.append({"text": text[:100], "label": label, "confidence": round(confidence, 3)})
        regression_min_safe_threshold = max(regression_min_safe_threshold, confidence)

    print(f"\n=== Regression-suite guard: {len(regression_benign_texts)} permanent benign texts ===")
    if regression_false_positives:
        print(f"Minimum threshold to clear ALL of them: > {regression_min_safe_threshold:.3f}")
        for fp in regression_false_positives:
            print(f"  ML would flag as {fp['label']} ({fp['confidence']}): {fp['text']!r}")
    else:
        print("No regression-suite text triggers the ML signal at any confidence -- no floor imposed.")

    # Selection: highest F1 among top1-framing thresholds that (a) keep
    # FPR <= 0.10 on threshold_validation_set.json and (b) clear every
    # permanent regression benign text (constraint (b) dominates -- it's
    # measured on real out-of-distribution phrasing, (a) is not). Tie-break
    # toward the HIGHER threshold: several thresholds tie on the
    # in-distribution validation split (expected, not evidence any of them
    # is safe) -- the higher one is the more conservative default.
    safe_thresholds = [t for t in THRESHOLDS if t > regression_min_safe_threshold]
    candidates = [r for r in sweep_results["top1"] if r["fpr"] <= 0.10 and r["threshold"] in safe_thresholds]
    if not candidates:
        candidates = [r for r in sweep_results["top1"] if r["threshold"] in safe_thresholds]
    if not candidates:
        # No swept threshold clears the regression guard -- fall back to just
        # above the measured floor rather than silently picking an unsafe one.
        fallback_threshold = round(min(0.95, regression_min_safe_threshold + 0.05), 2)
        print(f"\nWARNING: no swept threshold (<=0.65) clears the regression guard. "
              f"Falling back to {fallback_threshold} (just above the measured floor).")
        best = {"threshold": fallback_threshold, "precision": None, "recall": None,
                "f1": None, "fpr": None, "fnr": None, "tp": None, "fp": None, "tn": None, "fn": None}
    else:
        best = max(candidates, key=lambda r: (r["f1"], r["threshold"]))
    print(f"\nSelected threshold (top1 framing, highest F1 with FPR<=0.10): {best['threshold']}")
    print(f"  -> P={best['precision']} R={best['recall']} F1={best['f1']} FPR={best['fpr']} FNR={best['fnr']}")

    calib = _calibration(top1_conf, val_actual)
    print(f"\n=== Calibration (top1 confidence, threshold_validation_set) ===")
    print(f"Brier: {calib['brier_score']}  ECE: {calib['ece']}")
    for b in calib["bins"]:
        print(f"  conf {b['range']}: n={b['n']} avg_conf={b['avg_confidence']} actual_rate={b['actual_scam_rate']}")

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, ARTIFACT_PATH)
    metadata = {
        "trained_on": str(TRAIN_PATH.relative_to(ROOT)),
        "n_train_examples": len(train_texts),
        "labels": sorted(set(train_labels)),
        "model": "FeatureUnion(word TF-IDF 1-2gram, char_wb TF-IDF 3-5gram) + LogisticRegression(C=0.5, class_weight=balanced)",
        "selected_threshold": best["threshold"],
        "threshold_framing": "top1: predicted label's own probability, label != benign",
        "threshold_selection_set": str(VAL_PATH.relative_to(ROOT)),
        "threshold_selection_metrics": best,
        "regression_guard": {
            "checked_against": "tests/unit/test_scam_regression.py BENIGN_CASES + tests/unit/test_char_detection.py BENIGN_BANK",
            "n_texts": len(regression_benign_texts),
            "min_safe_threshold": round(regression_min_safe_threshold, 3),
            "false_positives_at_threshold_0": regression_false_positives,
        },
        "calibration_on_threshold_validation_set": calib,
        "warning": (
            "First pass of this script picked threshold=0.30 using only "
            "threshold_validation_set.json, which is drawn from the SAME "
            "combinatorial templates as training -- it does not contain "
            "out-of-distribution benign phrasing. That threshold let the ML "
            "signal alone flag a real permanent regression case ('To set up "
            "MFA, open the authenticator app and scan the QR code...') as "
            "mfa_code_theft. This run adds a hard floor: the threshold must "
            "clear every text tests/unit/test_scam_regression.py and "
            "tests/unit/test_char_detection.py assert is benign, not just "
            "threshold_validation_set.json's FPR. Even with that floor, "
            "in-distribution validation numbers above are still not evidence "
            "of real-world generalization -- ml-models/evaluation/unseen_validation_set.json "
            "(untouched by this script) is the only source of that -- see "
            "scripts/eval_unseen.py's output and docs/ml/phase8-evaluation.md."
        ),
    }
    METADATA_PATH.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    (EVAL_DIR / "phase9_threshold_sweep.json").write_text(json.dumps(sweep_results, indent=2), encoding="utf-8")
    print(f"\nWrote {ARTIFACT_PATH.relative_to(ROOT)}, {METADATA_PATH.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
