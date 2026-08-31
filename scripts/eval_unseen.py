"""Generalization evaluation on the UNSEEN validation set.

    uv run --extra semantic python scripts/eval_unseen.py

Runs ml-models/evaluation/unseen_validation_set.json (220 examples, 9
categories, none of it used to write RISK_SIGNALS/behavioral_signals.py or
to train either classifier) through six candidates (Phase 10 item 8 --
the TF-IDF candidate is kept, not replaced):

  A. rules_only       -- keyword/intelligence-extractor scoring, no behavioral signals, no ML
  B. tfidf_ml          -- packages/ml/text/supervised.py directly (was "ml_only")
  C. minilm_ml         -- packages/ml/text/semantic.py directly (new)
  D. combined_tfidf    -- rules + behavioral + TF-IDF only (no MiniLM)
  E. combined_minilm   -- rules + behavioral + MiniLM only (no TF-IDF)
  F. combined          -- scam_detector.analyze() as it exists today
                          (rules + behavioral + TF-IDF + MiniLM -- since
                          Phase 10 wired both classifiers into fusion, this
                          candidate IS "Architecture D" from the spec)

`combined_tfidf`/`combined_minilm` replicate detector.analyze()'s fusion +
decision logic (pattern signal, behavioral negation guard, 0.7 fused-score
override) restricted to one text-ML layer at a time -- the HF spam model and
LLM layers are excluded from every candidate here since they're identically
absent in this lite-mode evaluation environment for both, so excluding them
doesn't change what's being compared.

Reports binary precision/recall/F1/false-positive-rate/false-negative-rate/
confusion matrix for each, per-category recall broken out, and Brier score +
a 10-bin Expected Calibration Error for each classifier's own confidence.
"""

from __future__ import annotations

import asyncio
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).parent.parent
UNSEEN_PATH = ROOT / "ml-models" / "evaluation" / "unseen_validation_set.json"
PARAPHRASE_PATH = ROOT / "ml-models" / "evaluation" / "paraphrase_pairs.json"
SEMANTIC_PARAPHRASE_PATH = ROOT / "ml-models" / "evaluation" / "semantic_paraphrase_test.json"

# category -> the scamType `scam_detector.analyze()` would need to return
# for a *correct* classification, where the taxonomies actually line up.
# social_engineering/it_support_impersonation have no first-class scamType
# in detector.py yet (see docs/ml/phase8-evaluation.md) -- reported as
# binary detection only, not scamType-match accuracy, so the mismatch is
# visible rather than silently graded against the wrong target.
_CATEGORY_TO_SCAM_TYPE = {
    "mfa_otp_theft": "mfa_code_theft",
    "credential_access": "credential_access",
    "bank_impersonation": "bank_fraud",
    "investment_scam": "investment_scam",
    "payment_fraud": "payment_fraud",
    "phishing_url": "phishing",
}


async def _rules_only(text: str) -> bool:
    from packages.domain.entities import intelligence_extractor
    from packages.domain.risk.detector import calculate_risk_score

    intelligence = intelligence_extractor.get_scam_score(text)
    risk_result = calculate_risk_score(text)
    risk_score = risk_result["score"]
    confidence = min((risk_score * 0.7 + intelligence["score"] * 0.3) / 100.0, 1.0)
    return (
        risk_score >= 18
        or len(risk_result["signals"]) >= 2
        or confidence > 0.30
        or bool(intelligence["intelligence"].get("phishingLinks"))
    )


def _tfidf_only_confidence(text: str) -> float | None:
    """P(not benign) -- reported for calibration only. None if the artifact
    isn't trained."""
    from packages.ml.text import supervised

    pred = supervised.predict(text)
    if pred is None:
        return None
    return 1.0 - pred.proba.get("benign", 0.0)


async def _tfidf_only(text: str) -> bool | None:
    """Matches production's actual decision rule (detector.py's
    `is_supervised_scam` / packages/ml/model_registry.py's
    TEXT_SUPERVISED_MODEL.threshold) -- top1 framing (predicted label's own
    probability, label != benign), not the P(not-benign) framing
    `_tfidf_only_confidence` reports for calibration."""
    from packages.ml.model_registry import TEXT_SUPERVISED_MODEL
    from packages.ml.text import supervised

    pred = supervised.predict(text)
    if pred is None:
        return None
    return pred.label != "benign" and pred.confidence > TEXT_SUPERVISED_MODEL.threshold


def _minilm_only_confidence(text: str) -> float | None:
    """P(not benign) -- reported for calibration only. None if
    sentence-transformers isn't installed or the artifact isn't trained."""
    from packages.ml.text import semantic

    pred = semantic.predict(text)
    if pred is None:
        return None
    return 1.0 - pred.proba.get("benign", 0.0)


async def _minilm_only(text: str) -> bool | None:
    """Same top1 framing as _tfidf_only, using TEXT_SEMANTIC_MODEL's
    threshold -- the direct MiniLM-alone comparison spec item 12 asks for
    ("test semantic model independently... before combining it with
    rules... do not hide poor ML behavior behind the rules")."""
    from packages.ml.model_registry import TEXT_SEMANTIC_MODEL
    from packages.ml.text import semantic

    pred = semantic.predict(text)
    if pred is None:
        return None
    return pred.label != "benign" and pred.confidence > TEXT_SEMANTIC_MODEL.threshold


async def _fused_decision(text: str, *, use_tfidf: bool, use_minilm: bool) -> bool:
    """Replicates detector.analyze()'s pattern+behavioral+ML fusion and
    decision rule, restricted to whichever text-ML layer(s) are enabled --
    used for the combined_tfidf/combined_minilm architecture-comparison
    candidates (spec item 23), which detector.analyze() itself can't
    produce anymore now that it always fuses both layers together."""
    from packages.domain.risk import behavioral_signals
    from packages.domain.risk.detector import pattern_based_detection
    from packages.domain.risk.fusion import attach_weight, fuse
    from packages.ml import text as ml_text
    from packages.ml.model_registry import PATTERN_RULESET, TEXT_SEMANTIC_MODEL, TEXT_SUPERVISED_MODEL
    from packages.shared.schemas.signals import RiskSignal, SignalSource

    pattern_result = pattern_based_detection(text)
    pattern_signal = attach_weight(RiskSignal(
        source=SignalSource.PATTERN,
        score=min(pattern_result["confidence"], 1.0),
        label=pattern_result["scamType"],
        confidence=min(pattern_result["confidence"], 1.0),
        model_id=PATTERN_RULESET.id,
    ))
    signals = [pattern_signal]
    is_supervised_scam = is_semantic_scam = False

    if use_tfidf:
        supervised_signal = await ml_text.score_supervised(text)
        if supervised_signal is not None:
            signals.append(supervised_signal)
            is_supervised_scam = (
                supervised_signal.label != "benign"
                and supervised_signal.score > TEXT_SUPERVISED_MODEL.threshold
            )

    if use_minilm:
        semantic_result = await ml_text.score_semantic(text)
        if semantic_result.signal is not None:
            signals.append(semantic_result.signal)
            is_semantic_scam = (
                semantic_result.label != "benign"
                and semantic_result.signal.score > TEXT_SEMANTIC_MODEL.threshold
            )

    fusion_result = fuse(signals)
    negated = behavioral_signals.has_negated_credential_request(text)
    is_scam = (
        (is_supervised_scam and not negated)
        or (is_semantic_scam and not negated)
        or pattern_result["isScam"]
    )
    if fusion_result.risk_score >= 0.7:
        is_scam = True
    return is_scam


async def _combined_tfidf(text: str) -> bool:
    return await _fused_decision(text, use_tfidf=True, use_minilm=False)


async def _combined_minilm(text: str) -> bool:
    return await _fused_decision(text, use_tfidf=False, use_minilm=True)


async def _combined(text: str) -> dict:
    from packages.domain.risk import detector

    return await detector.analyze(text)


def _confusion(predictions: list[bool | None], actuals: list[bool]) -> dict:
    tp = fp = tn = fn = no_pred = 0
    for pred, actual in zip(predictions, actuals):
        if pred is None:
            no_pred += 1
        elif pred and actual:
            tp += 1
        elif pred and not actual:
            fp += 1
        elif not pred and not actual:
            tn += 1
        else:
            fn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn, "no_prediction": no_pred,
        "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
        "false_positive_rate": round(fpr, 3), "false_negative_rate": round(fnr, 3),
    }


def _calibration(confidences: list[float], actuals: list[bool], n_bins: int = 10) -> dict:
    """Brier score + Expected Calibration Error for a classifier's own
    P(not benign) against the actual is_scam label."""
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
        bin_report.append({
            "range": f"{i/n_bins:.1f}-{(i+1)/n_bins:.1f}", "n": len(bucket),
            "avg_confidence": round(avg_conf, 3), "actual_scam_rate": round(avg_acc, 3),
        })
    return {"brier_score": round(brier, 4), "ece": round(ece, 4), "bins": bin_report}


async def main() -> None:
    data = json.loads(UNSEEN_PATH.read_text(encoding="utf-8"))
    examples = data["examples"]
    assert data.get("purpose") == "unseen_validation", "wrong file -- this must be the unseen set"

    actuals = [ex["is_scam"] for ex in examples]
    rules_preds, tfidf_preds, minilm_preds = [], [], []
    combined_tfidf_preds, combined_minilm_preds, combined_preds = [], [], []
    tfidf_confidences, minilm_confidences = [], []
    combined_results = []
    per_category_rules = defaultdict(lambda: [0, 0])  # category -> [correct, total]
    per_category_combined = defaultdict(lambda: [0, 0])
    per_category_combined_minilm = defaultdict(lambda: [0, 0])
    scamtype_correct = defaultdict(lambda: [0, 0])  # category -> [correct_type, total_flagged_scam]

    for ex in examples:
        text, actual, category = ex["text"], ex["is_scam"], ex["category"]

        rp = await _rules_only(text)
        rules_preds.append(rp)
        per_category_rules[category][1] += 1
        if rp == actual:
            per_category_rules[category][0] += 1

        tconf = _tfidf_only_confidence(text)
        tfidf_confidences.append(tconf if tconf is not None else 0.0)
        tfidf_preds.append(await _tfidf_only(text))

        mconf = _minilm_only_confidence(text)
        minilm_confidences.append(mconf if mconf is not None else 0.0)
        minilm_preds.append(await _minilm_only(text))

        combined_tfidf_preds.append(await _combined_tfidf(text))

        cmp = await _combined_minilm(text)
        combined_minilm_preds.append(cmp)
        per_category_combined_minilm[category][1] += 1
        if cmp == actual:
            per_category_combined_minilm[category][0] += 1

        cr = await _combined(text)
        combined_results.append(cr)
        cp = bool(cr["isScam"])
        combined_preds.append(cp)
        per_category_combined[category][1] += 1
        if cp == actual:
            per_category_combined[category][0] += 1

        expected_type = _CATEGORY_TO_SCAM_TYPE.get(category)
        if expected_type is not None and actual:
            scamtype_correct[category][1] += 1
            if cp and cr["scamType"] == expected_type:
                scamtype_correct[category][0] += 1

    print(f"=== Unseen validation set: n={len(examples)} ===\n")

    candidates = [
        ("rules_only", rules_preds),
        ("tfidf_ml", tfidf_preds),
        ("minilm_ml", minilm_preds),
        ("combined_tfidf", combined_tfidf_preds),
        ("combined_minilm", combined_minilm_preds),
        ("combined (tfidf+minilm, today's detector.analyze())", combined_preds),
    ]
    for name, preds in candidates:
        result = _confusion(preds, actuals)
        print(f"{name}: {result}")

    print("\n=== Per-category detection rate (rules_only vs combined_minilm vs combined) ===")
    for category in sorted(set(ex["category"] for ex in examples)):
        r_correct, r_total = per_category_rules[category]
        m_correct, m_total = per_category_combined_minilm[category]
        c_correct, c_total = per_category_combined[category]
        print(f"  {category}: rules_only {r_correct}/{r_total} ({r_correct/r_total:.0%})  "
              f"combined_minilm {m_correct}/{m_total} ({m_correct/m_total:.0%})  "
              f"combined {c_correct}/{c_total} ({c_correct/c_total:.0%})")

    print("\n=== scamType exact-match accuracy (combined only, categories with a 1:1 taxonomy mapping) ===")
    for category, (correct, total) in sorted(scamtype_correct.items()):
        print(f"  {category}: {correct}/{total} ({correct/total:.0%})" if total else f"  {category}: n=0")

    print("\n=== Calibration: TF-IDF P(not benign) vs actual is_scam ===")
    calib = _calibration(tfidf_confidences, actuals)
    print(f"  Brier score: {calib['brier_score']}  ECE: {calib['ece']}")
    for b in calib["bins"]:
        print(f"    conf {b['range']}: n={b['n']} avg_confidence={b['avg_confidence']} actual_scam_rate={b['actual_scam_rate']}")

    print("\n=== Calibration: MiniLM P(not benign) vs actual is_scam ===")
    calib = _calibration(minilm_confidences, actuals)
    print(f"  Brier score: {calib['brier_score']}  ECE: {calib['ece']}")
    for b in calib["bins"]:
        print(f"    conf {b['range']}: n={b['n']} avg_confidence={b['avg_confidence']} actual_scam_rate={b['actual_scam_rate']}")

    # False positives / false negatives for the combined system, with text, for the final report.
    print("\n=== combined false positives (flagged scam, actually benign) ===")
    for ex, pred in zip(examples, combined_preds):
        if pred and not ex["is_scam"]:
            print(f"  [{ex['category']}] {ex['text'][:100]}")

    print("\n=== combined false negatives (missed, actually scam) ===")
    for ex, pred in zip(examples, combined_preds):
        if not pred and ex["is_scam"]:
            print(f"  [{ex['category']}] {ex['text'][:100]}")

    print("\n=== rules_only false negatives NOT recovered by combined (behavioral/ML both missed) ===")
    for ex, rp, cp in zip(examples, rules_preds, combined_preds):
        if not rp and ex["is_scam"] and not cp:
            print(f"  [{ex['category']}] {ex['text'][:100]}")

    await _eval_paraphrase_pairs()
    await _eval_semantic_paraphrase_test()


async def _eval_paraphrase_pairs() -> None:
    """Does `combined` (today's rules+behavioral+TF-IDF+MiniLM detector)
    detect the SAME intent whether it's phrased in the vocabulary
    behavioral_signals.py anchors on ('known') or paraphrased away from it
    ('unseen')? Never used for tuning -- this file is not touched by
    generate_dev_dataset.py or any training script."""
    data = json.loads(PARAPHRASE_PATH.read_text(encoding="utf-8"))
    pairs = data["pairs"]

    print(f"\n\n=== Paraphrase generalization probe (paraphrase_pairs.json): n={len(pairs)} pairs ===")
    known_correct = unseen_correct = 0
    for pair in pairs:
        known, unseen = pair["known"], pair["unseen"]
        known_result = await _combined(known["text"])
        unseen_result = await _combined(unseen["text"])
        known_ok = bool(known_result["isScam"]) == known["is_scam"]
        unseen_ok = bool(unseen_result["isScam"]) == unseen["is_scam"]
        known_correct += known_ok
        unseen_correct += unseen_ok
        status = "OK" if (known_ok and unseen_ok) else ("PARTIAL" if (known_ok or unseen_ok) else "FAIL")
        print(f"  [{status}] {pair['id']}")
        print(f"    known  (expect {known['is_scam']}): got {known_result['isScam']}  -- {known['text'][:70]!r}")
        print(f"    unseen (expect {unseen['is_scam']}): got {unseen_result['isScam']}  -- {unseen['text'][:70]!r}")

    print(f"\nknown accuracy:  {known_correct}/{len(pairs)} ({known_correct/len(pairs):.0%})")
    print(f"unseen accuracy: {unseen_correct}/{len(pairs)} ({unseen_correct/len(pairs):.0%})")


async def _eval_semantic_paraphrase_test() -> None:
    """Phase 10 items 9/10: the semantic_paraphrase_test.json probe, run
    through minilm_ml (MiniLM alone) and combined (today's full detector) --
    known-vs-paraphrased MFA/credential recall, plus benign_security_context
    as an explicit hard-negative check (spec item 15: mentioning
    secret-related vocabulary while explicitly NOT asking for the secret
    must not be flagged)."""
    if not SEMANTIC_PARAPHRASE_PATH.exists():
        print("\n(semantic_paraphrase_test.json not found -- run "
              "scripts/generate_semantic_paraphrase_test.py first)")
        return

    data = json.loads(SEMANTIC_PARAPHRASE_PATH.read_text(encoding="utf-8"))
    examples = data["examples"]
    print(f"\n\n=== Semantic paraphrase test (semantic_paraphrase_test.json): n={len(examples)} ===")

    for system_name, predict_fn in [("minilm_ml", _minilm_only), ("combined", None)]:
        preds = []
        for ex in examples:
            if predict_fn is not None:
                p = await predict_fn(ex["text"])
            else:
                cr = await _combined(ex["text"])
                p = bool(cr["isScam"])
            preds.append(p)

        actuals = [ex["is_scam"] for ex in examples]
        overall = _confusion(preds, actuals)
        print(f"\n-- {system_name} overall: {overall}")

        for category in data.get("categories", []):
            cat_examples = [(ex, p) for ex, p in zip(examples, preds) if ex["category"] == category]
            if not cat_examples:
                continue
            cat_actuals = [ex["is_scam"] for ex, _ in cat_examples]
            cat_preds = [p for _, p in cat_examples]
            result = _confusion(cat_preds, cat_actuals)
            if category in ("mfa_verification_intent", "credential_intent"):
                known = [(ex, p) for ex, p in cat_examples if ex.get("known_phrasing")]
                paraphrased = [(ex, p) for ex, p in cat_examples if not ex.get("known_phrasing")]
                known_recall = (
                    sum(1 for _, p in known if p) / len(known) if known else 0.0
                )
                paraphrase_recall = (
                    sum(1 for _, p in paraphrased if p) / len(paraphrased) if paraphrased else 0.0
                )
                print(f"   {category}: recall={result['recall']} "
                      f"(known-phrasing recall={known_recall:.0%} n={len(known)}, "
                      f"paraphrased recall={paraphrase_recall:.0%} n={len(paraphrased)})")
            else:
                print(f"   {category}: FPR={result['false_positive_rate']} "
                      f"(n={len(cat_examples)}, flagged={sum(1 for p in cat_preds if p)})")


if __name__ == "__main__":
    asyncio.run(main())
