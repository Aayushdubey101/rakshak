"""Benchmark detection candidates against the labeled evaluation set.

    uv run python scripts/eval_detection.py [path/to/labeled_set.json]

Reports precision, recall, F1, and per-item latency for three candidates,
per this session's detection audit item 12 ("compare ML-only vs rules-only
vs combined"):

  - `rules_only`: the pre-audit keyword/intelligence scoring alone (what
    `pattern_based_detection()` computed before behavioral-signal fusion was
    added) -- no notion of "this sentence is asking for a secret".
  - `ml_only`: `packages/ml/text/score()` directly. In this environment
    (`HF_LITE_MODE=true`, no torch/transformers installed) this always
    returns `None` -- see docs/ml/phase8-evaluation.md for why no ML
    candidate has ever been benchmarked here. Reported as "no prediction"
    rather than silently coerced to "not scam", so a 0.0 recall here reads
    as "absent", not "measured and failing".
  - `combined`: `scam_detector.analyze()` as it exists today -- rules +
    behavioral signals (+ ML/LLM when configured, absent in this environment).
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Awaitable, Callable, Optional

Candidate = Callable[[str], Awaitable[Optional[bool]]]


async def _rules_only(text: str) -> bool:
    """Keyword + intelligence-extractor scoring alone, bypassing
    `behavioral_signals` entirely -- reproduces the exact logic
    `pattern_based_detection()` used before this audit's fix, so its recall
    on the new credential/MFA examples shows what the behavioral-signal
    layer actually added."""
    from packages.domain.entities import intelligence_extractor
    from packages.domain.risk.detector import calculate_risk_score

    intelligence = intelligence_extractor.get_scam_score(text)
    risk_result = calculate_risk_score(text)
    risk_score = risk_result["score"]
    combined_score = (risk_score * 0.7) + (intelligence["score"] * 0.3)
    confidence = min(combined_score / 100.0, 1.0)
    return (
        risk_score >= 18
        or len(risk_result["signals"]) >= 2
        or confidence > 0.30
        or bool(intelligence["intelligence"].get("phishingLinks"))
    )


async def _ml_only(text: str) -> Optional[bool]:
    from packages.ml import text as ml_text
    from packages.ml.model_registry import TEXT_SPAM_MODEL

    signal = await ml_text.score(text)
    if signal is None:
        return None
    return signal.score > TEXT_SPAM_MODEL.threshold


async def _combined(text: str) -> bool:
    from packages.domain.risk import detector

    result = await detector.analyze(text)
    return bool(result["isScam"])


CANDIDATES: dict[str, Candidate] = {
    "rules_only": _rules_only,
    "ml_only": _ml_only,
    "combined": _combined,
}


def _load_examples(path: Path) -> list[dict]:
    data = json.loads(path.read_text())
    return data["examples"]


async def _evaluate(name: str, candidate: Candidate, examples: list[dict]) -> dict:
    tp = fp = tn = fn = no_prediction = 0
    latencies_ms: list[float] = []

    for example in examples:
        started = time.perf_counter()
        predicted = await candidate(example["text"])
        latencies_ms.append((time.perf_counter() - started) * 1000)

        if predicted is None:
            no_prediction += 1
            continue

        actual = example["is_scam"]
        if predicted and actual:
            tp += 1
        elif predicted and not actual:
            fp += 1
        elif not predicted and not actual:
            tn += 1
        else:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    latencies_ms.sort()
    p50 = latencies_ms[len(latencies_ms) // 2] if latencies_ms else 0.0

    return {
        "candidate": name, "n": len(examples),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn, "no_prediction": no_prediction,
        "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
        "latency_ms_p50": round(p50, 2),
        "latency_ms_mean": round(sum(latencies_ms) / len(latencies_ms), 2) if latencies_ms else 0.0,
    }


async def main(labeled_set_path: Path) -> list[dict]:
    examples = _load_examples(labeled_set_path)
    results = [await _evaluate(name, candidate, examples) for name, candidate in CANDIDATES.items()]

    for result in results:
        print(
            f"{result['candidate']}: precision={result['precision']} recall={result['recall']} "
            f"f1={result['f1']} latency_p50={result['latency_ms_p50']}ms "
            f"(n={result['n']}, tp={result['tp']} fp={result['fp']} tn={result['tn']} fn={result['fn']} "
            f"no_prediction={result['no_prediction']})"
        )
    return results


if __name__ == "__main__":
    default_path = Path(__file__).parent.parent / "ml-models" / "evaluation" / "labeled_set.json"
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else default_path
    asyncio.run(main(path))
