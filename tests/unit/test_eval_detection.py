"""scripts/eval_detection.py — the harness itself, not a re-check of
detection accuracy (test_char_detection.py already pins that)."""

import json

from scripts.eval_detection import main


async def test_eval_reports_precision_recall_f1_for_every_candidate(tmp_path):
    labeled_set = tmp_path / "labeled_set.json"
    labeled_set.write_text(json.dumps({
        "examples": [
            {"text": "Send Rs 5000 to scammer@okaxis right now to release your refund", "is_scam": True, "category": "upi_fraud"},
            {"text": "hey how are you doing today", "is_scam": False, "category": "greeting"},
        ]
    }))

    results = await main(labeled_set)

    assert len(results) == 3  # rules_only, ml_only, combined
    for result in results:
        assert result["n"] == 2
        assert {"precision", "recall", "f1", "latency_ms_p50", "no_prediction"} <= set(result)
        assert 0.0 <= result["precision"] <= 1.0
        assert 0.0 <= result["recall"] <= 1.0
        assert 0.0 <= result["f1"] <= 1.0


async def test_eval_runs_on_the_committed_labeled_set():
    """task.md's done-when: "the evaluation script runs on a committed
    labeled set." Runs the real ml-models/evaluation/labeled_set.json."""
    from pathlib import Path

    committed_set = Path(__file__).parent.parent.parent / "ml-models" / "evaluation" / "labeled_set.json"
    results = await main(committed_set)

    assert results[0]["n"] == 32
