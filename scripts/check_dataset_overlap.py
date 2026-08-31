"""Verify zero exact-text overlap between the new Phase 9 dev/validation
corpus and every frozen/regression set. Run before trusting any Phase 9
number -- a hit here would mean the "unseen" set isn't unseen anymore.

    uv run python scripts/check_dataset_overlap.py
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

ROOT = Path(__file__).parent.parent
EVAL_DIR = ROOT / "ml-models" / "evaluation"


def _texts_from_json(path: Path) -> set[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return {ex["text"] for ex in data["examples"]}


def _string_literals_from_py(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    literals: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) > 20:
            literals.add(node.value)
    return literals


def main() -> None:
    new_train = _texts_from_json(EVAL_DIR / "dev_train_set_v2.json")
    new_val = _texts_from_json(EVAL_DIR / "threshold_validation_set.json")
    new_all = new_train | new_val

    frozen_sets = {
        "unseen_validation_set.json": _texts_from_json(EVAL_DIR / "unseen_validation_set.json"),
        "labeled_set.json": _texts_from_json(EVAL_DIR / "labeled_set.json"),
        "dev_train_set.json (v1, superseded)": _texts_from_json(EVAL_DIR / "dev_train_set.json"),
    }
    frozen_sets["test_scam_regression.py literals"] = _string_literals_from_py(
        ROOT / "tests" / "unit" / "test_scam_regression.py"
    )
    frozen_sets["behavioral_signals.py literals"] = _string_literals_from_py(
        ROOT / "packages" / "domain" / "risk" / "behavioral_signals.py"
    )

    any_overlap = False
    for name, frozen_texts in frozen_sets.items():
        overlap = new_all & frozen_texts
        if overlap:
            any_overlap = True
            print(f"OVERLAP with {name}: {len(overlap)} example(s)")
            for text in list(overlap):
                print(f"  - {text[:100]!r}")
        else:
            print(f"OK: zero overlap with {name} ({len(frozen_texts)} texts checked)")

    train_val_overlap = new_train & new_val
    if train_val_overlap:
        any_overlap = True
        print(f"OVERLAP between dev_train_set_v2 and threshold_validation_set: {len(train_val_overlap)}")
    else:
        print("OK: zero overlap between dev_train_set_v2 and threshold_validation_set")

    print("\nRESULT:", "FAIL -- overlap found" if any_overlap else "PASS -- all sets disjoint")
    raise SystemExit(1 if any_overlap else 0)


if __name__ == "__main__":
    main()
