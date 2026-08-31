"""Train the supervised text classifier (packages/ml/text/supervised.py).

    uv run python scripts/train_supervised_classifier.py

Trains TF-IDF + multinomial logistic regression on
ml-models/evaluation/dev_train_set.json (90 examples, 9 classes) and writes
the fitted pipeline to ml-models/trained/supervised_classifier.joblib plus a
metadata sidecar recording what it was trained on and when.

This is deliberately NOT evaluated here -- ml-models/evaluation/unseen_validation_set.json
is a disjoint set reserved for reporting real metrics (scripts/eval_unseen.py).
Training on 90 examples across 9 classes (as few as 7 per class for some) is
too little data to expect strong generalization; this script exists so the
pipeline is reproducible and inspectable, not to claim the resulting model is
production-ready.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

ROOT = Path(__file__).parent.parent
DEV_SET_PATH = ROOT / "ml-models" / "evaluation" / "dev_train_set.json"
ARTIFACT_DIR = ROOT / "ml-models" / "trained"
ARTIFACT_PATH = ARTIFACT_DIR / "supervised_classifier.joblib"
METADATA_PATH = ARTIFACT_DIR / "supervised_classifier.metadata.json"


def train() -> dict:
    data = json.loads(DEV_SET_PATH.read_text(encoding="utf-8"))
    examples = data["examples"]
    texts = [ex["text"] for ex in examples]
    labels = [ex["label"] for ex in examples]

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True)),
        ("clf", LogisticRegression(max_iter=2000, class_weight="balanced")),
    ])
    pipeline.fit(texts, labels)

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, ARTIFACT_PATH)

    metadata = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "trained_on": str(DEV_SET_PATH.relative_to(ROOT)),
        "n_examples": len(examples),
        "label_counts": dict(Counter(labels)),
        "labels": sorted(set(labels)),
        "model": "TfidfVectorizer(ngram_range=(1,2)) + LogisticRegression(class_weight=balanced)",
        "warning": (
            "Trained on 90 examples across 9 classes (7-18 per class). This is "
            "too little data to claim production-quality generalization -- treat "
            "this as an experimental signal, not a validated classifier. See "
            "scripts/eval_unseen.py's output for the only honest measure of how "
            "well it actually generalizes."
        ),
    }
    METADATA_PATH.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


if __name__ == "__main__":
    meta = train()
    print(f"Trained on {meta['n_examples']} examples, {len(meta['labels'])} classes.")
    print("Label counts:", meta["label_counts"])
    print(f"Artifact: {ARTIFACT_PATH.relative_to(ROOT)}")
