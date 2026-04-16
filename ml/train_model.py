from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "dataset.csv"
MODEL_PATH = BASE_DIR.parent / "backend" / "artifacts" / "model.pkl"

FEATURE_COLUMNS = [
    "connect_rate",
    "message_rate",
    "topic_count",
    "avg_payload_size",
    "failed_auth_count",
]


def main() -> None:
    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found at {DATASET_PATH}. Run gen_dataset.py first."
        )

    frame = pd.read_csv(DATASET_PATH)
    X = frame[FEATURE_COLUMNS]
    y = frame["attack_type"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,
        min_samples_split=4,
        random_state=42,
    )
    model.fit(X_train, y_train)

    preds = model.predict(X_test)
    acc = accuracy_score(y_test, preds)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)

    print(f"Saved model to {MODEL_PATH}")
    print(f"Accuracy: {acc:.4f}")
    print(classification_report(y_test, preds))


if __name__ == "__main__":
    main()
