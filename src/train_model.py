from __future__ import annotations

import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from lab.simulator.scenarios import generate_training_events
from src.config import MODELS_DIR, PROCESSED_DIR, ensure_project_dirs
from src.evaluate_model import save_confusion_matrix, save_feature_importance
from src.preprocessing import preprocess_events


def train_model(model_dir: Path = MODELS_DIR) -> dict[str, float]:
    ensure_project_dirs()
    events = generate_training_events()
    raw_path = PROCESSED_DIR / "synthetic_training_data.csv"
    pd.DataFrame(events).to_csv(raw_path, index=False)

    features, labels, _ = preprocess_events(events, include_labels=True)
    x_train, x_test, y_train, y_test = train_test_split(
        features,
        labels,
        test_size=0.25,
        random_state=42,
        stratify=labels,
    )

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        random_state=42,
        class_weight="balanced",
    )
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)

    metrics = {
        "accuracy": round(float(accuracy_score(y_test, predictions)), 4),
        "precision_macro": round(float(precision_score(y_test, predictions, average="macro", zero_division=0)), 4),
        "recall_macro": round(float(recall_score(y_test, predictions, average="macro", zero_division=0)), 4),
        "macro_f1": round(float(f1_score(y_test, predictions, average="macro", zero_division=0)), 4),
        "training_rows": int(len(features)),
        "test_rows": int(len(x_test)),
    }

    model_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_dir / "threat_model.joblib")
    (model_dir / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    (model_dir / "classification_report.txt").write_text(
        classification_report(y_test, predictions, zero_division=0),
        encoding="utf-8",
    )
    save_confusion_matrix(y_test, predictions, model_dir / "confusion_matrix.png")
    save_feature_importance(model, features.columns.tolist(), model_dir / "feature_importance.csv")
    return metrics


def main() -> None:
    metrics = train_model()
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
