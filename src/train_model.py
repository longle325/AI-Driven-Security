from __future__ import annotations

import json
from datetime import datetime, timezone

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, precision_recall_fscore_support

from lab.simulator.scenarios import generate_events
from src.config import ensure_directories, settings
from src.data_loader import load_many, normalize_dataframe
from src.preprocessing import prepare_training_data
from src.schemas import FEATURE_COLUMNS


def _training_source() -> pd.DataFrame:
    preferred = settings.raw_data_dir / "ids2025_training_sample.csv"
    if preferred.exists():
        return load_many([preferred])

    raw_candidates = sorted(settings.raw_data_dir.glob("*.csv")) + sorted(settings.raw_data_dir.glob("*.jsonl"))
    if raw_candidates:
        return load_many(raw_candidates)

    df = normalize_dataframe(pd.DataFrame(generate_events("mixed", 2400, seed=2026)))
    rng = np.random.default_rng(2026)
    noisy_indexes = rng.choice(df.index.to_numpy(), size=max(1, int(len(df) * 0.055)), replace=False)
    labels = np.array(["normal", "botnet", "brute_force", "dos_ddos", "web_attack", "infiltration"])
    for idx in noisy_indexes:
        current = df.at[idx, "label"]
        choices = labels[labels != current]
        df.at[idx, "label"] = str(rng.choice(choices))
    return df


def _save_confusion_matrix(cm, labels: list[str]) -> None:
    fig, ax = plt.subplots(figsize=(7, 6))
    image = ax.imshow(cm, cmap="YlOrRd")
    ax.set_xticks(range(len(labels)), labels=labels, rotation=35, ha="right")
    ax.set_yticks(range(len(labels)), labels=labels)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title("Threat Classification Confusion Matrix")
    for row in range(cm.shape[0]):
        for col in range(cm.shape[1]):
            ax.text(col, row, str(cm[row, col]), ha="center", va="center", color="#24180f")
    fig.colorbar(image, ax=ax, fraction=0.046, pad=0.04)
    fig.tight_layout()
    fig.savefig(settings.model_dir / "confusion_matrix.png", dpi=160)
    plt.close(fig)


def _save_feature_importance(model: RandomForestClassifier) -> None:
    rows = sorted(
        zip(FEATURE_COLUMNS, model.feature_importances_),
        key=lambda item: item[1],
        reverse=True,
    )
    pd.DataFrame(rows, columns=["feature", "importance"]).to_csv(settings.model_dir / "feature_importance.csv", index=False)

    fig, ax = plt.subplots(figsize=(8, 5))
    features = [row[0] for row in rows]
    values = [row[1] for row in rows]
    ax.barh(features[::-1], values[::-1], color="#d97706")
    ax.set_title("Random Forest Feature Importance")
    ax.set_xlabel("Importance")
    fig.tight_layout()
    fig.savefig(settings.model_dir / "feature_importance.png", dpi=160)
    plt.close(fig)


def train_model() -> dict:
    ensure_directories()
    df = _training_source()
    processed = prepare_training_data(df)
    model = RandomForestClassifier(
        n_estimators=220,
        max_depth=12,
        min_samples_leaf=2,
        random_state=42,
        class_weight="balanced_subsample",
    )
    model.fit(processed.x_train, processed.y_train)
    predictions = model.predict(processed.x_test)

    labels = list(processed.label_encoder.classes_)
    precision, recall, f1, _ = precision_recall_fscore_support(
        processed.y_test,
        predictions,
        average="weighted",
        zero_division=0,
    )
    metrics = {
        "model": "RandomForestClassifier",
        "samples": int(len(df)),
        "labels": labels,
        "dataset": "prantokumar/ids-dataset-2025" if (settings.raw_data_dir / "ids2025_training_sample.csv").exists() else "synthetic_lab",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "accuracy": round(float(accuracy_score(processed.y_test, predictions)), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1_score": round(float(f1), 4),
        "feature_columns": FEATURE_COLUMNS,
    }

    report = classification_report(processed.y_test, predictions, target_names=labels, zero_division=0)
    cm = confusion_matrix(processed.y_test, predictions)

    joblib.dump(model, settings.model_path)
    settings.metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    (settings.model_dir / "classification_report.txt").write_text(report, encoding="utf-8")
    _save_confusion_matrix(cm, labels)
    _save_feature_importance(model)
    return metrics


def main() -> None:
    metrics = train_model()
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
