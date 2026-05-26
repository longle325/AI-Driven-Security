from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
from sklearn.metrics import ConfusionMatrixDisplay

from src.config import MODELS_DIR


def save_confusion_matrix(y_true, y_pred, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(8, 6))
    ConfusionMatrixDisplay.from_predictions(y_true, y_pred, ax=ax, xticks_rotation=35)
    fig.tight_layout()
    fig.savefig(output_path, dpi=160)
    plt.close(fig)


def save_feature_importance(model, feature_names: list[str], output_path: Path) -> None:
    if not hasattr(model, "feature_importances_"):
        pd.DataFrame(columns=["feature", "importance"]).to_csv(output_path, index=False)
        return
    importance = pd.DataFrame(
        {
            "feature": feature_names,
            "importance": model.feature_importances_,
        }
    ).sort_values("importance", ascending=False)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    importance.to_csv(output_path, index=False)


def load_metrics(model_dir: Path = MODELS_DIR) -> dict:
    metrics_path = model_dir / "metrics.json"
    if not metrics_path.exists():
        return {}
    return json.loads(metrics_path.read_text(encoding="utf-8"))


def main() -> None:
    metrics = load_metrics()
    if metrics:
        print(json.dumps(metrics, indent=2))
    else:
        print("No metrics found. Run `python -m src.train_model` first.")


if __name__ == "__main__":
    main()
