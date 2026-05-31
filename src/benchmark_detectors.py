from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.model_selection import train_test_split

from src.config import ensure_directories, settings
from src.data_loader import load_file
from src.feature_engineering import feature_matrix
from src.rules import evaluate_event
from src.train_model import train_model

TAXONOMY = ["botnet", "brute_force", "dos_ddos", "infiltration", "normal", "web_attack"]
DETECTOR_COLORS = {
    "rule_based": "#2563eb",
    "ai_model": "#f59e0b",
}
CHART_ARTIFACTS = [
    ("metric_comparison", "metric comparison", "Metric comparison"),
    ("error_profile", "binary error profile", "Binary error profile"),
    ("latency_comparison", "latency comparison", "Latency comparison"),
    ("normalized_confusion_comparison", "normalized confusion comparison", "Normalized confusion comparison"),
]


def _load_or_train_model():
    if not settings.model_path.exists() or not settings.label_encoder_path.exists():
        train_model()
    return joblib.load(settings.model_path), joblib.load(settings.label_encoder_path)


def _test_split(df: pd.DataFrame, test_size: float, random_state: int) -> pd.DataFrame:
    labels = df["label"].astype(str)
    stratify = labels if labels.nunique() > 1 and labels.value_counts().min() >= 2 else None
    _, test_df = train_test_split(
        df,
        test_size=test_size,
        random_state=random_state,
        stratify=stratify,
    )
    return test_df.reset_index(drop=True)


def _artifact(destination: Path, prefix: str, name: str) -> Path:
    return destination / f"{prefix}_{name}"


def _binary_labels(values: Iterable[str]) -> list[str]:
    return ["normal" if str(value) == "normal" else "threat" for value in values]


def _binary_metrics(y_true: list[str], y_pred: list[str]) -> dict:
    true_binary = _binary_labels(y_true)
    pred_binary = _binary_labels(y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(
        true_binary,
        pred_binary,
        pos_label="threat",
        average="binary",
        zero_division=0,
    )
    false_positives = sum(1 for actual, pred in zip(true_binary, pred_binary) if actual == "normal" and pred == "threat")
    false_negatives = sum(1 for actual, pred in zip(true_binary, pred_binary) if actual == "threat" and pred == "normal")
    true_positives = sum(1 for actual, pred in zip(true_binary, pred_binary) if actual == "threat" and pred == "threat")
    true_negatives = sum(1 for actual, pred in zip(true_binary, pred_binary) if actual == "normal" and pred == "normal")
    return {
        "accuracy": round(float(accuracy_score(true_binary, pred_binary)), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1_score": round(float(f1), 4),
        "true_positives": int(true_positives),
        "true_negatives": int(true_negatives),
        "false_positives": int(false_positives),
        "false_negatives": int(false_negatives),
    }


def _multiclass_metrics(y_true: list[str], y_pred: list[str]) -> dict:
    labels = sorted(set(TAXONOMY).union(y_true).union(y_pred))
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true,
        y_pred,
        labels=labels,
        average="weighted",
        zero_division=0,
    )
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision_weighted": round(float(precision), 4),
        "recall_weighted": round(float(recall), 4),
        "f1_weighted": round(float(f1), 4),
        "labels": labels,
    }


def _save_confusion_matrix(path: Path, y_true: list[str], y_pred: list[str], labels: list[str], title: str) -> None:
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    fig, ax = plt.subplots(figsize=(8, 6))
    image = ax.imshow(cm, cmap="YlOrRd")
    ax.set_xticks(range(len(labels)), labels=labels, rotation=35, ha="right")
    ax.set_yticks(range(len(labels)), labels=labels)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title(title)
    for row in range(cm.shape[0]):
        for col in range(cm.shape[1]):
            ax.text(col, row, str(cm[row, col]), ha="center", va="center", color="#221a10", fontsize=8)
    fig.colorbar(image, ax=ax, fraction=0.046, pad=0.04)
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)


def _annotate_vertical_bars(ax, bars, decimals: int = 3, suffix: str = "") -> None:
    for bar in bars:
        height = bar.get_height()
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            height,
            f"{height:.{decimals}f}{suffix}",
            ha="center",
            va="bottom",
            fontsize=9,
        )


def _annotate_horizontal_bars(ax, bars, decimals: int = 3, suffix: str = "") -> None:
    for bar in bars:
        width = bar.get_width()
        ax.text(
            width,
            bar.get_y() + bar.get_height() / 2,
            f" {width:.{decimals}f}{suffix}",
            va="center",
            fontsize=9,
        )


def _save_metric_comparison(path: Path, rule: dict, ai: dict) -> None:
    groups = [
        ("Binary precision", rule["binary"]["precision"], ai["binary"]["precision"]),
        ("Binary recall", rule["binary"]["recall"], ai["binary"]["recall"]),
        ("Binary F1", rule["binary"]["f1_score"], ai["binary"]["f1_score"]),
        ("Multiclass accuracy", rule["multiclass"]["accuracy"], ai["multiclass"]["accuracy"]),
        ("Multiclass F1", rule["multiclass"]["f1_weighted"], ai["multiclass"]["f1_weighted"]),
    ]
    labels = [item[0] for item in groups]
    rule_values = [item[1] for item in groups]
    ai_values = [item[2] for item in groups]
    x = np.arange(len(labels))
    width = 0.36

    fig, ax = plt.subplots(figsize=(11, 5.8))
    rule_bars = ax.bar(x - width / 2, rule_values, width, label="Rule-based", color=DETECTOR_COLORS["rule_based"])
    ai_bars = ax.bar(x + width / 2, ai_values, width, label="AI model", color=DETECTOR_COLORS["ai_model"])
    ax.set_title("Rule-based vs AI Model: Detection Quality")
    ax.set_ylabel("Score")
    ax.set_ylim(0, 1.08)
    ax.set_xticks(x, labels, rotation=18, ha="right")
    ax.grid(axis="y", alpha=0.25)
    ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.24), ncol=2)
    _annotate_vertical_bars(ax, rule_bars)
    _annotate_vertical_bars(ax, ai_bars)
    fig.tight_layout(rect=(0, 0.08, 1, 1))
    fig.savefig(path, dpi=180, bbox_inches="tight")
    plt.close(fig)


def _save_error_profile(path: Path, rule: dict, ai: dict) -> None:
    labels = ["False positives", "False negatives"]
    rule_values = [rule["binary"]["false_positives"], rule["binary"]["false_negatives"]]
    ai_values = [ai["binary"]["false_positives"], ai["binary"]["false_negatives"]]
    x = np.arange(len(labels))
    width = 0.36

    fig, ax = plt.subplots(figsize=(9, 5.4))
    rule_bars = ax.bar(x - width / 2, rule_values, width, label="Rule-based", color=DETECTOR_COLORS["rule_based"])
    ai_bars = ax.bar(x + width / 2, ai_values, width, label="AI model", color=DETECTOR_COLORS["ai_model"])
    ax.set_title("Binary Detection Error Profile")
    ax.set_ylabel("Logs")
    ax.set_xticks(x, labels)
    ax.grid(axis="y", alpha=0.25)
    ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=2)
    _annotate_vertical_bars(ax, rule_bars, decimals=0)
    _annotate_vertical_bars(ax, ai_bars, decimals=0)
    fig.tight_layout(rect=(0, 0.05, 1, 1))
    fig.savefig(path, dpi=180, bbox_inches="tight")
    plt.close(fig)


def _save_latency_comparison(path: Path, rule: dict, ai: dict) -> None:
    labels = ["Rule-based", "AI model"]
    values = [rule["latency"]["ms_per_log"], ai["latency"]["ms_per_log"]]
    colors = [DETECTOR_COLORS["rule_based"], DETECTOR_COLORS["ai_model"]]

    fig, ax = plt.subplots(figsize=(8.5, 4.8))
    bars = ax.barh(labels, values, color=colors)
    ax.set_title("Inference Latency, Lower Is Better")
    ax.set_xlabel("Milliseconds per log")
    ax.grid(axis="x", alpha=0.25)
    _annotate_horizontal_bars(ax, bars, decimals=6, suffix=" ms")
    fig.tight_layout()
    fig.savefig(path, dpi=180)
    plt.close(fig)


def _save_normalized_confusion_comparison(
    path: Path,
    y_true: list[str],
    rule_predictions: list[str],
    ai_predictions: list[str],
    labels: list[str],
) -> None:
    matrices = [
        ("Rule-based", confusion_matrix(y_true, rule_predictions, labels=labels, normalize="true")),
        ("AI model", confusion_matrix(y_true, ai_predictions, labels=labels, normalize="true")),
    ]
    fig, axes = plt.subplots(1, 2, figsize=(15, 6), sharey=True, constrained_layout=True)
    for ax, (title, matrix) in zip(axes, matrices):
        image = ax.imshow(matrix, cmap="YlGnBu", vmin=0, vmax=1)
        ax.set_title(title)
        ax.set_xlabel("Predicted")
        ax.set_xticks(range(len(labels)), labels=labels, rotation=35, ha="right")
        ax.set_yticks(range(len(labels)), labels=labels)
        for row in range(matrix.shape[0]):
            for col in range(matrix.shape[1]):
                ax.text(col, row, f"{matrix[row, col]:.2f}", ha="center", va="center", fontsize=8)
    axes[0].set_ylabel("Actual")
    fig.suptitle("Normalized Confusion Matrix by Actual Class")
    fig.colorbar(image, ax=axes, fraction=0.025, pad=0.04)
    fig.savefig(path, dpi=180)
    plt.close(fig)


def _detector_summary(name: str, y_true: list[str], y_pred: list[str], elapsed_seconds: float) -> dict:
    return {
        "name": name,
        "binary": _binary_metrics(y_true, y_pred),
        "multiclass": _multiclass_metrics(y_true, y_pred),
        "latency": {
            "total_seconds": round(elapsed_seconds, 6),
            "ms_per_log": round((elapsed_seconds / max(1, len(y_true))) * 1000, 6),
            "logs_per_second": round(len(y_true) / elapsed_seconds, 2) if elapsed_seconds > 0 else None,
        },
    }


def _write_markdown(path: Path, payload: dict) -> None:
    rule = payload["detectors"]["rule_based"]
    ai = payload["detectors"]["ai_model"]
    comparison = payload["comparison"]
    chart_images = "\n\n".join(
        f"![{alt}]({Path(payload['artifacts'][key]).name})"
        for key, _, alt in CHART_ARTIFACTS
    )
    artifact_lines = "\n".join(f"- `{Path(value).name}`" for value in payload["artifacts"].values() if value != str(path))
    text = f"""# Rule-based vs AI Model Benchmark

Generated at: {payload["generated_at"]}

## Dataset

- Dataset: {payload["dataset"]}
- Input file: `{payload["input"]}`
- Evaluation rows: {payload["rows"]}
- Test size: {payload["test_size"]}
- Random state: {payload["random_state"]}
- Labels: {", ".join(payload["labels"])}

## Summary

| Detector | Binary F1 | Binary recall | Binary precision | Multiclass accuracy | Multiclass F1 weighted | ms/log |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule-based | {rule["binary"]["f1_score"]:.4f} | {rule["binary"]["recall"]:.4f} | {rule["binary"]["precision"]:.4f} | {rule["multiclass"]["accuracy"]:.4f} | {rule["multiclass"]["f1_weighted"]:.4f} | {rule["latency"]["ms_per_log"]:.6f} |
| AI model | {ai["binary"]["f1_score"]:.4f} | {ai["binary"]["recall"]:.4f} | {ai["binary"]["precision"]:.4f} | {ai["multiclass"]["accuracy"]:.4f} | {ai["multiclass"]["f1_weighted"]:.4f} | {ai["latency"]["ms_per_log"]:.6f} |

## Decision Notes

- Binary detection checks whether the event is normal or malicious.
- Multiclass detection checks whether the exact IDS2025 attack family is correct.
- Rule-based output can include `suspicious`; that is counted as malicious in binary scoring and as an exact-label miss in multiclass scoring.
- AI model batch inference excludes model load time and measures prediction over the same test rows.

## Error Counts

| Detector | TP | TN | FP | FN |
| --- | ---: | ---: | ---: | ---: |
| Rule-based | {rule["binary"]["true_positives"]} | {rule["binary"]["true_negatives"]} | {rule["binary"]["false_positives"]} | {rule["binary"]["false_negatives"]} |
| AI model | {ai["binary"]["true_positives"]} | {ai["binary"]["true_negatives"]} | {ai["binary"]["false_positives"]} | {ai["binary"]["false_negatives"]} |

## Comparison

- Binary F1 delta, AI minus rule: {comparison["binary_f1_delta_ai_minus_rule"]:.4f}
- Multiclass accuracy delta, AI minus rule: {comparison["multiclass_accuracy_delta_ai_minus_rule"]:.4f}
- Multiclass F1 weighted delta, AI minus rule: {comparison["multiclass_f1_delta_ai_minus_rule"]:.4f}
- Speed ratio, rule ms/log divided by AI ms/log: {comparison["speed_ratio_rule_over_ai"]:.4f}

## Charts

Use the charts in this order for the report/demo: metric comparison for the conclusion, error profile for the trade-off, latency for runtime cost, and normalized confusion matrix for model behavior.

{chart_images}

## Artifacts

{artifact_lines}
"""
    path.write_text(text, encoding="utf-8")


def benchmark_detectors(
    input_path: Path | None = None,
    output_dir: Path | None = None,
    test_size: float = 0.25,
    random_state: int = 42,
) -> dict:
    ensure_directories()
    source = input_path or (settings.raw_data_dir / "ids2025_training_sample.csv")
    destination = output_dir or settings.evidence_dir
    destination.mkdir(parents=True, exist_ok=True)

    df = load_file(source)
    if df.empty:
        raise ValueError(f"No benchmark rows found at {source}")
    test_df = _test_split(df, test_size=test_size, random_state=random_state)
    y_true = test_df["label"].astype(str).tolist()
    prefix = "benchmark"

    rule_start = time.perf_counter()
    rule_decisions = [evaluate_event(row.to_dict()).to_dict() for _, row in test_df.iterrows()]
    rule_elapsed = time.perf_counter() - rule_start
    rule_predictions = [str(item["threat_type"]) for item in rule_decisions]

    model, label_encoder = _load_or_train_model()
    x_test = feature_matrix(test_df)
    ai_start = time.perf_counter()
    probabilities = model.predict_proba(x_test)
    ai_indexes = probabilities.argmax(axis=1)
    ai_predictions = label_encoder.inverse_transform(ai_indexes).astype(str).tolist()
    ai_confidences = probabilities.max(axis=1).tolist()
    ai_elapsed = time.perf_counter() - ai_start

    rule_summary = _detector_summary("rule_based", y_true, rule_predictions, rule_elapsed)
    ai_summary = _detector_summary("ai_model", y_true, ai_predictions, ai_elapsed)
    labels = sorted(set(TAXONOMY).union(rule_predictions).union(ai_predictions))

    prediction_rows = test_df.copy()
    prediction_rows["actual_label"] = y_true
    prediction_rows["rule_prediction"] = rule_predictions
    prediction_rows["rule_id"] = [str(item["rule_id"]) for item in rule_decisions]
    prediction_rows["rule_reason"] = [str(item["reason"]) for item in rule_decisions]
    prediction_rows["ai_prediction"] = ai_predictions
    prediction_rows["ai_confidence"] = [round(float(value), 6) for value in ai_confidences]
    prediction_rows.to_csv(_artifact(destination, prefix, "predictions.csv"), index=False)

    (_artifact(destination, prefix, "rule_classification_report.txt")).write_text(
        classification_report(y_true, rule_predictions, labels=labels, zero_division=0),
        encoding="utf-8",
    )
    (_artifact(destination, prefix, "ai_classification_report.txt")).write_text(
        classification_report(y_true, ai_predictions, labels=labels, zero_division=0),
        encoding="utf-8",
    )
    _save_confusion_matrix(
        _artifact(destination, prefix, "rule_confusion_matrix.png"),
        y_true,
        rule_predictions,
        labels,
        "Rule-based IDS2025 Confusion Matrix",
    )
    _save_confusion_matrix(
        _artifact(destination, prefix, "ai_confusion_matrix.png"),
        y_true,
        ai_predictions,
        labels,
        "AI Model IDS2025 Confusion Matrix",
    )
    _save_metric_comparison(_artifact(destination, prefix, "metric_comparison.png"), rule_summary, ai_summary)
    _save_error_profile(_artifact(destination, prefix, "error_profile.png"), rule_summary, ai_summary)
    _save_latency_comparison(_artifact(destination, prefix, "latency_comparison.png"), rule_summary, ai_summary)
    _save_normalized_confusion_comparison(
        _artifact(destination, prefix, "normalized_confusion_comparison.png"),
        y_true,
        rule_predictions,
        ai_predictions,
        labels,
    )

    rule_ms = rule_summary["latency"]["ms_per_log"]
    ai_ms = ai_summary["latency"]["ms_per_log"]
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": "prantokumar/ids-dataset-2025",
        "input": str(source),
        "rows": int(len(test_df)),
        "test_size": test_size,
        "random_state": random_state,
        "labels": sorted(set(y_true)),
        "detectors": {
            "rule_based": rule_summary,
            "ai_model": ai_summary,
        },
        "comparison": {
            "binary_f1_delta_ai_minus_rule": round(
                ai_summary["binary"]["f1_score"] - rule_summary["binary"]["f1_score"],
                4,
            ),
            "multiclass_accuracy_delta_ai_minus_rule": round(
                ai_summary["multiclass"]["accuracy"] - rule_summary["multiclass"]["accuracy"],
                4,
            ),
            "multiclass_f1_delta_ai_minus_rule": round(
                ai_summary["multiclass"]["f1_weighted"] - rule_summary["multiclass"]["f1_weighted"],
                4,
            ),
            "speed_ratio_rule_over_ai": round(rule_ms / ai_ms, 4) if ai_ms else None,
        },
        "artifacts": {
            "summary": str(_artifact(destination, prefix, "summary.md")),
            "metrics": str(_artifact(destination, prefix, "metrics.json")),
            "predictions": str(_artifact(destination, prefix, "predictions.csv")),
            "rule_report": str(_artifact(destination, prefix, "rule_classification_report.txt")),
            "ai_report": str(_artifact(destination, prefix, "ai_classification_report.txt")),
            "rule_confusion_matrix": str(_artifact(destination, prefix, "rule_confusion_matrix.png")),
            "ai_confusion_matrix": str(_artifact(destination, prefix, "ai_confusion_matrix.png")),
            "metric_comparison": str(_artifact(destination, prefix, "metric_comparison.png")),
            "error_profile": str(_artifact(destination, prefix, "error_profile.png")),
            "latency_comparison": str(_artifact(destination, prefix, "latency_comparison.png")),
            "normalized_confusion_comparison": str(_artifact(destination, prefix, "normalized_confusion_comparison.png")),
        },
    }

    Path(payload["artifacts"]["metrics"]).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    _write_markdown(Path(payload["artifacts"]["summary"]), payload)
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark rule-based and AI detectors on IDS2025.")
    parser.add_argument("--input", type=Path, default=settings.raw_data_dir / "ids2025_training_sample.csv")
    parser.add_argument("--output-dir", type=Path, default=settings.evidence_dir)
    parser.add_argument("--test-size", type=float, default=0.25)
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()
    result = benchmark_detectors(args.input, args.output_dir, args.test_size, args.random_state)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
