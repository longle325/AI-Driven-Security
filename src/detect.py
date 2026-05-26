from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import joblib
import pandas as pd

from src.alert_manager import combine_results
from src.config import ALERTS_CSV, ALERTS_JSONL, EVENTS_JSONL, MODELS_DIR, ensure_project_dirs
from src.io_utils import read_jsonl, write_csv, write_jsonl
from src.preprocessing import FEATURE_COLUMNS, preprocess_events
from src.rules import detect_rule_threats


def load_model(model_dir: Path = MODELS_DIR) -> Any | None:
    model_path = model_dir / "threat_model.joblib"
    if not model_path.exists():
        return None
    return joblib.load(model_path)


def predict_ml(event: dict[str, Any], model: Any | None = None) -> dict[str, Any]:
    if model is None:
        return {
            "is_threat": False,
            "predicted_label": "normal",
            "confidence": 0.0,
            "top_features": [],
            "detector": "ml_random_forest_unavailable",
        }

    features, _, _ = preprocess_events(pd.DataFrame([event]), include_labels=False)
    predicted_label = str(model.predict(features)[0])
    confidence = 0.0
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(features)[0]
        confidence = float(max(probabilities))

    top_features: list[str] = []
    if hasattr(model, "feature_importances_"):
        pairs = sorted(
            zip(FEATURE_COLUMNS, model.feature_importances_, strict=False),
            key=lambda item: item[1],
            reverse=True,
        )
        top_features = [feature for feature, _ in pairs[:5]]

    return {
        "is_threat": predicted_label != "normal",
        "predicted_label": predicted_label,
        "confidence": round(confidence, 4),
        "top_features": top_features,
        "detector": "ml_random_forest",
    }


def detect_event(
    event: dict[str, Any],
    event_index: int = 0,
    model: Any | None = None,
    log_file: str = "data/logs/events.jsonl",
) -> dict[str, Any]:
    rule_result = detect_rule_threats(event)
    ml_result = predict_ml(event, model=model)

    if not ml_result["is_threat"] and rule_result["is_threat"]:
        ml_result = {
            **ml_result,
            "predicted_label": rule_result["threat_type"],
            "is_threat": True,
            "confidence": 0.55,
        }

    return combine_results(event, rule_result, ml_result, event_index=event_index, log_file=log_file)


def run_detection(
    input_path: Path = EVENTS_JSONL,
    output_path: Path = ALERTS_JSONL,
    model_dir: Path = MODELS_DIR,
) -> list[dict[str, Any]]:
    ensure_project_dirs()
    events = read_jsonl(input_path)
    model = load_model(model_dir)
    alerts: list[dict[str, Any]] = []

    for index, event in enumerate(events):
        alert = detect_event(event, event_index=index, model=model, log_file=str(input_path))
        if alert["severity"] != "informational":
            alerts.append(alert)

    write_jsonl(output_path, alerts)
    csv_path = output_path.with_suffix(".csv")
    write_csv(csv_path, alerts)
    if output_path == ALERTS_JSONL:
        write_csv(ALERTS_CSV, alerts)
    return alerts


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run AI-SOC detection over JSONL events.")
    parser.add_argument("--input", type=Path, default=EVENTS_JSONL)
    parser.add_argument("--output", type=Path, default=ALERTS_JSONL)
    parser.add_argument("--model-dir", type=Path, default=MODELS_DIR)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    alerts = run_detection(args.input, args.output, args.model_dir)
    print(json.dumps({"alerts": len(alerts), "output": str(args.output)}, indent=2))


if __name__ == "__main__":
    main()
