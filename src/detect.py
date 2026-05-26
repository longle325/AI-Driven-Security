from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import pandas as pd

from src.alert_manager import build_alert
from src.config import ensure_directories, settings
from src.data_loader import load_file, normalize_dataframe
from src.feature_engineering import feature_matrix
from src.io_utils import write_jsonl
from src.rules import evaluate_event
from src.train_model import train_model


def _load_model_assets():
    if not settings.model_path.exists() or not settings.label_encoder_path.exists():
        train_model()
    model = joblib.load(settings.model_path)
    label_encoder = joblib.load(settings.label_encoder_path)
    return model, label_encoder


def detect_event(event: dict, alert_index: int = 1, evidence_ref: str = "stream") -> dict:
    model, label_encoder = _load_model_assets()
    df = normalize_dataframe(pd.DataFrame([event]))
    row = df.iloc[0].to_dict()
    probabilities = model.predict_proba(feature_matrix(df))
    class_index = probabilities.argmax(axis=1)[0]
    ml_prediction = str(label_encoder.inverse_transform([class_index])[0])
    ml_confidence = float(probabilities.max(axis=1)[0])
    rule_result = evaluate_event(row).to_dict()
    detected = {
        **row,
        "rule_prediction": rule_result["threat_type"],
        "rule_reason": rule_result["reason"],
        "rule_id": rule_result["rule_id"],
        "ml_prediction": ml_prediction,
        "ml_confidence": round(ml_confidence, 4),
        "evidence_ref": evidence_ref,
    }
    alert = build_alert(alert_index, row, rule_result, ml_prediction, ml_confidence, evidence_ref)
    return {"detected": detected, "alert": alert}


def run_detection(input_path: Path | None = None, output_path: Path | None = None) -> dict:
    ensure_directories()
    input_file = input_path or settings.events_jsonl
    df = normalize_dataframe(load_file(input_file))
    if df.empty:
        return {"events": 0, "alerts": 0, "message": f"No input logs found at {input_file}"}

    model, label_encoder = _load_model_assets()
    probabilities = model.predict_proba(feature_matrix(df))
    class_indexes = probabilities.argmax(axis=1)
    ml_predictions = label_encoder.inverse_transform(class_indexes)
    ml_confidences = probabilities.max(axis=1)

    detected_rows: list[dict] = []
    alerts: list[dict] = []
    alert_index = 1

    for row_index, (_, row) in enumerate(df.iterrows(), start=1):
        event = row.to_dict()
        rule_result = evaluate_event(event).to_dict()
        ml_prediction = str(ml_predictions[row_index - 1])
        ml_confidence = float(ml_confidences[row_index - 1])
        detected = {
            **event,
            "rule_prediction": rule_result["threat_type"],
            "rule_reason": rule_result["reason"],
            "rule_id": rule_result["rule_id"],
            "ml_prediction": ml_prediction,
            "ml_confidence": round(ml_confidence, 4),
            "evidence_ref": f"{input_file}:{row_index}",
        }
        detected_rows.append(detected)

        alert = build_alert(alert_index, event, rule_result, ml_prediction, ml_confidence, f"{input_file}:{row_index}")
        if alert:
            alerts.append(alert)
            alert_index += 1

    pd.DataFrame(detected_rows).to_csv(settings.detected_logs_csv, index=False)
    pd.DataFrame(alerts).to_csv(settings.alerts_csv, index=False)
    write_jsonl(settings.alerts_jsonl, alerts)

    if output_path:
        if output_path.suffix.lower() == ".jsonl":
            write_jsonl(output_path, alerts)
        elif output_path.suffix.lower() == ".csv":
            pd.DataFrame(alerts).to_csv(output_path, index=False)

    return {
        "events": len(detected_rows),
        "alerts": len(alerts),
        "input": str(input_file),
        "detected_logs": str(settings.detected_logs_csv),
        "alerts_csv": str(settings.alerts_csv),
        "alerts_jsonl": str(settings.alerts_jsonl),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run rule-based and ML detection over lab logs.")
    parser.add_argument("--input", type=Path, default=settings.events_jsonl)
    parser.add_argument("--output", type=Path, default=settings.alerts_jsonl)
    args = parser.parse_args()
    result = run_detection(args.input, args.output)
    print(result)


if __name__ == "__main__":
    main()
