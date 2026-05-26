from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

import pandas as pd

from src.config import EXPORT_DIR, LOGS_DIR, MODELS_DIR, ensure_project_dirs
from src.io_utils import read_jsonl, write_csv, write_jsonl


def _copy_if_exists(source: Path, destination: Path) -> None:
    if source.exists():
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def export_evidence(
    logs_dir: Path = LOGS_DIR,
    models_dir: Path = MODELS_DIR,
    export_dir: Path = EXPORT_DIR,
) -> dict[str, Any]:
    ensure_project_dirs()
    export_dir.mkdir(parents=True, exist_ok=True)

    alerts = read_jsonl(logs_dir / "alerts.jsonl")
    write_jsonl(export_dir / "alerts.jsonl", alerts)
    write_csv(export_dir / "alerts.csv", alerts)

    metrics_path = models_dir / "metrics.json"
    metrics = json.loads(metrics_path.read_text(encoding="utf-8")) if metrics_path.exists() else {}
    (export_dir / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    _copy_if_exists(models_dir / "classification_report.txt", export_dir / "classification_report.txt")
    _copy_if_exists(models_dir / "confusion_matrix.png", export_dir / "confusion_matrix.png")
    _copy_if_exists(models_dir / "feature_importance.csv", export_dir / "feature_importance.csv")

    alert_frame = pd.DataFrame(alerts)
    threat_types = sorted(alert_frame["threat_type"].dropna().unique().tolist()) if not alert_frame.empty else []
    test_case_results = """# Test Case Results

| TC ID | Scenario | Expected Result | Evidence |
|---|---|---|---|
| TC01 | Normal traffic | No critical alert | events.jsonl |
| TC02 | Port scan | Port scan alert | alerts.csv |
| TC03 | Brute force | Brute force alert | alerts.csv |
| TC04 | Web attack | Web attack alert | alerts.csv |
| TC05 | Traffic spike | Traffic spike alert | alerts.csv |
| TC06 | False positive case | Documented low/medium result | demo_summary.md |
| TC07 | False negative case | Documented limitation | demo_summary.md |
"""
    (export_dir / "test_case_results.md").write_text(test_case_results, encoding="utf-8")

    summary = f"""# Demo Summary

- Events file: `{logs_dir / "events.jsonl"}`
- Number of alerts: {len(alerts)}
- Threat types detected: {", ".join(threat_types) if threat_types else "none"}
- Best model: Random Forest classifier
- Accuracy: {metrics.get("accuracy", "not trained")}
- Macro F1-score: {metrics.get("macro_f1", "not trained")}
- Key screenshots to capture manually: Overview page, Live Alerts page, Model Metrics page, Evidence Export page.
- Ethical scope: local lab only, synthetic data only, no external target scanning or exploitation.
"""
    (export_dir / "demo_summary.md").write_text(summary, encoding="utf-8")
    return {
        "alert_count": len(alerts),
        "threat_types": threat_types,
        "export_dir": str(export_dir),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Export report-ready evidence artifacts.")
    parser.add_argument("--logs-dir", type=Path, default=LOGS_DIR)
    parser.add_argument("--models-dir", type=Path, default=MODELS_DIR)
    parser.add_argument("--export-dir", type=Path, default=EXPORT_DIR)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    result = export_evidence(args.logs_dir, args.models_dir, args.export_dir)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
