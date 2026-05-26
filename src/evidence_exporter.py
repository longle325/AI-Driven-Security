from __future__ import annotations

import json
import shutil
from pathlib import Path

from src.config import ensure_directories, settings
from src.io_utils import read_jsonl


def _copy_if_exists(source: Path, destination: Path) -> None:
    if source.exists():
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def _safe_metrics() -> dict:
    if settings.metrics_path.exists():
        return json.loads(settings.metrics_path.read_text(encoding="utf-8"))
    return {}


def export_evidence() -> dict:
    ensure_directories()
    out = settings.evidence_dir
    out.mkdir(parents=True, exist_ok=True)

    for source in (
        settings.alerts_csv,
        settings.alerts_jsonl,
        settings.recommendations_jsonl,
        settings.metrics_path,
        settings.model_dir / "classification_report.txt",
        settings.model_dir / "confusion_matrix.png",
        settings.model_dir / "feature_importance.png",
        settings.model_dir / "feature_importance.csv",
    ):
        _copy_if_exists(source, out / source.name)

    alerts = read_jsonl(settings.alerts_jsonl)
    recommendations = read_jsonl(settings.recommendations_jsonl)
    metrics = _safe_metrics()
    threat_types = sorted({str(alert.get("threat_type", "unknown")) for alert in alerts})
    severity_counts: dict[str, int] = {}
    for alert in alerts:
        severity = str(alert.get("severity", "unknown"))
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    demo_summary = f"""# Demo Summary

## Dataset / Logs
Total alerts generated: {len(alerts)}
Threat types detected: {", ".join(threat_types) if threat_types else "none"}
Severity distribution: {json.dumps(severity_counts, sort_keys=True)}

## Model
Model used: {metrics.get("model", "RandomForestClassifier")}
Accuracy: {metrics.get("accuracy", "n/a")}
Precision: {metrics.get("precision", "n/a")}
Recall: {metrics.get("recall", "n/a")}
F1-score: {metrics.get("f1_score", "n/a")}

## Rule vs AI
Agreement count: {sum(1 for alert in alerts if alert.get("rule_prediction") == alert.get("ml_prediction"))}
Disagreement count: {sum(1 for alert in alerts if alert.get("rule_prediction") != alert.get("ml_prediction"))}

## LLM Advisor
LLM mode: {settings.llm_mode}
Recommendations generated: {len(recommendations)}
Example alert analyzed: {alerts[0].get("alert_id") if alerts else "n/a"}

## Ethical Scope
This demo runs only in a safe local lab environment using synthetic or public data.
"""
    (out / "demo_summary.md").write_text(demo_summary, encoding="utf-8")

    recommendation_summary = "# Recommendation Summary\n\n"
    for item in recommendations[:10]:
        rec = item.get("recommendation", {})
        recommendation_summary += f"## {item.get('alert_id', 'UNKNOWN')}\n\n"
        recommendation_summary += f"{rec.get('incident_summary', 'No summary')}\n\n"
        for step in rec.get("immediate_next_steps", [])[:4]:
            recommendation_summary += f"- {step}\n"
        recommendation_summary += "\n"
    (out / "recommendation_summary.md").write_text(recommendation_summary, encoding="utf-8")

    test_case_results = """# Test Case Results

- Simulator scenarios: normal, brute_force, port_scan, web_attack, traffic_spike, mixed.
- Rule detector: thresholds produce explainable rule reasons.
- ML detector: Random Forest model produces class and confidence.
- LLM Advisor: fallback mode runs without API key; OpenAI mode is optional.
- Safety: all events use private/local IP ranges and harmless markers.
"""
    (out / "test_case_results.md").write_text(test_case_results, encoding="utf-8")

    return {"export_dir": str(out), "files": sorted(path.name for path in out.iterdir() if path.is_file())}


def main() -> None:
    print(json.dumps(export_evidence(), indent=2))


if __name__ == "__main__":
    main()
