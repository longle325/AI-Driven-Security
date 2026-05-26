import json
from pathlib import Path

from lab.simulator.scenarios import generate_scenario_events
from src.evidence_exporter import export_evidence


def test_simulator_generates_safe_labeled_events():
    events = generate_scenario_events("web_attack", count=5)

    assert len(events) == 5
    assert {event["label"] for event in events} == {"web_attack"}
    assert all(event["source_ip"].startswith("172.20.") for event in events)
    assert all("SIMULATED_" in event["payload_marker"] for event in events)


def test_export_evidence_creates_report_files(tmp_path: Path):
    logs_dir = tmp_path / "logs"
    models_dir = tmp_path / "models"
    export_dir = tmp_path / "exports"
    logs_dir.mkdir()
    models_dir.mkdir()
    alert = {
        "alert_id": "ALERT-20260526-0001",
        "timestamp": "2026-05-26T10:05:00Z",
        "threat_type": "brute_force",
        "severity": "high",
        "source_ip": "172.20.0.5",
        "endpoint": "/login",
        "recommended_action": "Enable rate limiting.",
    }
    (logs_dir / "alerts.jsonl").write_text(json.dumps(alert) + "\n", encoding="utf-8")
    (models_dir / "metrics.json").write_text(
        json.dumps({"accuracy": 0.9, "macro_f1": 0.88}),
        encoding="utf-8",
    )

    result = export_evidence(logs_dir=logs_dir, models_dir=models_dir, export_dir=export_dir)

    assert (export_dir / "alerts.csv").exists()
    assert (export_dir / "metrics.json").exists()
    assert (export_dir / "demo_summary.md").exists()
    assert result["alert_count"] == 1
