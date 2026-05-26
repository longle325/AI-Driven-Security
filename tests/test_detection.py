import json
from pathlib import Path

from src.detect import run_detection


def test_run_detection_writes_alerts_for_suspicious_events(tmp_path: Path):
    events_path = tmp_path / "events.jsonl"
    alerts_path = tmp_path / "alerts.jsonl"
    event = {
        "timestamp": "2026-05-26T10:00:00Z",
        "source_ip": "172.20.0.5",
        "user_id": "user_01",
        "event_type": "login_failed",
        "endpoint": "/login",
        "http_method": "POST",
        "status_code": 401,
        "request_count_1m": 15,
        "failed_login_count_5m": 9,
        "unique_ports_1m": 1,
        "status_4xx_count_5m": 9,
        "status_5xx_count_5m": 0,
        "payload_risk_score": 0.0,
        "label": "brute_force",
    }
    events_path.write_text(json.dumps(event) + "\n", encoding="utf-8")

    alerts = run_detection(events_path, alerts_path)

    assert len(alerts) == 1
    assert alerts[0]["threat_type"] == "brute_force"
    assert alerts_path.exists()
    assert "recommended_action" in alerts[0]
