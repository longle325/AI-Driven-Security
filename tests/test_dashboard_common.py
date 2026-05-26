from pathlib import Path

from dashboard.common import compute_soc_metrics, load_jsonl_frame


def test_dashboard_common_loads_missing_jsonl_as_empty_frame(tmp_path: Path):
    frame = load_jsonl_frame(tmp_path / "missing.jsonl")

    assert frame.empty


def test_compute_soc_metrics_distinguishes_event_alerts_from_incidents():
    import pandas as pd

    events = pd.DataFrame(
        [
            {"source_ip": "172.20.0.5", "label": "normal"},
            {"source_ip": "172.20.0.5", "label": "brute_force"},
            {"source_ip": "172.20.0.6", "label": "normal"},
        ]
    )
    alerts = pd.DataFrame(
        [
            {"source_ip": "172.20.0.5", "threat_type": "brute_force", "severity": "high"},
            {"source_ip": "172.20.0.5", "threat_type": "brute_force", "severity": "high"},
        ]
    )

    metrics = compute_soc_metrics(events, alerts, {"macro_f1": 0.91})

    assert metrics["event_count"] == 3
    assert metrics["alert_count"] == 2
    assert metrics["incident_count"] == 1
    assert metrics["normal_ratio"] == 2 / 3
