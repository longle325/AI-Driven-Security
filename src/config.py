from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
LOGS_DIR = DATA_DIR / "logs"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
EVIDENCE_DIR = DATA_DIR / "evidence"
EXPORT_DIR = EVIDENCE_DIR / "exports"
SCREENSHOT_DIR = EVIDENCE_DIR / "screenshots"
METRICS_EXPORT_DIR = EVIDENCE_DIR / "metrics"
MODELS_DIR = PROJECT_ROOT / "models"

EVENTS_JSONL = LOGS_DIR / "events.jsonl"
ALERTS_JSONL = LOGS_DIR / "alerts.jsonl"
ALERTS_CSV = LOGS_DIR / "alerts.csv"

LABELS = ["normal", "port_scan", "brute_force", "web_attack", "traffic_spike"]

RULE_THRESHOLDS = {
    "failed_login_count_5m": 5,
    "unique_ports_1m": 8,
    "request_count_1m": 80,
    "status_error_count_5m": 10,
    "admin_failure_count_5m": 3,
    "payload_risk_score": 0.7,
}

RECOMMENDED_ACTIONS = {
    "port_scan": "Restrict exposed services, review firewall rules, and monitor repeated scanning sources.",
    "brute_force": "Enable rate limiting, account lockout, MFA, and stronger authentication logging.",
    "web_attack": "Validate inputs, use parameterized queries, output encoding, and WAF-style rules.",
    "traffic_spike": "Apply rate limiting, autoscaling, queueing, and a DDoS protection strategy.",
    "normal": "No action required. Continue monitoring.",
}


def ensure_project_dirs() -> None:
    for path in [
        LOGS_DIR,
        RAW_DIR,
        PROCESSED_DIR,
        EXPORT_DIR,
        SCREENSHOT_DIR,
        METRICS_EXPORT_DIR,
        MODELS_DIR,
    ]:
        path.mkdir(parents=True, exist_ok=True)
