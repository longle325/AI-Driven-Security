from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from src.config import RECOMMENDED_ACTIONS


def recommended_action_for(threat_type: str) -> str:
    return RECOMMENDED_ACTIONS.get(threat_type, RECOMMENDED_ACTIONS["normal"])


def _timestamp_token(timestamp: str | None) -> str:
    if not timestamp:
        return datetime.now(tz=UTC).strftime("%Y%m%d")
    try:
        clean = timestamp.replace("Z", "+00:00")
        return datetime.fromisoformat(clean).strftime("%Y%m%d")
    except ValueError:
        return datetime.now(tz=UTC).strftime("%Y%m%d")


def _number(event: dict[str, Any], key: str, default: float = 0.0) -> float:
    try:
        return float(event.get(key, default) or default)
    except (TypeError, ValueError):
        return default


def _has_strong_confirmed_signal(event: dict[str, Any], threat_type: str) -> bool:
    if threat_type == "brute_force":
        return _number(event, "failed_login_count_5m") >= 12
    if threat_type == "port_scan":
        return _number(event, "unique_ports_1m") >= 18
    if threat_type == "traffic_spike":
        return _number(event, "request_count_1m") >= 150 or _number(event, "status_5xx_count_5m") >= 4
    if threat_type == "web_attack":
        return _number(event, "payload_risk_score") >= 0.9 or (
            event.get("endpoint") == "/admin" and _number(event, "status_4xx_count_5m") >= 4
        )
    return False


def map_severity(
    rule_result: dict[str, Any],
    ml_result: dict[str, Any],
    event: dict[str, Any] | None = None,
) -> str:
    ml_confidence = float(ml_result.get("confidence", 0.0) or 0.0)
    rule_threat = bool(rule_result.get("is_threat"))
    ml_threat = bool(ml_result.get("is_threat"))
    threat_type = str(rule_result.get("threat_type") or ml_result.get("predicted_label") or "normal")

    if rule_threat and ml_threat and ml_confidence >= 0.9 and _has_strong_confirmed_signal(event or {}, threat_type):
        return "critical"
    if rule_result.get("severity") in {"critical", "high"} or (ml_threat and ml_confidence >= 0.85):
        return "high"
    if rule_threat or (ml_threat and ml_confidence >= 0.6):
        return "medium"
    if ml_threat:
        return "low"
    return "informational"


def combine_results(
    event: dict[str, Any],
    rule_result: dict[str, Any],
    ml_result: dict[str, Any],
    event_index: int,
    log_file: str = "data/logs/events.jsonl",
) -> dict[str, Any]:
    severity = map_severity(rule_result, ml_result, event)
    if rule_result.get("is_threat"):
        threat_type = str(rule_result.get("threat_type", "normal"))
    elif ml_result.get("is_threat"):
        threat_type = str(ml_result.get("predicted_label", "normal"))
    else:
        threat_type = "normal"

    timestamp = str(event.get("timestamp") or datetime.now(tz=UTC).isoformat())
    return {
        "alert_id": f"ALERT-{_timestamp_token(timestamp)}-{event_index + 1:04d}",
        "timestamp": timestamp,
        "threat_type": threat_type,
        "severity": severity,
        "source_ip": event.get("source_ip", "unknown"),
        "endpoint": event.get("endpoint", "unknown"),
        "rule_result": rule_result,
        "ml_result": ml_result,
        "recommended_action": recommended_action_for(threat_type),
        "evidence": {
            "log_file": log_file,
            "event_index": event_index,
        },
    }
