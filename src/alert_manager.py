from __future__ import annotations

from src.schemas import RECOMMENDED_ACTIONS

SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _num(event: dict | None, key: str) -> float:
    if not event:
        return 0.0
    try:
        return float(event.get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0.0


def _extreme_signal(event: dict | None, threat_type: str) -> bool:
    if threat_type == "botnet":
        return _num(event, "payload_risk_score") >= 0.55 and _num(event, "avg_request_interval") <= 1.0
    if threat_type == "brute_force":
        return _num(event, "failed_login_count_5m") >= 38
    if threat_type == "port_scan":
        return _num(event, "unique_ports_1m") >= 80
    if threat_type == "web_attack":
        return _num(event, "payload_risk_score") >= 0.96
    if threat_type in {"dos_ddos", "traffic_spike"}:
        return _num(event, "request_count_1m") >= 380 or _num(event, "status_5xx_count_5m") >= 25
    if threat_type == "infiltration":
        return _num(event, "endpoint_risk_score") >= 0.9 and _num(event, "unique_ports_1m") >= 20
    return False


def choose_severity(rule_result: dict, ml_prediction: str, ml_confidence: float, event: dict | None = None) -> str:
    rule_threat = bool(rule_result.get("is_threat"))
    rule_type = rule_result.get("threat_type", "normal")

    if rule_threat and rule_type == ml_prediction and ml_confidence >= 0.90 and _extreme_signal(event, ml_prediction):
        return "critical"
    if rule_threat and rule_type == ml_prediction and ml_confidence >= 0.70:
        return "high"
    if rule_threat and ml_confidence >= 0.78:
        return "high"
    if ml_prediction != "normal" and ml_confidence >= 0.82:
        return "high"
    if rule_threat or (ml_prediction != "normal" and ml_confidence >= 0.58):
        return "medium"
    if ml_prediction != "normal":
        return "low"
    return "informational"


def choose_threat(rule_result: dict, ml_prediction: str, ml_confidence: float) -> str:
    rule_type = rule_result.get("threat_type", "normal")
    if rule_result.get("is_threat") and rule_type != "suspicious":
        return str(rule_type)
    if ml_prediction != "normal" and ml_confidence >= 0.72:
        return ml_prediction
    if rule_result.get("is_threat"):
        return str(rule_type)
    return "normal"


def build_alert(
    index: int,
    event: dict,
    rule_result: dict,
    ml_prediction: str,
    ml_confidence: float,
    evidence_ref: str,
) -> dict | None:
    threat_type = choose_threat(rule_result, ml_prediction, ml_confidence)
    if threat_type == "normal":
        return None
    severity = choose_severity(rule_result, ml_prediction, ml_confidence, event)

    important_features = {
        key: event.get(key)
        for key in (
            "request_count_1m",
            "failed_login_count_5m",
            "unique_ports_1m",
            "status_4xx_count_5m",
            "status_5xx_count_5m",
            "payload_risk_score",
            "endpoint_risk_score",
        )
    }

    return {
        "alert_id": f"ALERT-{index:04d}",
        "timestamp": event.get("timestamp"),
        "source_ip": event.get("source_ip"),
        "user_id": event.get("user_id", ""),
        "endpoint": event.get("endpoint"),
        "event_type": event.get("event_type"),
        "threat_type": threat_type,
        "severity": severity,
        "rule_prediction": rule_result.get("threat_type", "normal"),
        "rule_reason": rule_result.get("reason", ""),
        "rule_id": rule_result.get("rule_id", "NONE"),
        "ml_prediction": ml_prediction,
        "ml_confidence": round(float(ml_confidence), 4),
        "recommended_action": RECOMMENDED_ACTIONS.get(threat_type, RECOMMENDED_ACTIONS["suspicious"]),
        "evidence_ref": evidence_ref,
        "important_features": important_features,
    }


def severity_counts(alerts: list[dict]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for alert in alerts:
        counts[str(alert.get("severity", "informational")).lower()] = counts.get(str(alert.get("severity", "informational")).lower(), 0) + 1
    return counts
