from __future__ import annotations

from typing import Any

from src.config import RULE_THRESHOLDS


SEVERITY_RANK = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _number(event: dict[str, Any], key: str, default: float = 0.0) -> float:
    try:
        return float(event.get(key, default) or default)
    except (TypeError, ValueError):
        return default


def detect_rule_threats(event: dict[str, Any]) -> dict[str, Any]:
    matches: list[dict[str, str]] = []

    if _number(event, "failed_login_count_5m") >= RULE_THRESHOLDS["failed_login_count_5m"]:
        matches.append(
            {
                "rule_id": "R001",
                "threat_type": "brute_force",
                "severity": "high",
                "reason": "failed_login_count_5m exceeded threshold",
            }
        )

    if _number(event, "unique_ports_1m") >= RULE_THRESHOLDS["unique_ports_1m"]:
        matches.append(
            {
                "rule_id": "R002",
                "threat_type": "port_scan",
                "severity": "high",
                "reason": "unique_ports_1m exceeded threshold",
            }
        )

    if _number(event, "request_count_1m") >= RULE_THRESHOLDS["request_count_1m"]:
        matches.append(
            {
                "rule_id": "R003",
                "threat_type": "traffic_spike",
                "severity": "high",
                "reason": "request_count_1m exceeded threshold",
            }
        )

    marker = str(event.get("payload_marker", "")).upper()
    if (
        _number(event, "payload_risk_score") >= RULE_THRESHOLDS["payload_risk_score"]
        or "SIMULATED_WEB_ATTACK" in marker
        or "SIMULATED_SQLI" in marker
        or "SIMULATED_XSS" in marker
    ):
        matches.append(
            {
                "rule_id": "R004",
                "threat_type": "web_attack",
                "severity": "high",
                "reason": "suspicious simulated payload marker exists",
            }
        )

    error_count = _number(event, "status_4xx_count_5m") + _number(event, "status_5xx_count_5m")
    if error_count >= RULE_THRESHOLDS["status_error_count_5m"]:
        matches.append(
            {
                "rule_id": "R005",
                "threat_type": "web_attack",
                "severity": "medium",
                "reason": "too many 4xx/5xx responses in short time",
            }
        )

    endpoint = str(event.get("endpoint", ""))
    status_code = int(_number(event, "status_code", 200))
    if endpoint == "/admin" and status_code in {401, 403} and _number(event, "status_4xx_count_5m") >= 3:
        matches.append(
            {
                "rule_id": "R006",
                "threat_type": "web_attack",
                "severity": "high",
                "reason": "repeated admin access failure",
            }
        )

    if not matches:
        return {
            "is_threat": False,
            "threat_type": "normal",
            "severity": "informational",
            "reason": "no rule matched",
            "matched_rules": [],
            "detector": "rule_based",
        }

    strongest = max(matches, key=lambda match: SEVERITY_RANK[match["severity"]])
    return {
        "is_threat": True,
        "threat_type": strongest["threat_type"],
        "severity": strongest["severity"],
        "reason": strongest["reason"],
        "matched_rules": matches,
        "detector": "rule_based",
    }
