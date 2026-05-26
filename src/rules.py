from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.config import settings


@dataclass(frozen=True)
class RuleDecision:
    is_threat: bool
    threat_type: str
    severity: str
    reason: str
    detector: str = "rule_based"
    rule_id: str = "NONE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_threat": self.is_threat,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "reason": self.reason,
            "detector": self.detector,
            "rule_id": self.rule_id,
        }


def _num(event: dict, key: str) -> float:
    try:
        return float(event.get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0.0


def evaluate_event(event: dict) -> RuleDecision:
    failed = _num(event, "failed_login_count_5m")
    ports = _num(event, "unique_ports_1m")
    requests = _num(event, "request_count_1m")
    payload = _num(event, "payload_risk_score")
    errors = _num(event, "status_4xx_count_5m") + _num(event, "status_5xx_count_5m")
    endpoint = str(event.get("endpoint", "")).lower()
    event_type = str(event.get("event_type", "")).lower()
    endpoint_risk = _num(event, "endpoint_risk_score")
    interval = _num(event, "avg_request_interval")

    if failed >= settings.failed_login_threshold:
        severity = "critical" if failed >= settings.failed_login_threshold * 2 else "high"
        return RuleDecision(True, "brute_force", severity, "failed_login_count_5m exceeded threshold", rule_id="R001")
    if "beacon" in event_type or (interval <= 1.2 and payload >= 0.45 and 25 <= requests <= 120):
        severity = "high" if payload >= 0.55 else "medium"
        return RuleDecision(True, "botnet", severity, "beacon-like outbound pattern detected", rule_id="R002")
    if ports >= settings.unique_ports_threshold:
        severity = "critical" if ports >= settings.unique_ports_threshold * 2 else "high"
        return RuleDecision(True, "infiltration", severity, "multi-port lateral movement pattern exceeded threshold", rule_id="R003")
    if requests >= settings.request_spike_threshold:
        severity = "high" if requests >= settings.request_spike_threshold * 1.5 else "medium"
        return RuleDecision(True, "dos_ddos", severity, "request_count_1m exceeded threshold", rule_id="R004")
    if payload >= settings.payload_risk_threshold:
        severity = "critical" if payload >= 0.9 else "high"
        return RuleDecision(True, "web_attack", severity, "payload_risk_score exceeded threshold", rule_id="R005")
    if endpoint_risk >= 0.85 and ("admin" in endpoint or "export" in endpoint or errors >= settings.error_threshold):
        return RuleDecision(True, "infiltration", "medium", "sensitive endpoint risk exceeded threshold", rule_id="R006")
    if errors >= settings.error_threshold:
        return RuleDecision(True, "suspicious", "medium", "4xx/5xx error volume exceeded threshold", rule_id="R007")
    if "admin" in endpoint and _num(event, "status_code") in (401, 403, 404):
        return RuleDecision(True, "suspicious", "medium", "admin endpoint returned repeated failure status", rule_id="R008")

    return RuleDecision(False, "normal", "informational", "no configured rule matched")


def evaluate_events(events: list[dict]) -> list[dict]:
    return [evaluate_event(event).to_dict() for event in events]
