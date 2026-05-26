from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

THREAT_TYPES = ["normal", "botnet", "brute_force", "dos_ddos", "web_attack", "infiltration", "port_scan"]

FEATURE_COLUMNS = [
    "request_count_1m",
    "failed_login_count_5m",
    "unique_ports_1m",
    "status_4xx_count_5m",
    "status_5xx_count_5m",
    "payload_risk_score",
    "endpoint_risk_score",
    "avg_request_interval",
]

LOG_COLUMNS = [
    "timestamp",
    "source_ip",
    "user_id",
    "event_type",
    "endpoint",
    "http_method",
    "status_code",
    *FEATURE_COLUMNS,
    "label",
]

RECOMMENDED_ACTIONS = {
    "normal": "No immediate action required. Continue monitoring.",
    "botnet": "Isolate the suspected host, review outbound beaconing, block known command-and-control indicators, and preserve host/network evidence.",
    "port_scan": "Review exposed services, restrict unnecessary ports, and monitor repeated scanning sources.",
    "brute_force": "Enable rate limiting, account lockout, MFA, and stronger authentication logging.",
    "dos_ddos": "Apply rate limiting, autoscaling, queueing, upstream filtering, and service protection controls.",
    "web_attack": "Validate inputs, use parameterized queries, output encoding, and WAF-style rules.",
    "traffic_spike": "Apply rate limiting, autoscaling, queueing, and a DDoS protection strategy.",
    "infiltration": "Contain the affected segment, review lateral movement indicators, inspect authentication paths, and collect endpoint/network evidence.",
    "suspicious": "Review related logs, preserve evidence, and validate whether the pattern is expected in the lab.",
}


class SimulationRequest(BaseModel):
    scenario: str = Field(default="mixed")
    count: int = Field(default=500, ge=1, le=10000)
    replace: bool = Field(default=True)


class CommandResponse(BaseModel):
    ok: bool
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class AdvisorResponse(BaseModel):
    alert_id: str
    mode: str
    model: str | None = None
    recommendation: dict[str, Any]
