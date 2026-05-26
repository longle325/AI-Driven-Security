from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


ThreatLabel = Literal["normal", "port_scan", "brute_force", "web_attack", "traffic_spike"]


class SecurityEvent(BaseModel):
    timestamp: str
    source_ip: str
    event_type: str
    endpoint: str
    status_code: int
    user_id: str | None = None
    http_method: str = "GET"
    request_count_1m: int = 1
    failed_login_count_5m: int = 0
    unique_endpoints_5m: int = 1
    unique_ports_1m: int = 1
    status_4xx_count_5m: int = 0
    status_5xx_count_5m: int = 0
    payload_risk_score: float = 0.0
    avg_request_interval: float = 60.0
    user_agent: str = "lab-client"
    payload_marker: str = "SIMULATED_NONE"
    label: ThreatLabel | None = None


class DetectionRequest(BaseModel):
    event: SecurityEvent


class BatchDetectionRequest(BaseModel):
    events: list[SecurityEvent] = Field(default_factory=list)


class DetectionResponse(BaseModel):
    is_threat: bool
    threat_type: str
    severity: str
    confidence: float
    recommended_action: str
    evidence: dict[str, Any] | None = None
