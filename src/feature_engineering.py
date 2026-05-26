from __future__ import annotations

import re
from typing import Any

import pandas as pd


METHOD_ENCODING = {
    "GET": 0,
    "POST": 1,
    "PUT": 2,
    "DELETE": 3,
    "PATCH": 4,
    "OPTIONS": 5,
}

EVENT_TYPE_ENCODING = {
    "page_view": 0,
    "login_success": 1,
    "login_failed": 2,
    "search": 3,
    "admin_access": 4,
    "admin_access_denied": 5,
    "api_request": 6,
    "port_probe": 7,
    "rate_spike": 8,
    "error": 9,
}

ENDPOINT_RISK = {
    "/": 0.05,
    "/health": 0.02,
    "/profile": 0.15,
    "/search": 0.25,
    "/login": 0.35,
    "/api/events": 0.4,
    "/admin": 0.75,
}

SAFE_SUSPICIOUS_MARKERS = (
    "SIMULATED_WEB_ATTACK",
    "SIMULATED_SQLI_MARKER",
    "SIMULATED_XSS_MARKER",
    "SIMULATED_TRAVERSAL_MARKER",
)


def endpoint_risk_score(endpoint: str) -> float:
    if endpoint.startswith("tcp/port-"):
        return 0.65
    return ENDPOINT_RISK.get(endpoint, 0.2)


def payload_risk_score(payload_marker: str | None, query: str | None = None) -> float:
    text = f"{payload_marker or ''} {query or ''}".upper()
    if any(marker in text for marker in SAFE_SUSPICIOUS_MARKERS):
        return 0.9
    if re.search(r"SIMULATED_.+ATTACK", text):
        return 0.8
    return 0.0


def normalize_event_record(record: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(record)
    normalized.setdefault("http_method", "GET")
    normalized.setdefault("user_id", "anonymous")
    normalized.setdefault("user_agent", "lab-client")
    normalized.setdefault("payload_marker", "SIMULATED_NONE")
    normalized.setdefault("request_count_1m", 1)
    normalized.setdefault("unique_endpoints_5m", 1)
    normalized.setdefault("unique_ports_1m", 1)
    normalized.setdefault("avg_request_interval", 60.0)

    status_code = int(normalized.get("status_code", 200))
    event_type = str(normalized.get("event_type", "page_view"))

    if "failed_login_count_5m" not in normalized:
        normalized["failed_login_count_5m"] = 1 if event_type == "login_failed" else 0
    if "status_4xx_count_5m" not in normalized:
        normalized["status_4xx_count_5m"] = 1 if 400 <= status_code < 500 else 0
    if "status_5xx_count_5m" not in normalized:
        normalized["status_5xx_count_5m"] = 1 if status_code >= 500 else 0
    if "payload_risk_score" not in normalized:
        normalized["payload_risk_score"] = payload_risk_score(
            normalized.get("payload_marker"),
            normalized.get("query"),
        )

    endpoint = str(normalized.get("endpoint", "/"))
    method = str(normalized.get("http_method", "GET")).upper()
    normalized["endpoint_risk_score"] = endpoint_risk_score(endpoint)
    normalized["method_encoded"] = METHOD_ENCODING.get(method, 0)
    normalized["event_type_encoded"] = EVENT_TYPE_ENCODING.get(event_type, 0)
    return normalized


def add_temporal_features(frame: pd.DataFrame) -> pd.DataFrame:
    output = frame.copy()
    output["timestamp"] = pd.to_datetime(output["timestamp"], errors="coerce", utc=True)
    output["timestamp"] = output["timestamp"].fillna(pd.Timestamp.now(tz="UTC"))
    output["hour"] = output["timestamp"].dt.hour.astype(int)
    return output
