from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from lab.simulator.safe_payloads import SAFE_ADMIN_PATHS, SAFE_WEB_MARKERS

SCENARIOS = ["normal", "port_scan", "brute_force", "web_attack", "traffic_spike", "mixed"]
PRIVATE_IPS = [f"10.0.{segment}.{host}" for segment in range(1, 5) for host in range(10, 80)]
USERS = [f"user_{idx:02d}" for idx in range(1, 31)]
ENDPOINTS = ["/", "/login", "/search", "/profile", "/api/orders", "/api/health", "/settings"]


def _base_event(timestamp: datetime, label: str, rng: random.Random) -> dict:
    return {
        "timestamp": timestamp.isoformat(),
        "source_ip": rng.choice(PRIVATE_IPS),
        "user_id": rng.choice(USERS),
        "event_type": "request",
        "endpoint": rng.choice(ENDPOINTS),
        "http_method": rng.choice(["GET", "POST"]),
        "status_code": rng.choice([200, 200, 200, 204, 302]),
        "request_count_1m": rng.randint(3, 35),
        "failed_login_count_5m": rng.randint(0, 3),
        "unique_ports_1m": rng.randint(1, 4),
        "status_4xx_count_5m": rng.randint(0, 4),
        "status_5xx_count_5m": rng.randint(0, 1),
        "payload_risk_score": round(rng.uniform(0.0, 0.2), 3),
        "endpoint_risk_score": round(rng.uniform(0.1, 0.45), 3),
        "avg_request_interval": round(rng.uniform(2.2, 12.0), 3),
        "label": label,
    }


def _normal(timestamp: datetime, rng: random.Random) -> dict:
    return _base_event(timestamp, "normal", rng)


def _brute_force(timestamp: datetime, rng: random.Random) -> dict:
    event = _base_event(timestamp, "brute_force", rng)
    event.update(
        {
            "source_ip": rng.choice(["10.0.2.44", "10.0.2.45", "10.0.2.46"]),
            "event_type": "login_failed",
            "endpoint": "/login",
            "http_method": "POST",
            "status_code": 401,
            "request_count_1m": rng.randint(45, 105),
            "failed_login_count_5m": rng.randint(12, 44),
            "status_4xx_count_5m": rng.randint(12, 50),
            "payload_risk_score": round(rng.uniform(0.02, 0.18), 3),
            "endpoint_risk_score": 0.55,
            "avg_request_interval": round(rng.uniform(0.2, 1.4), 3),
        }
    )
    return event


def _port_scan(timestamp: datetime, rng: random.Random) -> dict:
    event = _base_event(timestamp, "port_scan", rng)
    event.update(
        {
            "source_ip": rng.choice(["10.0.3.90", "10.0.3.91", "10.0.3.92"]),
            "event_type": "service_probe",
            "endpoint": rng.choice(["/health", "/api/health", "/admin"]),
            "http_method": "GET",
            "status_code": rng.choice([200, 403, 404]),
            "request_count_1m": rng.randint(55, 130),
            "failed_login_count_5m": rng.randint(0, 2),
            "unique_ports_1m": rng.randint(24, 96),
            "status_4xx_count_5m": rng.randint(8, 35),
            "payload_risk_score": round(rng.uniform(0.1, 0.35), 3),
            "endpoint_risk_score": 0.7,
            "avg_request_interval": round(rng.uniform(0.1, 0.9), 3),
        }
    )
    return event


def _web_attack(timestamp: datetime, rng: random.Random) -> dict:
    event = _base_event(timestamp, "web_attack", rng)
    marker = rng.choice(SAFE_WEB_MARKERS)
    endpoint = rng.choice(["/search", "/login", *SAFE_ADMIN_PATHS])
    event.update(
        {
            "source_ip": rng.choice(["10.0.4.60", "10.0.4.61", "10.0.4.62"]),
            "event_type": marker,
            "endpoint": endpoint,
            "http_method": rng.choice(["GET", "POST"]),
            "status_code": rng.choice([400, 403, 404, 422]),
            "request_count_1m": rng.randint(18, 72),
            "failed_login_count_5m": rng.randint(0, 5),
            "unique_ports_1m": rng.randint(1, 8),
            "status_4xx_count_5m": rng.randint(12, 38),
            "status_5xx_count_5m": rng.randint(0, 6),
            "payload_risk_score": round(rng.uniform(0.74, 0.98), 3),
            "endpoint_risk_score": 0.88 if endpoint in SAFE_ADMIN_PATHS else 0.62,
            "avg_request_interval": round(rng.uniform(0.6, 3.4), 3),
        }
    )
    return event


def _traffic_spike(timestamp: datetime, rng: random.Random) -> dict:
    event = _base_event(timestamp, "traffic_spike", rng)
    event.update(
        {
            "source_ip": rng.choice(["10.0.1.210", "10.0.1.211", "10.0.1.212", "10.0.1.213"]),
            "event_type": "rate_spike",
            "endpoint": rng.choice(["/", "/api/orders", "/api/health"]),
            "http_method": "GET",
            "status_code": rng.choice([200, 429, 503]),
            "request_count_1m": rng.randint(155, 420),
            "failed_login_count_5m": rng.randint(0, 2),
            "unique_ports_1m": rng.randint(1, 5),
            "status_4xx_count_5m": rng.randint(3, 24),
            "status_5xx_count_5m": rng.randint(4, 28),
            "payload_risk_score": round(rng.uniform(0.02, 0.25), 3),
            "endpoint_risk_score": round(rng.uniform(0.25, 0.55), 3),
            "avg_request_interval": round(rng.uniform(0.02, 0.35), 3),
        }
    )
    return event


GENERATORS = {
    "normal": _normal,
    "brute_force": _brute_force,
    "port_scan": _port_scan,
    "web_attack": _web_attack,
    "traffic_spike": _traffic_spike,
}


def generate_events(scenario: str = "mixed", count: int = 500, seed: int = 42) -> list[dict]:
    if scenario not in SCENARIOS:
        raise ValueError(f"Unsupported scenario '{scenario}'. Expected one of {', '.join(SCENARIOS)}")

    rng = random.Random(seed)
    start = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=max(30, count // 8))
    events: list[dict] = []
    weights = [
        ("normal", 0.58),
        ("brute_force", 0.14),
        ("port_scan", 0.10),
        ("web_attack", 0.10),
        ("traffic_spike", 0.08),
    ]
    labels, probabilities = zip(*weights)

    for idx in range(count):
        timestamp = start + timedelta(seconds=idx * rng.randint(3, 18))
        chosen = rng.choices(labels, weights=probabilities, k=1)[0] if scenario == "mixed" else scenario
        events.append(GENERATORS[chosen](timestamp, rng))
    return events
