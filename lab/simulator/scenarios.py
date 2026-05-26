from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from lab.simulator.safe_payloads import SAFE_ADMIN_PATHS, SAFE_WEB_MARKERS

SCENARIOS = ["normal", "botnet", "brute_force", "dos_ddos", "web_attack", "infiltration", "mixed"]
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


def _botnet(timestamp: datetime, rng: random.Random) -> dict:
    event = _base_event(timestamp, "botnet", rng)
    event.update(
        {
            "source_ip": rng.choice(["10.0.3.70", "10.0.3.71", "10.0.3.72"]),
            "event_type": "c2_beacon",
            "endpoint": rng.choice(["/api/health", "/cdn/checkin", "/telemetry"]),
            "http_method": "POST",
            "status_code": rng.choice([200, 204]),
            "request_count_1m": rng.randint(32, 88),
            "failed_login_count_5m": rng.randint(0, 1),
            "unique_ports_1m": rng.randint(4, 11),
            "status_4xx_count_5m": rng.randint(0, 4),
            "status_5xx_count_5m": rng.randint(0, 2),
            "payload_risk_score": round(rng.uniform(0.28, 0.62), 3),
            "endpoint_risk_score": round(rng.uniform(0.62, 0.82), 3),
            "avg_request_interval": round(rng.uniform(0.35, 1.1), 3),
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


def _dos_ddos(timestamp: datetime, rng: random.Random) -> dict:
    event = _base_event(timestamp, "dos_ddos", rng)
    event.update(
        {
            "source_ip": rng.choice(["10.0.1.210", "10.0.1.211", "10.0.1.212", "10.0.1.213"]),
            "event_type": "service_flood",
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


def _infiltration(timestamp: datetime, rng: random.Random) -> dict:
    event = _base_event(timestamp, "infiltration", rng)
    event.update(
        {
            "source_ip": rng.choice(["10.0.4.90", "10.0.4.91", "10.0.4.92"]),
            "event_type": "lateral_movement",
            "endpoint": rng.choice(["/admin/audit", "/settings", "/api/orders/export"]),
            "http_method": rng.choice(["GET", "POST"]),
            "status_code": rng.choice([200, 403, 404]),
            "request_count_1m": rng.randint(38, 115),
            "failed_login_count_5m": rng.randint(0, 5),
            "unique_ports_1m": rng.randint(8, 28),
            "status_4xx_count_5m": rng.randint(8, 32),
            "status_5xx_count_5m": rng.randint(0, 8),
            "payload_risk_score": round(rng.uniform(0.38, 0.74), 3),
            "endpoint_risk_score": round(rng.uniform(0.78, 0.96), 3),
            "avg_request_interval": round(rng.uniform(0.4, 1.8), 3),
        }
    )
    return event


GENERATORS = {
    "normal": _normal,
    "botnet": _botnet,
    "brute_force": _brute_force,
    "web_attack": _web_attack,
    "dos_ddos": _dos_ddos,
    "infiltration": _infiltration,
}


def generate_events(scenario: str = "mixed", count: int = 500, seed: int = 42) -> list[dict]:
    if scenario not in SCENARIOS:
        raise ValueError(f"Unsupported scenario '{scenario}'. Expected one of {', '.join(SCENARIOS)}")

    rng = random.Random(seed)
    start = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=max(30, count // 8))
    events: list[dict] = []
    weights = [
        ("normal", 0.50),
        ("botnet", 0.10),
        ("brute_force", 0.14),
        ("dos_ddos", 0.10),
        ("web_attack", 0.09),
        ("infiltration", 0.07),
    ]
    labels, probabilities = zip(*weights)

    for idx in range(count):
        timestamp = start + timedelta(seconds=idx * rng.randint(3, 18))
        chosen = rng.choices(labels, weights=probabilities, k=1)[0] if scenario == "mixed" else scenario
        events.append(GENERATORS[chosen](timestamp, rng))
    return events
