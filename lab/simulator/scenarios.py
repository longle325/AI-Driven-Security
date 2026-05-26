from __future__ import annotations

from datetime import UTC, datetime, timedelta
import random
from typing import Any

from lab.simulator.safe_payloads import SAFE_PAYLOAD_MARKERS, SAFE_QUERIES
from src.config import LABELS


def _base_event(label: str, index: int, base_time: datetime, rng: random.Random) -> dict[str, Any]:
    return {
        "timestamp": (base_time + timedelta(seconds=index * rng.randint(1, 4))).isoformat().replace("+00:00", "Z"),
        "source_ip": f"172.20.{rng.randint(0, 3)}.{rng.randint(2, 240)}",
        "user_id": f"user_{rng.randint(1, 25):02d}",
        "event_type": "page_view",
        "endpoint": rng.choice(["/", "/profile", "/search"]),
        "http_method": "GET",
        "status_code": 200,
        "request_count_1m": rng.randint(1, 12),
        "failed_login_count_5m": 0,
        "unique_endpoints_5m": rng.randint(1, 4),
        "unique_ports_1m": 1,
        "status_4xx_count_5m": 0,
        "status_5xx_count_5m": 0,
        "payload_risk_score": 0.0,
        "avg_request_interval": round(rng.uniform(4.0, 60.0), 2),
        "user_agent": "lab-client",
        "payload_marker": SAFE_PAYLOAD_MARKERS["none"],
        "query": SAFE_QUERIES["normal"],
        "label": label,
    }


def _normal(index: int, base_time: datetime, rng: random.Random) -> dict[str, Any]:
    event = _base_event("normal", index, base_time, rng)
    event["event_type"] = rng.choice(["page_view", "login_success", "search", "api_request"])
    event["endpoint"] = rng.choice(["/", "/login", "/profile", "/search", "/api/events"])
    event["http_method"] = "POST" if event["event_type"] == "login_success" else "GET"
    return event


def _port_scan(index: int, base_time: datetime, rng: random.Random) -> dict[str, Any]:
    event = _base_event("port_scan", index, base_time, rng)
    event.update(
        {
            "event_type": "port_probe",
            "endpoint": f"tcp/port-{20 + (index % 30)}",
            "status_code": 404,
            "request_count_1m": rng.randint(20, 55),
            "unique_endpoints_5m": rng.randint(8, 20),
            "unique_ports_1m": rng.randint(9, 24),
            "status_4xx_count_5m": rng.randint(4, 12),
            "avg_request_interval": round(rng.uniform(0.1, 1.5), 2),
        }
    )
    return event


def _brute_force(index: int, base_time: datetime, rng: random.Random) -> dict[str, Any]:
    event = _base_event("brute_force", index, base_time, rng)
    event.update(
        {
            "event_type": "login_failed",
            "endpoint": "/login",
            "http_method": "POST",
            "status_code": 401,
            "request_count_1m": rng.randint(12, 36),
            "failed_login_count_5m": rng.randint(6, 18),
            "status_4xx_count_5m": rng.randint(6, 18),
            "avg_request_interval": round(rng.uniform(0.2, 2.0), 2),
        }
    )
    return event


def _web_attack(index: int, base_time: datetime, rng: random.Random) -> dict[str, Any]:
    event = _base_event("web_attack", index, base_time, rng)
    marker = rng.choice(["sql", "xss", "traversal", "web_attack"])
    event.update(
        {
            "event_type": "search",
            "endpoint": rng.choice(["/search", "/admin", "/api/events"]),
            "http_method": rng.choice(["GET", "POST"]),
            "status_code": rng.choice([400, 403, 404]),
            "request_count_1m": rng.randint(5, 25),
            "status_4xx_count_5m": rng.randint(3, 14),
            "payload_risk_score": round(rng.uniform(0.75, 0.98), 2),
            "payload_marker": SAFE_PAYLOAD_MARKERS[marker],
            "query": SAFE_QUERIES.get(marker, SAFE_QUERIES["sql"]),
        }
    )
    return event


def _traffic_spike(index: int, base_time: datetime, rng: random.Random) -> dict[str, Any]:
    event = _base_event("traffic_spike", index, base_time, rng)
    event.update(
        {
            "event_type": "rate_spike",
            "endpoint": rng.choice(["/", "/search", "/api/events"]),
            "status_code": rng.choice([200, 200, 429, 503]),
            "request_count_1m": rng.randint(85, 180),
            "unique_endpoints_5m": rng.randint(4, 8),
            "status_4xx_count_5m": rng.randint(0, 12),
            "status_5xx_count_5m": rng.randint(0, 5),
            "avg_request_interval": round(rng.uniform(0.05, 0.8), 2),
        }
    )
    return event


GENERATORS = {
    "normal": _normal,
    "port_scan": _port_scan,
    "brute_force": _brute_force,
    "web_attack": _web_attack,
    "traffic_spike": _traffic_spike,
}


def generate_scenario_events(scenario: str, count: int, seed: int = 42) -> list[dict[str, Any]]:
    if scenario not in {"mixed", *LABELS}:
        raise ValueError(f"Unsupported scenario: {scenario}")

    rng = random.Random(seed)
    base_time = datetime.now(tz=UTC).replace(microsecond=0)
    events: list[dict[str, Any]] = []
    mixed_labels = ["normal", "port_scan", "brute_force", "web_attack", "traffic_spike"]
    mixed_weights = [0.62, 0.09, 0.11, 0.1, 0.08]
    for index in range(count):
        label = rng.choices(mixed_labels, weights=mixed_weights, k=1)[0] if scenario == "mixed" else scenario
        events.append(GENERATORS[label](index, base_time, rng))
    return events


def generate_training_events(seed: int = 42) -> list[dict[str, Any]]:
    plan = {
        "normal": 1000,
        "port_scan": 500,
        "brute_force": 500,
        "web_attack": 500,
        "traffic_spike": 500,
    }
    events: list[dict[str, Any]] = []
    offset = 0
    for label, count in plan.items():
        generated = generate_scenario_events(label, count=count, seed=seed + offset)
        events.extend(generated)
        offset += 1
    return events
