import json
from pathlib import Path

from lab.web_app.app import create_app


def test_lab_web_app_health_and_failed_login_logging(tmp_path: Path):
    events_path = tmp_path / "events.jsonl"
    app = create_app({"TESTING": True, "LAB_EVENTS_PATH": events_path})

    client = app.test_client()
    health = client.get("/health")
    response = client.post("/login", data={"username": "demo", "password": "wrong"})

    assert health.status_code == 200
    assert response.status_code == 401

    events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines()]
    assert events[-1]["event_type"] == "login_failed"
    assert events[-1]["endpoint"] == "/login"
    assert events[-1]["label"] == "brute_force"
