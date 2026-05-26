from fastapi.testclient import TestClient

from api.main import app


def test_api_health_and_single_event_detection():
    client = TestClient(app)
    health = client.get("/health")
    response = client.post(
        "/detect/event",
        json={
            "event": {
                "timestamp": "2026-05-26T10:00:00Z",
                "source_ip": "172.20.0.5",
                "event_type": "login_failed",
                "endpoint": "/login",
                "status_code": 401,
                "http_method": "POST",
                "request_count_1m": 12,
                "failed_login_count_5m": 8,
                "unique_ports_1m": 1,
                "status_4xx_count_5m": 8,
                "status_5xx_count_5m": 0,
                "payload_risk_score": 0.0,
            }
        },
    )

    assert health.status_code == 200
    assert response.status_code == 200
    body = response.json()
    assert body["is_threat"] is True
    assert body["threat_type"] == "brute_force"
    assert body["recommended_action"]
