from fastapi.testclient import TestClient

from api.main import app


def test_health_endpoint():
    client = TestClient(app)
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_summary_endpoint_has_expected_shape():
    client = TestClient(app)
    response = client.get("/api/summary")

    assert response.status_code == 200
    payload = response.json()
    assert "total_logs" in payload
    assert "llm" in payload
