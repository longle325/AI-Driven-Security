from fastapi.testclient import TestClient

from api.main import _read_csv, app


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


def test_read_csv_returns_empty_list_for_empty_file(tmp_path):
    empty_csv = tmp_path / "empty.csv"
    empty_csv.write_text("\n", encoding="utf-8")

    assert _read_csv(empty_csv) == []
