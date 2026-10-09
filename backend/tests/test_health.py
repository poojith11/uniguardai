from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "UNIGUARD AI Engine Online"
    assert data["health"] == "/api/health"
    assert data["db_status"] == "/api/db/status"
    assert data["pcap_extractor"] == "/api/traffic/extract-pcap"


def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "uniguard-ai-backend"
    assert data["version"] == "0.2.0"
    assert "diode_channel" in data
    assert "timestamp" in data
    assert "database" in data
    assert "configured" in data["database"]


def test_db_status_endpoint():
    response = client.get("/api/db/status")
    assert response.status_code == 200
    data = response.json()
    assert "configured" in data
    assert "status" in data
    assert "message" in data
