from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture(scope="session")
def client() -> TestClient:
    return TestClient(app)


def test_api_health(client: TestClient):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "active_ml_model" in data


def test_api_model_info(client: TestClient):
    res = client.get("/api/ml/model-info")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "loaded"
    assert data["feature_count"] == 27
    assert "C2_BEACONING" in data["supported_classes"]
    assert "BENIGN" in data["supported_classes"]
    assert "EXFILTRATION" in data["unsupported_classes"]


def test_api_list_samples(client: TestClient):
    res = client.get("/api/ml/samples")
    assert res.status_code == 200
    data = res.json()
    assert "samples" in data
    assert len(data["samples"]) > 0


def test_api_analyze_sample_pcap(client: TestClient):
    res = client.post("/api/analyze/sample-pcap?filename=capWIN-172.31.67.95_Fri02.pcap&max_flows=50")
    assert res.status_code == 200
    data = res.json()
    assert "evaluated_flows" in data
    assert "threat_breakdown" in data
    assert data["evaluated_flows"] > 0
    assert len(data["flows"]) > 0

    first_flow = data["flows"][0]
    assert "predicted_class" in first_flow
    assert "anomaly_score" in first_flow
    assert "is_threat" in first_flow
