import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_returns_ok():
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert "timestamp" in body


def test_analyze_valid_iam_policy():
    response = client.post("/analyze", json={
        "input_type": "iam_policy",
        "content": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
    })
    assert response.status_code == 200
    assert "result" in response.json()


def test_analyze_invalid_type():
    response = client.post("/analyze", json={
        "input_type": "not_a_real_type",
        "content": "some content"
    })
    assert response.status_code == 400


def test_analyze_empty_content():
    response = client.post("/analyze", json={
        "input_type": "cloudtrail",
        "content": ""
    })
    assert response.status_code == 400


def test_analyze_missing_fields():
    response = client.post("/analyze", json={"input_type": "iam_policy"})
    assert response.status_code == 422
