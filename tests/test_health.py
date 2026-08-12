import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.config import settings

client = TestClient(app)

def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert settings.PROJECT_NAME in data["message"] or "SIEM" in data["message"]

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code in (200, 503)
    data = response.json()
    assert data["app"] == settings.PROJECT_NAME

def test_api_v1_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code in (200, 503)
    data = response.json()
    assert data["app"] == settings.PROJECT_NAME
