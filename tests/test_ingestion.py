from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.main import app
from backend.app.models.base import Base
from backend.app.models.user import User
from backend.app.models.enums import UserRole, AuditResult
from backend.app.models.audit_log import AuditLog
from backend.app.core.security import get_password_hash, create_access_token
from backend.app.db.session import get_db
from backend.app.services.ingestion_service import ingestion_service

# StaticPool shared in-memory SQLite engine
engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    admin_user = User(
        username="admin_ingest",
        email="admin@cyberwolf.local",
        display_name="Admin Ingest",
        password_hash=get_password_hash("AdminPass123!"),
        role=UserRole.ADMIN,
        is_active=True,
    )
    analyst_user = User(
        username="analyst_ingest",
        email="analyst@cyberwolf.local",
        display_name="Analyst Ingest",
        password_hash=get_password_hash("AnalystPass123!"),
        role=UserRole.ANALYST,
        is_active=True,
    )
    viewer_user = User(
        username="viewer_ingest",
        email="viewer@cyberwolf.local",
        display_name="Viewer Ingest",
        password_hash=get_password_hash("ViewerPass123!"),
        role=UserRole.VIEWER,
        is_active=True,
    )
    db.add_all([admin_user, analyst_user, viewer_user])
    db.commit()

    # Reset ingestion service in-memory state
    ingestion_service._seen_event_keys.clear()
    ingestion_service._envelope_buffer.clear()

    yield
    db.close()
    Base.metadata.drop_all(bind=engine)
    app.dependency_overrides.clear()

def get_headers(username: str, role: str) -> dict:
    token = create_access_token(subject=username, role=role)
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

# 1. Authorization Tests
def test_unauthenticated_single_ingest_rejected_401():
    payload = {"source_type": "linux_auth", "payload": {"message": "Failed password for root"}}
    response = client.post("/api/v1/events", json=payload)
    assert response.status_code == 401

def test_viewer_single_ingest_denied_403():
    headers = get_headers("viewer_ingest", "VIEWER")
    payload = {"source_type": "linux_auth", "payload": {"message": "Failed password for root"}}
    response = client.post("/api/v1/events", json=payload, headers=headers)
    assert response.status_code == 403

def test_analyst_single_ingest_accepted_202():
    headers = get_headers("analyst_ingest", "ANALYST")
    payload = {"source_type": "linux_auth", "payload": {"message": "Accepted password for ubuntu"}}
    response = client.post("/api/v1/events", json=payload, headers=headers)
    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "accepted"
    assert data["accepted"] == 1

def test_admin_single_ingest_accepted_202():
    headers = get_headers("admin_ingest", "ADMIN")
    payload = {"source_type": "json", "payload": {"event": "login_success", "user": "admin"}}
    response = client.post("/api/v1/events", json=payload, headers=headers)
    assert response.status_code == 202
    assert response.json()["accepted"] == 1

def test_unauthenticated_batch_ingest_rejected_401():
    batch = [{"source_type": "json", "payload": {"event": "test"}}]
    response = client.post("/api/v1/events/batch", json=batch)
    assert response.status_code == 401

def test_viewer_batch_ingest_denied_403():
    headers = get_headers("viewer_ingest", "VIEWER")
    batch = [{"source_type": "json", "payload": {"event": "test"}}]
    response = client.post("/api/v1/events/batch", json=batch, headers=headers)
    assert response.status_code == 403

def test_analyst_batch_ingest_accepted_202():
    headers = get_headers("analyst_ingest", "ANALYST")
    batch = [
        {"source_type": "linux_auth", "payload": {"event": "1"}},
        {"source_type": "json", "payload": {"event": "2"}}
    ]
    response = client.post("/api/v1/events/batch", json=batch, headers=headers)
    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "accepted"
    assert data["accepted"] == 2

# 2. Validation & Boundary Tests
def test_empty_batch_rejected_400():
    headers = get_headers("analyst_ingest", "ANALYST")
    response = client.post("/api/v1/events/batch", json=[], headers=headers)
    assert response.status_code == 400
    assert "cannot be empty" in response.json()["detail"]

def test_batch_size_max_boundary_accepted_100():
    headers = get_headers("analyst_ingest", "ANALYST")
    batch = [{"source_type": "json", "payload": {"idx": i}} for i in range(100)]
    response = client.post("/api/v1/events/batch", json=batch, headers=headers)
    assert response.status_code == 202
    assert response.json()["accepted"] == 100

def test_batch_size_exceeding_max_rejected_101():
    headers = get_headers("analyst_ingest", "ANALYST")
    batch = [{"source_type": "json", "payload": {"idx": i}} for i in range(101)]
    response = client.post("/api/v1/events/batch", json=batch, headers=headers)
    assert response.status_code == 400
    assert "exceeds maximum allowable limit" in response.json()["detail"]

def test_unknown_source_type_rejected_422():
    headers = get_headers("analyst_ingest", "ANALYST")
    payload = {"source_type": "unsupported_source_xyz", "payload": {"msg": "test"}}
    response = client.post("/api/v1/events", json=payload, headers=headers)
    assert response.status_code == 422

def test_invalid_ip_format_rejected_422():
    headers = get_headers("analyst_ingest", "ANALYST")
    payload = {
        "source_type": "linux_auth",
        "source_ip": "999.999.999.999", # invalid IP
        "payload": {"msg": "test"}
    }
    response = client.post("/api/v1/events", json=payload, headers=headers)
    assert response.status_code == 422

def test_valid_ipv4_and_ipv6_accepted():
    headers = get_headers("analyst_ingest", "ANALYST")
    payload_v4 = {
        "source_type": "linux_auth",
        "source_ip": "192.168.1.50",
        "destination_ip": "10.0.0.1",
        "payload": {"msg": "IPv4 test"}
    }
    resp_v4 = client.post("/api/v1/events", json=payload_v4, headers=headers)
    assert resp_v4.status_code == 202

    payload_v6 = {
        "source_type": "json",
        "source_ip": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "payload": {"msg": "IPv6 test"}
    }
    resp_v6 = client.post("/api/v1/events", json=payload_v6, headers=headers)
    assert resp_v6.status_code == 202

def test_forbidden_unexpected_top_level_field_rejected_422():
    headers = get_headers("analyst_ingest", "ANALYST")
    payload = {
        "source_type": "json",
        "payload": {"msg": "test"},
        "risk_score": 99.9, # Forbidden extra field
        "incident_id": "fake_id"
    }
    response = client.post("/api/v1/events", json=payload, headers=headers)
    assert response.status_code == 422

def test_wrong_content_type_rejected_415():
    token = create_access_token(subject="analyst_ingest", role="ANALYST")
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "text/plain"
    }
    response = client.post("/api/v1/events", content="raw text content", headers=headers)
    assert response.status_code == 415

# 3. Payload Safety Test (Inert Attack Strings)
def test_raw_telemetry_inert_attack_strings():
    headers = get_headers("analyst_ingest", "ANALYST")
    payload = {
        "source_type": "linux_auth",
        "payload": {
            "xss": "<script>alert(1)</script>",
            "sqli": "' OR 1=1 --",
            "cmd_injection": "$(whoami)",
            "path_traversal": "../../etc/passwd"
        }
    }
    response = client.post("/api/v1/events", json=payload, headers=headers)
    assert response.status_code == 202
    assert len(ingestion_service._envelope_buffer) == 1
    stored_payload = ingestion_service._envelope_buffer[0].raw_payload
    assert stored_payload["xss"] == "<script>alert(1)</script>"
    assert stored_payload["sqli"] == "' OR 1=1 --"

# 4. Request ID Propagation Test
def test_request_id_propagation():
    headers = get_headers("analyst_ingest", "ANALYST")
    headers["X-Request-ID"] = "ingest-req-trace-999"
    payload = {"source_type": "json", "payload": {"test": "id_propagation"}}
    
    response = client.post("/api/v1/events", json=payload, headers=headers)
    assert response.status_code == 202
    assert response.headers["X-Request-ID"] == "ingest-req-trace-999"
    data = response.json()
    assert data["request_id"] == "ingest-req-trace-999"
    assert ingestion_service._envelope_buffer[0].request_id == "ingest-req-trace-999"

# 5. Idempotency Test
def test_source_event_id_duplicate_handling():
    headers = get_headers("analyst_ingest", "ANALYST")
    payload = {
        "source_type": "linux_auth",
        "source_event_id": "EVT-UNIQUE-1001",
        "payload": {"message": "First arrival"}
    }
    
    # First ingest
    resp1 = client.post("/api/v1/events", json=payload, headers=headers)
    assert resp1.status_code == 202
    assert resp1.json()["is_duplicate"] is False

    # Second ingest (duplicate)
    resp2 = client.post("/api/v1/events", json=payload, headers=headers)
    assert resp2.status_code == 202
    assert resp2.json()["is_duplicate"] is True
