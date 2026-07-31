from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.main import app
from backend.app.models.base import Base
from backend.app.models.user import User
from backend.app.models.event import Event
from backend.app.models.enums import UserRole, EventOutcome, Severity
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
        username="admin_exp",
        email="admin@cyberwolf.local",
        display_name="Admin Exp",
        password_hash=get_password_hash("AdminPass123!"),
        role=UserRole.ADMIN,
        is_active=True,
    )
    analyst_user = User(
        username="analyst_exp",
        email="analyst@cyberwolf.local",
        display_name="Analyst Exp",
        password_hash=get_password_hash("AnalystPass123!"),
        role=UserRole.ANALYST,
        is_active=True,
    )
    viewer_user = User(
        username="viewer_exp",
        email="viewer@cyberwolf.local",
        display_name="Viewer Exp",
        password_hash=get_password_hash("ViewerPass123!"),
        role=UserRole.VIEWER,
        is_active=True,
    )
    db.add_all([admin_user, analyst_user, viewer_user])

    # Seed deterministic test events
    now = datetime.now(timezone.utc)
    ev1 = Event(
        timestamp=now - timedelta(minutes=10),
        ingested_at=now - timedelta(minutes=10),
        source_type="linux_auth",
        event_type="authentication",
        source_ip="192.168.1.10",
        hostname="web-server-01",
        username="ubuntu",
        action="login",
        outcome=EventOutcome.SUCCESS,
        severity=Severity.INFO,
        raw_event={"message": "Accepted password for ubuntu from 192.168.1.10"},
        event_metadata={"service": "sshd"}
    )
    ev2 = Event(
        timestamp=now - timedelta(minutes=5),
        ingested_at=now - timedelta(minutes=5),
        source_type="linux_auth",
        event_type="authentication",
        source_ip="10.0.0.99",
        hostname="auth-server-02",
        username="root",
        action="login",
        outcome=EventOutcome.FAILURE,
        severity=Severity.HIGH,
        raw_event={"message": "Failed password for root from 10.0.0.99"},
        event_metadata={"service": "sshd"}
    )
    ev3 = Event(
        timestamp=now,
        ingested_at=now,
        source_type="json",
        event_type="network_connection",
        source_ip="172.16.0.5",
        destination_ip="8.8.8.8",
        hostname="db-server-01",
        username="postgres",
        action="connect",
        outcome=EventOutcome.SUCCESS,
        severity=Severity.MEDIUM,
        raw_event={"event": "db_connect", "xss": "<script>alert(1)</script>"},
        event_metadata={"sqli": "' OR 1=1 --"}
    )
    db.add_all([ev1, ev2, ev3])
    db.commit()

    # Reset ingestion service state
    ingestion_service._seen_event_keys.clear()
    ingestion_service._envelope_buffer.clear()

    yield
    db.close()
    Base.metadata.drop_all(bind=engine)
    app.dependency_overrides.clear()

def get_headers(username: str, role: str) -> dict:
    token = create_access_token(subject=username, role=role)
    return {"Authorization": f"Bearer {token}"}

# 1. Authorization Tests
def test_unauthenticated_list_and_detail_rejected_401():
    resp_list = client.get("/api/v1/events")
    assert resp_list.status_code == 401
    
    resp_detail = client.get("/api/v1/events/00000000-0000-0000-0000-000000000000")
    assert resp_detail.status_code == 401

def test_viewer_list_and_detail_allowed_200():
    headers = get_headers("viewer_exp", "VIEWER")
    resp_list = client.get("/api/v1/events", headers=headers)
    assert resp_list.status_code == 200
    items = resp_list.json()["items"]
    assert len(items) == 3

    event_id = items[0]["id"]
    resp_detail = client.get(f"/api/v1/events/{event_id}", headers=headers)
    assert resp_detail.status_code == 200
    assert resp_detail.json()["id"] == event_id

def test_analyst_and_admin_read_allowed_200():
    analyst_headers = get_headers("analyst_exp", "ANALYST")
    assert client.get("/api/v1/events", headers=analyst_headers).status_code == 200

    admin_headers = get_headers("admin_exp", "ADMIN")
    assert client.get("/api/v1/events", headers=admin_headers).status_code == 200

# 2. Pagination & Ordering Tests
def test_pagination_bounds_and_structure():
    headers = get_headers("viewer_exp", "VIEWER")
    resp = client.get("/api/v1/events?page=1&page_size=2", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 2
    assert data["page"] == 1
    assert data["page_size"] == 2
    assert data["total"] == 3
    assert data["pages"] == 2

def test_page_size_exceeding_max_rejected_422():
    headers = get_headers("viewer_exp", "VIEWER")
    resp = client.get("/api/v1/events?page_size=101", headers=headers)
    assert resp.status_code == 422

# 3. Filtering & Search Tests
def test_filters_by_source_type_and_severity():
    headers = get_headers("viewer_exp", "VIEWER")
    resp = client.get("/api/v1/events?source_type=linux_auth&severity=HIGH", headers=headers)
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) == 1
    assert items[0]["username"] == "root"
    assert items[0]["severity"] == "HIGH"

def test_time_range_valid_and_invalid():
    headers = get_headers("viewer_exp", "VIEWER")
    now = datetime.now(timezone.utc)
    start = (now - timedelta(minutes=12)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end = (now - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")

    resp_valid = client.get(f"/api/v1/events?start_time={start}&end_time={end}", headers=headers)
    assert resp_valid.status_code == 200
    assert resp_valid.json()["total"] == 2

    # Invalid range: start > end
    resp_invalid = client.get(f"/api/v1/events?start_time={end}&end_time={start}", headers=headers)
    assert resp_invalid.status_code == 400
    assert "start_time cannot be greater than end_time" in resp_invalid.json()["detail"]

# 4. Detail & Unknown UUID Tests
def test_get_event_detail_unknown_uuid_404():
    headers = get_headers("viewer_exp", "VIEWER")
    resp = client.get("/api/v1/events/99999999-9999-9999-9999-999999999999", headers=headers)
    assert resp.status_code == 404

# 5. Inert Evidence & SQL Injection Safety Tests
def test_inert_evidence_and_sql_injection_safety():
    headers = get_headers("viewer_exp", "VIEWER")
    resp = client.get("/api/v1/events?q=' OR 1=1 --", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["total"] == 0

# 6. Stats Endpoint Test
def test_event_stats_endpoint():
    headers = get_headers("viewer_exp", "VIEWER")
    resp = client.get("/api/v1/events/stats", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_events"] == 3
    assert "HIGH" in data["events_by_severity"]
    assert "linux_auth" in data["events_by_source_type"]

# 7. End-to-End Pipeline Integration Test (M03 -> M04 -> M05)
def test_e2e_ingestion_normalization_and_m05_explorer_query():
    analyst_headers = get_headers("analyst_exp", "ANALYST")
    
    # 1. Post synthetic telemetry via M03
    telemetry = {
        "source_type": "linux_auth",
        "source_event_id": "SYNTH-EVT-7001",
        "payload": {
            "message": "Failed password for invalid user admin from 10.10.10.50 port 4444 ssh2"
        }
    }
    post_resp = client.post("/api/v1/events", json=telemetry, headers=analyst_headers)
    assert post_resp.status_code == 202

    # 2. Query via M05 Evidence Explorer
    viewer_headers = get_headers("viewer_exp", "VIEWER")
    get_resp = client.get("/api/v1/events?source_type=linux_auth&username=admin", headers=viewer_headers)
    assert get_resp.status_code == 200
    items = get_resp.json()["items"]
    assert len(items) == 1

    event_detail = items[0]
    assert event_detail["source_ip"] == "10.10.10.50"
    assert event_detail["username"] == "admin"
    assert event_detail["outcome"] == "FAILURE"
    assert event_detail["action"] == "login"
    assert event_detail["source_event_id"] == "SYNTH-EVT-7001"
