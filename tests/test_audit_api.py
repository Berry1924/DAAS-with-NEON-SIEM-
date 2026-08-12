import pytest
import uuid
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.main import app
from backend.app.models.base import Base
from backend.app.models.user import User
from backend.app.models.audit_log import AuditLog
from backend.app.models.enums import UserRole, AuditResult
from backend.app.core.security import get_password_hash, create_access_token
from backend.app.db.session import get_db

from backend.app.services.audit_service import audit_service, sanitize_metadata

# StaticPool in-memory SQLite engine
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

    admin = User(
        username="admin_audit",
        email="admin_audit@cyberwolf.local",
        display_name="Admin Audit",
        password_hash=get_password_hash("AdminPass123!"),
        role=UserRole.ADMIN,
        is_active=True,
    )
    analyst = User(
        username="analyst_audit",
        email="analyst_audit@cyberwolf.local",
        display_name="Analyst Audit",
        password_hash=get_password_hash("AnalystPass123!"),
        role=UserRole.ANALYST,
        is_active=True,
    )
    viewer = User(
        username="viewer_audit",
        email="viewer_audit@cyberwolf.local",
        display_name="Viewer Audit",
        password_hash=get_password_hash("ViewerPass123!"),
        role=UserRole.VIEWER,
        is_active=True,
    )
    db.add_all([admin, analyst, viewer])
    db.commit()

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

# ---------------------------------------------------------
# 1. AuditService Core & Persistence Tests
# ---------------------------------------------------------
def test_audit_service_creates_record():
    db = TestingSessionLocal()
    actor = db.scalar(select(User).where(User.username == "admin_audit"))

    log_entry = audit_service.log(
        db=db,
        action="TEST_ACTION",
        actor_id=actor.id,
        target_type="test_type",
        target_id="test_123",
        result=AuditResult.SUCCESS,
        request_id="req-abc-123",
        source_ip="127.0.0.1",
        metadata={"detail": "sample"}
    )

    assert log_entry.id is not None
    assert log_entry.action == "TEST_ACTION"
    assert log_entry.actor_id == actor.id
    assert log_entry.target_type == "test_type"
    assert log_entry.target_id == "test_123"
    assert log_entry.result == AuditResult.SUCCESS
    assert log_entry.request_id == "req-abc-123"
    assert log_entry.source_ip == "127.0.0.1"
    assert log_entry.audit_metadata == {"detail": "sample"}
    db.close()

# ---------------------------------------------------------
# 2. Sensitive Data Filtering Tests
# ---------------------------------------------------------
def test_sensitive_data_filtering():
    raw_meta = {
        "username": "alice",
        "password": "secret_password_123",
        "password_hash": "$2b$12$e...",
        "access_token": "eyJhbGci...",
        "api_key": "cw_live_9999",
        "secret": "top_secret_key",
        "authorization": "Bearer eyJhbGci...",
        "safe_field": "public_data"
    }

    sanitized = sanitize_metadata(raw_meta)
    assert sanitized["username"] == "alice"
    assert sanitized["password"] == "[REDACTED]"
    assert sanitized["password_hash"] == "[REDACTED]"
    assert sanitized["access_token"] == "[REDACTED]"
    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["secret"] == "[REDACTED]"
    assert sanitized["authorization"] == "[REDACTED]"
    assert sanitized["safe_field"] == "public_data"

def test_password_filtered_in_audit_service():
    db = TestingSessionLocal()
    log_entry = audit_service.log(
        db=db,
        action="LOGIN_FAILURE",
        metadata={"username": "bob", "password": "super_secret_password"}
    )
    assert log_entry.audit_metadata["password"] == "[REDACTED]"
    assert log_entry.audit_metadata["username"] == "bob"
    db.close()

# ---------------------------------------------------------
# 3. Authentication Auditing
# ---------------------------------------------------------
def test_login_success_audited():
    res = client.post("/api/v1/auth/login", json={"username": "admin_audit", "password": "AdminPass123!"})
    assert res.status_code == 200

    db = TestingSessionLocal()
    logs = list(db.scalars(select(AuditLog).where(AuditLog.action == audit_service.LOGIN_SUCCESS)).all())
    assert len(logs) >= 1
    assert logs[0].result == AuditResult.SUCCESS
    assert logs[0].audit_metadata["username"] == "admin_audit"
    db.close()

def test_login_failure_audited():
    res = client.post("/api/v1/auth/login", json={"username": "admin_audit", "password": "WrongPassword!"})
    assert res.status_code == 401

    db = TestingSessionLocal()
    logs = list(db.scalars(select(AuditLog).where(AuditLog.action == audit_service.LOGIN_FAILURE)).all())
    assert len(logs) >= 1
    assert logs[0].result == AuditResult.FAILURE
    assert logs[0].audit_metadata["username"] == "admin_audit"
    db.close()

# ---------------------------------------------------------
# 4. RBAC & API Endpoint Security Tests
# ---------------------------------------------------------
def test_unauthenticated_audit_access():
    res = client.get("/api/v1/audit")
    assert res.status_code == 401

def test_viewer_cannot_read_audit():
    h_viewer = get_headers("viewer_audit", "VIEWER")
    res = client.get("/api/v1/audit", headers=h_viewer)
    assert res.status_code == 403

def test_analyst_cannot_read_audit():
    h_analyst = get_headers("analyst_audit", "ANALYST")
    res = client.get("/api/v1/audit", headers=h_analyst)
    assert res.status_code == 403

def test_admin_can_read_audit():
    h_admin = get_headers("admin_audit", "ADMIN")
    res = client.get("/api/v1/audit", headers=h_admin)
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert "total" in data

# ---------------------------------------------------------
# 5. Pagination & Filtering Tests
# ---------------------------------------------------------
def test_audit_pagination_and_filtering():
    db = TestingSessionLocal()
    actor = db.scalar(select(User).where(User.username == "admin_audit"))

    # Seed audit logs
    for i in range(15):
        audit_service.log(
            db=db,
            action="BATCH_ACTION",
            actor_id=actor.id,
            target_type="system",
            target_id=f"target_{i}",
            request_id=f"req-{i}"
        )
    db.close()

    h_admin = get_headers("admin_audit", "ADMIN")
    res = client.get("/api/v1/audit?action=BATCH_ACTION&page=1&page_size=10", headers=h_admin)
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 15
    assert len(data["items"]) == 10
    assert data["pages"] == 2

def test_audit_page_size_bounded():
    h_admin = get_headers("admin_audit", "ADMIN")
    res = client.get("/api/v1/audit?page_size=500", headers=h_admin)
    assert res.status_code == 422  # Bounded to max page size

def test_filter_by_request_id():
    db = TestingSessionLocal()
    audit_service.log(db=db, action="UNIQUE_REQ_ACTION", request_id="unique-uuid-999")
    db.close()

    h_admin = get_headers("admin_audit", "ADMIN")
    res = client.get("/api/v1/audit?request_id=unique-uuid-999", headers=h_admin)
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 1
    assert data["items"][0]["request_id"] == "unique-uuid-999"

# ---------------------------------------------------------
# 6. Audit Immutability Tests
# ---------------------------------------------------------
def test_audit_cannot_be_modified_or_deleted():
    h_admin = get_headers("admin_audit", "ADMIN")
    random_id = str(uuid.uuid4())

    # PATCH (405)
    res1 = client.patch(f"/api/v1/audit/{random_id}", json={"action": "HACK"}, headers=h_admin)
    assert res1.status_code == 405

    # DELETE (405)
    res2 = client.delete(f"/api/v1/audit/{random_id}", headers=h_admin)
    assert res2.status_code == 405
