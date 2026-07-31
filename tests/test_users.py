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
        username="admin_sys",
        email="admin@cyberwolf.local",
        display_name="Admin User",
        password_hash=get_password_hash("AdminSecretPass123!"),
        role=UserRole.ADMIN,
        is_active=True,
    )
    analyst_user = User(
        username="analyst_sys",
        email="analyst@cyberwolf.local",
        display_name="Analyst User",
        password_hash=get_password_hash("AnalystSecretPass123!"),
        role=UserRole.ANALYST,
        is_active=True,
    )
    viewer_user = User(
        username="viewer_sys",
        email="viewer@cyberwolf.local",
        display_name="Viewer User",
        password_hash=get_password_hash("ViewerSecretPass123!"),
        role=UserRole.VIEWER,
        is_active=True,
    )
    db.add_all([admin_user, analyst_user, viewer_user])
    db.commit()
    yield
    db.close()
    Base.metadata.drop_all(bind=engine)
    app.dependency_overrides.clear()

def get_auth_header(username: str, role: str) -> dict:
    token = create_access_token(subject=username, role=role)
    return {"Authorization": f"Bearer {token}"}

# 1. User Administration Tests (ADMIN)
def test_admin_create_user_success():
    headers = get_auth_header("admin_sys", "ADMIN")
    payload = {
        "username": "new_analyst",
        "email": "new@cyberwolf.local",
        "display_name": "New Analyst",
        "password": "NewUserSecretPass123!",
        "role": "ANALYST"
    }
    response = client.post("/api/v1/users", json=payload, headers=headers)
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "new_analyst"
    assert data["role"] == "ANALYST"
    assert "password_hash" not in data

def test_admin_create_user_short_password():
    headers = get_auth_header("admin_sys", "ADMIN")
    payload = {
        "username": "short_user",
        "display_name": "Short Pass User",
        "password": "short",
        "role": "ANALYST"
    }
    response = client.post("/api/v1/users", json=payload, headers=headers)
    assert response.status_code == 400
    data = response.json()
    assert "Password must be at least 12 characters" in data["detail"]

def test_admin_create_user_duplicate_username():
    headers = get_auth_header("admin_sys", "ADMIN")
    payload = {
        "username": "analyst_sys",
        "display_name": "Dup User",
        "password": "ValidPassword123!",
        "role": "ANALYST"
    }
    response = client.post("/api/v1/users", json=payload, headers=headers)
    assert response.status_code == 400
    assert "Username already registered" in response.json()["detail"]

# 2. RBAC Enforcement on User Admin
def test_analyst_create_user_denied():
    headers = get_auth_header("analyst_sys", "ANALYST")
    payload = {
        "username": "unauthorized_created",
        "display_name": "User",
        "password": "ValidPassword123!",
        "role": "ANALYST"
    }
    response = client.post("/api/v1/users", json=payload, headers=headers)
    assert response.status_code == 403

def test_viewer_create_user_denied():
    headers = get_auth_header("viewer_sys", "VIEWER")
    payload = {
        "username": "unauthorized_created",
        "display_name": "User",
        "password": "ValidPassword123!",
        "role": "ANALYST"
    }
    response = client.post("/api/v1/users", json=payload, headers=headers)
    assert response.status_code == 403

# 3. User Deactivation & DB Authoritative Token Revocation
def test_admin_update_role_and_deactivate():
    admin_headers = get_auth_header("admin_sys", "ADMIN")
    
    db = TestingSessionLocal()
    analyst = db.query(User).filter(User.username == "analyst_sys").first()
    analyst_id = str(analyst.id)
    db.close()

    analyst_token = create_access_token(subject="analyst_sys", role="ANALYST")

    patch_resp = client.patch(
        f"/api/v1/users/{analyst_id}",
        json={"is_active": False, "role": "VIEWER"},
        headers=admin_headers
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["is_active"] is False
    assert patch_resp.json()["role"] == "VIEWER"

    me_resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {analyst_token}"})
    assert me_resp.status_code == 400
    assert "Inactive user account" in me_resp.json()["detail"]

# 4. Request ID & Header Bounding
def test_request_id_middleware_response_header():
    response = client.get("/health")
    assert response.status_code == 200
    assert "X-Request-ID" in response.headers
    
    custom_id = "test-req-id-12345"
    resp_custom = client.get("/health", headers={"X-Request-ID": custom_id})
    assert resp_custom.headers["X-Request-ID"] == custom_id
