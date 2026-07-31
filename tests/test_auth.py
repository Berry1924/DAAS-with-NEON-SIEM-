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
from backend.app.core.security import get_password_hash, verify_password, create_access_token, decode_access_token
from backend.app.db.session import get_db
from backend.app.api.deps import RequireRole

# StaticPool shared in-memory SQLite engine for multi-thread TestClient
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

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    # Seed test users
    admin_user = User(
        username="admin_user",
        email="admin@cyberwolf.local",
        display_name="Admin User",
        password_hash=get_password_hash("AdminPass123!"),
        role=UserRole.ADMIN,
        is_active=True,
    )
    analyst_user = User(
        username="analyst_user",
        email="analyst@cyberwolf.local",
        display_name="Analyst User",
        password_hash=get_password_hash("AnalystPass123!"),
        role=UserRole.ANALYST,
        is_active=True,
    )
    viewer_user = User(
        username="viewer_user",
        email="viewer@cyberwolf.local",
        display_name="Viewer User",
        password_hash=get_password_hash("ViewerPass123!"),
        role=UserRole.VIEWER,
        is_active=True,
    )
    db.add_all([admin_user, analyst_user, viewer_user])
    db.commit()
    yield
    db.close()
    Base.metadata.drop_all(bind=engine)

# 1. Security Core Unit Tests
def test_password_hashing_and_verification():
    raw_pass = "SecurePass123!"
    hashed = get_password_hash(raw_pass)
    assert hashed != raw_pass
    assert verify_password(raw_pass, hashed) is True
    assert verify_password("WrongPass!", hashed) is False

def test_jwt_token_generation_and_decoding():
    token = create_access_token(subject="analyst_user", role="ANALYST")
    payload = decode_access_token(token)
    assert payload is not None
    assert payload["sub"] == "analyst_user"
    assert payload["role"] == "ANALYST"
    assert payload["type"] == "access"

# 2. Login Endpoint Integration Tests
def test_successful_user_login():
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "analyst_user", "password": "AnalystPass123!"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["username"] == "analyst_user"
    assert data["user"]["role"] == "ANALYST"
    assert "password_hash" not in data["user"]

def test_failed_user_login_invalid_password():
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "analyst_user", "password": "WrongPassword!"}
    )
    assert response.status_code == 401
    data = response.json()
    assert data["detail"] == "Invalid username or password"

def test_failed_user_login_nonexistent_user():
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "nonexistent_user", "password": "SomePassword!"}
    )
    assert response.status_code == 401
    data = response.json()
    assert data["detail"] == "Invalid username or password"

# 3. Authenticated Me Endpoint Tests
def test_get_current_user_me_endpoint():
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"username": "analyst_user", "password": "AnalystPass123!"}
    )
    token = login_resp.json()["access_token"]

    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "analyst_user"
    assert data["role"] == "ANALYST"
    assert "password_hash" not in data

def test_me_endpoint_without_token():
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401

def test_me_endpoint_invalid_token():
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer invalid_token_xyz"}
    )
    assert response.status_code == 401

# 4. Server-Side RBAC Dependency Tests
def test_server_side_rbac_role_guard():
    db = TestingSessionLocal()
    admin_user = db.query(User).filter(User.username == "admin_user").first()
    analyst_user = db.query(User).filter(User.username == "analyst_user").first()
    viewer_user = db.query(User).filter(User.username == "viewer_user").first()

    admin_guard = RequireRole([UserRole.ADMIN])
    analyst_admin_guard = RequireRole([UserRole.ADMIN, UserRole.ANALYST])

    # Admin passes admin guard
    assert admin_guard(current_user=admin_user) == admin_user

    # Analyst passes analyst_admin guard
    assert analyst_admin_guard(current_user=analyst_user) == analyst_user

    # Analyst fails admin guard -> HTTP 403
    with pytest.raises(Exception) as exc_info:
        admin_guard(current_user=analyst_user)
    assert exc_info.value.status_code == 403

    # Viewer fails admin guard -> HTTP 403
    with pytest.raises(Exception) as exc_info:
        admin_guard(current_user=viewer_user)
    assert exc_info.value.status_code == 403

    db.close()

# 5. Audit Logging on Login
def test_login_audit_logging():
    # Successful login
    client.post(
        "/api/v1/auth/login",
        json={"username": "admin_user", "password": "AdminPass123!"}
    )
    # Failed login
    client.post(
        "/api/v1/auth/login",
        json={"username": "admin_user", "password": "WrongPassword!"}
    )

    db = TestingSessionLocal()
    success_audit = db.query(AuditLog).filter(AuditLog.action == "USER_LOGIN_SUCCESS").first()
    failed_audit = db.query(AuditLog).filter(AuditLog.action == "USER_LOGIN_FAILED").first()

    assert success_audit is not None
    assert success_audit.result == AuditResult.SUCCESS

    assert failed_audit is not None
    assert failed_audit.result == AuditResult.FAILURE
    db.close()
