from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from jose import jwt

from backend.app.main import app
from backend.app.models.base import Base
from backend.app.models.user import User
from backend.app.models.enums import UserRole, AuditResult
from backend.app.models.audit_log import AuditLog
from backend.app.core.security import get_password_hash, verify_password, create_access_token, decode_access_token, validate_password_strength, ALGORITHM
from backend.app.core.config import settings
from backend.app.db.session import get_db
from backend.app.api.deps import RequireRole

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
    app.dependency_overrides.clear()

# 1. Password Bounds Security Tests
def test_password_bounds_minimum_length():
    with pytest.raises(ValueError, match="at least 12 characters"):
        validate_password_strength("ShortPass1!")

def test_password_bounds_maximum_bytes():
    over_limit = "A" * 73
    with pytest.raises(ValueError, match="exceeds maximum allowable size"):
        validate_password_strength(over_limit)

def test_password_bounds_whitespace_only():
    with pytest.raises(ValueError, match="empty or whitespace-only"):
        validate_password_strength("            ")

def test_password_bounds_unicode_multibyte():
    valid_unicode = "Password123🔐🛡️"
    validate_password_strength(valid_unicode)
    hashed = get_password_hash(valid_unicode)
    assert verify_password(valid_unicode, hashed) is True

# 2. JWT Security & Expiration Tests
def test_jwt_expired_token_rejected():
    past_expiry = datetime.now(timezone.utc) - timedelta(minutes=10)
    expired_token = jwt.encode({"sub": "analyst_user", "exp": past_expiry}, settings.SECRET_KEY, algorithm=ALGORITHM)
    
    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert response.status_code == 401

def test_jwt_tampered_token_rejected():
    valid_token = create_access_token(subject="analyst_user", role="ANALYST")
    tampered_token = valid_token[:-4] + "xxxx"
    
    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tampered_token}"})
    assert response.status_code == 401

def test_jwt_malformed_token_rejected():
    response = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer not_a_valid_jwt_format"})
    assert response.status_code == 401

def test_jwt_wrong_bearer_scheme_rejected():
    valid_token = create_access_token(subject="analyst_user", role="ANALYST")
    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Basic {valid_token}"})
    assert response.status_code == 401

# 3. Login Endpoint Integration Tests
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
        json={"username": "analyst_user", "password": "WrongPassword123!"}
    )
    assert response.status_code == 401
    data = response.json()
    assert data["detail"] == "Invalid username or password"

def test_failed_user_login_nonexistent_user():
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "nonexistent_user", "password": "SomePassword123!"}
    )
    assert response.status_code == 401
    data = response.json()
    assert data["detail"] == "Invalid username or password"

# 4. Authenticated Me Endpoint Tests
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

# 5. Explicit RBAC Permission Matrix Verification
def test_rbac_matrix_explicit_permissions():
    db = TestingSessionLocal()
    admin_user = db.query(User).filter(User.username == "admin_user").first()
    analyst_user = db.query(User).filter(User.username == "analyst_user").first()
    viewer_user = db.query(User).filter(User.username == "viewer_user").first()

    read_guard = RequireRole([UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER])
    investigate_guard = RequireRole([UserRole.ADMIN, UserRole.ANALYST])
    administer_guard = RequireRole([UserRole.ADMIN])

    # VIEWER MATRIX: READ = PASS, INVESTIGATE = DENY (403), ADMINISTER = DENY (403)
    assert read_guard(current_user=viewer_user) == viewer_user
    with pytest.raises(Exception) as exc_v1:
        investigate_guard(current_user=viewer_user)
    assert exc_v1.value.status_code == 403
    with pytest.raises(Exception) as exc_v2:
        administer_guard(current_user=viewer_user)
    assert exc_v2.value.status_code == 403

    # ANALYST MATRIX: READ = PASS, INVESTIGATE = PASS, ADMINISTER = DENY (403)
    assert read_guard(current_user=analyst_user) == analyst_user
    assert investigate_guard(current_user=analyst_user) == analyst_user
    with pytest.raises(Exception) as exc_a1:
        administer_guard(current_user=analyst_user)
    assert exc_a1.value.status_code == 403

    # ADMIN MATRIX: READ = PASS, INVESTIGATE = PASS, ADMINISTER = PASS
    assert read_guard(current_user=admin_user) == admin_user
    assert investigate_guard(current_user=admin_user) == admin_user
    assert administer_guard(current_user=admin_user) == admin_user

    db.close()

# 6. Audit Logging & Secret Exclusion Test
def test_audit_logging_secret_exclusion():
    client.post(
        "/api/v1/auth/login",
        json={"username": "admin_user", "password": "AdminPass123!"}
    )
    client.post(
        "/api/v1/auth/login",
        json={"username": "admin_user", "password": "WrongPassword123!"}
    )

    db = TestingSessionLocal()
    success_audit = db.query(AuditLog).filter(AuditLog.action == "USER_LOGIN_SUCCESS").first()
    failed_audit = db.query(AuditLog).filter(AuditLog.action == "USER_LOGIN_FAILED").first()

    assert success_audit is not None
    assert failed_audit is not None

    for audit in [success_audit, failed_audit]:
        metadata_str = str(audit.audit_metadata)
        assert "AdminPass123!" not in metadata_str
        assert "WrongPassword123!" not in metadata_str
        assert "password_hash" not in metadata_str
        assert "Authorization" not in metadata_str
    db.close()
