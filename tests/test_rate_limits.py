import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.config import settings
from backend.app.core.security import create_access_token, get_password_hash
from backend.app.db.session import get_db
from backend.app.main import app
from backend.app.models.base import Base
from backend.app.models.enums import UserRole
from backend.app.models.user import User
from backend.app.services.ingestion_service import ingestion_service


engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
client = TestClient(app)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def setup_db():
    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    db.add(User(
        username="rate_limit_analyst",
        email="rate-limit@example.invalid",
        display_name="Rate Limit Analyst",
        password_hash=get_password_hash("RateLimitPass123!"),
        role=UserRole.ANALYST,
        is_active=True,
    ))
    db.commit()
    ingestion_service._seen_event_keys.clear()
    ingestion_service._envelope_buffer.clear()
    yield
    db.close()
    Base.metadata.drop_all(bind=engine)
    app.dependency_overrides.clear()


def _headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {create_access_token('rate_limit_analyst', 'ANALYST')}",
        "Content-Type": "application/json",
    }


def test_login_limit_returns_429_after_configured_test_threshold(monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_LOGIN", "1/minute")
    payload = {"username": "rate_limit_analyst", "password": "RateLimitPass123!"}

    assert client.post("/api/v1/auth/login", json=payload).status_code == 200
    assert client.post("/api/v1/auth/login", json=payload).status_code == 429


def test_single_ingestion_limit_returns_429_after_configured_test_threshold(monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_INGEST", "1/minute")
    payload = {"source_type": "json", "payload": {"event": "rate-limit-test"}}

    assert client.post("/api/v1/events", json=payload, headers=_headers()).status_code == 202
    assert client.post("/api/v1/events", json=payload, headers=_headers()).status_code == 429


def test_batch_ingestion_limit_returns_429_after_configured_test_threshold(monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_INGEST", "1/minute")
    payload = [{"source_type": "json", "payload": {"event": "rate-limit-batch-test"}}]

    assert client.post("/api/v1/events/batch", json=payload, headers=_headers()).status_code == 202
    assert client.post("/api/v1/events/batch", json=payload, headers=_headers()).status_code == 429
