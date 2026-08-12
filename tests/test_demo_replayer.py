import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.main import app
from backend.app.models.base import Base
from backend.app.models.user import User
from backend.app.models.event import Event
from backend.app.models.alert import Alert
from backend.app.models.correlation import CorrelationGroup
from backend.app.models.incident import Incident
from backend.app.models.audit_log import AuditLog
from backend.app.models.enums import UserRole
from backend.app.core.security import get_password_hash, create_access_token
from backend.app.db.session import get_db

from security_engine.detection.rule_loader import RuleLoader
from security_engine.demo.generator import GoldenPathDemoGenerator, demo_generator

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

    # Load detection rules
    loader = RuleLoader("rules")
    loader.sync(db)

    admin = User(
        username="admin_demo",
        email="admin_demo@cyberwolf.local",
        display_name="Admin Demo",
        password_hash=get_password_hash("AdminPass123!"),
        role=UserRole.ADMIN,
        is_active=True,
    )
    analyst = User(
        username="analyst_demo",
        email="analyst_demo@cyberwolf.local",
        display_name="Analyst Demo",
        password_hash=get_password_hash("AnalystPass123!"),
        role=UserRole.ANALYST,
        is_active=True,
    )
    db.add_all([admin, analyst])
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
# Unit Tests — Generator Determinism & Structure
# ---------------------------------------------------------
def test_golden_path_generates_17_events():
    gen = GoldenPathDemoGenerator()
    envelopes = gen.generate_envelopes()
    assert len(envelopes) == 17

def test_golden_path_events_are_deterministic():
    gen = GoldenPathDemoGenerator()
    fixed_base = datetime(2026, 8, 11, 12, 0, 0, tzinfo=timezone.utc)
    envelopes1 = gen.generate_envelopes(base_time=fixed_base)
    envelopes2 = gen.generate_envelopes(base_time=fixed_base)

    assert len(envelopes1) == len(envelopes2)
    for e1, e2 in zip(envelopes1, envelopes2):
        assert e1.source_type == e2.source_type
        assert e1.raw_payload == e2.raw_payload
        assert e1.source_event_id == e2.source_event_id

# ---------------------------------------------------------
# Integration Tests — Security Pipeline Stage Triggers
# ---------------------------------------------------------
def test_golden_path_triggers_port_scan():
    db = TestingSessionLocal()
    res = demo_generator.replay(db)
    assert "CW-NET-001" in res.rules_triggered
    db.close()

def test_golden_path_triggers_brute_force():
    db = TestingSessionLocal()
    res = demo_generator.replay(db)
    assert "CW-AUTH-001" in res.rules_triggered
    db.close()

def test_golden_path_triggers_suspicious_login():
    db = TestingSessionLocal()
    res = demo_generator.replay(db)
    assert "CW-LOGIN-001" in res.rules_triggered
    db.close()

def test_golden_path_triggers_privilege_escalation():
    db = TestingSessionLocal()
    res = demo_generator.replay(db)
    assert "CW-PRIV-001" in res.rules_triggered
    db.close()

def test_golden_path_creates_one_correlation():
    db = TestingSessionLocal()
    demo_generator.replay(db)
    corrs = list(db.scalars(select(CorrelationGroup)).all())
    assert len(corrs) == 1
    db.close()

def test_golden_path_detects_golden_sequence():
    db = TestingSessionLocal()
    res = demo_generator.replay(db)
    corr = db.scalar(select(CorrelationGroup).filter(CorrelationGroup.is_golden_sequence == True))
    assert corr is not None
    assert res.correlation_created is True
    db.close()

def test_golden_path_calculates_risk_100():
    db = TestingSessionLocal()
    res = demo_generator.replay(db)
    assert res.risk_score == 100
    assert res.severity == "CRITICAL"
    db.close()

def test_golden_path_creates_incident():
    db = TestingSessionLocal()
    res = demo_generator.replay(db)
    incidents = list(db.scalars(select(Incident)).all())
    assert len(incidents) == 1
    assert res.incident_key == incidents[0].incident_key
    assert "Potential Host Compromise" in incidents[0].title
    db.close()

def test_golden_path_creates_audit_records():
    db = TestingSessionLocal()
    res = demo_generator.replay(db)
    audits = list(db.scalars(select(AuditLog)).all())
    assert len(audits) >= 1
    assert res.audit_records_created == len(audits)
    db.close()

def test_golden_path_updates_dashboard():
    db = TestingSessionLocal()
    res = demo_generator.replay(db)
    assert res.dashboard_events_24h == 17
    db.close()

def test_replay_does_not_create_uncontrolled_duplicate_incidents():
    db = TestingSessionLocal()
    fixed_base = datetime.now(timezone.utc) - timedelta(minutes=5)
    
    # First run
    demo_generator.replay(db, base_time=fixed_base)
    incidents_count_1 = len(db.scalars(select(Incident)).all())
    assert incidents_count_1 == 1

    # Second run with same base time (duplicate envelopes skipped)
    demo_generator.replay(db, base_time=fixed_base)
    incidents_count_2 = len(db.scalars(select(Incident)).all())
    assert incidents_count_2 == 1
    db.close()

# ---------------------------------------------------------
# Determinism Test Across Two Isolated DB Instances
# ---------------------------------------------------------
def test_determinism_across_two_isolated_runs():
    fixed_base = datetime(2026, 8, 11, 10, 0, 0, tzinfo=timezone.utc)

    # DB Run 1
    engine1 = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Session1 = sessionmaker(autocommit=False, autoflush=False, bind=engine1)
    Base.metadata.create_all(bind=engine1)
    db1 = Session1()
    RuleLoader("rules").sync(db1)
    res1 = GoldenPathDemoGenerator().replay(db1, base_time=fixed_base)
    db1.close()

    # DB Run 2
    engine2 = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Session2 = sessionmaker(autocommit=False, autoflush=False, bind=engine2)
    Base.metadata.create_all(bind=engine2)
    db2 = Session2()
    RuleLoader("rules").sync(db2)
    res2 = GoldenPathDemoGenerator().replay(db2, base_time=fixed_base)
    db2.close()

    # Compare logical security outputs
    assert res1.events_generated == res2.events_generated == 17
    assert res1.alerts_created == res2.alerts_created == 4
    assert res1.rules_triggered == res2.rules_triggered == ["CW-AUTH-001", "CW-LOGIN-001", "CW-NET-001", "CW-PRIV-001"]
    assert res1.correlation_created == res2.correlation_created is True
    assert res1.risk_score == res2.risk_score == 100
    assert res1.severity == res2.severity == "CRITICAL"

# ---------------------------------------------------------
# API Tests — POST /api/v1/demo/replay (ADMIN Only)
# ---------------------------------------------------------
def test_unauthenticated_demo_replay_returns_401():
    res = client.post("/api/v1/demo/replay")
    assert res.status_code == 401

def test_analyst_demo_replay_returns_403():
    h = get_headers("analyst_demo", "ANALYST")
    res = client.post("/api/v1/demo/replay", headers=h)
    assert res.status_code == 403

def test_admin_demo_replay_success():
    h = get_headers("admin_demo", "ADMIN")
    res = client.post("/api/v1/demo/replay", headers=h)
    assert res.status_code == 200
    data = res.json()
    assert data["events_generated"] == 17
    assert data["events_persisted"] == 17
    assert data["alerts_created"] == 4
    assert data["correlation_created"] is True
    assert data["risk_score"] == 100
    assert data["severity"] == "CRITICAL"
    assert data["incident_key"] is not None
