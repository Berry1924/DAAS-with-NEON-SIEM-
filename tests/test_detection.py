import pytest
import uuid
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
from backend.app.models.alert_events import AlertEvent
from backend.app.models.detection_rule import DetectionRule
from backend.app.models.audit_log import AuditLog
from backend.app.models.enums import UserRole, EventOutcome, Severity, AlertStatus, AuditResult
from backend.app.core.security import get_password_hash, create_access_token
from backend.app.db.session import get_db
from security_engine.detection.rule_loader import RuleLoader, validate_rule, validate_conditions
from security_engine.detection.evaluator import RuleEvaluator

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

    # Create test users
    admin = User(
        username="admin_det",
        email="admin_det@cyberwolf.local",
        display_name="Admin Detection",
        password_hash=get_password_hash("AdminPass123!"),
        role=UserRole.ADMIN,
        is_active=True,
    )
    analyst = User(
        username="analyst_det",
        email="analyst_det@cyberwolf.local",
        display_name="Analyst Detection",
        password_hash=get_password_hash("AnalystPass123!"),
        role=UserRole.ANALYST,
        is_active=True,
    )
    viewer = User(
        username="viewer_det",
        email="viewer_det@cyberwolf.local",
        display_name="Viewer Detection",
        password_hash=get_password_hash("ViewerPass123!"),
        role=UserRole.VIEWER,
        is_active=True,
    )
    db.add_all([admin, analyst, viewer])
    db.commit()

    # Load rules into DB for testing
    loader = RuleLoader(rules_dir="rules")
    loader.sync(db)

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
# 1. Rule Loading & Validation Tests
# ---------------------------------------------------------
def test_rule_loader_loads_rules():
    db = TestingSessionLocal()
    rules = list(db.scalars(select(DetectionRule)).all())
    assert len(rules) >= 4
    rule_ids = {r.rule_id for r in rules}
    assert "CW-AUTH-001" in rule_ids
    assert "CW-NET-001" in rule_ids
    assert "CW-LOGIN-001" in rule_ids
    assert "CW-PRIV-001" in rule_ids
    db.close()

def test_validate_rule_rejects_missing_fields():
    invalid_rule = {"name": "Incomplete"}
    errors = validate_rule(invalid_rule)
    assert len(errors) > 0
    assert any("Missing required fields" in e for e in errors)

def test_validate_rule_rejects_unsafe_operators():
    invalid_rule = {
        "rule_id": "CW-TEST-BAD",
        "name": "Unsafe Rule",
        "description": "Test unsafe operator",
        "event_types": ["test"],
        "conditions": {"field": {"eval": "import os; os.system('whoami')"}},
        "severity": "HIGH",
        "enabled": True
    }
    errors = validate_rule(invalid_rule)
    assert len(errors) > 0
    assert any("Unsafe operator" in e for e in errors)

def test_validate_rule_rejects_out_of_bounds_threshold():
    invalid_rule = {
        "rule_id": "CW-TEST-BOUNDS",
        "name": "Bad Threshold",
        "description": "Test",
        "event_types": ["test"],
        "conditions": {},
        "severity": "LOW",
        "enabled": True,
        "threshold": 999999
    }
    errors = validate_rule(invalid_rule)
    assert len(errors) > 0
    assert any("threshold" in e for e in errors)

# ---------------------------------------------------------
# 2. Event Matching & Threshold Tests
# ---------------------------------------------------------
def test_single_event_below_threshold_does_not_trigger_alert():
    db = TestingSessionLocal()
    evaluator = RuleEvaluator()
    
    evt = Event(
        timestamp=datetime.now(timezone.utc),
        source_type="linux_auth",
        event_type="ssh_login_failed",
        source_ip="192.168.1.100",
        outcome=EventOutcome.FAILURE,
        severity=Severity.MEDIUM,
        raw_event={"msg": "Failed password"}
    )
    db.add(evt)
    db.commit()
    db.refresh(evt)

    alerts = evaluator.evaluate(evt, db)
    assert len(alerts) == 0
    db.close()

def test_threshold_matching_triggers_alert():
    db = TestingSessionLocal()
    evaluator = RuleEvaluator()
    now = datetime.now(timezone.utc)
    ip = "192.168.1.200"

    # Insert 4 prior failed events (below CW-AUTH-001 threshold 5)
    events = []
    for i in range(4):
        e = Event(
            timestamp=now - timedelta(seconds=10 * (4 - i)),
            source_type="linux_auth",
            event_type="ssh_login_failed",
            source_ip=ip,
            outcome=EventOutcome.FAILURE,
            severity=Severity.MEDIUM,
            raw_event={"msg": f"Failed {i}"}
        )
        db.add(e)
        events.append(e)
    db.commit()

    # 5th failed event triggers CW-AUTH-001
    trigger_evt = Event(
        timestamp=now,
        source_type="linux_auth",
        event_type="ssh_login_failed",
        source_ip=ip,
        outcome=EventOutcome.FAILURE,
        severity=Severity.MEDIUM,
        raw_event={"msg": "Failed 5th"}
    )
    db.add(trigger_evt)
    db.commit()
    db.refresh(trigger_evt)

    alerts = evaluator.evaluate(trigger_evt, db)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.severity == Severity.HIGH
    assert alert.source_ip == ip
    assert "Brute Force" in alert.title

    # Check evidence linking in alert_events table
    links = list(db.scalars(select(AlertEvent).where(AlertEvent.alert_id == alert.id)).all())
    assert len(links) >= 5
    roles = {l.evidence_role for l in links}
    assert "trigger" in roles
    assert "supporting" in roles
    db.close()

def test_time_window_expiration_prevents_alert():
    db = TestingSessionLocal()
    evaluator = RuleEvaluator()
    now = datetime.now(timezone.utc)
    ip = "192.168.1.201"

    # 4 events older than 300s window (CW-AUTH-001 window is 300s)
    for i in range(4):
        e = Event(
            timestamp=now - timedelta(seconds=400 + (10 * i)),
            source_type="linux_auth",
            event_type="ssh_login_failed",
            source_ip=ip,
            outcome=EventOutcome.FAILURE,
            severity=Severity.MEDIUM,
            raw_event={"msg": "Old failure"}
        )
        db.add(e)
    db.commit()

    # 5th event at current time (only 1 within window)
    trigger_evt = Event(
        timestamp=now,
        source_type="linux_auth",
        event_type="ssh_login_failed",
        source_ip=ip,
        outcome=EventOutcome.FAILURE,
        severity=Severity.MEDIUM,
        raw_event={"msg": "Current failure"}
    )
    db.add(trigger_evt)
    db.commit()
    db.refresh(trigger_evt)

    alerts = evaluator.evaluate(trigger_evt, db)
    assert len(alerts) == 0
    db.close()

def test_deduplication_prevents_duplicate_active_alerts():
    db = TestingSessionLocal()
    evaluator = RuleEvaluator()
    now = datetime.now(timezone.utc)
    ip = "192.168.1.202"

    # Create 5 failed events to trigger alert
    for i in range(5):
        e = Event(
            timestamp=now - timedelta(seconds=5 * (5 - i)),
            source_type="linux_auth",
            event_type="ssh_login_failed",
            source_ip=ip,
            outcome=EventOutcome.FAILURE,
            severity=Severity.MEDIUM,
            raw_event={"msg": "Fail"}
        )
        db.add(e)
    db.commit()
    last_evt = e

    # First evaluation creates alert
    alerts1 = evaluator.evaluate(last_evt, db)
    assert len(alerts1) == 1

    # 6th failed event shortly after
    evt6 = Event(
        timestamp=now + timedelta(seconds=1),
        source_type="linux_auth",
        event_type="ssh_login_failed",
        source_ip=ip,
        outcome=EventOutcome.FAILURE,
        severity=Severity.MEDIUM,
        raw_event={"msg": "Fail 6"}
    )
    db.add(evt6)
    db.commit()

    # Second evaluation should be deduplicated (active NEW alert exists)
    alerts2 = evaluator.evaluate(evt6, db)
    assert len(alerts2) == 0
    db.close()

# ---------------------------------------------------------
# 3. Alert REST API & RBAC Tests
# ---------------------------------------------------------
def test_unauthenticated_alerts_api_returns_401():
    response = client.get("/api/v1/alerts")
    assert response.status_code == 401

def test_list_alerts_rbac_access():
    headers_viewer = get_headers("viewer_det", "VIEWER")
    headers_analyst = get_headers("analyst_det", "ANALYST")

    res_v = client.get("/api/v1/alerts", headers=headers_viewer)
    assert res_v.status_code == 200

    res_a = client.get("/api/v1/alerts", headers=headers_analyst)
    assert res_a.status_code == 200

def test_alert_detail_api_with_linked_evidence():
    db = TestingSessionLocal()
    evaluator = RuleEvaluator()
    now = datetime.now(timezone.utc)
    ip = "10.0.0.99"

    for i in range(5):
        e = Event(
            timestamp=now - timedelta(seconds=2 * (5 - i)),
            source_type="linux_auth",
            event_type="ssh_login_failed",
            source_ip=ip,
            outcome=EventOutcome.FAILURE,
            severity=Severity.MEDIUM,
            raw_event={"msg": f"Event {i}"}
        )
        db.add(e)
    db.commit()

    alerts = evaluator.evaluate(e, db)
    assert len(alerts) == 1
    alert_id = alerts[0].id
    db.close()

    headers = get_headers("analyst_det", "ANALYST")
    response = client.get(f"/api/v1/alerts/{alert_id}", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(alert_id)
    assert "linked_events" in data
    assert len(data["linked_events"]) >= 5

def test_patch_alert_status_rbac_and_transitions():
    db = TestingSessionLocal()
    evaluator = RuleEvaluator()
    now = datetime.now(timezone.utc)
    ip = "10.0.0.100"

    for i in range(5):
        e = Event(
            timestamp=now - timedelta(seconds=2 * (5 - i)),
            source_type="linux_auth",
            event_type="ssh_login_failed",
            source_ip=ip,
            outcome=EventOutcome.FAILURE,
            severity=Severity.MEDIUM,
            raw_event={"msg": f"Event {i}"}
        )
        db.add(e)
    db.commit()

    alerts = evaluator.evaluate(e, db)
    alert_id = alerts[0].id
    db.close()

    # VIEWER forbidden from updating status
    h_viewer = get_headers("viewer_det", "VIEWER")
    r_v = client.patch(f"/api/v1/alerts/{alert_id}", json={"status": "ACKNOWLEDGED"}, headers=h_viewer)
    assert r_v.status_code == 403

    # ANALYST valid transition: NEW -> ACKNOWLEDGED
    h_analyst = get_headers("analyst_det", "ANALYST")
    r_a1 = client.patch(f"/api/v1/alerts/{alert_id}", json={"status": "ACKNOWLEDGED", "comment": "Triage started"}, headers=h_analyst)
    assert r_a1.status_code == 200
    assert r_a1.json()["status"] == "ACKNOWLEDGED"

    # ANALYST invalid transition: ACKNOWLEDGED -> NEW
    r_a2 = client.patch(f"/api/v1/alerts/{alert_id}", json={"status": "NEW"}, headers=h_analyst)
    assert r_a2.status_code == 400
    assert "Invalid status transition" in r_a2.json()["detail"]

    # Verify audit log entry created
    db = TestingSessionLocal()
    audit = db.scalars(select(AuditLog).where(AuditLog.action == "ALERT_STATUS_CHANGED")).first()
    assert audit is not None
    assert audit.target_id == str(alert_id)
    assert audit.result == AuditResult.SUCCESS
    db.close()
