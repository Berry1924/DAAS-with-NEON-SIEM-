import pytest
import uuid
import json
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.main import app
from backend.app.models.base import Base
from backend.app.models.user import User
from backend.app.models.event import Event
from backend.app.models.alert import Alert
from backend.app.models.alert_events import AlertEvent
from backend.app.models.detection_rule import DetectionRule
from backend.app.models.correlation import CorrelationGroup
from backend.app.models.incident import Incident
from backend.app.models.incident_alerts import IncidentAlert  # junction table
from backend.app.models.audit_log import AuditLog
from backend.app.models.enums import UserRole, EventOutcome, Severity, IncidentStatus, AlertStatus, AuditResult
from backend.app.core.security import get_password_hash, create_access_token
from backend.app.db.session import get_db
from security_engine.detection.rule_loader import RuleLoader
from security_engine.demo.generator import demo_generator, GoldenPathDemoGenerator

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
    loader = RuleLoader("rules")
    loader.sync(db)
    # Create 3 users
    admin = User(
        username="admin_m15",
        email="admin_m15@neon.local",
        display_name="Admin M15",
        password_hash=get_password_hash("AdminPass123!"),
        role=UserRole.ADMIN,
        is_active=True,
    )
    analyst = User(
        username="analyst_m15",
        email="analyst_m15@neon.local",
        display_name="Analyst M15",
        password_hash=get_password_hash("AnalystPass123!"),
        role=UserRole.ANALYST,
        is_active=True,
    )
    viewer = User(
        username="viewer_m15",
        email="viewer_m15@neon.local",
        display_name="Viewer M15",
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
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


@pytest.fixture
def golden_path_db():
    db = TestingSessionLocal()
    demo_generator.replay(db)
    yield db
    db.close()


# =====================================================================
# Section 1: Golden Path Pipeline (run demo once, verify all stages)
# =====================================================================

# 1.1 Event Verification
def test_golden_path_generates_17_events(golden_path_db):
    event_count = golden_path_db.query(Event).count()
    assert event_count == 17


def test_golden_path_events_have_valid_fields(golden_path_db):
    events = golden_path_db.query(Event).all()
    for event in events:
        assert event.timestamp is not None
        assert event.source_type is not None
        assert event.event_type is not None
        assert event.outcome is not None
        assert event.severity is not None


def test_golden_path_source_entity_preserved(golden_path_db):
    events = golden_path_db.query(Event).all()
    for event in events:
        # Based on demo generator spec
        assert event.source_ip == "192.168.1.50"


def test_golden_path_timestamps_within_detection_window(golden_path_db):
    events = golden_path_db.query(Event).order_by(Event.timestamp).all()
    assert len(events) == 17
    min_time = events[0].timestamp
    max_time = events[-1].timestamp
    # Demo window should be within 120 seconds
    assert (max_time - min_time).total_seconds() <= 120


def test_golden_path_event_types_correct(golden_path_db):
    events = golden_path_db.query(Event).all()
    connection_count = sum(1 for e in events if e.event_type == "connection")
    authentication_count = sum(1 for e in events if e.event_type == "authentication")
    privilege_escalation_count = sum(1 for e in events if e.event_type == "privilege_escalation")

    assert connection_count == 10
    # The spec mentions 5+1 authentication (6 total)
    assert authentication_count == 6
    assert privilege_escalation_count == 1


# 1.2 Detection Verification
def test_golden_path_creates_four_alerts(golden_path_db):
    alert_count = golden_path_db.query(Alert).count()
    assert alert_count == 4


def test_golden_path_alert_rule_ids(golden_path_db):
    alerts = golden_path_db.query(Alert).all()
    # Query the actual detection rules to check their rule_id strings
    db_rules = golden_path_db.query(DetectionRule).filter(DetectionRule.id.in_([a.rule_id for a in alerts])).all()
    triggered_rule_ids = {r.rule_id for r in db_rules}
    
    expected_rules = {"CW-NET-001", "CW-AUTH-001", "CW-LOGIN-001", "CW-PRIV-001"}
    assert expected_rules.issubset(triggered_rule_ids)


def test_golden_path_alerts_have_evidence_links(golden_path_db):
    alerts = golden_path_db.query(Alert).all()
    for alert in alerts:
        links_count = golden_path_db.query(AlertEvent).filter(AlertEvent.alert_id == alert.id).count()
        assert links_count >= 1


def test_golden_path_no_duplicate_alerts_on_replay(golden_path_db):
    # Replay again with same exact base_time/seed if possible, 
    # Since demo_generator.replay uses current time, we'll just check if it deduplicates or if we can mock it
    # We will simulate replaying with the exact same data to see if alerts duplicate
    original_alert_count = golden_path_db.query(Alert).count()
    
    # We assume replay creates new events with new times normally, 
    # but the test asks to "replay again with same base_time, count still 4"
    # The generator allows passing a base_time
    generator = GoldenPathDemoGenerator()
    base_time = golden_path_db.query(Event).order_by(Event.timestamp).first().timestamp
    generator.replay(golden_path_db, base_time=base_time)
    
    new_alert_count = golden_path_db.query(Alert).count()
    assert new_alert_count == original_alert_count


# 1.3 Correlation Verification
def test_golden_path_creates_one_correlation(golden_path_db):
    corr_count = golden_path_db.query(CorrelationGroup).count()
    assert corr_count == 1


def test_golden_path_correlation_is_golden(golden_path_db):
    corr = golden_path_db.query(CorrelationGroup).first()
    assert corr.is_golden_sequence is True
    assert "Potential Host Compromise" in corr.pattern_matched


def test_golden_path_correlation_links_alerts(golden_path_db):
    corr = golden_path_db.query(CorrelationGroup).first()
    # CorrelationGroup stores alert IDs in alert_ids JSON list
    assert corr.alert_count >= 2
    assert len(corr.alert_ids) >= 2


# 1.4 Risk Verification
def test_golden_path_risk_score_100(golden_path_db):
    incident = golden_path_db.query(Incident).first()
    assert incident.risk_score == 100


def test_golden_path_risk_explanation_factors(golden_path_db):
    incident = golden_path_db.query(Incident).first()
    explanation = incident.risk_explanation if isinstance(incident.risk_explanation, dict) else json.loads(incident.risk_explanation or "{}")
    
    assert "base_risk" in explanation
    assert "correlation_bonus" in explanation
    assert "compromise_indicator_bonus" in explanation
    assert "privilege_escalation_bonus" in explanation


# 1.5 Incident Verification
def test_golden_path_creates_one_incident(golden_path_db):
    incident_count = golden_path_db.query(Incident).count()
    assert incident_count == 1


def test_golden_path_incident_fields(golden_path_db):
    incident = golden_path_db.query(Incident).first()
    assert "Potential Host Compromise" in incident.title
    assert incident.severity == Severity.CRITICAL
    assert incident.risk_score == 100


def test_golden_path_incident_no_duplicate_on_replay(golden_path_db):
    original_incident_count = golden_path_db.query(Incident).count()
    
    generator = GoldenPathDemoGenerator()
    base_time = golden_path_db.query(Event).order_by(Event.timestamp).first().timestamp
    generator.replay(golden_path_db, base_time=base_time)
    
    new_incident_count = golden_path_db.query(Incident).count()
    assert new_incident_count == original_incident_count


# 1.6 Audit Verification
def test_golden_path_audit_records_created(golden_path_db):
    audit_count = golden_path_db.query(AuditLog).count()
    assert audit_count >= 1


def test_golden_path_audit_fields_valid(golden_path_db):
    audits = golden_path_db.query(AuditLog).all()
    for audit in audits:
        assert audit.action is not None
        assert audit.timestamp is not None


def test_golden_path_audit_sensitive_data_redacted(golden_path_db):
    # Simulate an audit log creation with sensitive data to test the redaction logic
    from backend.app.services.audit_service import audit_service as _audit_service
    
    metadata = {
        "normal_key": "normal_value",
        "password": "supersecretpassword",
        "token": "jwt-token-123",
        "secret": "my-secret-key"
    }
    
    admin_user = golden_path_db.query(User).filter(User.username == "admin_m15").first()
    
    audit_record = _audit_service.log(
        db=golden_path_db,
        action="TEST_ACTION",
        actor_id=admin_user.id,
        target_type="TEST",
        target_id="123",
        result=AuditResult.SUCCESS,
        metadata=metadata
    )
    
    saved_metadata = audit_record.audit_metadata if isinstance(audit_record.audit_metadata, dict) else json.loads(audit_record.audit_metadata)
    
    assert saved_metadata["normal_key"] == "normal_value"
    assert saved_metadata["password"] == "[REDACTED]"
    assert saved_metadata["token"] == "[REDACTED]"
    assert saved_metadata["secret"] == "[REDACTED]"


# =====================================================================
# Section 2: Dashboard API Verification
# =====================================================================

def test_dashboard_reflects_golden_path():
    headers = get_headers("viewer_m15", "VIEWER")
    
    # First replay demo to populate data
    db = TestingSessionLocal()
    demo_generator.replay(db)
    db.close()
    
    response = client.get("/api/v1/dashboard/summary", headers=headers)
    assert response.status_code == 200
    
    data = response.json()
    assert data["total_events_24h"] >= 17
    assert data["open_incidents"] == 1
    
    recent_incidents = data.get("recent_incidents", [])
    assert len(recent_incidents) >= 1
    assert "Potential Host Compromise" in recent_incidents[0]["title"]


def test_dashboard_top_rules_contains_golden_path():
    headers = get_headers("viewer_m15", "VIEWER")
    
    db = TestingSessionLocal()
    demo_generator.replay(db)
    db.close()
    
    response = client.get("/api/v1/dashboard/summary", headers=headers)
    assert response.status_code == 200
    
    data = response.json()
    top_rules = [r["rule_id"] for r in data.get("top_detection_rules", [])]
    
    expected_rules = {"CW-NET-001", "CW-AUTH-001", "CW-LOGIN-001", "CW-PRIV-001"}
    assert any(rule in top_rules for rule in expected_rules)


# =====================================================================
# Section 3: RBAC Regression
# =====================================================================

def test_viewer_can_read_incidents():
    headers = get_headers("viewer_m15", "VIEWER")
    response = client.get("/api/v1/incidents", headers=headers)
    assert response.status_code == 200


def test_viewer_cannot_mutate_incident():
    # Setup data
    db = TestingSessionLocal()
    demo_generator.replay(db)
    incident = db.query(Incident).first()
    incident_id = str(incident.id)
    db.close()

    headers = get_headers("viewer_m15", "VIEWER")
    response = client.patch(f"/api/v1/incidents/{incident_id}/status", json={"status": "ACKNOWLEDGED"}, headers=headers)
    assert response.status_code == 403


def test_analyst_can_mutate_incident():
    # Setup data
    db = TestingSessionLocal()
    demo_generator.replay(db)
    incident = db.query(Incident).first()
    incident_id = str(incident.id)
    db.close()

    headers = get_headers("analyst_m15", "ANALYST")
    response = client.patch(f"/api/v1/incidents/{incident_id}/status", json={"status": "ACKNOWLEDGED"}, headers=headers)
    assert response.status_code == 200


def test_admin_can_access_audit():
    headers = get_headers("admin_m15", "ADMIN")
    response = client.get("/api/v1/audit", headers=headers)
    assert response.status_code == 200


def test_viewer_cannot_access_audit():
    headers = get_headers("viewer_m15", "VIEWER")
    response = client.get("/api/v1/audit", headers=headers)
    assert response.status_code == 403


def test_analyst_cannot_access_audit():
    headers = get_headers("analyst_m15", "ANALYST")
    response = client.get("/api/v1/audit", headers=headers)
    assert response.status_code == 403


# =====================================================================
# Section 4: Authentication Security
# =====================================================================

def test_login_success():
    response = client.post("/api/v1/auth/login", json={"username": "admin_m15", "password": "AdminPass123!"})
    assert response.status_code == 200
    assert "access_token" in response.json()


def test_login_failure_no_password_leak():
    wrong_password = "WrongPassword123!"
    response = client.post("/api/v1/auth/login", json={"username": "admin_m15", "password": wrong_password})
    assert response.status_code == 401
    
    # Ensure password isn't leaked in the response
    response_text = response.text
    assert wrong_password not in response_text


def test_invalid_token_returns_401():
    headers = {"Authorization": "Bearer invalid_token", "Content-Type": "application/json"}
    response = client.get("/api/v1/incidents", headers=headers)
    assert response.status_code == 401
