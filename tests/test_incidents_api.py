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
from backend.app.models.correlation import CorrelationGroup
from backend.app.models.incident import Incident
from backend.app.models.enums import UserRole, EventOutcome, Severity, IncidentStatus, CorrelationStatus
from backend.app.core.security import get_password_hash, create_access_token
from backend.app.db.session import get_db

from security_engine.correlation.engine import CorrelationEngine
from backend.app.repositories.incident_repository import IncidentRepository

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
        username="admin_inc",
        email="admin_inc@cyberwolf.local",
        display_name="Admin Inc",
        password_hash=get_password_hash("AdminPass123!"),
        role=UserRole.ADMIN,
        is_active=True,
    )
    analyst = User(
        username="analyst_inc",
        email="analyst_inc@cyberwolf.local",
        display_name="Analyst Inc",
        password_hash=get_password_hash("AnalystPass123!"),
        role=UserRole.ANALYST,
        is_active=True,
    )
    viewer = User(
        username="viewer_inc",
        email="viewer_inc@cyberwolf.local",
        display_name="Viewer Inc",
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

def helper_create_alert(db, rule_id_str: str, name: str, severity: Severity, source_ip: str = "10.0.0.99") -> Alert:
    rule = db.scalar(select(DetectionRule).where(DetectionRule.rule_id == rule_id_str))
    if not rule:
        rule = DetectionRule(
            rule_id=rule_id_str,
            name=name,
            description="Rule description",
            event_types=["test"],
            conditions={},
            severity=severity,
            enabled=True
        )
        db.add(rule)
        db.commit()
        db.refresh(rule)

    now = datetime.now(timezone.utc)
    evt = Event(
        timestamp=now,
        source_type="linux_auth",
        event_type="test",
        source_ip=source_ip,
        outcome=EventOutcome.FAILURE,
        severity=severity,
        raw_event={"msg": "test"}
    )
    db.add(evt)
    db.commit()
    db.refresh(evt)

    alert = Alert(
        rule_id=rule.id,
        primary_event_id=evt.id,
        title=f"{rule.name} on {source_ip}",
        description=rule.description,
        severity=severity,
        risk_score=rule.risk_weight,
        status="NEW",
        source_ip=source_ip,
        evidence={"rule_id": rule.rule_id},
        first_seen_at=now,
        last_seen_at=now,
        created_at=now,
        updated_at=now
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    link = AlertEvent(alert_id=alert.id, event_id=evt.id, evidence_role="trigger")
    db.add(link)
    db.commit()
    return alert


# ---------------------------------------------------------
# 1. Incident Creation & Evidence Linking
# ---------------------------------------------------------
def test_incident_created_from_correlation():
    db = TestingSessionLocal()
    corr_engine = CorrelationEngine()

    a1 = helper_create_alert(db, "CW-NET-001", "Port Scan", Severity.MEDIUM, "192.168.1.100")
    a2 = helper_create_alert(db, "CW-AUTH-001", "Brute Force", Severity.HIGH, "192.168.1.100")

    corr_engine.correlate_alert(a1, db)
    grp = corr_engine.correlate_alert(a2, db)
    assert grp is not None

    repo = IncidentRepository(db)
    inc = repo.find_active_by_correlation_key(grp.correlation_key)
    assert inc is not None
    assert inc.incident_key.startswith("NEON-INC-")
    assert inc.title == grp.title
    assert inc.risk_score == grp.risk_score
    assert inc.severity == grp.severity
    db.close()

def test_incident_uses_persisted_risk():
    db = TestingSessionLocal()
    corr_engine = CorrelationEngine()

    a1 = helper_create_alert(db, "CW-NET-001", "Port Scan", Severity.MEDIUM, "10.10.10.10")
    a2 = helper_create_alert(db, "CW-AUTH-001", "Brute Force", Severity.HIGH, "10.10.10.10")

    corr_engine.correlate_alert(a1, db)
    grp = corr_engine.correlate_alert(a2, db)

    repo = IncidentRepository(db)
    inc = repo.find_active_by_correlation_key(grp.correlation_key)
    assert inc.risk_score == 65  # Base 60 (HIGH) + 5 correlation bonus
    assert inc.risk_explanation["base_risk"] == 60
    assert inc.risk_explanation["correlation_bonus"] == 5
    db.close()

def test_incident_links_alerts_and_events():
    db = TestingSessionLocal()
    corr_engine = CorrelationEngine()

    a1 = helper_create_alert(db, "CW-NET-001", "Port Scan", Severity.MEDIUM, "10.20.30.40")
    a2 = helper_create_alert(db, "CW-AUTH-001", "Brute Force", Severity.HIGH, "10.20.30.40")

    corr_engine.correlate_alert(a1, db)
    grp = corr_engine.correlate_alert(a2, db)

    repo = IncidentRepository(db)
    inc = repo.find_active_by_correlation_key(grp.correlation_key)

    h_analyst = get_headers("analyst_inc", "ANALYST")
    res = client.get(f"/api/v1/incidents/{inc.id}", headers=h_analyst)
    assert res.status_code == 200
    data = res.json()

    assert len(data["linked_alerts"]) == 2
    assert len(data["linked_events"]) >= 1
    assert len(data["timeline"]) >= 3  # CREATED + 2 ALERT_LINKED
    db.close()

# ---------------------------------------------------------
# 2. Deduplication & Idempotency
# ---------------------------------------------------------
def test_duplicate_correlation_does_not_create_duplicate_incident():
    db = TestingSessionLocal()
    corr_engine = CorrelationEngine()

    a1 = helper_create_alert(db, "CW-NET-001", "Port Scan", Severity.MEDIUM, "172.16.0.5")
    a2 = helper_create_alert(db, "CW-AUTH-001", "Brute Force", Severity.HIGH, "172.16.0.5")
    a3 = helper_create_alert(db, "CW-LOGIN-001", "Suspicious Login", Severity.HIGH, "172.16.0.5")

    corr_engine.correlate_alert(a1, db)
    grp1 = corr_engine.correlate_alert(a2, db)
    grp2 = corr_engine.correlate_alert(a3, db)

    repo = IncidentRepository(db)
    all_incidents = repo.list_incidents()
    assert len(all_incidents) == 1  # Only 1 incident created and updated
    assert all_incidents[0].risk_score >= 75
    db.close()

def test_golden_path_replay_is_idempotent():
    db = TestingSessionLocal()
    corr_engine = CorrelationEngine()

    a1 = helper_create_alert(db, "CW-NET-001", "Port Scan", Severity.MEDIUM, "10.0.0.1")
    a2 = helper_create_alert(db, "CW-AUTH-001", "Brute Force", Severity.HIGH, "10.0.0.1")

    corr_engine.correlate_alert(a1, db)
    grp = corr_engine.correlate_alert(a2, db)

    # Re-correlate same alert set
    grp_replayed = corr_engine.correlate_alert(a2, db)

    repo = IncidentRepository(db)
    incidents = repo.list_incidents()
    assert len(incidents) == 1
    db.close()

# ---------------------------------------------------------
# 3. Lifecycle Transitions
# ---------------------------------------------------------
def test_incident_lifecycle_transitions():
    db = TestingSessionLocal()
    corr_engine = CorrelationEngine()

    a1 = helper_create_alert(db, "CW-NET-001", "Port Scan", Severity.MEDIUM, "10.5.5.5")
    a2 = helper_create_alert(db, "CW-AUTH-001", "Brute Force", Severity.HIGH, "10.5.5.5")

    corr_engine.correlate_alert(a1, db)
    grp = corr_engine.correlate_alert(a2, db)
    repo = IncidentRepository(db)
    inc = repo.find_active_by_correlation_key(grp.correlation_key)
    inc_id = inc.id
    db.close()

    h_analyst = get_headers("analyst_inc", "ANALYST")

    # 1. NEW -> ACKNOWLEDGED
    res1 = client.patch(f"/api/v1/incidents/{inc_id}/status", json={"status": "ACKNOWLEDGED"}, headers=h_analyst)
    assert res1.status_code == 200
    assert res1.json()["status"] == "ACKNOWLEDGED"

    # 2. ACKNOWLEDGED -> INVESTIGATING
    res2 = client.patch(f"/api/v1/incidents/{inc_id}/status", json={"status": "INVESTIGATING"}, headers=h_analyst)
    assert res2.status_code == 200
    assert res2.json()["status"] == "INVESTIGATING"

    # 3. INVESTIGATING -> RESOLVED
    res3 = client.patch(f"/api/v1/incidents/{inc_id}/status", json={"status": "RESOLVED"}, headers=h_analyst)
    assert res3.status_code == 200
    assert res3.json()["status"] == "RESOLVED"
    assert res3.json()["resolved_at"] is not None

def test_invalid_status_transition_rejected():
    db = TestingSessionLocal()
    corr_engine = CorrelationEngine()

    a1 = helper_create_alert(db, "CW-NET-001", "Port Scan", Severity.MEDIUM, "10.6.6.6")
    a2 = helper_create_alert(db, "CW-AUTH-001", "Brute Force", Severity.HIGH, "10.6.6.6")

    corr_engine.correlate_alert(a1, db)
    grp = corr_engine.correlate_alert(a2, db)
    repo = IncidentRepository(db)
    inc = repo.find_active_by_correlation_key(grp.correlation_key)
    inc_id = inc.id

    # Transition to RESOLVED first
    inc.status = IncidentStatus.RESOLVED
    repo.update(inc)
    db.close()

    h_analyst = get_headers("analyst_inc", "ANALYST")

    # RESOLVED -> NEW invalid transition rejected (400)
    res = client.patch(f"/api/v1/incidents/{inc_id}/status", json={"status": "NEW"}, headers=h_analyst)
    assert res.status_code == 400
    assert "Invalid status transition" in res.json()["detail"]

# ---------------------------------------------------------
# 4. RBAC Matrix Tests
# ---------------------------------------------------------
def test_unauthenticated_incident_access():
    res = client.get("/api/v1/incidents")
    assert res.status_code == 401

def test_viewer_read_access_allowed():
    h_viewer = get_headers("viewer_inc", "VIEWER")
    res = client.get("/api/v1/incidents", headers=h_viewer)
    assert res.status_code == 200
    assert "items" in res.json()

def test_viewer_cannot_mutate_incident():
    db = TestingSessionLocal()
    corr_engine = CorrelationEngine()

    a1 = helper_create_alert(db, "CW-NET-001", "Port Scan", Severity.MEDIUM, "10.7.7.7")
    a2 = helper_create_alert(db, "CW-AUTH-001", "Brute Force", Severity.HIGH, "10.7.7.7")

    corr_engine.correlate_alert(a1, db)
    grp = corr_engine.correlate_alert(a2, db)
    repo = IncidentRepository(db)
    inc = repo.find_active_by_correlation_key(grp.correlation_key)
    inc_id = inc.id
    db.close()

    h_viewer = get_headers("viewer_inc", "VIEWER")

    # Status update (403)
    res1 = client.patch(f"/api/v1/incidents/{inc_id}/status", json={"status": "ACKNOWLEDGED"}, headers=h_viewer)
    assert res1.status_code == 403

    # Add note (403)
    res2 = client.post(f"/api/v1/incidents/{inc_id}/notes", json={"body": "Viewer note"}, headers=h_viewer)
    assert res2.status_code == 403

    # Assign (403)
    res3 = client.patch(f"/api/v1/incidents/{inc_id}/assign", json={"assigned_to": None}, headers=h_viewer)
    assert res3.status_code == 403

# ---------------------------------------------------------
# 5. Investigation Notes Tests
# ---------------------------------------------------------
def test_add_investigation_note():
    db = TestingSessionLocal()
    corr_engine = CorrelationEngine()

    a1 = helper_create_alert(db, "CW-NET-001", "Port Scan", Severity.MEDIUM, "10.8.8.8")
    a2 = helper_create_alert(db, "CW-AUTH-001", "Brute Force", Severity.HIGH, "10.8.8.8")

    corr_engine.correlate_alert(a1, db)
    grp = corr_engine.correlate_alert(a2, db)
    repo = IncidentRepository(db)
    inc = repo.find_active_by_correlation_key(grp.correlation_key)
    inc_id = inc.id
    db.close()

    h_analyst = get_headers("analyst_inc", "ANALYST")
    res = client.post(f"/api/v1/incidents/{inc_id}/notes", json={"body": "Investigating suspicious login pattern."}, headers=h_analyst)
    assert res.status_code == 200
    data = res.json()
    assert data["body"] == "Investigating suspicious login pattern."
    assert data["author_name"] == "Analyst Inc"

def test_empty_note_rejected():
    db = TestingSessionLocal()
    corr_engine = CorrelationEngine()

    a1 = helper_create_alert(db, "CW-NET-001", "Port Scan", Severity.MEDIUM, "10.9.9.9")
    a2 = helper_create_alert(db, "CW-AUTH-001", "Brute Force", Severity.HIGH, "10.9.9.9")

    corr_engine.correlate_alert(a1, db)
    grp = corr_engine.correlate_alert(a2, db)
    repo = IncidentRepository(db)
    inc = repo.find_active_by_correlation_key(grp.correlation_key)
    inc_id = inc.id
    db.close()

    h_analyst = get_headers("analyst_inc", "ANALYST")
    res = client.post(f"/api/v1/incidents/{inc_id}/notes", json={"body": "   "}, headers=h_analyst)
    assert res.status_code == 422 or res.status_code == 400

def test_oversized_note_rejected():
    db = TestingSessionLocal()
    corr_engine = CorrelationEngine()

    a1 = helper_create_alert(db, "CW-NET-001", "Port Scan", Severity.MEDIUM, "10.1.1.1")
    a2 = helper_create_alert(db, "CW-AUTH-001", "Brute Force", Severity.HIGH, "10.1.1.1")

    corr_engine.correlate_alert(a1, db)
    grp = corr_engine.correlate_alert(a2, db)
    repo = IncidentRepository(db)
    inc = repo.find_active_by_correlation_key(grp.correlation_key)
    inc_id = inc.id
    db.close()

    h_analyst = get_headers("analyst_inc", "ANALYST")
    big_body = "A" * 6000
    res = client.post(f"/api/v1/incidents/{inc_id}/notes", json={"body": big_body}, headers=h_analyst)
    assert res.status_code == 422 or res.status_code == 400

# ---------------------------------------------------------
# 6. Assignment Tests
# ---------------------------------------------------------
def test_incident_assignment():
    db = TestingSessionLocal()
    corr_engine = CorrelationEngine()

    a1 = helper_create_alert(db, "CW-NET-001", "Port Scan", Severity.MEDIUM, "10.2.2.2")
    a2 = helper_create_alert(db, "CW-AUTH-001", "Brute Force", Severity.HIGH, "10.2.2.2")

    corr_engine.correlate_alert(a1, db)
    grp = corr_engine.correlate_alert(a2, db)
    repo = IncidentRepository(db)
    inc = repo.find_active_by_correlation_key(grp.correlation_key)
    inc_id = inc.id

    analyst_user = db.scalar(select(User).where(User.username == "analyst_inc"))
    analyst_id = str(analyst_user.id)
    db.close()

    h_admin = get_headers("admin_inc", "ADMIN")
    res = client.patch(f"/api/v1/incidents/{inc_id}/assign", json={"assigned_to": analyst_id}, headers=h_admin)
    assert res.status_code == 200
    assert res.json()["assigned_to"] == analyst_id

# ---------------------------------------------------------
# 7. Security & Client Override Prevention Tests
# ---------------------------------------------------------
def test_client_cannot_override_risk():
    db = TestingSessionLocal()
    corr_engine = CorrelationEngine()

    a1 = helper_create_alert(db, "CW-NET-001", "Port Scan", Severity.MEDIUM, "10.3.3.3")
    a2 = helper_create_alert(db, "CW-AUTH-001", "Brute Force", Severity.HIGH, "10.3.3.3")

    corr_engine.correlate_alert(a1, db)
    grp = corr_engine.correlate_alert(a2, db)
    repo = IncidentRepository(db)
    inc = repo.find_active_by_correlation_key(grp.correlation_key)
    inc_id = inc.id
    original_risk = inc.risk_score
    db.close()

    h_analyst = get_headers("analyst_inc", "ANALYST")

    # Attempt to send extra risk_score field in status update
    res = client.patch(f"/api/v1/incidents/{inc_id}/status", json={"status": "ACKNOWLEDGED", "risk_score": 0}, headers=h_analyst)
    assert res.status_code == 200
    assert res.json()["risk_score"] == original_risk  # Unmodified!

def test_unknown_incident_returns_404():
    h_analyst = get_headers("analyst_inc", "ANALYST")
    random_id = str(uuid.uuid4())
    res = client.get(f"/api/v1/incidents/{random_id}", headers=h_analyst)
    assert res.status_code == 404
