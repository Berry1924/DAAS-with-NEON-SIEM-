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
from backend.app.models.detection_rule import DetectionRule
from backend.app.models.incident import Incident
from backend.app.models.enums import UserRole, Severity, AlertStatus, IncidentStatus, EventOutcome
from backend.app.core.security import get_password_hash, create_access_token
from backend.app.db.session import get_db

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
        username="admin_dash",
        email="admin_dash@cyberwolf.local",
        display_name="Admin Dash",
        password_hash=get_password_hash("AdminPass123!"),
        role=UserRole.ADMIN,
        is_active=True,
    )
    analyst = User(
        username="analyst_dash",
        email="analyst_dash@cyberwolf.local",
        display_name="Analyst Dash",
        password_hash=get_password_hash("AnalystPass123!"),
        role=UserRole.ANALYST,
        is_active=True,
    )
    viewer = User(
        username="viewer_dash",
        email="viewer_dash@cyberwolf.local",
        display_name="Viewer Dash",
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
# 1. Endpoint & Authentication Tests
# ---------------------------------------------------------
def test_dashboard_requires_auth():
    res = client.get("/api/v1/dashboard/summary")
    assert res.status_code == 401

def test_viewer_can_read_dashboard():
    h = get_headers("viewer_dash", "VIEWER")
    res = client.get("/api/v1/dashboard/summary", headers=h)
    assert res.status_code == 200
    data = res.json()
    assert "total_events_24h" in data
    assert "active_alerts_by_severity" in data
    assert "open_incidents" in data
    assert "top_detection_rules" in data
    assert "recent_incidents" in data
    assert "event_trend" in data

def test_analyst_can_read_dashboard():
    h = get_headers("analyst_dash", "ANALYST")
    res = client.get("/api/v1/dashboard/summary", headers=h)
    assert res.status_code == 200

def test_admin_can_read_dashboard():
    h = get_headers("admin_dash", "ADMIN")
    res = client.get("/api/v1/dashboard/summary", headers=h)
    assert res.status_code == 200

# ---------------------------------------------------------
# 2. Event Metric & Time Window Tests
# ---------------------------------------------------------
def test_total_events_24h_and_outside_window():
    db = TestingSessionLocal()
    now = datetime.now(timezone.utc)

    # 3 events within 24h
    e1 = Event(source_type="linux_auth", event_type="authentication", outcome=EventOutcome.FAILURE, severity=Severity.MEDIUM, timestamp=now - timedelta(hours=2), raw_event={}, event_metadata={})
    e2 = Event(source_type="linux_auth", event_type="authentication", outcome=EventOutcome.FAILURE, severity=Severity.HIGH, timestamp=now - timedelta(hours=5), raw_event={}, event_metadata={})
    e3 = Event(source_type="linux_auth", event_type="authentication", outcome=EventOutcome.SUCCESS, severity=Severity.LOW, timestamp=now - timedelta(hours=10), raw_event={}, event_metadata={})

    # 2 old events > 24h
    e4 = Event(source_type="linux_auth", event_type="authentication", outcome=EventOutcome.FAILURE, severity=Severity.INFO, timestamp=now - timedelta(hours=30), raw_event={}, event_metadata={})
    e5 = Event(source_type="linux_auth", event_type="authentication", outcome=EventOutcome.FAILURE, severity=Severity.INFO, timestamp=now - timedelta(days=5), raw_event={}, event_metadata={})

    db.add_all([e1, e2, e3, e4, e5])
    db.commit()
    db.close()

    h = get_headers("analyst_dash", "ANALYST")
    res = client.get("/api/v1/dashboard/summary", headers=h)
    assert res.status_code == 200
    data = res.json()
    assert data["total_events_24h"] == 3

# ---------------------------------------------------------
# 3. Active Alerts by Severity & Resolution Exclusion
# ---------------------------------------------------------
def test_active_alerts_by_severity_and_resolved_exclusion():
    db = TestingSessionLocal()
    now = datetime.now(timezone.utc)

    rule = DetectionRule(
        rule_id="CW-TEST-001",
        name="Test Rule",
        description="Test rule description",
        event_types=["test"],
        conditions={},
        severity=Severity.HIGH,
        enabled=True
    )
    dummy_evt = Event(source_type="linux_auth", event_type="test", outcome=EventOutcome.FAILURE, severity=Severity.HIGH, timestamp=now, raw_event={}, event_metadata={})
    db.add_all([rule, dummy_evt])
    db.commit()

    # Active alerts
    a1 = Alert(rule_id=rule.id, primary_event_id=dummy_evt.id, title="Alert 1", severity=Severity.CRITICAL, status=AlertStatus.NEW, first_seen_at=now, last_seen_at=now, created_at=now)
    a2 = Alert(rule_id=rule.id, primary_event_id=dummy_evt.id, title="Alert 2", severity=Severity.CRITICAL, status=AlertStatus.INVESTIGATING, first_seen_at=now, last_seen_at=now, created_at=now)
    a3 = Alert(rule_id=rule.id, primary_event_id=dummy_evt.id, title="Alert 3", severity=Severity.HIGH, status=AlertStatus.ACKNOWLEDGED, first_seen_at=now, last_seen_at=now, created_at=now)

    # Terminal alerts (should be excluded)
    a4 = Alert(rule_id=rule.id, primary_event_id=dummy_evt.id, title="Alert 4", severity=Severity.CRITICAL, status=AlertStatus.RESOLVED, first_seen_at=now, last_seen_at=now, created_at=now)
    a5 = Alert(rule_id=rule.id, primary_event_id=dummy_evt.id, title="Alert 5", severity=Severity.HIGH, status=AlertStatus.FALSE_POSITIVE, first_seen_at=now, last_seen_at=now, created_at=now)

    db.add_all([a1, a2, a3, a4, a5])
    db.commit()
    db.close()

    h = get_headers("admin_dash", "ADMIN")
    res = client.get("/api/v1/dashboard/summary", headers=h)
    assert res.status_code == 200
    data = res.json()

    sevs = {item["severity"]: item["count"] for item in data["active_alerts_by_severity"]}
    assert sevs["CRITICAL"] == 2
    assert sevs["HIGH"] == 1
    assert sevs["MEDIUM"] == 0
    assert sevs["LOW"] == 0
    assert sevs["INFO"] == 0

# ---------------------------------------------------------
# 4. Open Incidents Count
# ---------------------------------------------------------
def test_open_incidents_count():
    db = TestingSessionLocal()
    now = datetime.now(timezone.utc)

    inc1 = Incident(incident_key="NEON-INC-000001", title="Inc 1", incident_type="Correlated Security Incident", severity=Severity.CRITICAL, risk_score=90, status=IncidentStatus.NEW, first_seen_at=now, last_seen_at=now, created_at=now, updated_at=now)
    inc2 = Incident(incident_key="NEON-INC-000002", title="Inc 2", incident_type="Correlated Security Incident", severity=Severity.HIGH, risk_score=70, status=IncidentStatus.INVESTIGATING, first_seen_at=now, last_seen_at=now, created_at=now, updated_at=now)

    # Closed incidents
    inc3 = Incident(incident_key="NEON-INC-000003", title="Inc 3", incident_type="Correlated Security Incident", severity=Severity.MEDIUM, risk_score=40, status=IncidentStatus.RESOLVED, first_seen_at=now, last_seen_at=now, created_at=now, updated_at=now)
    inc4 = Incident(incident_key="NEON-INC-000004", title="Inc 4", incident_type="Correlated Security Incident", severity=Severity.LOW, risk_score=20, status=IncidentStatus.FALSE_POSITIVE, first_seen_at=now, last_seen_at=now, created_at=now, updated_at=now)

    db.add_all([inc1, inc2, inc3, inc4])
    db.commit()
    db.close()

    h = get_headers("viewer_dash", "VIEWER")
    res = client.get("/api/v1/dashboard/summary", headers=h)
    assert res.status_code == 200
    data = res.json()
    assert data["open_incidents"] == 2

# ---------------------------------------------------------
# 5. Top Detection Rules Ranking
# ---------------------------------------------------------
def test_top_detection_rules_limited_to_five_and_sorted():
    db = TestingSessionLocal()
    now = datetime.now(timezone.utc)

    dummy_evt = Event(source_type="linux_auth", event_type="test", outcome=EventOutcome.FAILURE, severity=Severity.HIGH, timestamp=now, raw_event={}, event_metadata={})
    db.add(dummy_evt)

    rules = []
    for i in range(1, 8):
        rule = DetectionRule(
            rule_id=f"CW-RULE-00{i}",
            name=f"Rule {i}",
            description=f"Rule {i} description",
            event_types=["test"],
            conditions={},
            severity=Severity.HIGH,
            enabled=True
        )
        rules.append(rule)
    db.add_all(rules)
    db.commit()

    # Trigger rule 1 seven times, rule 2 five times, rule 3 three times...
    alerts = []
    for rule_idx, count in [(1, 7), (2, 5), (3, 3), (4, 2), (5, 1), (6, 10)]:
        r = rules[rule_idx - 1]
        for _ in range(count):
            alerts.append(Alert(rule_id=r.id, primary_event_id=dummy_evt.id, title=r.name, severity=r.severity, status=AlertStatus.NEW, first_seen_at=now, last_seen_at=now, created_at=now))
    db.add_all(alerts)
    db.commit()
    db.close()

    h = get_headers("admin_dash", "ADMIN")
    res = client.get("/api/v1/dashboard/summary", headers=h)
    assert res.status_code == 200
    data = res.json()

    top = data["top_detection_rules"]
    assert len(top) == 5
    # Most triggered rule is Rule 6 (10 times)
    assert top[0]["rule_id"] == "CW-RULE-006"
    assert top[0]["count"] == 10
    # Second is Rule 1 (7 times)
    assert top[1]["rule_id"] == "CW-RULE-001"
    assert top[1]["count"] == 7

# ---------------------------------------------------------
# 6. Recent Incidents
# ---------------------------------------------------------
def test_recent_incidents_limited_to_five():
    db = TestingSessionLocal()
    now = datetime.now(timezone.utc)

    for i in range(1, 10):
        inc = Incident(
            incident_key=f"NEON-INC-00000{i}",
            title=f"Incident {i}",
            incident_type="Correlated Security Incident",
            severity=Severity.HIGH,
            risk_score=50 + i,
            status=IncidentStatus.NEW,
            first_seen_at=now,
            last_seen_at=now,
            created_at=now + timedelta(minutes=i),
            updated_at=now + timedelta(minutes=i),
        )
        db.add(inc)
    db.commit()
    db.close()

    h = get_headers("analyst_dash", "ANALYST")
    res = client.get("/api/v1/dashboard/summary", headers=h)
    assert res.status_code == 200
    data = res.json()

    recent = data["recent_incidents"]
    assert len(recent) == 5
    # Most recent created_at first
    assert recent[0]["incident_key"] == "NEON-INC-000009"
    assert recent[4]["incident_key"] == "NEON-INC-000005"

# ---------------------------------------------------------
# 7. Hourly Event Trend Buckets
# ---------------------------------------------------------
def test_hourly_event_trend_24_buckets():
    h = get_headers("admin_dash", "ADMIN")
    res = client.get("/api/v1/dashboard/summary", headers=h)
    assert res.status_code == 200
    data = res.json()

    trend = data["event_trend"]
    assert len(trend) == 24
    for bucket in trend:
        assert "hour" in bucket
        assert "count" in bucket
        assert isinstance(bucket["count"], int)

# ---------------------------------------------------------
# 8. Security & Secret Redaction
# ---------------------------------------------------------
def test_dashboard_does_not_expose_secrets():
    h = get_headers("admin_dash", "ADMIN")
    res = client.get("/api/v1/dashboard/summary", headers=h)
    assert res.status_code == 200
    raw_json = res.text
    assert "password" not in raw_json.lower()
    assert "secret" not in raw_json.lower()
    assert "access_token" not in raw_json.lower()
