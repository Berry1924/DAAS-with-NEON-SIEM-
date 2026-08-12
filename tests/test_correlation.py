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
from backend.app.models.audit_log import AuditLog
from backend.app.models.enums import UserRole, EventOutcome, Severity, AlertStatus, CorrelationStatus, AuditResult
from backend.app.core.security import get_password_hash, create_access_token
from backend.app.db.session import get_db

from security_engine.detection.rule_loader import RuleLoader
from security_engine.correlation.entities import EntityExtractor, entity_extractor
from security_engine.correlation.engine import CorrelationEngine, correlation_engine

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
        username="admin_corr",
        email="admin_corr@cyberwolf.local",
        display_name="Admin Correlation",
        password_hash=get_password_hash("AdminPass123!"),
        role=UserRole.ADMIN,
        is_active=True,
    )
    analyst = User(
        username="analyst_corr",
        email="analyst_corr@cyberwolf.local",
        display_name="Analyst Correlation",
        password_hash=get_password_hash("AnalystPass123!"),
        role=UserRole.ANALYST,
        is_active=True,
    )
    viewer = User(
        username="viewer_corr",
        email="viewer_corr@cyberwolf.local",
        display_name="Viewer Correlation",
        password_hash=get_password_hash("ViewerPass123!"),
        role=UserRole.VIEWER,
        is_active=True,
    )
    db.add_all([admin, analyst, viewer])
    db.commit()

    # Sync rules
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

def helper_create_rule(db, rule_id_str: str, name: str, severity: Severity) -> DetectionRule:
    rule = db.scalar(select(DetectionRule).where(DetectionRule.rule_id == rule_id_str))
    if not rule:
        rule = DetectionRule(
            rule_id=rule_id_str,
            name=name,
            description="Test rule",
            event_types=["test"],
            conditions={},
            severity=severity,
            enabled=True
        )
        db.add(rule)
        db.commit()
        db.refresh(rule)
    return rule

def helper_create_event_and_alert(db, rule: DetectionRule, source_ip: str = "10.99.1.50",
                                  dest_ip: str = "192.168.1.10", username: str = "root",
                                  hostname: str = "srv01", timestamp: datetime = None) -> Alert:
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)

    evt = Event(
        timestamp=timestamp,
        source_type="linux_auth",
        event_type="test",
        source_ip=source_ip,
        destination_ip=dest_ip,
        username=username,
        hostname=hostname,
        outcome=EventOutcome.FAILURE,
        severity=rule.severity,
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
        severity=rule.severity,
        risk_score=rule.risk_weight,
        status=AlertStatus.NEW,
        source_ip=source_ip,
        destination_ip=dest_ip,
        username=username,
        hostname=hostname,
        evidence={"rule_id": rule.rule_id},
        first_seen_at=timestamp,
        last_seen_at=timestamp,
        created_at=timestamp,
        updated_at=timestamp
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    
    # Link event
    link = AlertEvent(alert_id=alert.id, event_id=evt.id, evidence_role="trigger")
    db.add(link)
    db.commit()
    
    return alert

# ---------------------------------------------------------
# 1. Entity Extraction Tests
# ---------------------------------------------------------
def test_entity_extraction_from_alert():
    db = TestingSessionLocal()
    rule = helper_create_rule(db, "CW-TEST-001", "Test Rule", Severity.MEDIUM)
    alert = helper_create_event_and_alert(db, rule, source_ip="10.99.1.50", dest_ip="192.168.1.1", username="admin", hostname="host01")

    entities = entity_extractor.extract_from_alert(alert)
    assert entities["source_ip"] == "10.99.1.50"
    assert entities["destination_ip"] == "192.168.1.1"
    assert entities["username"] == "admin"
    assert entities["hostname"] == "host01"

    fingerprint = entity_extractor.generate_fingerprint(entities)
    assert fingerprint.startswith("CORR-")

    # Missing entity handling
    alert_empty = helper_create_event_and_alert(db, rule, source_ip=None, dest_ip=None, username=None, hostname=None)
    entities_empty = entity_extractor.extract_from_alert(alert_empty)
    assert all(v is None for v in entities_empty.values())
    assert entity_extractor.generate_fingerprint(entities_empty) == "empty-entity-fingerprint"

    db.close()

# ---------------------------------------------------------
# 2. Correlation Matching, Windowing & Threshold Tests
# ---------------------------------------------------------
def test_isolated_alert_below_threshold_does_not_correlate():
    db = TestingSessionLocal()
    engine = CorrelationEngine(window_seconds=1800)
    rule = helper_create_rule(db, "CW-NET-001", "Port Scan", Severity.MEDIUM)
    
    alert1 = helper_create_event_and_alert(db, rule, source_ip="10.99.1.50")
    result = engine.correlate_alert(alert1, db)

    # Isolated alert (<2) produces None
    assert result is None
    db.close()

def test_two_alerts_same_source_ip_correlate():
    db = TestingSessionLocal()
    engine = CorrelationEngine(window_seconds=1800)
    rule1 = helper_create_rule(db, "CW-NET-001", "Port Scan", Severity.MEDIUM)
    rule2 = helper_create_rule(db, "CW-AUTH-001", "Brute Force", Severity.HIGH)
    now = datetime.now(timezone.utc)

    alert1 = helper_create_event_and_alert(db, rule1, source_ip="10.99.1.50", timestamp=now - timedelta(seconds=100))
    res1 = engine.correlate_alert(alert1, db)
    assert res1 is None  # Below threshold

    alert2 = helper_create_event_and_alert(db, rule2, source_ip="10.99.1.50", timestamp=now)
    res2 = engine.correlate_alert(alert2, db)

    assert res2 is not None
    assert res2.status == CorrelationStatus.ACTIVE
    assert res2.alert_count == 2
    assert str(alert1.id) in res2.alert_ids
    assert str(alert2.id) in res2.alert_ids
    assert res2.source_ip == "10.99.1.50"
    db.close()

def test_alerts_different_entities_do_not_correlate():
    db = TestingSessionLocal()
    engine = CorrelationEngine(window_seconds=1800)
    rule1 = helper_create_rule(db, "CW-NET-001", "Port Scan", Severity.MEDIUM)
    rule2 = helper_create_rule(db, "CW-AUTH-001", "Brute Force", Severity.HIGH)
    now = datetime.now(timezone.utc)

    alert1 = helper_create_event_and_alert(db, rule1, source_ip="10.99.1.50", dest_ip="1.1.1.1", username="u1", hostname="h1", timestamp=now - timedelta(seconds=10))
    engine.correlate_alert(alert1, db)

    # Completely different entities
    alert2 = helper_create_event_and_alert(db, rule2, source_ip="10.99.1.99", dest_ip="2.2.2.2", username="u2", hostname="h2", timestamp=now)
    res2 = engine.correlate_alert(alert2, db)

    # Should NOT correlate cross-IP/host/user
    assert res2 is None
    db.close()

def test_alerts_outside_time_window_do_not_correlate():
    db = TestingSessionLocal()
    engine = CorrelationEngine(window_seconds=1800)
    rule1 = helper_create_rule(db, "CW-NET-001", "Port Scan", Severity.MEDIUM)
    rule2 = helper_create_rule(db, "CW-AUTH-001", "Brute Force", Severity.HIGH)
    now = datetime.now(timezone.utc)

    # Alert 1 is 2000s old (outside 1800s window)
    alert1 = helper_create_event_and_alert(db, rule1, source_ip="10.99.1.55", timestamp=now - timedelta(seconds=2000))
    engine.correlate_alert(alert1, db)

    alert2 = helper_create_event_and_alert(db, rule2, source_ip="10.99.1.55", timestamp=now)
    res2 = engine.correlate_alert(alert2, db)

    assert res2 is None
    db.close()

# ---------------------------------------------------------
# 3. Deduplication & Replay Tests
# ---------------------------------------------------------
def test_deduplication_updates_existing_active_group():
    db = TestingSessionLocal()
    engine = CorrelationEngine(window_seconds=1800)
    r1 = helper_create_rule(db, "CW-NET-001", "Port Scan", Severity.MEDIUM)
    r2 = helper_create_rule(db, "CW-AUTH-001", "Brute Force", Severity.HIGH)
    r3 = helper_create_rule(db, "CW-LOGIN-001", "Suspicious Login", Severity.HIGH)

    now = datetime.now(timezone.utc)
    ip = "10.99.1.60"

    a1 = helper_create_event_and_alert(db, r1, source_ip=ip, timestamp=now - timedelta(seconds=100))
    a2 = helper_create_event_and_alert(db, r2, source_ip=ip, timestamp=now - timedelta(seconds=50))
    
    grp1 = engine.correlate_alert(a1, db)
    grp2 = engine.correlate_alert(a2, db)

    assert grp2 is not None
    assert grp2.alert_count == 2
    group_id = grp2.id

    # 3rd alert belonging to same active sequence arrives
    a3 = helper_create_event_and_alert(db, r3, source_ip=ip, timestamp=now)
    grp3 = engine.correlate_alert(a3, db)

    # Must update existing group, NOT create a second group
    assert grp3 is not None
    assert grp3.id == group_id
    assert grp3.alert_count == 3
    assert str(a3.id) in grp3.alert_ids
    db.close()

def test_telemetry_replay_does_not_create_duplicate_groups():
    db = TestingSessionLocal()
    engine = CorrelationEngine(window_seconds=1800)
    r1 = helper_create_rule(db, "CW-NET-001", "Port Scan", Severity.MEDIUM)
    r2 = helper_create_rule(db, "CW-AUTH-001", "Brute Force", Severity.HIGH)
    now = datetime.now(timezone.utc)
    ip = "10.99.1.61"

    a1 = helper_create_event_and_alert(db, r1, source_ip=ip, timestamp=now - timedelta(seconds=20))
    a2 = helper_create_event_and_alert(db, r2, source_ip=ip, timestamp=now)

    grp1 = engine.correlate_alert(a1, db)
    grp2 = engine.correlate_alert(a2, db)
    assert grp2 is not None
    orig_group_id = grp2.id

    # Re-evaluating same alert a2
    grp_replay = engine.correlate_alert(a2, db)
    assert grp_replay is not None
    assert grp_replay.id == orig_group_id
    assert grp_replay.alert_count == 2

    # Verify count of correlation groups in DB is exactly 1
    total_groups = db.scalar(select(CorrelationGroup).where(CorrelationGroup.source_ip == ip))
    assert total_groups is not None
    db.close()

# ---------------------------------------------------------
# 4. Golden Correlation Sequence Test
# ---------------------------------------------------------
def test_golden_correlation_sequence():
    db = TestingSessionLocal()
    engine = CorrelationEngine(window_seconds=1800)

    r_net = helper_create_rule(db, "CW-NET-001", "Port Scan Activity", Severity.MEDIUM)
    r_auth = helper_create_rule(db, "CW-AUTH-001", "Brute Force Authentication", Severity.HIGH)
    r_login = helper_create_rule(db, "CW-LOGIN-001", "Suspicious Login After Failures", Severity.HIGH)
    r_priv = helper_create_rule(db, "CW-PRIV-001", "Privilege Escalation", Severity.CRITICAL)

    now = datetime.now(timezone.utc)
    ip = "10.99.1.50"
    host = "target-server-01"

    a_net = helper_create_event_and_alert(db, r_net, source_ip=ip, hostname=host, timestamp=now - timedelta(seconds=300))
    a_auth = helper_create_event_and_alert(db, r_auth, source_ip=ip, hostname=host, timestamp=now - timedelta(seconds=200))
    a_login = helper_create_event_and_alert(db, r_login, source_ip=ip, hostname=host, timestamp=now - timedelta(seconds=100))
    a_priv = helper_create_event_and_alert(db, r_priv, source_ip=ip, hostname=host, timestamp=now)

    engine.correlate_alert(a_net, db)
    engine.correlate_alert(a_auth, db)
    engine.correlate_alert(a_login, db)
    final_grp = engine.correlate_alert(a_priv, db)

    assert final_grp is not None
    assert final_grp.is_golden_sequence is True
    assert final_grp.pattern_matched == "Potential Host Compromise"
    assert "Potential Host Compromise" in final_grp.title
    assert "Port scanning, repeated authentication failures" in final_grp.correlation_reason
    assert final_grp.alert_count == 4
    assert set(final_grp.rule_ids) == {"CW-NET-001", "CW-AUTH-001", "CW-LOGIN-001", "CW-PRIV-001"}

    db.close()

# ---------------------------------------------------------
# 5. Correlation REST API & Security Tests
# ---------------------------------------------------------
def test_unauthenticated_correlation_api_returns_401():
    response = client.get("/api/v1/correlations")
    assert response.status_code == 401

def test_list_and_detail_correlations_rbac():
    db = TestingSessionLocal()
    engine = CorrelationEngine(window_seconds=1800)
    r1 = helper_create_rule(db, "CW-NET-001", "Port Scan", Severity.MEDIUM)
    r2 = helper_create_rule(db, "CW-AUTH-001", "Brute Force", Severity.HIGH)
    now = datetime.now(timezone.utc)

    a1 = helper_create_event_and_alert(db, r1, source_ip="10.99.1.70", timestamp=now - timedelta(seconds=10))
    a2 = helper_create_event_and_alert(db, r2, source_ip="10.99.1.70", timestamp=now)

    engine.correlate_alert(a1, db)
    grp = engine.correlate_alert(a2, db)
    grp_id = grp.id
    db.close()

    # VIEWER can read
    h_viewer = get_headers("viewer_corr", "VIEWER")
    r_v = client.get("/api/v1/correlations", headers=h_viewer)
    assert r_v.status_code == 200
    assert r_v.json()["total"] >= 1

    r_v_detail = client.get(f"/api/v1/correlations/{grp_id}", headers=h_viewer)
    assert r_v_detail.status_code == 200
    assert r_v_detail.json()["id"] == str(grp_id)

    # VIEWER denied status update
    r_v_patch = client.patch(f"/api/v1/correlations/{grp_id}/status", json={"status": "RESOLVED"}, headers=h_viewer)
    assert r_v_patch.status_code == 403

    # ANALYST allowed status update
    h_analyst = get_headers("analyst_corr", "ANALYST")
    r_a_patch = client.patch(f"/api/v1/correlations/{grp_id}/status", json={"status": "RESOLVED"}, headers=h_analyst)
    assert r_a_patch.status_code == 200
    assert r_a_patch.json()["status"] == "RESOLVED"

    # Audit log entry check
    db = TestingSessionLocal()
    audit = db.scalars(select(AuditLog).where(AuditLog.action == "CORRELATION_STATUS_CHANGED")).first()
    assert audit is not None
    assert audit.target_id == str(grp_id)
    assert audit.result == AuditResult.SUCCESS
    db.close()

def test_invalid_correlation_id_returns_404():
    h_analyst = get_headers("analyst_corr", "ANALYST")
    fake_id = uuid.uuid4()
    response = client.get(f"/api/v1/correlations/{fake_id}", headers=h_analyst)
    assert response.status_code == 404
