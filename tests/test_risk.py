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
from backend.app.models.correlation import CorrelationGroup
from backend.app.models.enums import UserRole, EventOutcome, Severity, CorrelationStatus
from backend.app.core.security import get_password_hash, create_access_token
from backend.app.db.session import get_db

from security_engine.risk.calculator import RiskCalculator, risk_calculator, SEVERITY_BASE_MAP
from security_engine.correlation.engine import CorrelationEngine

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

    admin = User(
        username="admin_risk",
        email="admin_risk@cyberwolf.local",
        display_name="Admin Risk",
        password_hash=get_password_hash("AdminPass123!"),
        role=UserRole.ADMIN,
        is_active=True,
    )
    analyst = User(
        username="analyst_risk",
        email="analyst_risk@cyberwolf.local",
        display_name="Analyst Risk",
        password_hash=get_password_hash("AnalystPass123!"),
        role=UserRole.ANALYST,
        is_active=True,
    )
    viewer = User(
        username="viewer_risk",
        email="viewer_risk@cyberwolf.local",
        display_name="Viewer Risk",
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

def helper_create_alert_with_rule(db, rule_id_str: str, name: str, severity: Severity,
                                  source_ip: str = "10.99.1.50") -> Alert:
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
    return alert

# ---------------------------------------------------------
# 1. Base Severity Mapping Tests
# ---------------------------------------------------------
def test_info_base_risk():
    db = TestingSessionLocal()
    group = CorrelationGroup(first_seen_at=datetime.now(timezone.utc), last_seen_at=datetime.now(timezone.utc))
    alert = helper_create_alert_with_rule(db, "CW-INFO-001", "Info Rule", Severity.INFO)
    res = risk_calculator.calculate(group, [alert])
    assert res.base_risk == 10
    db.close()

def test_low_base_risk():
    db = TestingSessionLocal()
    group = CorrelationGroup(first_seen_at=datetime.now(timezone.utc), last_seen_at=datetime.now(timezone.utc))
    alert = helper_create_alert_with_rule(db, "CW-LOW-001", "Low Rule", Severity.LOW)
    res = risk_calculator.calculate(group, [alert])
    assert res.base_risk == 20
    db.close()

def test_medium_base_risk():
    db = TestingSessionLocal()
    group = CorrelationGroup(first_seen_at=datetime.now(timezone.utc), last_seen_at=datetime.now(timezone.utc))
    alert = helper_create_alert_with_rule(db, "CW-MED-001", "Medium Rule", Severity.MEDIUM)
    res = risk_calculator.calculate(group, [alert])
    assert res.base_risk == 40
    db.close()

def test_high_base_risk():
    db = TestingSessionLocal()
    group = CorrelationGroup(first_seen_at=datetime.now(timezone.utc), last_seen_at=datetime.now(timezone.utc))
    alert = helper_create_alert_with_rule(db, "CW-HIGH-001", "High Rule", Severity.HIGH)
    res = risk_calculator.calculate(group, [alert])
    assert res.base_risk == 60
    db.close()

def test_critical_base_risk():
    db = TestingSessionLocal()
    group = CorrelationGroup(first_seen_at=datetime.now(timezone.utc), last_seen_at=datetime.now(timezone.utc))
    alert = helper_create_alert_with_rule(db, "CW-CRIT-001", "Critical Rule", Severity.CRITICAL)
    res = risk_calculator.calculate(group, [alert])
    assert res.base_risk == 80
    db.close()

# ---------------------------------------------------------
# 2. Correlation Bonus Tests
# ---------------------------------------------------------
def test_two_alerts_bonus():
    db = TestingSessionLocal()
    group = CorrelationGroup(first_seen_at=datetime.now(timezone.utc), last_seen_at=datetime.now(timezone.utc))
    a1 = helper_create_alert_with_rule(db, "CW-NET-001", "Rule 1", Severity.MEDIUM)
    a2 = helper_create_alert_with_rule(db, "CW-OTHER-002", "Rule 2", Severity.MEDIUM)

    res = risk_calculator.calculate(group, [a1, a2])
    assert res.correlation_bonus == 5
    db.close()

def test_three_alerts_bonus():
    db = TestingSessionLocal()
    group = CorrelationGroup(first_seen_at=datetime.now(timezone.utc), last_seen_at=datetime.now(timezone.utc))
    a1 = helper_create_alert_with_rule(db, "CW-R1", "Rule 1", Severity.MEDIUM)
    a2 = helper_create_alert_with_rule(db, "CW-R2", "Rule 2", Severity.MEDIUM)
    a3 = helper_create_alert_with_rule(db, "CW-R3", "Rule 3", Severity.MEDIUM)

    res = risk_calculator.calculate(group, [a1, a2, a3])
    assert res.correlation_bonus == 10
    db.close()

def test_four_alerts_bonus():
    db = TestingSessionLocal()
    group = CorrelationGroup(first_seen_at=datetime.now(timezone.utc), last_seen_at=datetime.now(timezone.utc))
    alerts = [helper_create_alert_with_rule(db, f"CW-R{i}", f"Rule {i}", Severity.MEDIUM) for i in range(4)]

    res = risk_calculator.calculate(group, alerts)
    assert res.correlation_bonus == 15
    db.close()

def test_correlation_bonus_cap():
    db = TestingSessionLocal()
    group = CorrelationGroup(first_seen_at=datetime.now(timezone.utc), last_seen_at=datetime.now(timezone.utc))
    alerts = [helper_create_alert_with_rule(db, f"CW-CAP-{i}", f"Rule {i}", Severity.MEDIUM) for i in range(10)]

    res = risk_calculator.calculate(group, alerts)
    assert res.correlation_bonus == 15  # Capped at 15
    db.close()

# ---------------------------------------------------------
# 3. Compromise & Privilege Bonus Tests
# ---------------------------------------------------------
def test_failed_then_successful_login_bonus():
    db = TestingSessionLocal()
    group = CorrelationGroup(first_seen_at=datetime.now(timezone.utc), last_seen_at=datetime.now(timezone.utc))
    a_failed = helper_create_alert_with_rule(db, "CW-AUTH-001", "Brute Force", Severity.HIGH)
    a_success = helper_create_alert_with_rule(db, "CW-LOGIN-001", "Suspicious Login", Severity.HIGH)

    res = risk_calculator.calculate(group, [a_failed, a_success])
    assert res.compromise_indicator_bonus == 10
    db.close()

def test_missing_successful_login_no_bonus():
    db = TestingSessionLocal()
    group = CorrelationGroup(first_seen_at=datetime.now(timezone.utc), last_seen_at=datetime.now(timezone.utc))
    a_failed = helper_create_alert_with_rule(db, "CW-AUTH-001", "Brute Force", Severity.HIGH)
    a_net = helper_create_alert_with_rule(db, "CW-NET-001", "Port Scan", Severity.MEDIUM)

    res = risk_calculator.calculate(group, [a_failed, a_net])
    assert res.compromise_indicator_bonus == 0
    db.close()

def test_privilege_escalation_bonus():
    db = TestingSessionLocal()
    group = CorrelationGroup(first_seen_at=datetime.now(timezone.utc), last_seen_at=datetime.now(timezone.utc))
    a_priv = helper_create_alert_with_rule(db, "CW-PRIV-001", "Privilege Escalation", Severity.CRITICAL)
    a_net = helper_create_alert_with_rule(db, "CW-NET-001", "Port Scan", Severity.MEDIUM)

    res = risk_calculator.calculate(group, [a_net, a_priv])
    assert res.privilege_escalation_bonus == 5
    db.close()

def test_no_privilege_activity_no_bonus():
    db = TestingSessionLocal()
    group = CorrelationGroup(first_seen_at=datetime.now(timezone.utc), last_seen_at=datetime.now(timezone.utc))
    a_net = helper_create_alert_with_rule(db, "CW-NET-001", "Port Scan", Severity.MEDIUM)
    a_auth = helper_create_alert_with_rule(db, "CW-AUTH-001", "Brute Force", Severity.HIGH)

    res = risk_calculator.calculate(group, [a_net, a_auth])
    assert res.privilege_escalation_bonus == 0
    db.close()

# ---------------------------------------------------------
# 4. Bounds & Clamping Tests
# ---------------------------------------------------------
def test_score_minimum_zero():
    db = TestingSessionLocal()
    group = CorrelationGroup(first_seen_at=datetime.now(timezone.utc), last_seen_at=datetime.now(timezone.utc))
    alert = helper_create_alert_with_rule(db, "CW-MIN-001", "Info Rule", Severity.INFO)
    # Apply negative asset modifier
    res = risk_calculator.calculate(group, [alert], asset_criticality_modifier=-50)
    assert res.final_score == 0
    db.close()

def test_score_maximum_100():
    db = TestingSessionLocal()
    group = CorrelationGroup(first_seen_at=datetime.now(timezone.utc), last_seen_at=datetime.now(timezone.utc))
    alerts = [
        helper_create_alert_with_rule(db, "CW-AUTH-001", "Brute Force", Severity.HIGH),
        helper_create_alert_with_rule(db, "CW-LOGIN-001", "Suspicious Login", Severity.HIGH),
        helper_create_alert_with_rule(db, "CW-PRIV-001", "Privilege Escalation", Severity.CRITICAL),
        helper_create_alert_with_rule(db, "CW-NET-001", "Port Scan", Severity.MEDIUM),
    ]
    res = risk_calculator.calculate(group, alerts, asset_criticality_modifier=20)
    assert res.final_score == 100  # Clamped to 100
    db.close()

# ---------------------------------------------------------
# 5. Severity Tiers Tests
# ---------------------------------------------------------
def test_severity_tiers_mapping():
    assert risk_calculator._get_severity_tier(10) == Severity.LOW
    assert risk_calculator._get_severity_tier(24) == Severity.LOW
    assert risk_calculator._get_severity_tier(25) == Severity.MEDIUM
    assert risk_calculator._get_severity_tier(49) == Severity.MEDIUM
    assert risk_calculator._get_severity_tier(50) == Severity.HIGH
    assert risk_calculator._get_severity_tier(74) == Severity.HIGH
    assert risk_calculator._get_severity_tier(75) == Severity.CRITICAL
    assert risk_calculator._get_severity_tier(100) == Severity.CRITICAL

# ---------------------------------------------------------
# 6. Golden Path Risk Calculation Test
# ---------------------------------------------------------
def test_golden_path_risk_calculation():
    db = TestingSessionLocal()
    corr_engine = CorrelationEngine(window_seconds=1800)

    a_net = helper_create_alert_with_rule(db, "CW-NET-001", "Port Scan Activity", Severity.MEDIUM)
    a_auth = helper_create_alert_with_rule(db, "CW-AUTH-001", "Brute Force Authentication", Severity.HIGH)
    a_login = helper_create_alert_with_rule(db, "CW-LOGIN-001", "Suspicious Login After Failures", Severity.HIGH)
    a_priv = helper_create_alert_with_rule(db, "CW-PRIV-001", "Privilege Escalation", Severity.CRITICAL)

    corr_engine.correlate_alert(a_net, db)
    corr_engine.correlate_alert(a_auth, db)
    corr_engine.correlate_alert(a_login, db)
    group = corr_engine.correlate_alert(a_priv, db)

    assert group is not None
    assert group.risk_score >= 90
    assert group.severity == Severity.CRITICAL

    exp = group.risk_explanation
    assert exp["base_risk"] == 80
    assert exp["correlation_bonus"] == 15
    assert exp["compromise_indicator_bonus"] == 10
    assert exp["privilege_escalation_bonus"] == 5
    assert exp["final_score"] == 100
    assert exp["severity"] == "CRITICAL"
    assert len(exp["factors"]) == 5

    db.close()

# ---------------------------------------------------------
# 7. Determinism Test
# ---------------------------------------------------------
def test_risk_calculation_determinism():
    db = TestingSessionLocal()
    group = CorrelationGroup(first_seen_at=datetime.now(timezone.utc), last_seen_at=datetime.now(timezone.utc))
    a1 = helper_create_alert_with_rule(db, "CW-AUTH-001", "Brute Force", Severity.HIGH)
    a2 = helper_create_alert_with_rule(db, "CW-LOGIN-001", "Suspicious Login", Severity.HIGH)

    results = [risk_calculator.calculate(group, [a1, a2]) for _ in range(50)]
    first_dict = results[0].to_dict()

    for r in results[1:]:
        assert r.to_dict() == first_dict
    db.close()

# ---------------------------------------------------------
# 8. REST API & Security Tests
# ---------------------------------------------------------
def test_correlation_risk_api_endpoint():
    db = TestingSessionLocal()
    corr_engine = CorrelationEngine(window_seconds=1800)

    a1 = helper_create_alert_with_rule(db, "CW-NET-001", "Port Scan", Severity.MEDIUM, source_ip="10.0.0.88")
    a2 = helper_create_alert_with_rule(db, "CW-AUTH-001", "Brute Force", Severity.HIGH, source_ip="10.0.0.88")

    corr_engine.correlate_alert(a1, db)
    grp = corr_engine.correlate_alert(a2, db)
    grp_id = grp.id
    db.close()

    # Unauthenticated rejected (401)
    res_unauth = client.get(f"/api/v1/correlations/{grp_id}/risk")
    assert res_unauth.status_code == 401

    # VIEWER allowed (200)
    h_viewer = get_headers("viewer_risk", "VIEWER")
    res_v = client.get(f"/api/v1/correlations/{grp_id}/risk", headers=h_viewer)
    assert res_v.status_code == 200
    data = res_v.json()
    assert data["correlation_id"] == str(grp_id)
    assert data["base_risk"] == 60
    assert data["correlation_bonus"] == 5
    assert data["final_score"] == 65
    assert data["severity"] == "HIGH"
    assert len(data["factors"]) == 5
