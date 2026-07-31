import uuid
from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from backend.app.models import (
    Base,
    User,
    UserRole,
    Asset,
    AssetStatus,
    Event,
    EventOutcome,
    Severity,
    DetectionRule,
    Alert,
    AlertStatus,
    AlertEvent,
    Incident,
    IncidentStatus,
    IncidentAlert,
    IncidentTimeline,
    IncidentNote,
    AuditLog,
    AuditResult,
)
from backend.app.repositories import EventRepository, AlertRepository, IncidentRepository
from backend.app.schemas.user import UserRead

@pytest.fixture
def db_session():
    """Isolated in-memory SQLite engine fixture for unit testing."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()

def test_alembic_metadata_tables():
    tables = Base.metadata.tables.keys()
    required = {
        "users",
        "assets",
        "events",
        "detection_rules",
        "alerts",
        "alert_events",
        "incidents",
        "incident_alerts",
        "incident_timeline",
        "incident_notes",
        "audit_logs",
    }
    assert required.issubset(set(tables))

def test_user_creation_and_uniqueness(db_session):
    user1 = User(
        username="analyst_jane",
        email="jane@cyberwolf.local",
        display_name="Jane Doe",
        password_hash="$2b$12$eImiTXuWVxfM37uY4JANjO5E/8/d6.",
        role=UserRole.ANALYST,
        is_active=True,
    )
    db_session.add(user1)
    db_session.commit()

    assert user1.id is not None
    assert user1.is_active is True

    # Test username uniqueness
    user2 = User(
        username="analyst_jane",
        email="jane2@cyberwolf.local",
        display_name="Jane Duplicate",
        password_hash="hash",
        is_active=True,
    )
    db_session.add(user2)
    with pytest.raises(IntegrityError):
        db_session.commit()

def test_user_schema_excludes_password_hash():
    user = User(
        id=uuid.uuid4(),
        username="analyst_bob",
        email="bob@cyberwolf.local",
        display_name="Bob Smith",
        password_hash="secret_hash_value_never_expose",
        role=UserRole.ANALYST,
        is_active=True,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    schema = UserRead.model_validate(user)
    dumped = schema.model_dump()
    assert "password_hash" not in dumped
    assert "password" not in dumped
    assert dumped["username"] == "analyst_bob"
    assert dumped["role"] == UserRole.ANALYST

def test_evidence_chain_and_traversal(db_session):
    # 1. Create Asset & Event
    asset = Asset(hostname="server-01", ip_address="192.168.1.50", criticality=80, status=AssetStatus.ACTIVE)
    db_session.add(asset)
    db_session.commit()

    now = datetime.now(timezone.utc)
    event = Event(
        timestamp=now,
        source_type="linux_auth",
        event_type="authentication_failure",
        source_ip="192.168.1.100",
        destination_ip="192.168.1.50",
        hostname="server-01",
        username="root",
        outcome=EventOutcome.FAILURE,
        severity=Severity.HIGH,
        raw_event={"msg": "Failed password for root"},
        asset_id=asset.id,
    )
    db_session.add(event)
    db_session.commit()

    # 2. Create DetectionRule & Alert
    rule = DetectionRule(
        rule_id="CW-AUTH-001",
        name="Repeated Auth Failures",
        description="Detects multiple authentication failures",
        event_types=["authentication_failure"],
        conditions={"threshold": 5},
        severity=Severity.HIGH,
        risk_weight=70,
    )
    db_session.add(rule)
    db_session.commit()

    alert = Alert(
        rule_id=rule.id,
        primary_event_id=event.id,
        title="Brute Force Auth Failure",
        severity=Severity.HIGH,
        risk_score=70,
        status=AlertStatus.NEW,
        source_ip="192.168.1.100",
        first_seen_at=now,
        last_seen_at=now,
    )
    db_session.add(alert)
    db_session.commit()

    # Junction AlertEvent
    link_ae = AlertEvent(alert_id=alert.id, event_id=event.id, evidence_role="trigger")
    db_session.add(link_ae)
    db_session.commit()

    # 3. Create Incident & IncidentAlert
    incident = Incident(
        incident_key="CW-INC-0042",
        title="Potential Host Compromise",
        incident_type="Compromise",
        severity=Severity.CRITICAL,
        risk_score=94,
        status=IncidentStatus.NEW,
        primary_asset_id=asset.id,
        source_ip="192.168.1.100",
        first_seen_at=now,
        last_seen_at=now,
    )
    db_session.add(incident)
    db_session.commit()

    link_ia = IncidentAlert(incident_id=incident.id, alert_id=alert.id, correlation_role="contributing")
    db_session.add(link_ia)
    db_session.commit()

    # 4. Traverse Incident -> Alert -> Event
    fetched_incident = db_session.get(Incident, incident.id)
    assert fetched_incident.incident_key == "CW-INC-0042"
    assert len(fetched_incident.alert_links) == 1
    
    fetched_alert = fetched_incident.alert_links[0].alert
    assert fetched_alert.title == "Brute Force Auth Failure"
    assert len(fetched_alert.event_links) == 1

    fetched_event = fetched_alert.event_links[0].event
    assert fetched_event.event_type == "authentication_failure"
    assert fetched_event.source_ip == "192.168.1.100"

def test_evidence_deletion_policy(db_session):
    """Deleting an Incident or Alert MUST NOT destroy the underlying Event evidence."""
    now = datetime.now(timezone.utc)
    event = Event(
        timestamp=now,
        source_type="syslog",
        event_type="port_scan",
        raw_event={"port": 80},
    )
    rule = DetectionRule(
        rule_id="CW-NET-001",
        name="Port Scan Pattern",
        description="Detects port scan activity",
        event_types=["port_scan"],
        conditions={},
        severity=Severity.MEDIUM,
    )
    db_session.add_all([event, rule])
    db_session.commit()

    alert = Alert(
        rule_id=rule.id,
        primary_event_id=event.id,
        title="Port Scan Alert",
        severity=Severity.MEDIUM,
        first_seen_at=now,
        last_seen_at=now,
    )
    db_session.add(alert)
    db_session.commit()

    link_ae = AlertEvent(alert_id=alert.id, event_id=event.id)
    db_session.add(link_ae)
    db_session.commit()

    incident = Incident(
        incident_key="CW-INC-0099",
        title="Reconnaissance Activity",
        incident_type="Recon",
        severity=Severity.MEDIUM,
        first_seen_at=now,
        last_seen_at=now,
    )
    db_session.add(incident)
    db_session.commit()

    link_ia = IncidentAlert(incident_id=incident.id, alert_id=alert.id)
    db_session.add(link_ia)
    db_session.commit()

    # Delete Incident
    db_session.delete(incident)
    db_session.commit()

    # Verify Alert and Event still exist!
    assert db_session.get(Alert, alert.id) is not None
    assert db_session.get(Event, event.id) is not None

def test_repository_pattern_basics(db_session):
    event_repo = EventRepository(db_session)
    alert_repo = AlertRepository(db_session)
    incident_repo = IncidentRepository(db_session)

    now = datetime.now(timezone.utc)
    ev = Event(timestamp=now, source_type="api", event_type="login", raw_event={"user": "admin"})
    created_ev = event_repo.create(ev)
    assert created_ev.id is not None

    rule = DetectionRule(
        rule_id="CW-LOGIN-001", name="Login", description="Desc", event_types=["login"], conditions={}, severity=Severity.LOW
    )
    db_session.add(rule)
    db_session.commit()

    al = Alert(rule_id=rule.id, primary_event_id=created_ev.id, title="Login", severity=Severity.LOW, first_seen_at=now, last_seen_at=now)
    created_al = alert_repo.create(al)
    assert created_al.id is not None

    inc = Incident(incident_key="CW-INC-0100", title="Inc", incident_type="Login", severity=Severity.LOW, first_seen_at=now, last_seen_at=now)
    created_inc = incident_repo.create(inc)
    assert created_inc.id is not None

    link = incident_repo.link_alert(created_inc.id, created_al.id)
    assert link.incident_id == created_inc.id

def test_audit_log_creation(db_session):
    audit = AuditLog(
        action="INCIDENT_STATUS_CHANGE",
        target_type="incident",
        target_id="CW-INC-0042",
        result=AuditResult.SUCCESS,
        audit_metadata={"old_status": "NEW", "new_status": "INVESTIGATING"},
    )
    db_session.add(audit)
    db_session.commit()
    assert audit.id is not None
    assert audit.result == AuditResult.SUCCESS
