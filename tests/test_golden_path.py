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
from backend.app.models.incident import Incident
from backend.app.models.enums import UserRole, EventOutcome, Severity, IncidentStatus
from backend.app.core.security import get_password_hash, create_access_token
from backend.app.db.session import get_db

from security_engine.detection.rule_loader import RuleLoader
from security_engine.detection.evaluator import rule_evaluator
from security_engine.correlation.engine import correlation_engine
from security_engine.pipeline import processing_service
from security_engine.demo.generator import demo_generator


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

    # Load rules into DB
    loader = RuleLoader("rules")
    loader.sync(db)

    # Seed users
    analyst = User(
        username="golden_analyst",
        email="golden_analyst@cyberwolf.local",
        display_name="Golden Analyst",
        password_hash=get_password_hash("AnalystPass123!"),
        role=UserRole.ANALYST,
        is_active=True,
    )
    db.add(analyst)
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

def test_golden_path_end_to_end_telemetry_to_incident():
    """Golden Path Integration Test:
    Telemetry -> Processing -> Event Persistence -> M07 Alert -> M08 Correlation -> M09 Risk -> M10 Incident
    """
    db = TestingSessionLocal()
    h_analyst = get_headers("golden_analyst", "ANALYST")
    source_ip = "192.168.1.50"
    target_user = "root_user"
    hostname = "web-server-01"

    now = datetime.now(timezone.utc)

    # 1. Replay Telemetry Sequence using GoldenPathDemoGenerator through full production pipeline
    demo_generator.replay(db, base_time=now)

    # 3. Query created Incident via API
    res_list = client.get("/api/v1/incidents", headers=h_analyst)
    assert res_list.status_code == 200
    list_data = res_list.json()

    assert list_data["total"] == 1
    inc_summary = list_data["items"][0]
    inc_id = inc_summary["id"]

    # 4. Detailed Incident Verification
    res_detail = client.get(f"/api/v1/incidents/{inc_id}", headers=h_analyst)
    assert res_detail.status_code == 200
    inc = res_detail.json()

    # Title: Must be "Potential Host Compromise"
    assert "Potential Host Compromise" in inc["title"]

    # Risk: Must be 100/100 (CRITICAL)
    assert inc["risk_score"] == 100
    assert inc["severity"] == "CRITICAL"

    # Risk Explanation verification
    exp = inc["risk_explanation"]
    assert exp["base_risk"] == 80
    assert exp["correlation_bonus"] == 15
    assert exp["compromise_indicator_bonus"] == 10
    assert exp["privilege_escalation_bonus"] == 5
    assert exp["final_score"] == 100

    # Linked Alerts: 4 distinct rule alerts (CW-NET-001, CW-AUTH-001, CW-LOGIN-001, CW-PRIV-001)
    linked_rule_ids = {a["rule_id"] for a in inc["linked_alerts"]}
    assert "CW-NET-001" in linked_rule_ids
    assert "CW-AUTH-001" in linked_rule_ids
    assert "CW-LOGIN-001" in linked_rule_ids
    assert "CW-PRIV-001" in linked_rule_ids
    assert len(inc["linked_alerts"]) == 4

    # Linked Events: Traceable back to original telemetry
    assert len(inc["linked_events"]) >= 4

    # 5. M13 Dashboard Summary Verification
    res_dash = client.get("/api/v1/dashboard/summary", headers=h_analyst)
    assert res_dash.status_code == 200
    dash = res_dash.json()

    assert dash["total_events_24h"] == 17
    assert dash["open_incidents"] == 1
    assert len(dash["recent_incidents"]) == 1
    assert "Potential Host Compromise" in dash["recent_incidents"][0]["title"]
    assert dash["recent_incidents"][0]["risk_score"] == 100

    top_rule_ids = [r["rule_id"] for r in dash["top_detection_rules"]]
    assert len(top_rule_ids) >= 1
    assert any(rid in ["CW-NET-001", "CW-AUTH-001", "CW-LOGIN-001", "CW-PRIV-001"] for rid in top_rule_ids)

    db.close()

