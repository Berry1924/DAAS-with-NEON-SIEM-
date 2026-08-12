import time
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import select

from backend.app.schemas.telemetry import IngestionEnvelope
from backend.app.models.event import Event
from backend.app.models.alert import Alert
from backend.app.models.correlation import CorrelationGroup
from backend.app.models.incident import Incident
from backend.app.models.audit_log import AuditLog
from security_engine.pipeline import processing_service, ProcessingResult
from backend.app.services.dashboard_service import dashboard_service

logger = logging.getLogger(__name__)

DEMO_SOURCE_IP = "192.168.1.50"
DEMO_TARGET_USER = "root_user"
DEMO_HOSTNAME = "web-server-01"
DEMO_DEST_BASE_IP = "10.0.1."

@dataclass
class DemoResult:
    events_generated: int
    events_persisted: int
    alerts_created: int
    rules_triggered: List[str]
    correlation_created: bool
    incident_key: Optional[str]
    risk_score: int
    severity: str
    audit_records_created: int
    dashboard_events_24h: int
    processing_results: List[ProcessingResult] = field(default_factory=list)

class GoldenPathDemoGenerator:
    """
    Deterministic telemetry generator & replayer for NEON SIEM Golden Path attack.
    Reproduces: Port Scan -> Brute Force -> Suspicious Login -> Privilege Escalation -> Incident (Risk 100 CRITICAL).
    """

    def generate_envelopes(self, base_time: Optional[datetime] = None) -> List[IngestionEnvelope]:
        """
        Generate 17 deterministic telemetry IngestionEnvelope objects for the Golden Path attack.
        """
        if base_time is None:
            base_time = datetime.now(timezone.utc) - timedelta(minutes=5)

        if base_time.tzinfo is None:
            base_time = base_time.replace(tzinfo=timezone.utc)

        envelopes: List[IngestionEnvelope] = []

        # Stage 1: 10 Network Port Scan events to 10 distinct destination IPs
        for i in range(10):
            ts = base_time + timedelta(seconds=i * 2)
            dest_ip = f"{DEMO_DEST_BASE_IP}{10 + i}"
            envelope = IngestionEnvelope(
                request_id=f"req-demo-gp-scan-{i}",
                ingested_by="demo_generator",
                source_type="json",
                raw_payload={
                    "timestamp": ts.isoformat(),
                    "event_type": "connection",
                    "source_ip": DEMO_SOURCE_IP,
                    "destination_ip": dest_ip,
                    "username": DEMO_TARGET_USER,
                    "hostname": DEMO_HOSTNAME,
                    "outcome": "SUCCESS",
                    "severity": "MEDIUM",
                    "action": "network_scan",
                    "demo_run_id": "NEON-GOLDEN-PATH",
                    "raw": f"Port scan connection {i} from {DEMO_SOURCE_IP} to {dest_ip}:80"
                },
                source_event_id=f"demo-gp-scan-{i}-{ts.strftime('%Y%m%d%H%M%S')}"
            )
            envelopes.append(envelope)

        # Stage 2: 5 Failed Authentication events from DEMO_SOURCE_IP
        for i in range(5):
            ts = base_time + timedelta(seconds=30 + i * 2)
            envelope = IngestionEnvelope(
                request_id=f"req-demo-gp-authfail-{i}",
                ingested_by="demo_generator",
                source_type="json",
                raw_payload={
                    "timestamp": ts.isoformat(),
                    "event_type": "authentication",
                    "source_ip": DEMO_SOURCE_IP,
                    "destination_ip": "10.0.0.1",
                    "username": DEMO_TARGET_USER,
                    "hostname": DEMO_HOSTNAME,
                    "outcome": "FAILURE",
                    "severity": "HIGH",
                    "action": "login",
                    "demo_run_id": "NEON-GOLDEN-PATH",
                    "raw": f"Failed password for {DEMO_TARGET_USER} from {DEMO_SOURCE_IP} port 4500{i} ssh2"
                },
                source_event_id=f"demo-gp-authfail-{i}-{ts.strftime('%Y%m%d%H%M%S')}"
            )
            envelopes.append(envelope)

        # Stage 3: 1 Successful Authentication event after failures
        ts_login = base_time + timedelta(seconds=50)
        envelope_login = IngestionEnvelope(
            request_id="req-demo-gp-login",
            ingested_by="demo_generator",
            source_type="json",
            raw_payload={
                "timestamp": ts_login.isoformat(),
                "event_type": "authentication",
                "source_ip": DEMO_SOURCE_IP,
                "destination_ip": "10.0.0.1",
                "username": DEMO_TARGET_USER,
                "hostname": DEMO_HOSTNAME,
                "outcome": "SUCCESS",
                "severity": "HIGH",
                "action": "login",
                "demo_run_id": "NEON-GOLDEN-PATH",
                "raw": f"Accepted password for {DEMO_TARGET_USER} from {DEMO_SOURCE_IP} port 45010 ssh2"
            },
            source_event_id=f"demo-gp-login-{ts_login.strftime('%Y%m%d%H%M%S')}"
        )
        envelopes.append(envelope_login)

        # Stage 4: 1 Privilege Escalation event (sudo)
        ts_priv = base_time + timedelta(seconds=60)
        envelope_priv = IngestionEnvelope(
            request_id="req-demo-gp-priv",
            ingested_by="demo_generator",
            source_type="json",
            raw_payload={
                "timestamp": ts_priv.isoformat(),
                "event_type": "privilege_escalation",
                "source_ip": DEMO_SOURCE_IP,
                "destination_ip": "10.0.0.1",
                "username": DEMO_TARGET_USER,
                "hostname": DEMO_HOSTNAME,
                "outcome": "SUCCESS",
                "severity": "CRITICAL",
                "action": "sudo",
                "demo_run_id": "NEON-GOLDEN-PATH",
                "raw": f"sudo: {DEMO_TARGET_USER} : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/bin/bash"
            },
            source_event_id=f"demo-gp-priv-{ts_priv.strftime('%Y%m%d%H%M%S')}"
        )
        envelopes.append(envelope_priv)

        return envelopes

    def replay(
        self,
        db: Session,
        base_time: Optional[datetime] = None,
        slow: bool = False,
        pace_delay: float = 0.5
    ) -> DemoResult:
        """
        Replay Golden Path attack telemetry through actual NEON production pipeline.
        """
        envelopes = self.generate_envelopes(base_time=base_time)
        results: List[ProcessingResult] = []

        logger.info(f"Starting NEON Golden Path Demo Replay ({len(envelopes)} events)...")

        for idx, env in enumerate(envelopes, 1):
            if slow and idx in (1, 11, 16, 17):
                time.sleep(pace_delay)
            res = processing_service.process(env, db)
            results.append(res)

        return self.verify_results(db, results)

    def verify_results(self, db: Session, results: Optional[List[ProcessingResult]] = None) -> DemoResult:
        """Query DB state to verify actual security results."""
        if results is None:
            results = []

        events_persisted = len(db.scalars(select(Event)).all())
        alerts = list(db.scalars(select(Alert)).all())

        rule_ids = set()
        for a in alerts:
            if a.evidence and isinstance(a.evidence, dict) and a.evidence.get("rule_id"):
                rule_ids.add(a.evidence.get("rule_id"))
            elif a.rule:
                rule_ids.add(a.rule.rule_id)

        corr = db.scalar(select(CorrelationGroup).filter(CorrelationGroup.is_golden_sequence == True))
        inc = db.scalar(select(Incident).order_by(Incident.created_at.desc()))
        audits = len(db.scalars(select(AuditLog)).all())
        dash_summary = dashboard_service.get_summary(db)

        return DemoResult(
            events_generated=17,
            events_persisted=events_persisted,
            alerts_created=len(alerts),
            rules_triggered=sorted(rule_ids),
            correlation_created=corr is not None,
            incident_key=inc.incident_key if inc else None,
            risk_score=inc.risk_score if inc else (corr.risk_score if corr else 0),
            severity=inc.severity.value if inc else (corr.severity.value if corr else "NONE"),
            audit_records_created=audits,
            dashboard_events_24h=dash_summary.total_events_24h,
            processing_results=results
        )

demo_generator = GoldenPathDemoGenerator()
