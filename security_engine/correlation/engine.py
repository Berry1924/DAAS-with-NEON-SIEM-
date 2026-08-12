import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Set
from sqlalchemy.orm import Session
from sqlalchemy import select, and_, or_

from backend.app.models.alert import Alert
from backend.app.models.alert_events import AlertEvent
from backend.app.models.detection_rule import DetectionRule
from backend.app.models.correlation import CorrelationGroup
from backend.app.models.enums import CorrelationStatus
from security_engine.correlation.entities import entity_extractor
from security_engine.risk.calculator import risk_calculator
from backend.app.services.incident_service import incident_service

logger = logging.getLogger(__name__)

GOLDEN_SEQUENCE_RULES = {"CW-NET-001", "CW-AUTH-001", "CW-LOGIN-001", "CW-PRIV-001"}
DEFAULT_CORRELATION_WINDOW_SECONDS = 1800
MINIMUM_CORRELATION_THRESHOLD = 2

class CorrelationEngine:
    """Deterministic security-alert correlation engine."""

    def __init__(self, window_seconds: int = DEFAULT_CORRELATION_WINDOW_SECONDS):
        self.window_seconds = window_seconds

    def correlate_alert(self, alert: Alert, db: Session) -> Optional[CorrelationGroup]:
        """Process an alert through entity extraction, time windowing, and correlation grouping."""
        try:
            alert_entities = entity_extractor.extract_from_alert(alert)
            
            # Check if any entity is populated
            if not any(alert_entities.values()):
                logger.debug(f"Alert {alert.id} has no extracted entities; skipping correlation.")
                return None

            window_start = alert.created_at - timedelta(seconds=self.window_seconds)

            # 1. Search for an existing ACTIVE correlation group matching entities
            active_group = self._find_active_group(alert_entities, window_start, db)

            if active_group:
                return self._add_alert_to_group(active_group, alert, db)

            # 2. Search for candidate standalone alerts sharing entities within window
            candidate_alerts = self._find_candidate_alerts(alert, alert_entities, window_start, db)

            # Ensure incoming alert is in candidates
            candidate_ids = {str(a.id) for a in candidate_alerts}
            if str(alert.id) not in candidate_ids:
                candidate_alerts.append(alert)

            # Enforce minimum threshold (>= 2)
            if len(candidate_alerts) < MINIMUM_CORRELATION_THRESHOLD:
                logger.debug(f"Alert {alert.id} candidate count ({len(candidate_alerts)}) below threshold {MINIMUM_CORRELATION_THRESHOLD}")
                return None

            # 3. Create new correlation group
            return self._create_group(candidate_alerts, db)

        except Exception as e:
            logger.error(f"Error during correlation for alert {alert.id}: {e}", exc_info=True)
            return None

    def _find_active_group(
        self, alert_entities: Dict[str, Optional[str]], window_start: datetime, db: Session
    ) -> Optional[CorrelationGroup]:
        """Find active correlation group matching any shared entity within window."""
        conditions = [
            CorrelationGroup.status == CorrelationStatus.ACTIVE,
            CorrelationGroup.updated_at >= window_start,
        ]

        entity_matches = []
        if alert_entities.get("source_ip"):
            entity_matches.append(CorrelationGroup.source_ip == alert_entities["source_ip"])
        if alert_entities.get("destination_ip"):
            entity_matches.append(CorrelationGroup.destination_ip == alert_entities["destination_ip"])
        if alert_entities.get("hostname"):
            entity_matches.append(CorrelationGroup.hostname == alert_entities["hostname"])
        if alert_entities.get("username"):
            entity_matches.append(CorrelationGroup.username == alert_entities["username"])

        if not entity_matches:
            return None

        conditions.append(or_(*entity_matches))
        stmt = select(CorrelationGroup).where(and_(*conditions)).order_by(CorrelationGroup.updated_at.desc()).limit(1)
        return db.scalar(stmt)

    def _find_candidate_alerts(
        self, alert: Alert, alert_entities: Dict[str, Optional[str]], window_start: datetime, db: Session
    ) -> List[Alert]:
        """Find alerts within correlation window matching any shared entity attribute."""
        conditions = [
            Alert.created_at >= window_start,
            Alert.id != alert.id,
        ]

        entity_matches = []
        if alert_entities.get("source_ip"):
            entity_matches.append(Alert.source_ip == alert_entities["source_ip"])
        if alert_entities.get("destination_ip"):
            entity_matches.append(Alert.destination_ip == alert_entities["destination_ip"])
        if alert_entities.get("hostname"):
            entity_matches.append(Alert.hostname == alert_entities["hostname"])
        if alert_entities.get("username"):
            entity_matches.append(Alert.username == alert_entities["username"])

        if not entity_matches:
            return []

        conditions.append(or_(*entity_matches))
        stmt = select(Alert).where(and_(*conditions)).order_by(Alert.created_at.asc()).limit(100)
        candidates = list(db.scalars(stmt).all())

        # Strict entity check: candidate must share at least one non-null entity attribute
        valid_candidates = []
        for cand in candidates:
            cand_entities = entity_extractor.extract_from_alert(cand)
            if entity_extractor.shares_entity(alert_entities, cand_entities):
                valid_candidates.append(cand)

        return valid_candidates

    def _add_alert_to_group(self, group: CorrelationGroup, alert: Alert, db: Session) -> CorrelationGroup:
        """Update existing active correlation group with new alert."""
        alert_id_str = str(alert.id)
        existing_alert_ids = list(group.alert_ids)

        if alert_id_str not in existing_alert_ids:
            existing_alert_ids.append(alert_id_str)

        # Query all alerts in updated set
        uuid_list = [uuid.UUID(aid) for aid in existing_alert_ids]
        all_alerts = list(db.scalars(select(Alert).where(Alert.id.in_(uuid_list))).all())

        self._recalculate_group_fields(group, all_alerts, db)
        group.updated_at = datetime.now(timezone.utc)
        
        db.commit()
        db.refresh(group)
        logger.info(f"Updated correlation group {group.correlation_key} with alert {alert.id} (total alerts: {group.alert_count}, risk: {group.risk_score})")

        # Trigger M10 Incident Management creation/update
        incident_service.process_correlation(group, db)
        return group

    def _create_group(self, alerts: List[Alert], db: Session) -> CorrelationGroup:
        """Create new correlation group from list of related alerts."""
        now = datetime.now(timezone.utc)

        group = CorrelationGroup(
            correlation_key=f"CORR-{uuid.uuid4().hex[:12]}",
            title="Correlated Activity",
            status=CorrelationStatus.ACTIVE,
            entities={},
            alert_ids=[],
            event_ids=[],
            rule_ids=[],
            alert_count=0,
            correlation_reason="",
            first_seen_at=now,
            last_seen_at=now,
        )

        self._recalculate_group_fields(group, alerts, db)
        db.add(group)
        db.commit()
        db.refresh(group)
        logger.info(f"Created correlation group {group.correlation_key} with {group.alert_count} alerts (risk={group.risk_score}, golden={group.is_golden_sequence})")

        # Trigger M10 Incident Management creation/update
        incident_service.process_correlation(group, db)
        return group

    def _recalculate_group_fields(self, group: CorrelationGroup, alerts: List[Alert], db: Session) -> None:
        """Recalculate summary fields, entities, event links, golden sequence, risk score, and explanation."""
        if not alerts:
            return

        alert_ids = [str(a.id) for a in alerts]
        rule_map = {}
        for a in alerts:
            if a.rule_id and a.rule:
                rule_map[a.rule.rule_id] = a.rule
            elif a.evidence and "rule_id" in a.evidence:
                rule_map[a.evidence["rule_id"]] = None

        # Fetch rules for rule_ids if needed
        rule_ids_set = set(rule_map.keys())
        if not rule_ids_set:
            # Query rules by rule_id from DB
            rule_uuids = [a.rule_id for a in alerts if a.rule_id]
            if rule_uuids:
                rules_db = list(db.scalars(select(DetectionRule).where(DetectionRule.id.in_(rule_uuids))).all())
                rule_ids_set = {r.rule_id for r in rules_db}

        # Collect event IDs linked to these alerts via AlertEvent junction table
        alert_uuids = [a.id for a in alerts]
        event_links = list(db.scalars(select(AlertEvent.event_id).where(AlertEvent.alert_id.in_(alert_uuids))).all())
        primary_event_ids = [a.primary_event_id for a in alerts if a.primary_event_id]
        all_event_ids = sorted(list({str(eid) for eid in (event_links + primary_event_ids)}))

        # Consolidated entity values
        source_ips = {a.source_ip for a in alerts if a.source_ip}
        dest_ips = {a.destination_ip for a in alerts if a.destination_ip}
        usernames = {a.username for a in alerts if a.username}
        hostnames = {a.hostname for a in alerts if a.hostname}

        combined_entities = {
            "source_ip": next(iter(source_ips)) if len(source_ips) == 1 else (list(source_ips) if source_ips else None),
            "destination_ip": next(iter(dest_ips)) if len(dest_ips) == 1 else (list(dest_ips) if dest_ips else None),
            "username": next(iter(usernames)) if len(usernames) == 1 else (list(usernames) if usernames else None),
            "hostname": next(iter(hostnames)) if len(hostnames) == 1 else (list(hostnames) if hostnames else None),
        }

        group.source_ip = next(iter(source_ips)) if source_ips else None
        group.destination_ip = next(iter(dest_ips)) if dest_ips else None
        group.username = next(iter(usernames)) if usernames else None
        group.hostname = next(iter(hostnames)) if hostnames else None

        group.alert_ids = alert_ids
        group.event_ids = all_event_ids
        group.rule_ids = sorted(list(rule_ids_set))
        group.alert_count = len(alerts)
        group.entities = combined_entities

        # Timestamps
        timestamps = [a.created_at for a in alerts]
        group.first_seen_at = min(timestamps)
        group.last_seen_at = max(timestamps)

        # Check Golden Sequence
        is_golden = GOLDEN_SEQUENCE_RULES.issubset(rule_ids_set)
        group.is_golden_sequence = is_golden

        shared_entity_desc = entity_extractor.get_shared_entity_description(combined_entities)

        if is_golden:
            group.pattern_matched = "Potential Host Compromise"
            group.title = f"Potential Host Compromise: {shared_entity_desc}"
            group.correlation_reason = (
                "Port scanning, repeated authentication failures, successful authentication after failures, "
                "and privilege activity were observed from the same source/entity within the configured correlation window."
            )
        else:
            group.pattern_matched = None
            rules_str = ", ".join(sorted(rule_ids_set)) if rule_ids_set else "alerts"
            group.title = f"Correlated Activity: {shared_entity_desc}"
            group.correlation_reason = (
                f"{group.alert_count} security alerts ({rules_str}) were correlated because they share "
                f"{shared_entity_desc} and occurred within the configured {self.window_seconds}-second correlation window."
            )

        # M09 Risk Engine Calculation
        risk_result = risk_calculator.calculate(group=group, alerts=alerts)
        group.risk_score = risk_result.final_score
        group.severity = risk_result.severity
        group.risk_explanation = risk_result.to_dict()


correlation_engine = CorrelationEngine()
