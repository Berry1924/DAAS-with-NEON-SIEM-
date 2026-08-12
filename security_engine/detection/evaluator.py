import re
import uuid
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import select, func, and_

from backend.app.models.event import Event
from backend.app.models.alert import Alert
from backend.app.models.alert_events import AlertEvent
from backend.app.models.detection_rule import DetectionRule
from backend.app.models.enums import Severity, AlertStatus, EventOutcome

logger = logging.getLogger(__name__)

class ConditionEvaluator:
    """Evaluates rule conditions against event fields safely."""

    @staticmethod
    def evaluate_condition(field_value: Any, operator: str, expected_value: Any) -> bool:
        """Safely evaluate a single condition operator."""
        try:
            if operator == "eq":
                if isinstance(expected_value, str) and hasattr(EventOutcome, "value") and hasattr(EventOutcome, "_member_names_") and (expected_value in EventOutcome._member_names_ or expected_value in [e.value for e in EventOutcome]):
                    return field_value == expected_value or (isinstance(field_value, EventOutcome) and (field_value.value == expected_value or field_value.name == expected_value))
                if isinstance(field_value, EventOutcome):
                    return field_value.value == expected_value or field_value.name == expected_value
                return field_value == expected_value
            elif operator == "ne":
                if isinstance(field_value, EventOutcome):
                    return field_value.value != expected_value and field_value.name != expected_value
                return field_value != expected_value
            elif operator == "contains":
                if not isinstance(field_value, str) or not isinstance(expected_value, str):
                    return False
                return expected_value in field_value
            elif operator == "gte":
                if field_value is None:
                    return False
                return field_value >= expected_value
            elif operator == "lte":
                if field_value is None:
                    return False
                return field_value <= expected_value
            elif operator == "in":
                if not isinstance(expected_value, list):
                    return False
                if isinstance(field_value, EventOutcome):
                    return field_value.value in expected_value or field_value.name in expected_value
                return field_value in expected_value
            elif operator == "regex":
                if not isinstance(field_value, str) or not isinstance(expected_value, str):
                    return False
                if len(expected_value) > 500:
                    logger.warning(f"Regex pattern too long (>500 chars), dropping evaluation.")
                    return False
                return bool(re.search(expected_value, field_value))
            return False
        except Exception as e:
            logger.error(f"Error evaluating condition: {e}")
            return False

class RuleEvaluator:
    """Core detection engine that evaluates events against loaded rules."""
    
    def evaluate(self, event: Event, db: Session) -> List[Alert]:
        """Evaluates an event against all enabled rules."""
        alerts = []
        try:
            enabled_rules = list(db.scalars(select(DetectionRule).where(DetectionRule.enabled == True)).all())
            for rule in enabled_rules:
                try:
                    if event.event_type not in rule.event_types:
                        continue
                    
                    if not self._check_conditions(event, rule.conditions):
                        continue
                    
                    met_threshold, supporting_events = self._check_threshold(event, rule, db)
                    if not met_threshold:
                        continue
                    
                    if "requires_prior" in rule.conditions:
                        met_prior, prior_events = self._check_requires_prior(event, rule.conditions["requires_prior"], db)
                        if not met_prior:
                            continue
                        supporting_events.extend(prior_events)
                    
                    if self._check_dedup(rule, event, db):
                        logger.info(f"Duplicate alert skipped for rule {rule.rule_id}")
                        continue
                    
                    alert = self._create_alert(rule, event, supporting_events, db)
                    alerts.append(alert)
                except Exception as rule_err:
                    logger.error(f"Error evaluating rule {rule.rule_id}: {rule_err}", exc_info=True)
        except Exception as eval_err:
            logger.error(f"Fatal error in evaluate(): {eval_err}", exc_info=True)
            
        return alerts

    def _check_conditions(self, event: Event, conditions: Dict[str, Any]) -> bool:
        """Check all field conditions against event."""
        if not conditions:
            return True
        for field, condition in conditions.items():
            if field in ("requires_prior", "count_distinct"):
                continue
            field_value = getattr(event, field, None)
            if isinstance(condition, dict):
                for operator, expected_value in condition.items():
                    if not ConditionEvaluator.evaluate_condition(field_value, operator, expected_value):
                        return False
        return True

    def _check_threshold(self, event: Event, rule: DetectionRule, db: Session) -> tuple[bool, List[Event]]:
        """Query recent events in window matching group_by, return (met, supporting_events)."""
        if not rule.threshold or rule.threshold <= 1:
            return True, []
        
        group_field = rule.group_by
        group_value = getattr(event, group_field, None) if group_field else None
        
        if group_field and not group_value:
            return False, []

        window_start = event.timestamp - timedelta(seconds=rule.window_seconds)

        conditions = [
            Event.event_type.in_(rule.event_types),
            Event.timestamp >= window_start,
            Event.timestamp <= event.timestamp,
        ]
        if group_field:
            conditions.append(getattr(Event, group_field) == group_value)

        for field, condition_data in rule.conditions.items():
            if field in ("requires_prior", "count_distinct"):
                continue
            if isinstance(condition_data, dict):
                for op, exp_val in condition_data.items():
                    if op == "eq":
                        conditions.append(getattr(Event, field) == exp_val)
                    elif op == "ne":
                        conditions.append(getattr(Event, field) != exp_val)
                    elif op == "in":
                        conditions.append(getattr(Event, field).in_(exp_val))

        stmt = select(Event).where(and_(*conditions)).order_by(Event.timestamp.desc()).limit(rule.threshold + 10)
        matching_events = list(db.scalars(stmt).all())

        if "count_distinct" in rule.conditions:
            distinct_field = rule.conditions["count_distinct"]
            distinct_values = {getattr(e, distinct_field) for e in matching_events if getattr(e, distinct_field, None)}
            return len(distinct_values) >= rule.threshold, matching_events

        return len(matching_events) >= rule.threshold, matching_events

    def _check_requires_prior(self, event: Event, requires_prior: Dict[str, Any], db: Session) -> tuple[bool, List[Event]]:
        """Check for prior events based on requires_prior specification."""
        min_count = requires_prior.get("min_count", 1)
        window_seconds = requires_prior.get("window_seconds", 300)
        window_start = event.timestamp - timedelta(seconds=window_seconds)
        
        conditions = [
            Event.timestamp >= window_start,
            Event.timestamp < event.timestamp,
        ]
        
        if "event_types" in requires_prior:
            conditions.append(Event.event_type.in_(requires_prior["event_types"]))
            
        group_field = getattr(event, "group_by", "source_ip")
        group_val = getattr(event, group_field, None)
        if group_val:
            conditions.append(getattr(Event, group_field) == group_val)
            
        for field, condition_data in requires_prior.items():
            if field in ("min_count", "window_seconds", "event_types"):
                continue
            if isinstance(condition_data, dict):
                for op, exp_val in condition_data.items():
                    if op == "eq":
                        conditions.append(getattr(Event, field) == exp_val)

        stmt = select(Event).where(and_(*conditions)).order_by(Event.timestamp.desc()).limit(min_count)
        prior_events = list(db.scalars(stmt).all())
        
        return len(prior_events) >= min_count, prior_events

    def _check_dedup(self, rule: DetectionRule, event: Event, db: Session) -> bool:
        """Check if duplicate active alert exists."""
        group_value = getattr(event, rule.group_by, None) if rule.group_by else None
        window_start = event.timestamp - timedelta(seconds=rule.window_seconds) if rule.window_seconds else None
        
        conditions = [
            Alert.rule_id == rule.id,
            Alert.status.in_([AlertStatus.NEW, AlertStatus.ACKNOWLEDGED, AlertStatus.INVESTIGATING]),
        ]
        
        if group_value and rule.group_by:
            if hasattr(Alert, rule.group_by):
                conditions.append(getattr(Alert, rule.group_by) == group_value)
                
        if window_start:
            conditions.append(Alert.created_at >= window_start)
        
        existing = db.scalar(select(func.count(Alert.id)).where(and_(*conditions)))
        return existing > 0

    def _create_alert(self, rule: DetectionRule, trigger_event: Event, supporting_events: List[Event], db: Session) -> Alert:
        """Create alert and link events."""
        now = datetime.now(timezone.utc)
        timestamps = [e.timestamp for e in supporting_events] + [trigger_event.timestamp]
        
        alert = Alert(
            rule_id=rule.id,
            primary_event_id=trigger_event.id,
            title=f"{rule.name}: {getattr(trigger_event, rule.group_by, 'unknown') if rule.group_by else 'detected'}",
            description=rule.description,
            severity=rule.severity,
            risk_score=rule.risk_weight,
            status=AlertStatus.NEW,
            source_ip=trigger_event.source_ip,
            destination_ip=trigger_event.destination_ip,
            username=trigger_event.username,
            hostname=trigger_event.hostname,
            evidence={
                "rule_id": rule.rule_id,
                "rule_name": rule.name,
                "group_by": rule.group_by,
                "group_value": getattr(trigger_event, rule.group_by, None) if rule.group_by else None,
                "threshold": rule.threshold,
                "event_count": len(supporting_events),
                "window_seconds": rule.window_seconds,
                "mitre": rule.mitre_metadata,
            },
            first_seen_at=min(timestamps),
            last_seen_at=max(timestamps),
        )
        db.add(alert)
        db.flush()  # Get alert.id
        
        # Link trigger event as primary
        link = AlertEvent(alert_id=alert.id, event_id=trigger_event.id, evidence_role="trigger")
        db.add(link)
        
        # Link supporting events
        seen_event_ids = {trigger_event.id}
        for evt in supporting_events:
            if evt.id not in seen_event_ids:
                link = AlertEvent(alert_id=alert.id, event_id=evt.id, evidence_role="supporting")
                db.add(link)
                seen_event_ids.add(evt.id)
        
        db.commit()
        db.refresh(alert)
        logger.info(f"Alert created: {alert.title} (rule={rule.rule_id}, severity={rule.severity.value})")
        return alert

rule_evaluator = RuleEvaluator()
