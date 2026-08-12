from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import select, func, and_, desc

from backend.app.models.event import Event
from backend.app.models.alert import Alert
from backend.app.models.detection_rule import DetectionRule
from backend.app.models.incident import Incident
from backend.app.models.user import User
from backend.app.models.enums import Severity, AlertStatus, IncidentStatus
from backend.app.schemas.dashboard import (
    SeverityCount,
    RuleTriggerCount,
    HourlyBucket,
    DashboardRecentIncident,
)

ACTIVE_ALERT_STATUSES = [AlertStatus.NEW, AlertStatus.ACKNOWLEDGED, AlertStatus.INVESTIGATING]
OPEN_INCIDENT_STATUSES = [IncidentStatus.NEW, IncidentStatus.ACKNOWLEDGED, IncidentStatus.INVESTIGATING]

class DashboardRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_total_events_24h(self, window_start: datetime) -> int:
        """Count total events ingested with timestamp >= window_start."""
        stmt = select(func.count(Event.id)).where(Event.timestamp >= window_start)
        return self.db.scalar(stmt) or 0

    def get_active_alerts_by_severity(self) -> List[SeverityCount]:
        """Aggregate active alerts grouped by severity tier."""
        stmt = (
            select(Alert.severity, func.count(Alert.id))
            .where(Alert.status.in_(ACTIVE_ALERT_STATUSES))
            .group_by(Alert.severity)
        )
        counts_by_sev = dict(self.db.execute(stmt).all())

        # Preserve all 5 severity categories cleanly
        result = []
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            result.append(SeverityCount(severity=sev, count=counts_by_sev.get(sev, 0)))
        return result

    def get_open_incidents_count(self) -> int:
        """Count non-terminal active incidents."""
        stmt = select(func.count(Incident.id)).where(Incident.status.in_(OPEN_INCIDENT_STATUSES))
        return self.db.scalar(stmt) or 0

    def get_top_detection_rules(self, limit: int = 5) -> List[RuleTriggerCount]:
        """Return top detection rules ordered by trigger count DESC."""
        # Join Alert and DetectionRule
        stmt = (
            select(DetectionRule.rule_id, DetectionRule.name, func.count(Alert.id).label("cnt"))
            .join(DetectionRule, Alert.rule_id == DetectionRule.id)
            .group_by(DetectionRule.rule_id, DetectionRule.name)
            .order_by(desc("cnt"), DetectionRule.rule_id.asc())
            .limit(limit)
        )
        rows = self.db.execute(stmt).all()
        result = []
        for rule_id, name, count in rows:
            result.append(RuleTriggerCount(rule_id=rule_id, name=name, count=count))
        return result

    def get_recent_incidents(self, limit: int = 5) -> List[DashboardRecentIncident]:
        """Return N most recent incidents ordered by created_at DESC."""
        stmt = (
            select(Incident, User.display_name)
            .outerjoin(User, Incident.assigned_to == User.id)
            .order_by(Incident.created_at.desc())
            .limit(limit)
        )
        rows = self.db.execute(stmt).all()
        result = []
        for inc, assignee_name in rows:
            result.append(
                DashboardRecentIncident(
                    id=inc.id,
                    incident_key=inc.incident_key,
                    title=inc.title,
                    severity=inc.severity,
                    risk_score=inc.risk_score,
                    status=inc.status,
                    created_at=inc.created_at,
                    assigned_to=inc.assigned_to,
                    assignee_name=assignee_name,
                )
            )
        return result

    def get_hourly_event_trend(self, now_utc: datetime, window_start: datetime) -> List[HourlyBucket]:
        """
        Generate exactly 24 hourly UTC buckets covering [now - 24h, now].
        Computes counts efficiently across SQLite & PostgreSQL.
        """
        # Fetch event timestamps in window
        stmt = select(Event.timestamp).where(Event.timestamp >= window_start)
        timestamps = list(self.db.scalars(stmt).all())

        # Build 24 discrete 1-hour bucket boundaries
        # Normalize now_utc to start of current hour
        current_hour_start = now_utc.replace(minute=0, second=0, microsecond=0)
        hour_starts = [current_hour_start - timedelta(hours=i) for i in range(23, -1, -1)]

        bucket_counts = {h: 0 for h in hour_starts}

        for ts in timestamps:
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            # Truncate ts to hour
            ts_hour = ts.replace(minute=0, second=0, microsecond=0)
            if ts_hour in bucket_counts:
                bucket_counts[ts_hour] += 1

        result = []
        for h in hour_starts:
            hour_str = h.strftime("%H:00")
            result.append(HourlyBucket(hour=hour_str, count=bucket_counts[h]))

        return result
