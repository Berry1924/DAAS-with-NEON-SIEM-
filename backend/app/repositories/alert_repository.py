import uuid
import math
from typing import List, Optional, Tuple, Dict, Any
from datetime import datetime
from dataclasses import dataclass
from sqlalchemy.orm import Session
from sqlalchemy import select, func, and_

from backend.app.models.alert import Alert
from backend.app.models.alert_events import AlertEvent
from backend.app.models.enums import Severity, AlertStatus

@dataclass
class AlertFilter:
    status: Optional[AlertStatus] = None
    severity: Optional[Severity] = None
    source_ip: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    rule_id: Optional[uuid.UUID] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    sort_by: str = "created_at"
    sort_order: str = "desc"

SORT_ALLOWLIST = {"created_at", "updated_at", "severity", "risk_score", "status"}

class AlertRepository:
    def __init__(self, db: Session):
        self.db = db

    def create(self, alert: Alert) -> Alert:
        self.db.add(alert)
        self.db.commit()
        self.db.refresh(alert)
        return alert

    def get_by_id(self, alert_id: uuid.UUID) -> Optional[Alert]:
        return self.db.get(Alert, alert_id)

    def link_event(self, alert_id: uuid.UUID, event_id: uuid.UUID, role: str = "supporting") -> AlertEvent:
        link = AlertEvent(alert_id=alert_id, event_id=event_id, evidence_role=role)
        self.db.add(link)
        self.db.commit()
        return link

    def list_alerts(self, limit: int = 50, offset: int = 0) -> List[Alert]:
        stmt = select(Alert).order_by(Alert.created_at.desc()).limit(limit).offset(offset)
        return list(self.db.scalars(stmt).all())

    def search(self, filter_params: AlertFilter, page: int = 1, page_size: int = 50) -> Tuple[List[Alert], int]:
        """Search alerts with filters, sorting, and bounded pagination."""
        conditions = []
        
        if filter_params.status:
            conditions.append(Alert.status == filter_params.status)
        if filter_params.severity:
            conditions.append(Alert.severity == filter_params.severity)
        if filter_params.source_ip:
            conditions.append(Alert.source_ip == filter_params.source_ip)
        if filter_params.username:
            conditions.append(Alert.username == filter_params.username)
        if filter_params.hostname:
            conditions.append(Alert.hostname == filter_params.hostname)
        if filter_params.rule_id:
            conditions.append(Alert.rule_id == filter_params.rule_id)
        if filter_params.start_time:
            conditions.append(Alert.created_at >= filter_params.start_time)
        if filter_params.end_time:
            conditions.append(Alert.created_at <= filter_params.end_time)
        
        # Count
        count_stmt = select(func.count(Alert.id))
        if conditions:
            count_stmt = count_stmt.where(and_(*conditions))
        total = self.db.scalar(count_stmt) or 0
        
        # Query
        stmt = select(Alert)
        if conditions:
            stmt = stmt.where(and_(*conditions))
        
        sort_field = filter_params.sort_by if filter_params.sort_by in SORT_ALLOWLIST else "created_at"
        column = getattr(Alert, sort_field)
        if filter_params.sort_order.lower() == "asc":
            stmt = stmt.order_by(column.asc(), Alert.id.asc())
        else:
            stmt = stmt.order_by(column.desc(), Alert.id.desc())
        
        offset = (page - 1) * page_size
        stmt = stmt.offset(offset).limit(page_size)
        
        alerts = list(self.db.scalars(stmt).all())
        return alerts, total

    def count(self, filter_params: Optional[AlertFilter] = None) -> int:
        """Count alerts matching optional filters."""
        stmt = select(func.count(Alert.id))
        if filter_params:
            conditions = []
            if filter_params.status:
                conditions.append(Alert.status == filter_params.status)
            if filter_params.severity:
                conditions.append(Alert.severity == filter_params.severity)
            if conditions:
                stmt = stmt.where(and_(*conditions))
        return self.db.scalar(stmt) or 0

    def update_status(self, alert: Alert, new_status: AlertStatus) -> Alert:
        """Update alert status."""
        alert.status = new_status
        self.db.commit()
        self.db.refresh(alert)
        return alert

    def get_active_by_rule_and_entity(
        self, rule_id: uuid.UUID, entity_field: str, entity_value: str,
        window_start: Optional[datetime] = None
    ) -> Optional[Alert]:
        """Find an active (non-terminal) alert for the same rule and entity value."""
        conditions = [
            Alert.rule_id == rule_id,
            Alert.status.in_([AlertStatus.NEW, AlertStatus.ACKNOWLEDGED, AlertStatus.INVESTIGATING]),
        ]
        # Match entity field dynamically (source_ip, username, hostname)
        entity_col = getattr(Alert, entity_field, None)
        if entity_col is not None:
            conditions.append(entity_col == entity_value)
        if window_start:
            conditions.append(Alert.created_at >= window_start)
        
        stmt = select(Alert).where(and_(*conditions)).order_by(Alert.created_at.desc()).limit(1)
        return self.db.scalar(stmt)
