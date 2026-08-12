import uuid
from typing import List, Optional, Tuple, Dict, Any
from datetime import datetime
from dataclasses import dataclass
from sqlalchemy.orm import Session
from sqlalchemy import select, func, and_, or_

from backend.app.models.incident import Incident
from backend.app.models.incident_alerts import IncidentAlert
from backend.app.models.incident_timeline import IncidentTimeline
from backend.app.models.incident_notes import IncidentNote
from backend.app.models.enums import Severity, IncidentStatus

@dataclass
class IncidentFilter:
    status: Optional[IncidentStatus] = None
    severity: Optional[Severity] = None
    min_risk: Optional[int] = None
    source_ip: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    sort_by: str = "created_at"
    sort_order: str = "desc"

SORT_ALLOWLIST = {"created_at", "updated_at", "risk_score", "severity", "status"}

class IncidentRepository:
    def __init__(self, db: Session):
        self.db = db

    def create(self, incident: Incident) -> Incident:
        self.db.add(incident)
        self.db.commit()
        self.db.refresh(incident)
        return incident

    def get_by_id(self, incident_id: uuid.UUID) -> Optional[Incident]:
        return self.db.get(Incident, incident_id)

    def get_by_key(self, incident_key: str) -> Optional[Incident]:
        stmt = select(Incident).where(Incident.incident_key == incident_key)
        return self.db.scalar(stmt)

    def find_active_by_correlation_key(self, correlation_key: str) -> Optional[Incident]:
        """Find active incident matching a correlation key."""
        active_statuses = [IncidentStatus.NEW, IncidentStatus.ACKNOWLEDGED, IncidentStatus.INVESTIGATING]
        stmt = (
            select(Incident)
            .where(
                and_(
                    Incident.correlation_rule == correlation_key,
                    Incident.status.in_(active_statuses)
                )
            )
            .order_by(Incident.created_at.desc())
            .limit(1)
        )
        return self.db.scalar(stmt)

    def find_active_by_entities(
        self,
        source_ip: Optional[str] = None,
        username: Optional[str] = None,
        hostname: Optional[str] = None
    ) -> Optional[Incident]:
        """Find active incident matching shared entities."""
        active_statuses = [IncidentStatus.NEW, IncidentStatus.ACKNOWLEDGED, IncidentStatus.INVESTIGATING]
        conditions = [Incident.status.in_(active_statuses)]

        entity_matches = []
        if source_ip:
            entity_matches.append(Incident.source_ip == source_ip)
        if username:
            entity_matches.append(Incident.username == username)

        if not entity_matches:
            return None

        conditions.append(or_(*entity_matches))
        stmt = select(Incident).where(and_(*conditions)).order_by(Incident.created_at.desc()).limit(1)
        return self.db.scalar(stmt)

    def link_alert(self, incident_id: uuid.UUID, alert_id: uuid.UUID, role: str = "contributing") -> IncidentAlert:
        existing = self.db.scalar(
            select(IncidentAlert).where(
                and_(IncidentAlert.incident_id == incident_id, IncidentAlert.alert_id == alert_id)
            )
        )
        if existing:
            return existing
        link = IncidentAlert(incident_id=incident_id, alert_id=alert_id, correlation_role=role)
        self.db.add(link)
        self.db.commit()
        return link

    def add_timeline_entry(self, entry: IncidentTimeline) -> IncidentTimeline:
        self.db.add(entry)
        self.db.commit()
        self.db.refresh(entry)
        return entry

    def add_note(self, note: IncidentNote) -> IncidentNote:
        self.db.add(note)
        self.db.commit()
        self.db.refresh(note)
        return note

    def list_incidents(self, limit: int = 50, offset: int = 0) -> List[Incident]:
        stmt = select(Incident).order_by(Incident.created_at.desc()).limit(limit).offset(offset)
        return list(self.db.scalars(stmt).all())

    def search(self, filter_params: IncidentFilter, page: int = 1, page_size: int = 50) -> Tuple[List[Incident], int]:
        """Search incidents using typed filters, deterministic sorting, and bounded pagination."""
        conditions = []

        if filter_params.status:
            conditions.append(Incident.status == filter_params.status)
        if filter_params.severity:
            conditions.append(Incident.severity == filter_params.severity)
        if filter_params.min_risk is not None:
            conditions.append(Incident.risk_score >= filter_params.min_risk)
        if filter_params.source_ip:
            conditions.append(Incident.source_ip == filter_params.source_ip)
        if filter_params.username:
            conditions.append(Incident.username == filter_params.username)
        if filter_params.start_time:
            conditions.append(Incident.created_at >= filter_params.start_time)
        if filter_params.end_time:
            conditions.append(Incident.created_at <= filter_params.end_time)

        count_stmt = select(func.count(Incident.id))
        if conditions:
            count_stmt = count_stmt.where(and_(*conditions))
        total = self.db.scalar(count_stmt) or 0

        stmt = select(Incident)
        if conditions:
            stmt = stmt.where(and_(*conditions))

        sort_field = filter_params.sort_by if filter_params.sort_by in SORT_ALLOWLIST else "created_at"
        column = getattr(Incident, sort_field)
        if filter_params.sort_order.lower() == "asc":
            stmt = stmt.order_by(column.asc(), Incident.id.asc())
        else:
            stmt = stmt.order_by(column.desc(), Incident.id.desc())

        offset = (page - 1) * page_size
        stmt = stmt.offset(offset).limit(page_size)

        incidents = list(self.db.scalars(stmt).all())
        return incidents, total

    def update(self, incident: Incident) -> Incident:
        self.db.commit()
        self.db.refresh(incident)
        return incident

    def next_incident_key(self) -> str:
        """Generate next human-readable unique incident key NEON-INC-XXXXXX."""
        count = self.db.scalar(select(func.count(Incident.id))) or 0
        return f"NEON-INC-{(count + 1):06d}"
