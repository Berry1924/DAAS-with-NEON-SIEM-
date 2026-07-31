import uuid
from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import select
from backend.app.models.incident import Incident
from backend.app.models.incident_alerts import IncidentAlert
from backend.app.models.incident_timeline import IncidentTimeline

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

    def link_alert(self, incident_id: uuid.UUID, alert_id: uuid.UUID, role: str = "contributing") -> IncidentAlert:
        link = IncidentAlert(incident_id=incident_id, alert_id=alert_id, correlation_role=role)
        self.db.add(link)
        self.db.commit()
        return link

    def add_timeline_entry(self, entry: IncidentTimeline) -> IncidentTimeline:
        self.db.add(entry)
        self.db.commit()
        self.db.refresh(entry)
        return entry

    def list_incidents(self, limit: int = 50, offset: int = 0) -> List[Incident]:
        stmt = select(Incident).order_by(Incident.created_at.desc()).limit(limit).offset(offset)
        return list(self.db.scalars(stmt).all())
