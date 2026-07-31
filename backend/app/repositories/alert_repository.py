import uuid
from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import select
from backend.app.models.alert import Alert
from backend.app.models.alert_events import AlertEvent

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
