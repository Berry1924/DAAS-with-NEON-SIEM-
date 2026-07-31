import uuid
from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import select
from backend.app.models.event import Event

class EventRepository:
    def __init__(self, db: Session):
        self.db = db

    def create(self, event: Event) -> Event:
        self.db.add(event)
        self.db.commit()
        self.db.refresh(event)
        return event

    def get_by_id(self, event_id: uuid.UUID) -> Optional[Event]:
        return self.db.get(Event, event_id)

    def list_events(self, limit: int = 50, offset: int = 0) -> List[Event]:
        stmt = select(Event).order_by(Event.timestamp.desc()).limit(limit).offset(offset)
        return list(self.db.scalars(stmt).all())
