import uuid
import math
from typing import List, Optional, Tuple, Dict, Any
from datetime import datetime
from dataclasses import dataclass
from sqlalchemy.orm import Session
from sqlalchemy import select, func, or_, and_

from backend.app.models.event import Event
from backend.app.models.enums import EventOutcome, Severity

@dataclass
class EventFilter:
    source_type: Optional[str] = None
    event_type: Optional[str] = None
    severity: Optional[Severity] = None
    outcome: Optional[EventOutcome] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    asset_id: Optional[uuid.UUID] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    search_query: Optional[str] = None
    sort_by: str = "timestamp"
    sort_order: str = "desc"

SORT_ALLOWLIST = {"timestamp", "ingested_at", "severity", "source_type", "event_type"}

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
        stmt = select(Event).order_by(Event.timestamp.desc(), Event.id.desc()).limit(limit).offset(offset)
        return list(self.db.scalars(stmt).all())

    def search(self, filter_params: EventFilter, page: int = 1, page_size: int = 50) -> Tuple[List[Event], int]:
        """Search canonical events using typed filters, deterministic sorting, and bounded pagination."""
        if filter_params.start_time and filter_params.end_time:
            if filter_params.start_time > filter_params.end_time:
                raise ValueError("start_time cannot be greater than end_time")

        conditions = []

        if filter_params.source_type:
            conditions.append(Event.source_type == filter_params.source_type)
        if filter_params.event_type:
            conditions.append(Event.event_type == filter_params.event_type)
        if filter_params.severity:
            conditions.append(Event.severity == filter_params.severity)
        if filter_params.outcome:
            conditions.append(Event.outcome == filter_params.outcome)
        if filter_params.source_ip:
            conditions.append(Event.source_ip == filter_params.source_ip)
        if filter_params.destination_ip:
            conditions.append(Event.destination_ip == filter_params.destination_ip)
        if filter_params.hostname:
            conditions.append(Event.hostname == filter_params.hostname)
        if filter_params.username:
            conditions.append(Event.username == filter_params.username)
        if filter_params.asset_id:
            conditions.append(Event.asset_id == filter_params.asset_id)
        if filter_params.start_time:
            conditions.append(Event.timestamp >= filter_params.start_time)
        if filter_params.end_time:
            conditions.append(Event.timestamp <= filter_params.end_time)

        if filter_params.search_query:
            q = f"%{filter_params.search_query.strip()}%"
            conditions.append(
                or_(
                    Event.hostname.ilike(q),
                    Event.username.ilike(q),
                    Event.event_type.ilike(q),
                    Event.source_type.ilike(q)
                )
            )

        # Count total items matching conditions
        count_stmt = select(func.count(Event.id))
        if conditions:
            count_stmt = count_stmt.where(and_(*conditions))
        total = self.db.scalar(count_stmt) or 0

        # Build main query with sorting
        stmt = select(Event)
        if conditions:
            stmt = stmt.where(and_(*conditions))

        # Safe sorting using allowlist
        sort_field = filter_params.sort_by if filter_params.sort_by in SORT_ALLOWLIST else "timestamp"
        column = getattr(Event, sort_field)

        if filter_params.sort_order.lower() == "asc":
            stmt = stmt.order_by(column.asc(), Event.id.asc())
        else:
            stmt = stmt.order_by(column.desc(), Event.id.desc())

        # Bounded pagination
        offset = (page - 1) * page_size
        stmt = stmt.offset(offset).limit(page_size)

        events = list(self.db.scalars(stmt).all())
        return events, total

    def get_stats(self, filter_params: Optional[EventFilter] = None) -> Dict[str, Any]:
        """Aggregate event statistics summary."""
        conditions = []
        if filter_params:
            if filter_params.start_time:
                conditions.append(Event.timestamp >= filter_params.start_time)
            if filter_params.end_time:
                conditions.append(Event.timestamp <= filter_params.end_time)
            if filter_params.source_type:
                conditions.append(Event.source_type == filter_params.source_type)

        # Total count
        total_stmt = select(func.count(Event.id))
        if conditions:
            total_stmt = total_stmt.where(and_(*conditions))
        total_events = self.db.scalar(total_stmt) or 0

        # Severity breakdown
        sev_stmt = select(Event.severity, func.count(Event.id))
        if conditions:
            sev_stmt = sev_stmt.where(and_(*conditions))
        sev_stmt = sev_stmt.group_by(Event.severity)
        sev_rows = self.db.execute(sev_stmt).all()
        events_by_severity = {s.name if hasattr(s, 'name') else str(s): count for s, count in sev_rows}

        # Outcome breakdown
        out_stmt = select(Event.outcome, func.count(Event.id))
        if conditions:
            out_stmt = out_stmt.where(and_(*conditions))
        out_stmt = out_stmt.group_by(Event.outcome)
        out_rows = self.db.execute(out_stmt).all()
        events_by_outcome = {o.name if hasattr(o, 'name') else str(o): count for o, count in out_rows}

        # Source type breakdown
        src_stmt = select(Event.source_type, func.count(Event.id))
        if conditions:
            src_stmt = src_stmt.where(and_(*conditions))
        src_stmt = src_stmt.group_by(Event.source_type)
        src_rows = self.db.execute(src_stmt).all()
        events_by_source_type = {src: count for src, count in src_rows}

        return {
            "total_events": total_events,
            "events_by_severity": events_by_severity,
            "events_by_outcome": events_by_outcome,
            "events_by_source_type": events_by_source_type
        }
