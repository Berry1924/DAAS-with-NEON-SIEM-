import uuid
from typing import List, Optional, Tuple, Dict, Any
from datetime import datetime
from dataclasses import dataclass
from sqlalchemy.orm import Session
from sqlalchemy import select, func, and_, or_

from backend.app.models.correlation import CorrelationGroup
from backend.app.models.enums import CorrelationStatus

@dataclass
class CorrelationFilter:
    status: Optional[CorrelationStatus] = None
    source_ip: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    is_golden_sequence: Optional[bool] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    sort_by: str = "updated_at"
    sort_order: str = "desc"

SORT_ALLOWLIST = {"updated_at", "created_at", "first_seen_at", "last_seen_at", "alert_count", "status"}

class CorrelationRepository:
    def __init__(self, db: Session):
        self.db = db

    def create(self, group: CorrelationGroup) -> CorrelationGroup:
        self.db.add(group)
        self.db.commit()
        self.db.refresh(group)
        return group

    def get_by_id(self, group_id: uuid.UUID) -> Optional[CorrelationGroup]:
        return self.db.get(CorrelationGroup, group_id)

    def get_by_key(self, key: str) -> Optional[CorrelationGroup]:
        stmt = select(CorrelationGroup).where(CorrelationGroup.correlation_key == key)
        return self.db.scalar(stmt)

    def find_active_by_entities(
        self,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        hostname: Optional[str] = None,
        username: Optional[str] = None,
        window_start: Optional[datetime] = None
    ) -> Optional[CorrelationGroup]:
        """Find an existing active correlation group matching any provided non-null entity attribute within correlation window."""
        conditions = [CorrelationGroup.status == CorrelationStatus.ACTIVE]
        
        if window_start:
            conditions.append(CorrelationGroup.updated_at >= window_start)

        entity_matches = []
        if source_ip:
            entity_matches.append(CorrelationGroup.source_ip == source_ip)
        if destination_ip:
            entity_matches.append(CorrelationGroup.destination_ip == destination_ip)
        if hostname:
            entity_matches.append(CorrelationGroup.hostname == hostname)
        if username:
            entity_matches.append(CorrelationGroup.username == username)

        if not entity_matches:
            return None

        conditions.append(or_(*entity_matches))
        stmt = select(CorrelationGroup).where(and_(*conditions)).order_by(CorrelationGroup.updated_at.desc()).limit(1)
        return self.db.scalar(stmt)

    def search(self, filter_params: CorrelationFilter, page: int = 1, page_size: int = 50) -> Tuple[List[CorrelationGroup], int]:
        """Search correlation groups with filters, safe sorting, and bounded pagination."""
        conditions = []

        if filter_params.status:
            conditions.append(CorrelationGroup.status == filter_params.status)
        if filter_params.source_ip:
            conditions.append(CorrelationGroup.source_ip == filter_params.source_ip)
        if filter_params.username:
            conditions.append(CorrelationGroup.username == filter_params.username)
        if filter_params.hostname:
            conditions.append(CorrelationGroup.hostname == filter_params.hostname)
        if filter_params.is_golden_sequence is not None:
            conditions.append(CorrelationGroup.is_golden_sequence == filter_params.is_golden_sequence)
        if filter_params.start_time:
            conditions.append(CorrelationGroup.updated_at >= filter_params.start_time)
        if filter_params.end_time:
            conditions.append(CorrelationGroup.updated_at <= filter_params.end_time)

        count_stmt = select(func.count(CorrelationGroup.id))
        if conditions:
            count_stmt = count_stmt.where(and_(*conditions))
        total = self.db.scalar(count_stmt) or 0

        stmt = select(CorrelationGroup)
        if conditions:
            stmt = stmt.where(and_(*conditions))

        sort_field = filter_params.sort_by if filter_params.sort_by in SORT_ALLOWLIST else "updated_at"
        column = getattr(CorrelationGroup, sort_field)
        if filter_params.sort_order.lower() == "asc":
            stmt = stmt.order_by(column.asc(), CorrelationGroup.id.asc())
        else:
            stmt = stmt.order_by(column.desc(), CorrelationGroup.id.desc())

        offset = (page - 1) * page_size
        stmt = stmt.offset(offset).limit(page_size)

        groups = list(self.db.scalars(stmt).all())
        return groups, total

    def update(self, group: CorrelationGroup) -> CorrelationGroup:
        self.db.commit()
        self.db.refresh(group)
        return group
