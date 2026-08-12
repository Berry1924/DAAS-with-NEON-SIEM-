import uuid
from datetime import datetime
from typing import List, Optional, Tuple, Dict, Any
from dataclasses import dataclass
from sqlalchemy.orm import Session
from sqlalchemy import select, func, and_

from backend.app.models.audit_log import AuditLog
from backend.app.models.user import User
from backend.app.models.enums import AuditResult
from backend.app.schemas.audit import AuditLogRead

@dataclass
class AuditFilter:
    actor_id: Optional[uuid.UUID] = None
    actor_name: Optional[str] = None
    action: Optional[str] = None
    target_type: Optional[str] = None
    target_id: Optional[str] = None
    result: Optional[AuditResult] = None
    request_id: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    sort_by: str = "timestamp"
    sort_order: str = "desc"

SORT_ALLOWLIST = {"timestamp", "action", "result", "target_type"}

class AuditRepository:
    """Data access repository for structured, immutable audit logs."""

    def __init__(self, db: Session):
        self.db = db

    def create(self, audit_log: AuditLog) -> AuditLog:
        self.db.add(audit_log)
        self.db.commit()
        self.db.refresh(audit_log)
        return audit_log

    def get_by_id(self, audit_id: uuid.UUID) -> Optional[AuditLogRead]:
        audit_log = self.db.get(AuditLog, audit_id)
        if not audit_log:
            return None
        actor_name = audit_log.actor.display_name if audit_log.actor else None
        read_obj = AuditLogRead.model_validate(audit_log)
        read_obj.actor_name = actor_name
        return read_obj

    def search(self, filter_params: AuditFilter, page: int = 1, page_size: int = 50) -> Tuple[List[AuditLogRead], int]:
        """Bounded, paginated search over audit records with optional filters."""
        conditions = []

        if filter_params.actor_id:
            conditions.append(AuditLog.actor_id == filter_params.actor_id)
        if filter_params.action:
            conditions.append(AuditLog.action == filter_params.action)
        if filter_params.target_type:
            conditions.append(AuditLog.target_type == filter_params.target_type)
        if filter_params.target_id:
            conditions.append(AuditLog.target_id == str(filter_params.target_id))
        if filter_params.result:
            conditions.append(AuditLog.result == filter_params.result)
        if filter_params.request_id:
            conditions.append(AuditLog.request_id == filter_params.request_id)
        if filter_params.start_time:
            conditions.append(AuditLog.timestamp >= filter_params.start_time)
        if filter_params.end_time:
            conditions.append(AuditLog.timestamp <= filter_params.end_time)

        # Actor name subquery/join filter if provided
        if filter_params.actor_name:
            user_ids = list(self.db.scalars(
                select(User.id).where(User.username.ilike(f"%{filter_params.actor_name}%"))
            ).all())
            if user_ids:
                conditions.append(AuditLog.actor_id.in_(user_ids))
            else:
                return [], 0

        count_stmt = select(func.count(AuditLog.id))
        if conditions:
            count_stmt = count_stmt.where(and_(*conditions))
        total = self.db.scalar(count_stmt) or 0

        # Query records joined with User for actor_name
        stmt = (
            select(AuditLog, User.display_name)
            .outerjoin(User, User.id == AuditLog.actor_id)
        )
        if conditions:
            stmt = stmt.where(and_(*conditions))

        sort_field = filter_params.sort_by if filter_params.sort_by in SORT_ALLOWLIST else "timestamp"
        column = getattr(AuditLog, sort_field)
        if filter_params.sort_order.lower() == "asc":
            stmt = stmt.order_by(column.asc(), AuditLog.id.asc())
        else:
            stmt = stmt.order_by(column.desc(), AuditLog.id.desc())

        offset = (page - 1) * page_size
        stmt = stmt.offset(offset).limit(page_size)

        rows = self.db.execute(stmt).all()
        results = []
        for audit_obj, actor_name in rows:
            obj = AuditLogRead.model_validate(audit_obj)
            obj.actor_name = actor_name
            results.append(obj)

        return results, total
