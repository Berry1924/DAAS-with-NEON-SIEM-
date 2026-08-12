import uuid
from datetime import datetime
from typing import Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.db.session import get_db
from backend.app.models.user import User
from backend.app.models.enums import UserRole, AuditResult
from backend.app.schemas.audit import AuditLogRead, PaginatedAuditResponse
from backend.app.repositories.audit_repository import AuditRepository, AuditFilter
from backend.app.api.deps import RequireRole

router = APIRouter(prefix="/audit", tags=["Centralized Audit Service"])

# Strictly ADMIN-only access policy for security audit logs
require_admin = RequireRole([UserRole.ADMIN])

@router.get("", response_model=PaginatedAuditResponse)
def list_audit_logs(
    actor_id: Optional[uuid.UUID] = Query(None, description="Filter by actor user UUID"),
    actor_name: Optional[str] = Query(None, description="Filter by actor username search"),
    action: Optional[str] = Query(None, description="Filter by audit action constant"),
    target_type: Optional[str] = Query(None, description="Filter by target type (e.g. incident, alert, user)"),
    target_id: Optional[str] = Query(None, description="Filter by target entity ID"),
    result: Optional[AuditResult] = Query(None, description="Filter by result (SUCCESS, FAILURE, DENIED)"),
    request_id: Optional[str] = Query(None, description="Filter by request ID boundary"),
    start_time: Optional[datetime] = Query(None, description="Start timestamp boundary"),
    end_time: Optional[datetime] = Query(None, description="End timestamp boundary"),
    sort_by: str = Query("timestamp", description="Sort column (timestamp, action, result, target_type)"),
    sort_order: str = Query("desc", description="Sort direction (asc, desc)"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=settings.MAX_PAGE_SIZE, description="Page size"),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
) -> Any:
    """Search and retrieve structured, immutable audit log records (ADMIN only)."""
    filter_params = AuditFilter(
        actor_id=actor_id,
        actor_name=actor_name,
        action=action,
        target_type=target_type,
        target_id=target_id,
        result=result,
        request_id=request_id,
        start_time=start_time,
        end_time=end_time,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    repo = AuditRepository(db)
    items, total = repo.search(filter_params, page=page, page_size=page_size)
    pages = (total + page_size - 1) // page_size if total > 0 else 0

    return PaginatedAuditResponse(
        items=items,
        page=page,
        page_size=page_size,
        total=total,
        pages=pages,
    )

@router.get("/{audit_id}", response_model=AuditLogRead)
def get_audit_log_detail(
    audit_id: uuid.UUID,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
) -> Any:
    """Retrieve detailed single audit log record by UUID (ADMIN only)."""
    repo = AuditRepository(db)
    log_entry = repo.get_by_id(audit_id)
    if not log_entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit log record '{audit_id}' not found"
        )
    return log_entry
