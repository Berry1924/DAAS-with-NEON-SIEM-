import uuid
from datetime import datetime, timezone
from typing import Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.db.session import get_db
from backend.app.models.user import User
from backend.app.models.enums import UserRole, CorrelationStatus, AuditResult
from backend.app.models.audit_log import AuditLog
from backend.app.schemas.correlation import (
    CorrelationRead,
    PaginatedCorrelationResponse,
    CorrelationStatusUpdate,
    CorrelationRiskRead,
)
from backend.app.repositories.correlation_repository import CorrelationRepository, CorrelationFilter
from backend.app.api.deps import RequireRole
from backend.app.services.audit_service import audit_service

router = APIRouter(prefix="/correlations", tags=["Correlation Engine"])
require_read = RequireRole([UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER])
require_manage = RequireRole([UserRole.ADMIN, UserRole.ANALYST])

@router.get("", response_model=PaginatedCorrelationResponse)
def list_correlations(
    status: Optional[CorrelationStatus] = Query(None, description="Filter by correlation status"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    username: Optional[str] = Query(None, description="Filter by username"),
    hostname: Optional[str] = Query(None, description="Filter by hostname"),
    is_golden_sequence: Optional[bool] = Query(None, description="Filter golden sequence matches"),
    start_time: Optional[datetime] = Query(None, description="Start timestamp boundary"),
    end_time: Optional[datetime] = Query(None, description="End timestamp boundary"),
    sort_by: str = Query("updated_at", description="Sort column (updated_at, created_at, alert_count, status)"),
    sort_order: str = Query("desc", description="Sort direction (asc, desc)"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=settings.MAX_PAGE_SIZE, description="Page size"),
    current_user: User = Depends(require_read),
    db: Session = Depends(get_db)
) -> Any:
    """Bounded, paginated correlation group search API (ADMIN, ANALYST, VIEWER)."""
    filter_params = CorrelationFilter(
        status=status,
        source_ip=source_ip,
        username=username,
        hostname=hostname,
        is_golden_sequence=is_golden_sequence,
        start_time=start_time,
        end_time=end_time,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    
    repo = CorrelationRepository(db)
    items, total = repo.search(filter_params, page=page, page_size=page_size)
    pages = (total + page_size - 1) // page_size if total > 0 else 0

    return PaginatedCorrelationResponse(
        items=items,
        page=page,
        page_size=page_size,
        total=total,
        pages=pages,
    )

@router.get("/{correlation_id}", response_model=CorrelationRead)
def get_correlation_detail(
    correlation_id: uuid.UUID,
    current_user: User = Depends(require_read),
    db: Session = Depends(get_db)
) -> Any:
    """Retrieve detailed correlation group by UUID (ADMIN, ANALYST, VIEWER)."""
    repo = CorrelationRepository(db)
    group = repo.get_by_id(correlation_id)
    if not group:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Correlation group '{correlation_id}' not found"
        )
    return group

@router.get("/{correlation_id}/risk", response_model=CorrelationRiskRead)
def get_correlation_risk(
    correlation_id: uuid.UUID,
    current_user: User = Depends(require_read),
    db: Session = Depends(get_db)
) -> Any:
    """Retrieve explainable risk scoring breakdown for a correlation group (ADMIN, ANALYST, VIEWER)."""
    repo = CorrelationRepository(db)
    group = repo.get_by_id(correlation_id)
    if not group:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Correlation group '{correlation_id}' not found"
        )
    
    exp = group.risk_explanation or {}
    return CorrelationRiskRead(
        correlation_id=group.id,
        base_risk=exp.get("base_risk", 40),
        correlation_bonus=exp.get("correlation_bonus", 0),
        compromise_indicator_bonus=exp.get("compromise_indicator_bonus", 0),
        privilege_escalation_bonus=exp.get("privilege_escalation_bonus", 0),
        asset_criticality_modifier=exp.get("asset_criticality_modifier", 0),
        final_score=group.risk_score,
        severity=group.severity,
        factors=exp.get("factors", []),
        explanation_summary=exp.get("explanation_summary", f"Risk score {group.risk_score}/100"),
    )

@router.patch("/{correlation_id}/status", response_model=CorrelationRead)
def update_correlation_status(
    request: Request,
    correlation_id: uuid.UUID,
    update: CorrelationStatusUpdate,
    current_user: User = Depends(require_manage),
    db: Session = Depends(get_db)
) -> Any:
    """Update correlation status (ADMIN, ANALYST)."""
    repo = CorrelationRepository(db)
    group = repo.get_by_id(correlation_id)
    if not group:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Correlation group '{correlation_id}' not found"
        )

    old_status = group.status
    group.status = update.status
    group.updated_at = datetime.now(timezone.utc)
    repo.update(group)

    # Audit log entry via AuditService
    request_id = getattr(request.state, "request_id", "unknown")
    client_ip = request.client.host if request.client else None
    audit_service.log(
        db=db,
        action=audit_service.CORRELATION_STATUS_CHANGED,
        actor_id=current_user.id,
        target_type="correlation",
        target_id=str(group.id),
        result=AuditResult.SUCCESS,
        request_id=request_id,
        source_ip=client_ip,
        metadata={
            "correlation_key": group.correlation_key,
            "old_status": old_status.value,
            "new_status": update.status.value,
        }
    )

    return group


