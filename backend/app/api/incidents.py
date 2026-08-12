import uuid
from datetime import datetime
from typing import Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.db.session import get_db
from backend.app.models.user import User
from backend.app.models.enums import UserRole, Severity, IncidentStatus
from backend.app.schemas.incident import (
    IncidentRead,
    IncidentDetailRead,
    PaginatedIncidentResponse,
    IncidentStatusUpdate,
    IncidentAssignUpdate,
    IncidentNoteCreate,
    IncidentNoteRead,
)
from backend.app.repositories.incident_repository import IncidentRepository, IncidentFilter
from backend.app.services.incident_service import incident_service
from backend.app.api.deps import RequireRole

router = APIRouter(prefix="/incidents", tags=["Incident Management"])
require_read = RequireRole([UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER])
require_manage = RequireRole([UserRole.ADMIN, UserRole.ANALYST])

@router.get("", response_model=PaginatedIncidentResponse)
def list_incidents(
    status: Optional[IncidentStatus] = Query(None, description="Filter by incident status"),
    severity: Optional[Severity] = Query(None, description="Filter by severity"),
    min_risk: Optional[int] = Query(None, ge=0, le=100, description="Minimum risk score filter"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    username: Optional[str] = Query(None, description="Filter by username"),
    start_time: Optional[datetime] = Query(None, description="Start time filter"),
    end_time: Optional[datetime] = Query(None, description="End time filter"),
    sort_by: str = Query("created_at", description="Sort column (created_at, updated_at, risk_score, severity, status)"),
    sort_order: str = Query("desc", description="Sort direction (asc, desc)"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=settings.MAX_PAGE_SIZE, description="Page size"),
    current_user: User = Depends(require_read),
    db: Session = Depends(get_db)
) -> Any:
    """List and search incidents with bounded pagination and RBAC (ADMIN, ANALYST, VIEWER)."""
    filter_params = IncidentFilter(
        status=status,
        severity=severity,
        min_risk=min_risk,
        source_ip=source_ip,
        username=username,
        start_time=start_time,
        end_time=end_time,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    repo = IncidentRepository(db)
    items, total = repo.search(filter_params, page=page, page_size=page_size)
    pages = (total + page_size - 1) // page_size if total > 0 else 0

    return PaginatedIncidentResponse(
        items=items,
        page=page,
        page_size=page_size,
        total=total,
        pages=pages,
    )

@router.get("/{incident_id}", response_model=IncidentDetailRead)
def get_incident_detail(
    incident_id: uuid.UUID,
    current_user: User = Depends(require_read),
    db: Session = Depends(get_db)
) -> Any:
    """Retrieve full incident detail including evidence chain, timeline, and notes (ADMIN, ANALYST, VIEWER)."""
    detail = incident_service.get_incident_detail(incident_id, db)
    if not detail:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found"
        )
    return detail

@router.patch("/{incident_id}/status", response_model=IncidentRead)
def update_incident_status(
    request: Request,
    incident_id: uuid.UUID,
    update: IncidentStatusUpdate,
    current_user: User = Depends(require_manage),
    db: Session = Depends(get_db)
) -> Any:
    """Update incident status lifecycle state (ADMIN, ANALYST)."""
    request_id = getattr(request.state, "request_id", "unknown")
    try:
        updated = incident_service.update_status(
            incident_id=incident_id,
            new_status=update.status,
            comment=update.comment,
            user=current_user,
            request_id=request_id,
            db=db,
        )
        return updated
    except ValueError as e:
        err_str = str(e)
        if "not found" in err_str:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=err_str)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err_str)

@router.patch("/{incident_id}/assign", response_model=IncidentRead)
def assign_incident(
    request: Request,
    incident_id: uuid.UUID,
    update: IncidentAssignUpdate,
    current_user: User = Depends(require_manage),
    db: Session = Depends(get_db)
) -> Any:
    """Assign or reassign an incident to an analyst (ADMIN, ANALYST)."""
    request_id = getattr(request.state, "request_id", "unknown")
    try:
        updated = incident_service.assign_analyst(
            incident_id=incident_id,
            assigned_to=update.assigned_to,
            user=current_user,
            request_id=request_id,
            db=db,
        )
        return updated
    except ValueError as e:
        err_str = str(e)
        if "not found" in err_str:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=err_str)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err_str)

@router.post("/{incident_id}/notes", response_model=IncidentNoteRead)
def add_incident_note(
    request: Request,
    incident_id: uuid.UUID,
    note_in: IncidentNoteCreate,
    current_user: User = Depends(require_manage),
    db: Session = Depends(get_db)
) -> Any:
    """Add an analyst investigation note to an incident (ADMIN, ANALYST)."""
    request_id = getattr(request.state, "request_id", "unknown")
    try:
        note = incident_service.add_note(
            incident_id=incident_id,
            body=note_in.body,
            user=current_user,
            request_id=request_id,
            db=db,
        )
        note_read = IncidentNoteRead.model_validate(note)
        note_read.author_name = current_user.display_name
        return note_read
    except ValueError as e:
        err_str = str(e)
        if "not found" in err_str:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=err_str)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err_str)
