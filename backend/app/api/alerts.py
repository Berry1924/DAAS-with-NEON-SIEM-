import uuid
import math
from typing import Optional
from datetime import datetime
from fastapi import APIRouter, Depends, Query, HTTPException, Request

from sqlalchemy.orm import Session
from sqlalchemy import select

from backend.app.db.session import get_db
from backend.app.api.deps import RequireRole
from backend.app.models.enums import UserRole, AlertStatus, Severity, AuditResult
from backend.app.models.alert import Alert
from backend.app.models.event import Event
from backend.app.models.alert_events import AlertEvent
from backend.app.models.audit_log import AuditLog
from backend.app.schemas.alert import (
    AlertRead,
    AlertDetailRead,
    AlertStatusUpdate,
    PaginatedAlertResponse,
)
from backend.app.repositories.alert_repository import AlertRepository, AlertFilter
from backend.app.services.audit_service import audit_service

router = APIRouter(prefix="/alerts", tags=["Alert Management"])
require_read = RequireRole([UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER])
require_manage = RequireRole([UserRole.ADMIN, UserRole.ANALYST])

VALID_TRANSITIONS = {
    AlertStatus.NEW: {AlertStatus.ACKNOWLEDGED, AlertStatus.INVESTIGATING, AlertStatus.FALSE_POSITIVE},
    AlertStatus.ACKNOWLEDGED: {AlertStatus.INVESTIGATING, AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE},
    AlertStatus.INVESTIGATING: {AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE},
    AlertStatus.RESOLVED: set(),  # Terminal
    AlertStatus.FALSE_POSITIVE: set(),  # Terminal
}

@router.get("", response_model=PaginatedAlertResponse, dependencies=[Depends(require_read)])
def list_alerts(
    status: Optional[AlertStatus] = Query(None),
    severity: Optional[Severity] = Query(None),
    source_ip: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    hostname: Optional[str] = Query(None),
    start_time: Optional[datetime] = Query(None),
    end_time: Optional[datetime] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db)
):
    repo = AlertRepository(db)
    filter_params = AlertFilter(
        status=status,
        severity=severity,
        source_ip=source_ip,
        username=username,
        hostname=hostname,
        start_time=start_time,
        end_time=end_time
    )
    
    alerts, total = repo.search(filter_params, page=page, page_size=page_size)
    pages = math.ceil(total / page_size) if total > 0 else 0
    
    return PaginatedAlertResponse(
        items=alerts,
        page=page,
        page_size=page_size,
        total=total,
        pages=pages
    )

@router.get("/{alert_id}", response_model=AlertDetailRead, dependencies=[Depends(require_read)])
def get_alert(alert_id: uuid.UUID, db: Session = Depends(get_db)):
    repo = AlertRepository(db)
    alert = repo.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    stmt = select(Event, AlertEvent.evidence_role).join(
        AlertEvent, AlertEvent.event_id == Event.id
    ).where(AlertEvent.alert_id == alert.id).order_by(Event.timestamp.desc())
    rows = db.execute(stmt).all()

    linked_events = []
    for event, role in rows:
        linked_events.append({
            "id": event.id,
            "timestamp": event.timestamp,
            "source_type": event.source_type,
            "event_type": event.event_type,
            "source_ip": event.source_ip,
            "destination_ip": event.destination_ip,
            "username": event.username,
            "hostname": event.hostname,
            "outcome": event.outcome.value if hasattr(event.outcome, 'value') else event.outcome,
            "severity": event.severity.value if hasattr(event.severity, 'value') else event.severity,
            "evidence_role": role,
        })
        
    alert_dict = alert.__dict__.copy()
    alert_dict["linked_events"] = linked_events
    
    return alert_dict

@router.patch("/{alert_id}", response_model=AlertRead)
def update_alert_status(
    request: Request,
    alert_id: uuid.UUID, 
    update: AlertStatusUpdate, 
    current_user = Depends(require_manage),
    db: Session = Depends(get_db)
):
    repo = AlertRepository(db)
    alert = repo.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    if update.status not in VALID_TRANSITIONS.get(alert.status, set()):
        raise HTTPException(status_code=400, detail="Invalid status transition")
        
    old_status = alert.status
    alert = repo.update_status(alert, update.status)
    
    request_id = getattr(request.state, "request_id", "unknown")
    client_ip = request.client.host if request.client else None
    audit_service.log(
        db=db,
        action=audit_service.ALERT_STATUS_CHANGED,
        actor_id=current_user.id,
        target_type="alert",
        target_id=str(alert.id),
        result=AuditResult.SUCCESS,
        request_id=request_id,
        source_ip=client_ip,
        metadata={
            "alert_title": alert.title,
            "old_status": old_status.value if hasattr(old_status, 'value') else old_status,
            "new_status": update.status.value if hasattr(update.status, 'value') else update.status,
            "comment": update.comment,
        }
    )
    
    return alert

