import uuid
from datetime import datetime
from typing import List, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.db.session import get_db
from backend.app.models.user import User
from backend.app.models.enums import UserRole, EventOutcome, Severity
from backend.app.schemas.telemetry import (
    RawTelemetryRequest,
    SingleIngestResponse,
    BatchIngestResponse,
)
from backend.app.schemas.event import (
    EventRead,
    PaginatedEventResponse,
    EventStatsResponse,
)
from backend.app.repositories.event_repository import EventFilter
from backend.app.api.deps import RequireRole
from backend.app.services.ingestion_service import ingestion_service
from backend.app.services.event_service import event_service

router = APIRouter(prefix="/events", tags=["Telemetry Ingestion & Evidence Explorer"])
require_ingest = RequireRole([UserRole.ADMIN, UserRole.ANALYST])
require_read = RequireRole([UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER])

def check_json_content_type(request: Request) -> None:
    """Validate application/json content type."""
    content_type = request.headers.get("content-type", "")
    if "application/json" not in content_type.lower():
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Unsupported Media Type: Content-Type must be application/json"
        )

# INGESTION ENDPOINTS (M03)
@router.post("", response_model=SingleIngestResponse, status_code=status.HTTP_202_ACCEPTED)
def ingest_single_event(
    request: Request,
    telemetry: RawTelemetryRequest,
    current_user: User = Depends(require_ingest),
    db: Session = Depends(get_db)
) -> Any:
    """Ingest a single raw telemetry event (ADMIN, ANALYST)."""
    check_json_content_type(request)
    request_id = getattr(request.state, "request_id", "unknown-request-id")
    return ingestion_service.ingest_single(
        telemetry=telemetry,
        request_id=request_id,
        user=current_user,
        db=db
    )

@router.post("/batch", response_model=BatchIngestResponse, status_code=status.HTTP_202_ACCEPTED)
def ingest_batch_events(
    request: Request,
    batch: List[RawTelemetryRequest],
    current_user: User = Depends(require_ingest),
    db: Session = Depends(get_db)
) -> Any:
    """Ingest a batch of raw telemetry events (ADMIN, ANALYST)."""
    check_json_content_type(request)
    request_id = getattr(request.state, "request_id", "unknown-request-id")

    if not batch or len(batch) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Batch ingestion payload cannot be empty"
        )

    if len(batch) > settings.MAX_BATCH_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Batch size {len(batch)} exceeds maximum allowable limit of {settings.MAX_BATCH_SIZE}"
        )

    return ingestion_service.ingest_batch(
        batch=batch,
        request_id=request_id,
        user=current_user,
        db=db
    )

# EVIDENCE EXPLORER & RETRIEVAL ENDPOINTS (M05)
@router.get("", response_model=PaginatedEventResponse)
def list_events(
    source_type: Optional[str] = Query(None, description="Filter by source type"),
    event_type: Optional[str] = Query(None, description="Filter by event category"),
    severity: Optional[Severity] = Query(None, description="Filter by severity"),
    outcome: Optional[EventOutcome] = Query(None, description="Filter by outcome"),
    hostname: Optional[str] = Query(None, description="Filter by hostname"),
    username: Optional[str] = Query(None, description="Filter by username"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    destination_ip: Optional[str] = Query(None, description="Filter by destination IP"),
    asset_id: Optional[uuid.UUID] = Query(None, description="Filter by asset UUID"),
    start_time: Optional[datetime] = Query(None, description="Start timestamp boundary"),
    end_time: Optional[datetime] = Query(None, description="End timestamp boundary"),
    q: Optional[str] = Query(None, description="Bounded text search query"),
    sort_by: str = Query("timestamp", description="Sort column (timestamp, ingested_at, severity, source_type, event_type)"),
    sort_order: str = Query("desc", description="Sort direction (asc, desc)"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=settings.MAX_PAGE_SIZE, description="Page size"),
    current_user: User = Depends(require_read),
    db: Session = Depends(get_db)
) -> Any:
    """Bounded, paginated canonical event search API (ADMIN, ANALYST, VIEWER)."""
    filter_params = EventFilter(
        source_type=source_type,
        event_type=event_type,
        severity=severity,
        outcome=outcome,
        hostname=hostname,
        username=username,
        source_ip=source_ip,
        destination_ip=destination_ip,
        asset_id=asset_id,
        start_time=start_time,
        end_time=end_time,
        search_query=q,
        sort_by=sort_by,
        sort_order=sort_order
    )
    try:
        return event_service.search_events(db, filter_params, page=page, page_size=page_size)
    except ValueError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err))

@router.get("/stats", response_model=EventStatsResponse)
def get_events_stats(
    start_time: Optional[datetime] = Query(None, description="Start timestamp boundary"),
    end_time: Optional[datetime] = Query(None, description="End timestamp boundary"),
    source_type: Optional[str] = Query(None, description="Filter by source type"),
    current_user: User = Depends(require_read),
    db: Session = Depends(get_db)
) -> Any:
    """Get aggregated event statistics summary (ADMIN, ANALYST, VIEWER)."""
    filter_params = EventFilter(
        start_time=start_time,
        end_time=end_time,
        source_type=source_type
    )
    return event_service.get_event_stats(db, filter_params)

@router.get("/{event_id}", response_model=EventRead)
def get_event_detail(
    event_id: uuid.UUID,
    current_user: User = Depends(require_read),
    db: Session = Depends(get_db)
) -> Any:
    """Retrieve single canonical Event evidence detail by UUID (ADMIN, ANALYST, VIEWER)."""
    event = event_service.get_event_by_id(db, event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event '{event_id}' not found"
        )
    return event
