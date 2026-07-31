from typing import List, Any
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.util import get_remote_address

from backend.app.core.config import settings
from backend.app.db.session import get_db
from backend.app.models.user import User
from backend.app.models.enums import UserRole
from backend.app.schemas.telemetry import (
    RawTelemetryRequest,
    SingleIngestResponse,
    BatchIngestResponse,
)
from backend.app.api.deps import RequireRole
from backend.app.services.ingestion_service import ingestion_service

router = APIRouter(prefix="/events", tags=["Telemetry Ingestion"])
require_ingest = RequireRole([UserRole.ADMIN, UserRole.ANALYST])

def check_json_content_type(request: Request) -> None:
    """Validate application/json content type."""
    content_type = request.headers.get("content-type", "")
    if "application/json" not in content_type.lower():
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Unsupported Media Type: Content-Type must be application/json"
        )

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
