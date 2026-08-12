from typing import Any
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.models.user import User
from backend.app.models.enums import UserRole
from backend.app.schemas.dashboard import DashboardSummary
from backend.app.services.dashboard_service import dashboard_service
from backend.app.api.deps import RequireRole

router = APIRouter(prefix="/dashboard", tags=["Dashboard Engine"])

# Read-only SOC metrics policy: ADMIN, ANALYST, VIEWER allowed
require_read = RequireRole([UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER])

@router.get("/summary", response_model=DashboardSummary)
def get_dashboard_summary(
    current_user: User = Depends(require_read),
    db: Session = Depends(get_db)
) -> Any:
    """
    Retrieve authoritative, database-derived SOC dashboard aggregate summary metrics (24h UTC window).
    """
    return dashboard_service.get_summary(db)
