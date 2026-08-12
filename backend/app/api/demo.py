from typing import Any, Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from backend.app.core.config import settings
from backend.app.db.session import get_db
from backend.app.models.user import User
from backend.app.models.enums import UserRole
from backend.app.api.deps import RequireRole
from security_engine.demo.generator import demo_generator, DemoResult
from security_engine.detection.rule_loader import RuleLoader

router = APIRouter(prefix="/demo", tags=["Demo Generator"])

require_admin = RequireRole([UserRole.ADMIN])

class DemoReplayResponse(BaseModel):
    events_generated: int
    events_persisted: int
    alerts_created: int
    rules_triggered: list[str]
    correlation_created: bool
    incident_key: Optional[str]
    risk_score: int
    severity: str
    audit_records_created: int
    dashboard_events_24h: int

@router.post("/replay", response_model=DemoReplayResponse)
def replay_golden_path_demo(
    slow: bool = Query(False, description="Introduce visual pacing delay for live demo"),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
) -> Any:
    """
    ADMIN-only API endpoint to replay the deterministic Golden Path attack sequence through the production pipeline.
    """
    if not settings.DEMO_MODE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Demo replay is disabled. Set DEMO_MODE=true to enable."
        )

    # Ensure detection rules are synced in DB
    rule_loader = RuleLoader("rules")
    rule_loader.sync(db)

    res: DemoResult = demo_generator.replay(db, slow=slow)

    return DemoReplayResponse(
        events_generated=res.events_generated,
        events_persisted=res.events_persisted,
        alerts_created=res.alerts_created,
        rules_triggered=res.rules_triggered,
        correlation_created=res.correlation_created,
        incident_key=res.incident_key,
        risk_score=res.risk_score,
        severity=res.severity,
        audit_records_created=res.audit_records_created,
        dashboard_events_24h=res.dashboard_events_24h
    )
