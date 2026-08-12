import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from backend.app.models.enums import Severity, AlertStatus

class AlertRead(BaseModel):
    """Alert summary for list views."""
    model_config = ConfigDict(from_attributes=True)
    
    id: uuid.UUID
    rule_id: uuid.UUID
    primary_event_id: uuid.UUID
    title: str
    description: Optional[str] = None
    severity: Severity
    risk_score: int
    status: AlertStatus
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime

class LinkedEventRead(BaseModel):
    """Minimal event representation for alert evidence chains."""
    model_config = ConfigDict(from_attributes=True)
    
    id: uuid.UUID
    timestamp: datetime
    source_type: str
    event_type: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    outcome: str
    severity: str
    evidence_role: str  # "trigger" or "supporting" - from the junction table

class AlertDetailRead(AlertRead):
    """Alert detail with linked evidence events."""
    linked_events: List[LinkedEventRead] = Field(default_factory=list)

class AlertStatusUpdate(BaseModel):
    """Request body for alert status transition."""
    status: AlertStatus
    comment: Optional[str] = Field(None, max_length=1000)

class PaginatedAlertResponse(BaseModel):
    """Structured paginated alert response."""
    items: List[AlertRead]
    page: int
    page_size: int
    total: int
    pages: int
