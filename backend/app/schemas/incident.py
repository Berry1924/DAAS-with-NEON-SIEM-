import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from backend.app.models.enums import Severity, IncidentStatus

class IncidentNoteCreate(BaseModel):
    """Request body for creating an investigation note."""
    body: str = Field(..., min_length=1, max_length=5000, description="Analyst note body")

class IncidentNoteRead(BaseModel):
    """Pydantic schema for an incident investigation note."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    incident_id: uuid.UUID
    author_id: uuid.UUID
    author_name: Optional[str] = None
    body: str
    created_at: datetime
    updated_at: datetime

class IncidentTimelineRead(BaseModel):
    """Pydantic schema for an incident timeline entry."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    incident_id: uuid.UUID
    timestamp: datetime
    entry_type: str
    event_id: Optional[uuid.UUID] = None
    alert_id: Optional[uuid.UUID] = None
    title: str
    summary: Optional[str] = None
    timeline_metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime

class IncidentAlertLinkRead(BaseModel):
    """Minimal representation of linked alert for evidence chain."""
    alert_id: uuid.UUID
    title: str
    severity: str
    risk_score: int
    rule_id: str
    correlation_role: str

class IncidentEventEvidenceRead(BaseModel):
    """Minimal representation of linked event evidence."""
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

class IncidentRead(BaseModel):
    """Incident summary for listing endpoints."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    incident_key: str
    title: str
    incident_type: str
    description: Optional[str] = None
    severity: Severity
    risk_score: int
    status: IncidentStatus
    assigned_to: Optional[uuid.UUID] = None
    assignee_name: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    correlation_rule: Optional[str] = None
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None

class IncidentDetailRead(IncidentRead):
    """Full incident detail with complete evidence chain, risk explanation, timeline, and notes."""
    risk_explanation: Dict[str, Any] = Field(default_factory=dict)
    linked_alerts: List[IncidentAlertLinkRead] = Field(default_factory=list)
    linked_events: List[IncidentEventEvidenceRead] = Field(default_factory=list)
    timeline: List[IncidentTimelineRead] = Field(default_factory=list)
    notes: List[IncidentNoteRead] = Field(default_factory=list)

class IncidentStatusUpdate(BaseModel):
    """Request body for incident status lifecycle update."""
    status: IncidentStatus
    comment: Optional[str] = Field(None, max_length=1000)

class IncidentAssignUpdate(BaseModel):
    """Request body for analyst assignment."""
    assigned_to: Optional[uuid.UUID] = None

class PaginatedIncidentResponse(BaseModel):
    """Structured paginated response for incident queries."""
    items: List[IncidentRead]
    page: int
    page_size: int
    total: int
    pages: int
