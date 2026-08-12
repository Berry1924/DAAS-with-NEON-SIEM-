import uuid
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field, ConfigDict

from backend.app.models.enums import Severity, IncidentStatus

class SeverityCount(BaseModel):
    severity: Severity
    count: int = Field(..., ge=0, description="Count of active alerts for this severity tier")

class RuleTriggerCount(BaseModel):
    rule_id: str = Field(..., description="Detection rule ID")
    name: Optional[str] = Field(None, description="Detection rule name")
    count: int = Field(..., ge=0, description="Number of times rule triggered")

class HourlyBucket(BaseModel):
    hour: str = Field(..., description="UTC Hour bucket boundary (ISO or HH:00 format)")
    count: int = Field(..., ge=0, description="Number of events in this hour bucket")

class DashboardRecentIncident(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    incident_key: str
    title: str
    severity: Severity
    risk_score: int
    status: IncidentStatus
    created_at: datetime
    assigned_to: Optional[uuid.UUID] = None
    assignee_name: Optional[str] = None

class DashboardSummary(BaseModel):
    total_events_24h: int = Field(..., ge=0, description="Total events ingested in last 24 hours")
    active_alerts_by_severity: List[SeverityCount] = Field(..., description="Active non-terminal alerts grouped by severity")
    open_incidents: int = Field(..., ge=0, description="Count of open non-terminal incidents")
    top_detection_rules: List[RuleTriggerCount] = Field(..., description="Top 5 detection rules triggered by count")
    recent_incidents: List[DashboardRecentIncident] = Field(..., description="5 most recent incidents")
    event_trend: List[HourlyBucket] = Field(..., description="24 1-hour UTC event count buckets")
