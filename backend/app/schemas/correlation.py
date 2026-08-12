import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from backend.app.models.enums import CorrelationStatus, Severity

class CorrelationRead(BaseModel):
    """Pydantic schema for Correlated Security Group representation."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    correlation_key: str
    title: str
    description: Optional[str] = None
    status: CorrelationStatus
    severity: Severity
    risk_score: int
    risk_explanation: Dict[str, Any] = Field(default_factory=dict)
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    entities: Dict[str, Any] = Field(default_factory=dict)
    alert_ids: List[str] = Field(default_factory=list)
    event_ids: List[str] = Field(default_factory=list)
    rule_ids: List[str] = Field(default_factory=list)
    alert_count: int
    correlation_reason: str
    is_golden_sequence: bool = False
    pattern_matched: Optional[str] = None
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime

class CorrelationRiskRead(BaseModel):
    """Structured response for correlation risk calculation details."""
    correlation_id: uuid.UUID
    base_risk: int
    correlation_bonus: int
    compromise_indicator_bonus: int
    privilege_escalation_bonus: int
    asset_criticality_modifier: int
    final_score: int
    severity: Severity
    factors: List[Dict[str, Any]]
    explanation_summary: str

class PaginatedCorrelationResponse(BaseModel):
    """Structured paginated response for correlation queries."""
    items: List[CorrelationRead]
    page: int
    page_size: int
    total: int
    pages: int

class CorrelationStatusUpdate(BaseModel):
    """Request body for correlation status update."""
    status: CorrelationStatus
