import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from backend.app.models.enums import EventOutcome, Severity

class EventRead(BaseModel):
    """Pydantic schema for canonical Event evidence (M05)."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    timestamp: datetime
    ingested_at: datetime
    source_type: str
    event_type: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    action: Optional[str] = None
    outcome: EventOutcome
    severity: Severity
    source_event_id: Optional[str] = None
    asset_id: Optional[uuid.UUID] = None
    raw_event: Dict[str, Any] = Field(default_factory=dict)
    event_metadata: Dict[str, Any] = Field(default_factory=dict, alias="event_metadata")
    created_at: datetime

class PaginatedEventResponse(BaseModel):
    """Structured paginated event search response."""
    items: List[EventRead]
    page: int
    page_size: int
    total: int
    pages: int

class EventStatsResponse(BaseModel):
    """Aggregated event statistics summary."""
    total_events: int
    events_by_severity: Dict[str, int]
    events_by_outcome: Dict[str, int]
    events_by_source_type: Dict[str, int]
