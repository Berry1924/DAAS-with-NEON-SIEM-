from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from datetime import datetime
from pydantic import BaseModel, Field

from backend.app.models.enums import EventOutcome, Severity
from backend.app.schemas.telemetry import IngestionEnvelope

class ParsedEvent(BaseModel):
    """Intermediate parsed event structure before canonical normalization."""
    source_type: str
    event_type: str = "generic"
    timestamp: Optional[datetime] = None
    hostname: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    action: Optional[str] = None
    outcome: EventOutcome = EventOutcome.UNKNOWN
    severity: Severity = Severity.INFO
    source_event_id: Optional[str] = None
    raw_event: Dict[str, Any]
    metadata: Dict[str, Any] = Field(default_factory=dict)
    request_id: Optional[str] = None

class BaseParser(ABC):
    """Abstract Base Class for telemetry parsers."""
    
    @abstractmethod
    def supports(self, source_type: str) -> bool:
        """Check if parser supports the given source_type."""
        pass

    @abstractmethod
    def parse(self, envelope: IngestionEnvelope) -> ParsedEvent:
        """Parse raw telemetry envelope into intermediate ParsedEvent structure."""
        pass
