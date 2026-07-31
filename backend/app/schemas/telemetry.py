import uuid
import ipaddress
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator, ConfigDict

from backend.app.core.config import settings

class RawTelemetryRequest(BaseModel):
    """Raw Telemetry Request contract (M03).
    
    Accepts raw telemetry input from producers.
    Strict model config forbids unexpected top-level transport fields.
    Payload contains raw event data for downstream M04 parsing/normalization.
    """
    model_config = ConfigDict(extra="forbid")

    source_type: str = Field(..., max_length=80, description="Controlled source type (e.g. linux_auth, json)")
    payload: Dict[str, Any] = Field(..., description="Raw telemetry payload")
    timestamp: Optional[datetime] = Field(None, description="Event timestamp provided by source")
    hostname: Optional[str] = Field(None, max_length=255, description="Source hostname")
    source_ip: Optional[str] = Field(None, max_length=45, description="Source IPv4 or IPv6 address")
    destination_ip: Optional[str] = Field(None, max_length=45, description="Destination IPv4 or IPv6 address")
    source_event_id: Optional[str] = Field(None, max_length=255, description="Upstream source event ID for idempotency")
    event_type: Optional[str] = Field(None, max_length=120, description="Source event classification")

    @field_validator("source_type")
    @classmethod
    def validate_source_type(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("source_type cannot be empty")
        v_clean = v.strip().lower()
        if v_clean not in settings.SUPPORTED_SOURCE_TYPES:
            raise ValueError(f"Unsupported source_type '{v}'. Supported source types: {settings.SUPPORTED_SOURCE_TYPES}")
        return v_clean

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def validate_ip_address(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v_clean = v.strip()
        if not v_clean:
            return None
        try:
            ipaddress.ip_address(v_clean)
            return v_clean
        except ValueError:
            raise ValueError(f"Invalid IP address format: '{v}'")

    @field_validator("hostname", "source_event_id", "event_type")
    @classmethod
    def validate_string_bounds(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and len(v) > 255:
            raise ValueError("Field length exceeds 255 characters limit")
        return v

class IngestionEnvelope(BaseModel):
    """Internal service contract separating transport input from M04 processing boundary."""
    envelope_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    request_id: str
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ingested_by: str
    source_type: str
    source_event_id: Optional[str] = None
    raw_payload: Dict[str, Any]
    provided_timestamp: Optional[datetime] = None
    provided_hostname: Optional[str] = None
    provided_source_ip: Optional[str] = None
    provided_destination_ip: Optional[str] = None
    provided_event_type: Optional[str] = None
    is_duplicate: bool = False

class SingleIngestResponse(BaseModel):
    status: str = "accepted"
    request_id: str
    accepted: int = 1
    envelope_id: str
    is_duplicate: bool = False

class BatchIngestResponse(BaseModel):
    status: str = "accepted"
    request_id: str
    accepted: int
    rejected: int = 0
    duplicates: int = 0
