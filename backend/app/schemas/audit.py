import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from backend.app.models.enums import AuditResult

class AuditLogRead(BaseModel):
    """Pydantic schema for structured audit log retrieval."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    timestamp: datetime
    actor_id: Optional[uuid.UUID] = None
    actor_name: Optional[str] = None
    action: str
    target_type: Optional[str] = None
    target_id: Optional[str] = None
    result: AuditResult
    request_id: Optional[str] = None
    source_ip: Optional[str] = None
    audit_metadata: Dict[str, Any] = Field(default_factory=dict)

class PaginatedAuditResponse(BaseModel):
    """Structured paginated response for audit queries."""
    items: List[AuditLogRead]
    page: int
    page_size: int
    total: int
    pages: int
