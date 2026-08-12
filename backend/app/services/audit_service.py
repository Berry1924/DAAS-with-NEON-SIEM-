import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union
from sqlalchemy.orm import Session

from backend.app.models.audit_log import AuditLog
from backend.app.models.enums import AuditResult
from backend.app.repositories.audit_repository import AuditRepository

logger = logging.getLogger(__name__)

SENSITIVE_KEY_SUBSTRINGS = (
    "password", "passwd", "secret", "token", "auth", "jwt",
    "cookie", "session", "api_key", "apikey", "credential", "private_key"
)

def sanitize_metadata(metadata: Any) -> Any:
    """Recursively redact sensitive credential keys and truncate oversized strings."""
    if isinstance(metadata, dict):
        sanitized = {}
        for key, val in metadata.items():
            key_lower = str(key).lower()
            if any(sub in key_lower for sub in SENSITIVE_KEY_SUBSTRINGS):
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = sanitize_metadata(val)
        return sanitized
    elif isinstance(metadata, list):
        return [sanitize_metadata(item) for item in metadata]
    elif isinstance(metadata, str):
        # Redact raw authorization headers or bearer strings if accidentally passed
        if metadata.lower().startswith("bearer ") or len(metadata) > 1000:
            if metadata.lower().startswith("bearer "):
                return "[REDACTED_TOKEN]"
            return metadata[:1000] + "... [TRUNCATED]"
        return metadata
    else:
        return metadata

class AuditService:
    """Centralized Audit Service responsible for logging all security-sensitive operations."""

    # Action Constants
    LOGIN_SUCCESS = "USER_LOGIN_SUCCESS"
    LOGIN_FAILURE = "USER_LOGIN_FAILED"
    ALERT_STATUS_CHANGED = "ALERT_STATUS_CHANGED"
    CORRELATION_STATUS_CHANGED = "CORRELATION_STATUS_CHANGED"
    INCIDENT_CREATED = "INCIDENT_CREATED"
    INCIDENT_STATUS_CHANGED = "INCIDENT_STATUS_CHANGED"
    INCIDENT_ASSIGNED = "INCIDENT_ASSIGNED"
    INCIDENT_NOTE_ADDED = "INCIDENT_NOTE_ADDED"
    USER_CREATED = "USER_CREATED"
    USER_ROLE_CHANGED = "USER_ROLE_CHANGED"
    USER_STATUS_CHANGED = "USER_STATUS_CHANGED"
    RULE_CREATED = "RULE_CREATED"
    RULE_UPDATED = "RULE_UPDATED"
    RULE_DELETED = "RULE_DELETED"


    def log(
        self,
        db: Session,
        action: str,
        actor_id: Optional[uuid.UUID] = None,
        target_type: Optional[str] = None,
        target_id: Optional[Union[str, uuid.UUID]] = None,
        result: AuditResult = AuditResult.SUCCESS,
        request_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditLog:
        """Centralized logging method. Sanitizes metadata, validates request_id, and persists audit entry."""
        sanitized_meta = sanitize_metadata(metadata or {})
        target_id_str = str(target_id) if target_id is not None else None

        audit_entry = AuditLog(
            actor_id=actor_id,
            action=action,
            target_type=target_type,
            target_id=target_id_str,
            result=result,
            request_id=request_id or "unknown",
            source_ip=source_ip,
            audit_metadata=sanitized_meta,
            timestamp=datetime.now(timezone.utc),
        )

        repo = AuditRepository(db)
        repo.create(audit_entry)
        logger.info(f"Audit record logged: {action} (actor={actor_id}, target={target_type}/{target_id_str}, result={result.value})")
        return audit_entry

audit_service = AuditService()
