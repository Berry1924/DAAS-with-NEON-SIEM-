import uuid
import ipaddress
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from dateutil import parser as date_parser

from security_engine.parsers.base import ParsedEvent
from backend.app.schemas.telemetry import IngestionEnvelope
from backend.app.models.event import Event
from backend.app.models.enums import EventOutcome, Severity

SENSITIVE_KEYS = {
    "password", "password_hash", "token", "access_token",
    "refresh_token", "authorization", "cookie", "secret", "api_key"
}

def sanitize_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Defensively redact sensitive credential keys in normalized metadata."""
    sanitized = {}
    for key, value in metadata.items():
        if key.lower() in SENSITIVE_KEYS:
            sanitized[key] = "[REDACTED]"
        elif isinstance(value, dict):
            sanitized[key] = sanitize_metadata(value)
        else:
            sanitized[key] = value
    return sanitized

class EventNormalizer:
    """Canonical Event Normalizer engine."""

    def normalize(self, parsed: ParsedEvent, envelope: IngestionEnvelope) -> Event:
        """Transform ParsedEvent & IngestionEnvelope into a validated canonical Event ORM entity."""

        # 1. Timestamp Normalization (Must be UTC timezone-aware)
        event_timestamp: datetime = envelope.received_at
        ts_input = parsed.timestamp or envelope.provided_timestamp

        if ts_input:
            if isinstance(ts_input, datetime):
                if ts_input.tzinfo is None:
                    event_timestamp = ts_input.replace(tzinfo=timezone.utc)
                else:
                    event_timestamp = ts_input.astimezone(timezone.utc)
            elif isinstance(ts_input, str):
                try:
                    dt = date_parser.parse(ts_input)
                    if dt.tzinfo is None:
                        event_timestamp = dt.replace(tzinfo=timezone.utc)
                    else:
                        event_timestamp = dt.astimezone(timezone.utc)
                except Exception:
                    raise ValueError(f"Invalid timestamp format: '{ts_input}'")
            else:
                raise ValueError(f"Invalid timestamp type: {type(ts_input)}")

        # 2. IP Address Validation & Normalization
        norm_source_ip = self._normalize_ip(parsed.source_ip or envelope.provided_source_ip)
        norm_dest_ip = self._normalize_ip(parsed.destination_ip or envelope.provided_destination_ip)

        # 3. String Field Truncation & Boundary Protection
        hostname = (parsed.hostname or envelope.provided_hostname or "")[:255] or None
        username = (parsed.username or "")[:255] or None
        action = (parsed.action or "")[:120] or None
        event_type = (parsed.event_type or "generic")[:120]
        source_type = envelope.source_type[:80]
        source_event_id = envelope.source_event_id[:255] if envelope.source_event_id else None

        # 4. Metadata Defensive Redaction
        metadata = sanitize_metadata(parsed.metadata or {})
        metadata["parser"] = parsed.source_type
        metadata["request_id"] = envelope.request_id

        # 5. Construct Canonical Event ORM entity
        return Event(
            id=uuid.uuid4(),
            timestamp=event_timestamp,
            ingested_at=envelope.received_at,
            source_type=source_type,
            event_type=event_type,
            source_ip=norm_source_ip,
            destination_ip=norm_dest_ip,
            hostname=hostname,
            username=username,
            action=action,
            outcome=parsed.outcome or EventOutcome.UNKNOWN,
            severity=parsed.severity or Severity.INFO,
            raw_event=envelope.raw_payload,
            event_metadata=metadata,
            source_event_id=source_event_id
        )

    def _normalize_ip(self, ip_str: Optional[str]) -> Optional[str]:
        if not ip_str or not str(ip_str).strip():
            return None
        clean_ip = str(ip_str).strip()
        try:
            parsed_ip = ipaddress.ip_address(clean_ip)
            return str(parsed_ip)
        except ValueError:
            raise ValueError(f"Invalid IP address format: '{ip_str}'")

event_normalizer = EventNormalizer()
