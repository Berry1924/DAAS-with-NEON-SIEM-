from typing import Optional, Dict, Any
from dateutil import parser as date_parser
from datetime import datetime, timezone

from security_engine.parsers.base import BaseParser, ParsedEvent
from backend.app.models.enums import EventOutcome, Severity
from backend.app.schemas.telemetry import IngestionEnvelope

def _extract_alias(payload: Dict[str, Any], aliases: list) -> Optional[Any]:
    for alias in aliases:
        if alias in payload and payload[alias] is not None:
            return payload[alias]
    return None

class JsonParser(BaseParser):
    """Safe, deterministic parser for generic JSON security telemetry."""

    def supports(self, source_type: str) -> bool:
        return source_type == "json"

    def parse(self, envelope: IngestionEnvelope) -> ParsedEvent:
        raw_payload = envelope.raw_payload or {}

        # 1. Extract values using deterministic alias mappings
        raw_ts = _extract_alias(raw_payload, ["timestamp", "@timestamp", "time", "datetime", "date"])
        event_type = str(_extract_alias(raw_payload, ["event_type", "type", "category"]) or envelope.provided_event_type or "generic")
        source_ip = _extract_alias(raw_payload, ["source_ip", "src_ip", "client_ip", "source_address", "ip"]) or envelope.provided_source_ip
        destination_ip = _extract_alias(raw_payload, ["destination_ip", "dst_ip", "server_ip", "dest_ip"]) or envelope.provided_destination_ip
        username = _extract_alias(raw_payload, ["username", "user", "user_name", "account", "principal"])
        hostname = _extract_alias(raw_payload, ["hostname", "host", "computer", "server"]) or envelope.provided_hostname
        action = _extract_alias(raw_payload, ["action", "activity", "event", "operation"])
        raw_outcome = _extract_alias(raw_payload, ["outcome", "status", "result"])
        raw_severity = _extract_alias(raw_payload, ["severity", "level", "priority"])

        # Timestamp parsing
        parsed_timestamp: Optional[datetime] = envelope.provided_timestamp
        if raw_ts and not parsed_timestamp:
            if isinstance(raw_ts, datetime):
                parsed_timestamp = raw_ts
            elif isinstance(raw_ts, (int, float)):
                parsed_timestamp = datetime.fromtimestamp(raw_ts, tz=timezone.utc)
            elif isinstance(raw_ts, str):
                try:
                    parsed_timestamp = date_parser.parse(raw_ts)
                except Exception:
                    raise ValueError(f"Invalid timestamp format: '{raw_ts}'")

        # Outcome mapping
        outcome = EventOutcome.UNKNOWN
        if raw_outcome:
            out_str = str(raw_outcome).upper()
            if out_str in ["SUCCESS", "SUCCESSFUL", "OK", "PASS", "0", "200"]:
                outcome = EventOutcome.SUCCESS
            elif out_str in ["FAILURE", "FAILED", "FAIL", "ERROR", "DENIED", "1", "401", "403"]:
                outcome = EventOutcome.FAILURE

        # Severity mapping
        severity = Severity.INFO
        if raw_severity:
            sev_str = str(raw_severity).upper()
            if sev_str in Severity.__members__:
                severity = Severity[sev_str]
            elif sev_str in ["WARN", "WARNING"]:
                severity = Severity.MEDIUM
            elif sev_str in ["ERR", "ERROR", "FATAL"]:
                severity = Severity.HIGH

        # Preserve unknown keys under metadata safely
        known_keys = {
            "timestamp", "@timestamp", "time", "datetime", "date",
            "event_type", "type", "category",
            "source_ip", "src_ip", "client_ip", "source_address", "ip",
            "destination_ip", "dst_ip", "server_ip", "dest_ip",
            "username", "user", "user_name", "account", "principal",
            "hostname", "host", "computer", "server",
            "action", "activity", "event", "operation",
            "outcome", "status", "result",
            "severity", "level", "priority"
        }
        metadata: Dict[str, Any] = {
            k: v for k, v in raw_payload.items() if k not in known_keys
        }
        metadata["request_id"] = envelope.request_id

        return ParsedEvent(
            source_type=envelope.source_type,
            event_type=event_type,
            timestamp=parsed_timestamp,
            hostname=str(hostname) if hostname is not None else None,
            source_ip=str(source_ip) if source_ip is not None else None,
            destination_ip=str(destination_ip) if destination_ip is not None else None,
            username=str(username) if username is not None else None,
            action=str(action) if action is not None else None,
            outcome=outcome,
            severity=severity,
            source_event_id=envelope.source_event_id,
            raw_event=raw_payload,
            metadata=metadata,
            request_id=envelope.request_id
        )
