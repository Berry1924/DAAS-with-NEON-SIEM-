import re
from typing import Optional, Dict, Any
from dateutil import parser as date_parser

from security_engine.parsers.base import BaseParser, ParsedEvent
from backend.app.models.enums import EventOutcome, Severity
from backend.app.schemas.telemetry import IngestionEnvelope

LINUX_AUTH_PATTERNS = [
    (
        re.compile(r"Accepted password for (?P<username>[^\s]+) from (?P<source_ip>[^\s]+) port (?P<port>\d+) ssh2"),
        "authentication", "login", EventOutcome.SUCCESS, Severity.INFO
    ),
    (
        re.compile(r"Failed password for invalid user (?P<username>[^\s]+) from (?P<source_ip>[^\s]+) port (?P<port>\d+) ssh2"),
        "authentication", "login", EventOutcome.FAILURE, Severity.LOW
    ),
    (
        re.compile(r"Failed password for (?P<username>[^\s]+) from (?P<source_ip>[^\s]+) port (?P<port>\d+) ssh2"),
        "authentication", "login", EventOutcome.FAILURE, Severity.LOW
    ),
    (
        re.compile(r"session opened for user (?P<username>[^\s]+)"),
        "authentication", "session_open", EventOutcome.SUCCESS, Severity.INFO
    ),
    (
        re.compile(r"session closed for user (?P<username>[^\s]+)"),
        "authentication", "session_close", EventOutcome.SUCCESS, Severity.INFO
    ),
]

class LinuxAuthParser(BaseParser):
    """Parser for Linux authentication syslog & SSHD telemetry."""

    def supports(self, source_type: str) -> bool:
        return source_type == "linux_auth"

    def parse(self, envelope: IngestionEnvelope) -> ParsedEvent:
        raw_payload = envelope.raw_payload or {}
        log_message = ""

        if isinstance(raw_payload, dict):
            log_message = str(raw_payload.get("message") or raw_payload.get("log") or raw_payload.get("raw") or str(raw_payload))
        else:
            log_message = str(raw_payload)

        event_type = "authentication"
        action = "auth_event"
        outcome = EventOutcome.UNKNOWN
        severity = Severity.INFO
        username: Optional[str] = None
        source_ip: Optional[str] = envelope.provided_source_ip
        hostname: Optional[str] = envelope.provided_hostname
        port: Optional[str] = None
        metadata: Dict[str, Any] = {"service": "sshd", "request_id": envelope.request_id}

        matched = False
        for pattern, ev_type, act, out, sev in LINUX_AUTH_PATTERNS:
            match = pattern.search(log_message)
            if match:
                matched = True
                event_type = ev_type
                action = act
                outcome = out
                severity = sev
                match_dict = match.groupdict()
                username = match_dict.get("username")
                if match_dict.get("source_ip"):
                    source_ip = match_dict.get("source_ip")
                if match_dict.get("port"):
                    port = match_dict.get("port")
                    metadata["port"] = int(port)
                if "invalid user" in log_message:
                    metadata["invalid_user"] = True
                break

        if not matched:
            action = "unknown_auth_event"
            outcome = EventOutcome.UNKNOWN

        return ParsedEvent(
            source_type=envelope.source_type,
            event_type=event_type,
            timestamp=envelope.provided_timestamp,
            hostname=hostname,
            source_ip=source_ip,
            destination_ip=envelope.provided_destination_ip,
            username=username,
            action=action,
            outcome=outcome,
            severity=severity,
            source_event_id=envelope.source_event_id,
            raw_event=raw_payload,
            metadata=metadata,
            request_id=envelope.request_id
        )
