from typing import List, Set, Tuple, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from backend.app.schemas.telemetry import (
    RawTelemetryRequest,
    IngestionEnvelope,
    SingleIngestResponse,
    BatchIngestResponse,
)
from backend.app.models.audit_log import AuditLog
from backend.app.models.enums import AuditResult
from backend.app.models.user import User
from security_engine.pipeline import processing_service

class IngestionService:
    """Service orchestrating telemetry ingestion, idempotency check, envelope creation, and M04 pipeline execution."""

    def __init__(self):
        # In-memory idempotency set tracking seen (source_type, source_event_id)
        self._seen_event_keys: Set[str] = set()
        # In-memory queue storing accepted envelopes
        self._envelope_buffer: List[IngestionEnvelope] = []

    def ingest_single(
        self,
        telemetry: RawTelemetryRequest,
        request_id: str,
        user: User,
        db: Session
    ) -> SingleIngestResponse:
        """Process single raw telemetry request through intake, parsing, normalization, and persistence."""
        is_dup = False
        if telemetry.source_event_id:
            key = f"{telemetry.source_type}:{telemetry.source_event_id}"
            if key in self._seen_event_keys:
                is_dup = True
            else:
                self._seen_event_keys.add(key)

        envelope = IngestionEnvelope(
            request_id=request_id,
            received_at=datetime.now(timezone.utc),
            ingested_by=user.username,
            source_type=telemetry.source_type,
            source_event_id=telemetry.source_event_id,
            raw_payload=telemetry.payload,
            provided_timestamp=telemetry.timestamp,
            provided_hostname=telemetry.hostname,
            provided_source_ip=telemetry.source_ip,
            provided_destination_ip=telemetry.destination_ip,
            provided_event_type=telemetry.event_type,
            is_duplicate=is_dup
        )

        if not is_dup:
            self._envelope_buffer.append(envelope)
            # Execute M04 Parsing -> Normalization -> Persistence pipeline
            proc_result = processing_service.process(envelope, db)
        else:
            proc_result = None

        # Operational Audit Log (safe metadata only, NO raw payload or tokens)
        audit_log = AuditLog(
            actor_id=user.id,
            action="INGEST_ACCEPTED",
            target_type="telemetry",
            target_id=envelope.envelope_id,
            result=AuditResult.SUCCESS,
            request_id=request_id,
            audit_metadata={
                "source_type": telemetry.source_type,
                "record_count": 1,
                "is_duplicate": is_dup,
                "source_event_id": telemetry.source_event_id,
                "pipeline_status": proc_result.status if proc_result else "DUPLICATE"
            }
        )
        db.add(audit_log)
        db.commit()

        return SingleIngestResponse(
            status="accepted",
            request_id=request_id,
            accepted=1,
            envelope_id=envelope.envelope_id,
            is_duplicate=is_dup
        )

    def ingest_batch(
        self,
        batch: List[RawTelemetryRequest],
        request_id: str,
        user: User,
        db: Session
    ) -> BatchIngestResponse:
        """Process atomic batch raw telemetry request through intake, parsing, normalization, and persistence."""
        accepted_count = 0
        duplicates_count = 0

        for telemetry in batch:
            is_dup = False
            if telemetry.source_event_id:
                key = f"{telemetry.source_type}:{telemetry.source_event_id}"
                if key in self._seen_event_keys:
                    is_dup = True
                    duplicates_count += 1
                else:
                    self._seen_event_keys.add(key)

            envelope = IngestionEnvelope(
                request_id=request_id,
                received_at=datetime.now(timezone.utc),
                ingested_by=user.username,
                source_type=telemetry.source_type,
                source_event_id=telemetry.source_event_id,
                raw_payload=telemetry.payload,
                provided_timestamp=telemetry.timestamp,
                provided_hostname=telemetry.hostname,
                provided_source_ip=telemetry.source_ip,
                provided_destination_ip=telemetry.destination_ip,
                provided_event_type=telemetry.event_type,
                is_duplicate=is_dup
            )

            if not is_dup:
                self._envelope_buffer.append(envelope)
                processing_service.process(envelope, db)
            accepted_count += 1

        # Operational Audit Log for batch
        primary_source_type = batch[0].source_type if batch else "unknown"
        audit_log = AuditLog(
            actor_id=user.id,
            action="INGEST_ACCEPTED",
            target_type="telemetry_batch",
            target_id=request_id,
            result=AuditResult.SUCCESS,
            request_id=request_id,
            audit_metadata={
                "source_type": primary_source_type,
                "record_count": len(batch),
                "accepted": accepted_count,
                "duplicates": duplicates_count
            }
        )
        db.add(audit_log)
        db.commit()

        return BatchIngestResponse(
            status="accepted",
            request_id=request_id,
            accepted=accepted_count,
            rejected=0,
            duplicates=duplicates_count
        )

# Global singleton instance for M03 ingestion service boundary
ingestion_service = IngestionService()
