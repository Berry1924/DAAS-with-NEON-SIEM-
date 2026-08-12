import uuid
import logging
from dataclasses import dataclass
from typing import Optional, List
from sqlalchemy.orm import Session

from backend.app.schemas.telemetry import IngestionEnvelope
from backend.app.models.event import Event
from backend.app.repositories.event_repository import EventRepository
from security_engine.parsers.registry import parser_registry
from security_engine.normalization.normalizer import event_normalizer
from security_engine.detection.evaluator import rule_evaluator
from security_engine.correlation.engine import correlation_engine

logger = logging.getLogger(__name__)

@dataclass
class ProcessingResult:
    """Processing status result for an IngestionEnvelope."""
    status: str  # NORMALIZED, PARSE_FAILED, VALIDATION_FAILED, DUPLICATE
    event_id: Optional[uuid.UUID] = None
    error: Optional[str] = None

class ProcessingService:
    """Orchestration service running Parsing -> Normalization -> Persistence -> Detection -> Correlation pipeline."""

    def process(self, envelope: IngestionEnvelope, db: Session) -> ProcessingResult:
        """Process a single IngestionEnvelope end-to-end."""
        if envelope.is_duplicate:
            return ProcessingResult(
                status="DUPLICATE",
                error=f"Duplicate event skipped (source_event_id: {envelope.source_event_id})"
            )

        # 1. Select Parser
        try:
            parser = parser_registry.get_parser(envelope.source_type)
        except ValueError as err:
            return ProcessingResult(status="PARSE_FAILED", error=str(err))

        # 2. Execute Parser
        try:
            parsed_event = parser.parse(envelope)
        except Exception as err:
            return ProcessingResult(status="PARSE_FAILED", error=f"Parse failure: {str(err)}")

        # 3. Execute Normalization
        try:
            canonical_event = event_normalizer.normalize(parsed_event, envelope)
        except Exception as err:
            return ProcessingResult(status="VALIDATION_FAILED", error=f"Normalization failure: {str(err)}")

        # 4. Database Persistence via EventRepository
        try:
            repo = EventRepository(db)
            persisted_event = repo.create(canonical_event)
        except Exception as err:
            db.rollback()
            return ProcessingResult(status="VALIDATION_FAILED", error=f"Persistence error: {str(err)}")

        # 5. Detection Engine & 6. Correlation Engine Evaluation
        try:
            alerts = rule_evaluator.evaluate(persisted_event, db)
            for alert in alerts:
                correlation_engine.correlate_alert(alert, db)
        except Exception as err:
            logger.error(f"Detection/Correlation evaluation error: {err}", exc_info=True)

        return ProcessingResult(status="NORMALIZED", event_id=persisted_event.id)


processing_service = ProcessingService()

