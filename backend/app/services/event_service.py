import uuid
import math
from typing import Optional
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.repositories.event_repository import EventRepository, EventFilter
from backend.app.schemas.event import (
    EventRead,
    PaginatedEventResponse,
    EventStatsResponse,
)

class EventService:
    """Service layer for Event retrieval, filtering, pagination, and stats."""

    def search_events(
        self,
        db: Session,
        filter_params: EventFilter,
        page: int = 1,
        page_size: int = 50
    ) -> PaginatedEventResponse:
        """Execute bounded, paginated search over canonical Event evidence."""
        # Enforce page and page_size boundaries
        if page < 1:
            raise ValueError("Page number must be greater than or equal to 1")
        if page_size < 1 or page_size > settings.MAX_PAGE_SIZE:
            raise ValueError(f"Page size must be between 1 and {settings.MAX_PAGE_SIZE}")

        repo = EventRepository(db)
        events, total = repo.search(filter_params, page=page, page_size=page_size)

        pages = math.ceil(total / page_size) if total > 0 else 0
        items = [EventRead.model_validate(e) for e in events]

        return PaginatedEventResponse(
            items=items,
            page=page,
            page_size=page_size,
            total=total,
            pages=pages
        )

    def get_event_by_id(self, db: Session, event_id: uuid.UUID) -> Optional[EventRead]:
        """Get canonical Event evidence detail by UUID."""
        repo = EventRepository(db)
        event = repo.get_by_id(event_id)
        if not event:
            return None
        return EventRead.model_validate(event)

    def get_event_stats(self, db: Session, filter_params: Optional[EventFilter] = None) -> EventStatsResponse:
        """Get aggregated event statistics."""
        repo = EventRepository(db)
        stats = repo.get_stats(filter_params)
        return EventStatsResponse(**stats)

event_service = EventService()
