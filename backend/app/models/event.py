import uuid
from datetime import datetime, timezone
from typing import Any, Dict
from sqlalchemy import String, DateTime, ForeignKey, Enum as SQLEnum, JSON, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.models.base import Base
from backend.app.models.enums import EventOutcome, Severity

class Event(Base):
    __tablename__ = "events"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    source_type: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    action: Mapped[str | None] = mapped_column(String(120), nullable=True)
    outcome: Mapped[EventOutcome] = mapped_column(
        SQLEnum(EventOutcome), nullable=False, default=EventOutcome.UNKNOWN
    )
    severity: Mapped[Severity] = mapped_column(
        SQLEnum(Severity), nullable=False, default=Severity.INFO
    )
    raw_event: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    event_metadata: Mapped[Dict[str, Any]] = mapped_column("metadata", JSON, nullable=False, default=dict)
    source_event_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    asset = relationship("Asset", back_populates="events")
    alert_links = relationship("AlertEvent", back_populates="event", cascade="all, delete-orphan")
    timeline_entries = relationship("IncidentTimeline", back_populates="event")

__table_args__ = (
    Index("idx_events_type_timestamp", Event.event_type, Event.timestamp.desc()),
    Index("idx_events_source_ip_timestamp", Event.source_ip, Event.timestamp.desc()),
    Index("idx_events_username_timestamp", Event.username, Event.timestamp.desc()),
    Index("idx_events_hostname_timestamp", Event.hostname, Event.timestamp.desc()),
)
