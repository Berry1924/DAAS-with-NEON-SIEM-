import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, ForeignKey, PrimaryKeyConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.models.base import Base

class AlertEvent(Base):
    __tablename__ = "alert_events"

    alert_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("events.id", ondelete="RESTRICT"), nullable=False
    )
    evidence_role: Mapped[str] = mapped_column(String(80), nullable=False, default="supporting")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    __table_args__ = (
        PrimaryKeyConstraint("alert_id", "event_id"),
    )

    # Relationships
    alert = relationship("Alert", back_populates="event_links")
    event = relationship("Event", back_populates="alert_links")
