import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, ForeignKey, PrimaryKeyConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.models.base import Base

class IncidentAlert(Base):
    __tablename__ = "incident_alerts"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    alert_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("alerts.id", ondelete="RESTRICT"), nullable=False
    )
    correlation_role: Mapped[str] = mapped_column(String(80), nullable=False, default="contributing")
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    __table_args__ = (
        PrimaryKeyConstraint("incident_id", "alert_id"),
    )

    # Relationships
    incident = relationship("Incident", back_populates="alert_links")
    alert = relationship("Alert", back_populates="incident_links")
