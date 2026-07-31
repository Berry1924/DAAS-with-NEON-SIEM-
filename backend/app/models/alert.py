import uuid
from datetime import datetime, timezone
from typing import Any, Dict
from sqlalchemy import String, Text, SmallInteger, DateTime, ForeignKey, Enum as SQLEnum, JSON, CheckConstraint, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.models.base import Base
from backend.app.models.enums import Severity, AlertStatus

class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    rule_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("detection_rules.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    primary_event_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("events.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[Severity] = mapped_column(SQLEnum(Severity), nullable=False, default=Severity.MEDIUM)
    risk_score: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=50)
    status: Mapped[AlertStatus] = mapped_column(
        SQLEnum(AlertStatus), nullable=False, default=AlertStatus.NEW, index=True
    )
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    evidence: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="check_alert_risk_score_bounds"),
        Index("idx_alerts_status_severity_created", "status", "severity", "created_at"),
    )

    # Relationships
    rule = relationship("DetectionRule", back_populates="alerts")
    primary_event = relationship("Event", foreign_keys=[primary_event_id])
    event_links = relationship("AlertEvent", back_populates="alert", cascade="all, delete-orphan")
    incident_links = relationship("IncidentAlert", back_populates="alert", cascade="all, delete-orphan")
    timeline_entries = relationship("IncidentTimeline", back_populates="alert")
