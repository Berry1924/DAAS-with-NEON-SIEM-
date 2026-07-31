import uuid
from datetime import datetime, timezone
from typing import Any, Dict
from sqlalchemy import String, Text, SmallInteger, DateTime, ForeignKey, Enum as SQLEnum, JSON, CheckConstraint, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.models.base import Base
from backend.app.models.enums import Severity, IncidentStatus

class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    incident_key: Mapped[str] = mapped_column(String(80), unique=True, index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    incident_type: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[Severity] = mapped_column(SQLEnum(Severity), nullable=False, default=Severity.HIGH)
    risk_score: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=50)
    status: Mapped[IncidentStatus] = mapped_column(
        SQLEnum(IncidentStatus), nullable=False, default=IncidentStatus.NEW, index=True
    )
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    primary_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    correlation_rule: Mapped[str | None] = mapped_column(String(120), nullable=True)
    risk_explanation: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
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
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="check_incident_risk_score_bounds"),
        Index("idx_incidents_status_risk_created", "status", "risk_score", "created_at"),
    )

    # Relationships
    assignee = relationship("User", back_populates="assigned_incidents")
    primary_asset = relationship("Asset", back_populates="primary_incidents")
    alert_links = relationship("IncidentAlert", back_populates="incident", cascade="all, delete-orphan")
    timeline = relationship("IncidentTimeline", back_populates="incident", cascade="all, delete-orphan")
    notes = relationship("IncidentNote", back_populates="incident", cascade="all, delete-orphan")
