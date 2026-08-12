import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List
from sqlalchemy import String, Text, Integer, SmallInteger, Boolean, DateTime, Enum as SQLEnum, JSON, CheckConstraint, Index
from sqlalchemy.orm import Mapped, mapped_column
from backend.app.models.base import Base
from backend.app.models.enums import CorrelationStatus, Severity

class CorrelationGroup(Base):
    __tablename__ = "correlation_groups"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    correlation_key: Mapped[str] = mapped_column(String(120), unique=True, index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[CorrelationStatus] = mapped_column(
        SQLEnum(CorrelationStatus), nullable=False, default=CorrelationStatus.ACTIVE, index=True
    )
    severity: Mapped[Severity] = mapped_column(
        SQLEnum(Severity), nullable=False, default=Severity.MEDIUM, index=True
    )
    risk_score: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=50)
    risk_explanation: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    entities: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    alert_ids: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)
    event_ids: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)
    rule_ids: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)
    alert_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    correlation_reason: Mapped[str] = mapped_column(Text, nullable=False)
    is_golden_sequence: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    pattern_matched: Mapped[str | None] = mapped_column(String(120), nullable=True)
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
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="check_correlation_risk_score_bounds"),
        Index("idx_correlation_status_updated", "status", "updated_at"),
        Index("idx_correlation_source_ip", "source_ip", "status"),
        Index("idx_correlation_username", "username", "status"),
        Index("idx_correlation_hostname", "hostname", "status"),
    )
