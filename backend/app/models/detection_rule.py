import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List
from sqlalchemy import String, Text, Boolean, Integer, SmallInteger, DateTime, Enum as SQLEnum, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.models.base import Base
from backend.app.models.enums import Severity

class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    rule_id: Mapped[str] = mapped_column(String(80), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str | None] = mapped_column(String(80), nullable=True)
    event_types: Mapped[List[str]] = mapped_column(JSON, nullable=False)
    conditions: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    group_by: Mapped[str | None] = mapped_column(String(80), nullable=True)
    threshold: Mapped[int | None] = mapped_column(Integer, nullable=True)
    window_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    severity: Mapped[Severity] = mapped_column(SQLEnum(Severity), nullable=False, default=Severity.MEDIUM)
    risk_weight: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=50)
    mitre_metadata: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    alerts = relationship("Alert", back_populates="rule")
