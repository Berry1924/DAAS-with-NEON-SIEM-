import uuid
from datetime import datetime, timezone
from typing import Any, Dict
from sqlalchemy import String, DateTime, ForeignKey, Enum as SQLEnum, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.models.base import Base
from backend.app.models.enums import AuditResult

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True
    )
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    action: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    target_type: Mapped[str | None] = mapped_column(String(80), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    result: Mapped[AuditResult] = mapped_column(SQLEnum(AuditResult), nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    audit_metadata: Mapped[Dict[str, Any]] = mapped_column("metadata", JSON, nullable=False, default=dict)

    # Relationships
    actor = relationship("User", back_populates="audit_logs")
