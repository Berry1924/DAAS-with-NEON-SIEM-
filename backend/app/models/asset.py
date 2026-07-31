import uuid
from datetime import datetime, timezone
from typing import Any, Dict
from sqlalchemy import String, SmallInteger, DateTime, Enum as SQLEnum, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.models.base import Base
from backend.app.models.enums import AssetStatus

class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    hostname: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    os: Mapped[str | None] = mapped_column(String(120), nullable=True)
    asset_type: Mapped[str | None] = mapped_column(String(80), nullable=True)
    criticality: Mapped[int] = mapped_column(SmallInteger, default=50, nullable=False)
    status: Mapped[AssetStatus] = mapped_column(
        SQLEnum(AssetStatus), nullable=False, default=AssetStatus.UNKNOWN
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True, nullable=True)
    asset_metadata: Mapped[Dict[str, Any]] = mapped_column("metadata", JSON, nullable=False, default=dict)
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
    events = relationship("Event", back_populates="asset")
    primary_incidents = relationship("Incident", back_populates="primary_asset")
