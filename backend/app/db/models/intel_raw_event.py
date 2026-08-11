from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, utcnow


class IntelRawEvent(TimestampMixin, Base):
    __tablename__ = "intel_raw_events"
    __table_args__ = (
        UniqueConstraint(
            "provider",
            "generation_id",
            "external_key",
            "payload_hash",
            name="uq_intel_raw_events_generation_record",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    provider: Mapped[str] = mapped_column(String(64), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    external_key: Mapped[str] = mapped_column(String(255), index=True)
    source_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    payload: Mapped[dict] = mapped_column(JSON)
    payload_hash: Mapped[str] = mapped_column(String(64))
    processing_status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    processed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    vulnerability_id: Mapped[str | None] = mapped_column(
        ForeignKey("vulnerabilities.id"),
        nullable=True,
        index=True,
    )
    generation_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    page_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    artifact_uri: Mapped[str | None] = mapped_column(Text, nullable=True)
    artifact_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    vulnerability: Mapped["Vulnerability | None"] = relationship(back_populates="raw_events")
    source_links: Mapped[list["VulnerabilitySource"]] = relationship(back_populates="raw_event")
