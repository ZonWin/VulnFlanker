from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin


class IntelSourceConfig(TimestampMixin, Base):
    __tablename__ = "intel_source_configs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    source_name: Mapped[str] = mapped_column(String(64), unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    schedule_seconds: Mapped[int] = mapped_column(Integer, default=86_400)
    update_mode: Mapped[str] = mapped_column(String(32), default="snapshot")
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=30)
    page_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    stale_after_seconds: Mapped[int] = mapped_column(Integer, default=172_800)
    expire_after_seconds: Mapped[int] = mapped_column(Integer, default=604_800)
    cursor_json: Mapped[dict] = mapped_column(JSON, default=dict)
    active_generation_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    settings_json: Mapped[dict] = mapped_column(JSON, default=dict)
