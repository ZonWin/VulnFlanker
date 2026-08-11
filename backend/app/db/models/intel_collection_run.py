from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, utcnow


class IntelCollectionRun(TimestampMixin, Base):
    __tablename__ = "intel_collection_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    source_name: Mapped[str] = mapped_column(String(64), index=True)
    trigger_type: Mapped[str] = mapped_column(String(32), default="manual", index=True)
    status: Mapped[str] = mapped_column(String(32), default="running", index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fetched_count: Mapped[int] = mapped_column(Integer, default=0)
    stored_count: Mapped[int] = mapped_column(Integer, default=0)
    processed_count: Mapped[int] = mapped_column(Integer, default=0)
    skipped_count: Mapped[int] = mapped_column(Integer, default=0)
    failed_count: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    task_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    parameters_json: Mapped[dict] = mapped_column(JSON, default=dict)
    generation_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    update_mode: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cursor_before_json: Mapped[dict] = mapped_column(JSON, default=dict)
    cursor_after_json: Mapped[dict] = mapped_column(JSON, default=dict)
    completeness_json: Mapped[dict] = mapped_column(JSON, default=dict)
    parser_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    artifacts_count: Mapped[int] = mapped_column(Integer, default=0)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)

