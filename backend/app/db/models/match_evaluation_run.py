from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin


class MatchEvaluationRun(TimestampMixin, Base):
    __tablename__ = "match_evaluation_runs"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    trigger_type: Mapped[str] = mapped_column(
        String(32), default="manual", index=True
    )
    asset_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    vulnerability_id: Mapped[str | None] = mapped_column(
        String(128), nullable=True, index=True
    )
    requested_by: Mapped[str | None] = mapped_column(
        String(36), nullable=True, index=True
    )
    task_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    active_scope_key: Mapped[str | None] = mapped_column(
        String(64), nullable=True, unique=True
    )
    total_count: Mapped[int] = mapped_column(Integer, default=0)
    processed_count: Mapped[int] = mapped_column(Integer, default=0)
    evaluated_count: Mapped[int] = mapped_column(Integer, default=0)
    skipped_count: Mapped[int] = mapped_column(Integer, default=0)
    failed_count: Mapped[int] = mapped_column(Integer, default=0)
    sample_result_ids_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    recent_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
