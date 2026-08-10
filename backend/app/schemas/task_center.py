from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


TaskCenterItemType = Literal[
    "verification",
    "intel_collection",
    "risk_queue_item",
    "ai_enrichment",
    "match_evaluation",
]
TaskCenterStatusGroup = Literal[
    "pending",
    "running",
    "success",
    "failed",
    "cancelled",
    "attention",
]


class TaskCenterSummaryOut(BaseModel):
    total: int = 0
    pending: int = 0
    running: int = 0
    success: int = 0
    failed: int = 0
    cancelled: int = 0
    attention: int = 0
    by_type: dict[str, int] = Field(default_factory=dict)


class TaskCenterItemOut(BaseModel):
    id: str
    raw_id: str
    item_type: TaskCenterItemType
    title: str
    status: str
    status_group: TaskCenterStatusGroup
    source: str | None = None
    trigger_type: str | None = None
    asset_id: str | None = None
    asset_name: str | None = None
    agent_id: str | None = None
    vulnerability_id: str | None = None
    vulnerability_title: str | None = None
    risk_priority: str | None = None
    risk_score: float | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    updated_at: datetime
    error_message: str | None = None
    detail_path: str
    available_actions: list[str] = Field(default_factory=list)
    metrics: dict[str, int] = Field(default_factory=dict)
