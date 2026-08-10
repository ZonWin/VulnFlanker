from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from sqlalchemy import desc, select
from sqlalchemy.orm import Session, selectinload

from app.db.models import (
    AIEnrichmentBatchRun,
    IntelCollectionRun,
    MatchEvaluationRun,
    MatchResult,
    VerificationTask,
)
from app.schemas.task_center import (
    TaskCenterItemOut,
    TaskCenterItemType,
    TaskCenterStatusGroup,
    TaskCenterSummaryOut,
)
from app.services.match_results import list_risk_queue
from app.services.verification_tasks import list_verification_tasks


DEFAULT_TASK_CENTER_LIMIT = 100
MAX_TASK_CENTER_LIMIT = 500
MANUAL_INTEL_SOURCES = {"cisa-kev", "aliyun-avd", "watchvuln"}


def get_task_center_summary(db: Session) -> TaskCenterSummaryOut:
    items = list_task_center_items(db, limit=MAX_TASK_CENTER_LIMIT)
    by_group = Counter(item.status_group for item in items)
    by_type = Counter(item.item_type for item in items)
    return TaskCenterSummaryOut(
        total=len(items),
        pending=by_group["pending"],
        running=by_group["running"],
        success=by_group["success"],
        failed=by_group["failed"],
        cancelled=by_group["cancelled"],
        attention=by_group["attention"],
        by_type=dict(by_type),
    )


def list_task_center_items(
    db: Session,
    *,
    item_type: TaskCenterItemType | None = None,
    status_group: TaskCenterStatusGroup | None = None,
    status: str | None = None,
    source: str | None = None,
    trigger_type: str | None = None,
    keyword: str | None = None,
    limit: int = DEFAULT_TASK_CENTER_LIMIT,
) -> list[TaskCenterItemOut]:
    normalized_limit = max(1, min(limit, MAX_TASK_CENTER_LIMIT))
    items: list[TaskCenterItemOut] = []

    if item_type in (None, "verification"):
        items.extend(_verification_items(db, limit=normalized_limit))
    if item_type in (None, "intel_collection"):
        items.extend(_intel_collection_items(db, limit=normalized_limit))
    if item_type in (None, "risk_queue_item"):
        items.extend(_risk_queue_items(db, limit=normalized_limit))
    if item_type in (None, "ai_enrichment"):
        items.extend(_ai_enrichment_items(db, limit=normalized_limit))
    if item_type in (None, "match_evaluation"):
        items.extend(_match_evaluation_items(db, limit=normalized_limit))

    filtered = [
        item
        for item in items
        if _matches_filters(
            item,
            status_group=status_group,
            status=status,
            source=source,
            trigger_type=trigger_type,
            keyword=keyword,
        )
    ]
    filtered.sort(
        key=lambda item: (
            _sort_timestamp(item.updated_at),
            item.risk_score if item.risk_score is not None else -1,
        ),
        reverse=True,
    )
    return filtered[:normalized_limit]


def _verification_items(db: Session, *, limit: int) -> list[TaskCenterItemOut]:
    tasks = list_verification_tasks(db, limit=limit)
    items: list[TaskCenterItemOut] = []
    for task in tasks:
        actions = ["view"]
        if task.status in {"queued", "in_progress"}:
            actions.append("cancel")
        if task.status in {"failed", "rejected", "cancelled"}:
            actions.append("retry")

        vulnerability_id = task.vulnerability_canonical_id or task.vulnerability_id
        asset_name = task.asset_hostname or task.asset_id
        title = "验证任务"
        if vulnerability_id or asset_name:
            title = f"验证 {vulnerability_id or '-'} / {asset_name or '-'}"

        items.append(
            TaskCenterItemOut(
                id=f"verification:{task.id}",
                raw_id=task.id,
                item_type="verification",
                title=title,
                status=task.status,
                status_group=_verification_status_group(task.status),
                source="verification",
                trigger_type="manual",
                asset_id=task.asset_id,
                asset_name=asset_name,
                agent_id=task.asset_agent_id,
                vulnerability_id=vulnerability_id,
                vulnerability_title=task.vulnerability_title,
                started_at=task.created_at,
                finished_at=task.completed_at,
                updated_at=task.updated_at,
                error_message=task.error_message,
                detail_path=f"/verification-tasks/{task.id}",
                available_actions=actions,
                metrics={
                    "evidence_count": task.evidence_count,
                    "retry_count": task.retry_count,
                },
            )
        )
    return items


def _intel_collection_items(db: Session, *, limit: int) -> list[TaskCenterItemOut]:
    statement = (
        select(IntelCollectionRun)
        .order_by(desc(IntelCollectionRun.started_at), desc(IntelCollectionRun.updated_at))
        .limit(limit)
    )
    items = []
    for run in db.scalars(statement).all():
        actions = ["view"]
        if run.source_name in MANUAL_INTEL_SOURCES:
            actions.append("collect")
        source_label = _intel_source_label(run.source_name)
        items.append(
            TaskCenterItemOut(
                id=f"intel_collection:{run.id}",
                raw_id=run.id,
                item_type="intel_collection",
                title=f"{source_label} 情报采集",
                status=run.status,
                status_group=_collection_status_group(run.status),
                source=run.source_name,
                trigger_type=run.trigger_type,
                started_at=run.started_at,
                finished_at=run.finished_at,
                updated_at=run.updated_at,
                error_message=run.error_message,
                detail_path="/intel",
                available_actions=actions,
                metrics={
                    "fetched_count": run.fetched_count,
                    "stored_count": run.stored_count,
                    "processed_count": run.processed_count,
                    "skipped_count": run.skipped_count,
                    "failed_count": run.failed_count,
                },
            )
        )
    return items


def _risk_queue_items(db: Session, *, limit: int) -> list[TaskCenterItemOut]:
    # Load ORM rows first so the existing risk queue serializer has all context loaded.
    # The list_risk_queue service keeps risk ordering and current operational filters aligned.
    results = list_risk_queue(db, limit=limit)
    items: list[TaskCenterItemOut] = []
    for result in results:
        actions = ["view", "create_verification", "reevaluate"]
        vulnerability_id = result.vulnerability_canonical_id or result.vulnerability_id
        title = f"风险待处理 {vulnerability_id} / {result.asset_hostname}"
        items.append(
            TaskCenterItemOut(
                id=f"risk_queue_item:{result.id}",
                raw_id=result.id,
                item_type="risk_queue_item",
                title=title,
                status=result.status,
                status_group=_risk_status_group(result.status),
                source="risk-queue",
                trigger_type="system",
                asset_id=result.asset_id,
                asset_name=result.asset_hostname,
                agent_id=result.asset_agent_id,
                vulnerability_id=vulnerability_id,
                vulnerability_title=result.vulnerability_title,
                risk_priority=result.risk_priority,
                risk_score=result.risk_score,
                started_at=result.last_evaluated_at,
                finished_at=None,
                updated_at=result.last_evaluated_at or _match_result_updated_at(db, result.id),
                error_message=None,
                detail_path=f"/matching/{result.id}",
                available_actions=actions,
                metrics={
                    "verification_task_count": result.verification_task_count,
                    "verification_evidence_count": result.verification_evidence_count,
                },
            )
        )
    return items


def _ai_enrichment_items(db: Session, *, limit: int) -> list[TaskCenterItemOut]:
    statement = (
        select(AIEnrichmentBatchRun)
        .order_by(desc(AIEnrichmentBatchRun.created_at), desc(AIEnrichmentBatchRun.updated_at))
        .limit(limit)
    )
    items: list[TaskCenterItemOut] = []
    for run in db.scalars(statement).all():
        actions = ["view"]
        title = "AI 漏洞补全"
        if run.selected_count:
            title = f"AI 漏洞补全 {run.selected_count} 条"
        items.append(
            TaskCenterItemOut(
                id=f"ai_enrichment:{run.id}",
                raw_id=run.id,
                item_type="ai_enrichment",
                title=title,
                status=run.status,
                status_group=_ai_enrichment_status_group(run.status),
                source="ai-enrichment",
                trigger_type=run.trigger_type,
                started_at=run.started_at or run.created_at,
                finished_at=run.finished_at,
                updated_at=run.updated_at,
                error_message=run.recent_error,
                detail_path=f"/ai-enrichments/batches/{run.id}",
                available_actions=actions,
                metrics={
                    "selected_count": run.selected_count,
                    "processed_count": run.processed_count,
                    "success_count": run.success_count,
                    "failed_count": run.failed_count,
                    "skipped_count": run.skipped_count,
                    "pending_review_count": run.pending_review_count,
                    "insufficient_count": run.insufficient_count,
                },
            )
        )
    return items


def _match_evaluation_items(db: Session, *, limit: int) -> list[TaskCenterItemOut]:
    statement = (
        select(MatchEvaluationRun)
        .order_by(
            desc(MatchEvaluationRun.created_at),
            desc(MatchEvaluationRun.updated_at),
        )
        .limit(limit)
    )
    items: list[TaskCenterItemOut] = []
    for run in db.scalars(statement).all():
        if run.asset_id and run.vulnerability_id:
            title = f"定向匹配评估 {run.asset_id} / {run.vulnerability_id}"
        elif run.asset_id:
            title = f"资产匹配评估 {run.asset_id}"
        elif run.vulnerability_id:
            title = f"漏洞匹配评估 {run.vulnerability_id}"
        else:
            title = "全量风险匹配评估"
        items.append(
            TaskCenterItemOut(
                id=f"match_evaluation:{run.id}",
                raw_id=run.id,
                item_type="match_evaluation",
                title=title,
                status=run.status,
                status_group=_match_evaluation_status_group(run.status),
                source="matching",
                trigger_type=run.trigger_type,
                asset_id=run.asset_id,
                vulnerability_id=run.vulnerability_id,
                started_at=run.started_at or run.created_at,
                finished_at=run.finished_at,
                updated_at=run.updated_at,
                error_message=run.recent_error,
                detail_path="/matching",
                available_actions=["view"],
                metrics={
                    "total_count": run.total_count,
                    "processed_count": run.processed_count,
                    "evaluated_count": run.evaluated_count,
                    "skipped_count": run.skipped_count,
                    "failed_count": run.failed_count,
                },
            )
        )
    return items


def _match_result_updated_at(db: Session, match_result_id: str):
    result = db.scalar(
        select(MatchResult)
        .options(selectinload(MatchResult.vulnerability))
        .where(MatchResult.id == match_result_id)
    )
    if result is None:
        raise ValueError(f"Match result {match_result_id} disappeared during task center load.")
    return result.updated_at


def _matches_filters(
    item: TaskCenterItemOut,
    *,
    status_group: TaskCenterStatusGroup | None,
    status: str | None,
    source: str | None,
    trigger_type: str | None,
    keyword: str | None,
) -> bool:
    if status_group and item.status_group != status_group:
        return False
    if status and item.status != status:
        return False
    if source and item.source != source:
        return False
    if trigger_type and item.trigger_type != trigger_type:
        return False
    if keyword and not _matches_keyword(item, keyword):
        return False
    return True


def _matches_keyword(item: TaskCenterItemOut, keyword: str) -> bool:
    words = [word for word in keyword.lower().split() if word]
    if not words:
        return True
    haystack = " ".join(
        str(value)
        for value in (
            item.id,
            item.raw_id,
            item.title,
            item.status,
            item.source,
            item.trigger_type,
            item.asset_id,
            item.asset_name,
            item.agent_id,
            item.vulnerability_id,
            item.vulnerability_title,
        )
        if value
    ).lower()
    return all(word in haystack for word in words)


def _sort_timestamp(value: datetime) -> float:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.timestamp()


def _verification_status_group(status: str) -> TaskCenterStatusGroup:
    if status == "queued":
        return "pending"
    if status in {"in_progress", "cancel_requested"}:
        return "running"
    if status == "completed":
        return "success"
    if status in {"failed", "rejected"}:
        return "failed"
    if status == "cancelled":
        return "cancelled"
    return "attention"


def _collection_status_group(status: str) -> TaskCenterStatusGroup:
    if status in {"queued", "pending"}:
        return "pending"
    if status == "running":
        return "running"
    if status in {"completed", "processed", "skipped"}:
        return "success"
    if status in {"failed", "rejected"}:
        return "failed"
    if status == "cancelled":
        return "cancelled"
    return "attention"


def _ai_enrichment_status_group(status: str) -> TaskCenterStatusGroup:
    if status == "queued":
        return "pending"
    if status == "running":
        return "running"
    if status == "completed":
        return "success"
    if status == "failed":
        return "failed"
    if status == "cancelled":
        return "cancelled"
    return "attention"


def _match_evaluation_status_group(status: str) -> TaskCenterStatusGroup:
    if status == "queued":
        return "pending"
    if status == "running":
        return "running"
    if status == "completed":
        return "success"
    if status == "failed":
        return "failed"
    return "attention"


def _risk_status_group(status: str) -> TaskCenterStatusGroup:
    if status == "verified":
        return "success"
    if status in {"affected", "needs_review"}:
        return "attention"
    if status == "not_affected":
        return "success"
    return "attention"


def _intel_source_label(source_name: str) -> str:
    labels = {
        "cisa-kev": "CISA KEV",
        "aliyun-avd": "阿里云漏洞库",
        "watchvuln": "WatchVuln",
    }
    return labels.get(source_name, source_name)
