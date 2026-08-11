from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.connectors.registry import build_builtin_registry
from app.db.base import utcnow
from app.db.models import (
    IntelCollectionRun,
    IntelSourceConfig,
    VulnerabilitySourceContribution,
)
from app.services.intel_generations import get_or_create_source_config
from app.services.intel_source_collection import (
    build_builtin_mapper_registry,
    collect_enrichment_source,
)
from app.services.matching import evaluate_matches


ACTIVE_RUN_STATUSES = {"queued", "running", "staging", "ready"}


@dataclass(frozen=True, slots=True)
class ReevaluationBatchResult:
    run_id: str
    processed_count: int
    failed_count: int
    next_cursor: str | None


def enrichment_source_names() -> tuple[str, ...]:
    collector_names = set(build_builtin_registry().source_names())
    mapper_names = set(build_builtin_mapper_registry().source_names())
    return tuple(sorted(collector_names & mapper_names))


def get_enrichment_source_config(
    db: Session,
    source_name: str,
    *,
    create: bool = False,
) -> IntelSourceConfig | None:
    connector, _mapper = _registered_pair(source_name)
    config = db.scalar(
        select(IntelSourceConfig).where(IntelSourceConfig.source_name == source_name)
    )
    if config is None and create:
        metadata = connector.metadata
        config = get_or_create_source_config(
            db,
            source_name=source_name,
            update_mode=metadata.update_mode.value,
            schedule_seconds=metadata.default_schedule_seconds,
        )
    return config


def update_enrichment_source_config(
    db: Session,
    source_name: str,
    *,
    enabled: bool | None = None,
    schedule_seconds: int | None = None,
    stale_after_seconds: int | None = None,
    expire_after_seconds: int | None = None,
) -> IntelSourceConfig:
    config = get_enrichment_source_config(db, source_name, create=True)
    assert config is not None
    next_stale = (
        stale_after_seconds
        if stale_after_seconds is not None
        else config.stale_after_seconds
    )
    next_expire = (
        expire_after_seconds
        if expire_after_seconds is not None
        else config.expire_after_seconds
    )
    if next_expire <= next_stale:
        raise ValueError("expire_after_seconds must be greater than stale_after_seconds")
    if enabled is not None:
        config.enabled = enabled
    if schedule_seconds is not None:
        config.schedule_seconds = schedule_seconds
    if stale_after_seconds is not None:
        config.stale_after_seconds = stale_after_seconds
    if expire_after_seconds is not None:
        config.expire_after_seconds = expire_after_seconds
    db.add(config)
    db.commit()
    db.refresh(config)
    return config


def collect_registered_enrichment_source(
    db: Session,
    source_name: str,
    *,
    trigger_type: str = "manual",
    limit: int | None = None,
    force_baseline: bool = False,
    dispatch_reevaluation: bool = True,
) -> IntelCollectionRun:
    connector, mapper = _registered_pair(source_name)
    config = get_enrichment_source_config(db, source_name, create=True)
    assert config is not None
    if trigger_type == "scheduled" and not config.enabled:
        raise ValueError(f"enrichment source is disabled: {source_name}")
    fetch_kwargs: dict[str, Any] = {"limit": limit}
    if force_baseline:
        if source_name not in {"cve-list-v5", "redhat-csaf"}:
            raise ValueError(f"source does not support forced baseline: {source_name}")
        fetch_kwargs["force_baseline"] = True
    run = collect_enrichment_source(
        db,
        connector=connector,
        mapper=mapper,
        trigger_type=trigger_type,
        parameters={
            "limit": limit,
            "force_baseline": force_baseline,
        },
        **fetch_kwargs,
    )
    if dispatch_reevaluation:
        dispatch_enrichment_reevaluation(db, run)
    return run


def due_enrichment_source_names(
    db: Session,
    *,
    now: datetime | None = None,
) -> list[str]:
    current = now or utcnow()
    registered = set(enrichment_source_names())
    configs = db.scalars(
        select(IntelSourceConfig).where(
            IntelSourceConfig.enabled.is_(True),
            IntelSourceConfig.source_name.in_(registered),
        )
    ).all()
    due: list[str] = []
    for config in configs:
        active_run = db.scalar(
            select(IntelCollectionRun.id)
            .where(
                IntelCollectionRun.source_name == config.source_name,
                IntelCollectionRun.status.in_(ACTIVE_RUN_STATUSES),
            )
            .limit(1)
        )
        if active_run is not None:
            continue
        anchor = config.last_attempt_at or config.last_success_at
        comparable_current = current
        if anchor is not None and anchor.tzinfo is None:
            comparable_current = current.replace(tzinfo=None)
        if (
            anchor is None
            or anchor + timedelta(seconds=config.schedule_seconds) <= comparable_current
        ):
            due.append(config.source_name)
    return sorted(due)


def reserve_due_enrichment_sources(
    db: Session,
    *,
    now: datetime | None = None,
) -> list[str]:
    current = now or utcnow()
    source_names = due_enrichment_source_names(db, now=current)
    for source_name in source_names:
        config = db.scalar(
            select(IntelSourceConfig).where(IntelSourceConfig.source_name == source_name)
        )
        if config is not None:
            config.last_attempt_at = current
            db.add(config)
    db.commit()
    return source_names


def dispatch_enrichment_reevaluation(
    db: Session,
    run: IntelCollectionRun,
) -> str | None:
    completeness = dict(run.completeness_json or {})
    try:
        from app.workers.tasks import reevaluate_enrichment_run_task

        task = reevaluate_enrichment_run_task.delay(run.id)
        completeness["reevaluation"] = {
            "status": "queued",
            "task_id": task.id,
            "processed_count": 0,
            "failed_count": 0,
        }
        task_id = task.id
    except Exception as exc:
        completeness["reevaluation"] = {
            "status": "dispatch_failed",
            "error": str(exc)[:1000],
            "processed_count": 0,
            "failed_count": 0,
        }
        task_id = None
    run.completeness_json = completeness
    db.add(run)
    db.commit()
    return task_id


def pending_enrichment_reevaluation_runs(
    db: Session,
    *,
    limit: int = 100,
) -> list[IntelCollectionRun]:
    registered = set(enrichment_source_names())
    candidates = db.scalars(
        select(IntelCollectionRun)
        .where(
            IntelCollectionRun.source_name.in_(registered),
            IntelCollectionRun.status == "activated",
            IntelCollectionRun.generation_id.is_not(None),
        )
        .order_by(IntelCollectionRun.activated_at.desc())
        .limit(limit)
    ).all()
    pending = []
    for run in candidates:
        reevaluation = (run.completeness_json or {}).get("reevaluation")
        if not isinstance(reevaluation, dict) or reevaluation.get("status") == "dispatch_failed":
            pending.append(run)
    return pending


def reevaluate_enrichment_run(
    db: Session,
    run_id: str,
    *,
    after_vulnerability_id: str | None = None,
    batch_size: int = 100,
) -> ReevaluationBatchResult:
    run = db.get(IntelCollectionRun, run_id)
    if run is None or not run.generation_id:
        raise ValueError("enrichment collection run not found")
    statement = (
        select(VulnerabilitySourceContribution.vulnerability_id)
        .where(
            VulnerabilitySourceContribution.source_name == run.source_name,
            VulnerabilitySourceContribution.generation_id == run.generation_id,
        )
        .distinct()
        .order_by(VulnerabilitySourceContribution.vulnerability_id)
        .limit(batch_size + 1)
    )
    if after_vulnerability_id:
        statement = statement.where(
            VulnerabilitySourceContribution.vulnerability_id > after_vulnerability_id
        )
    vulnerability_ids = list(db.scalars(statement).all())
    has_more = len(vulnerability_ids) > batch_size
    current_batch = vulnerability_ids[:batch_size]
    processed = 0
    failed = 0
    for vulnerability_id in current_batch:
        try:
            evaluate_matches(
                db,
                vulnerability_id=vulnerability_id,
                raise_if_vulnerability_blocked=False,
                trigger_type="intel_enrichment",
            )
            processed += 1
        except Exception:
            db.rollback()
            failed += 1

    run = db.get(IntelCollectionRun, run_id)
    assert run is not None
    completeness = dict(run.completeness_json or {})
    previous = completeness.get("reevaluation")
    previous = previous if isinstance(previous, dict) else {}
    next_cursor = current_batch[-1] if has_more and current_batch else None
    final_status = (
        "queued"
        if next_cursor
        else "completed_with_errors" if failed else "completed"
    )
    completeness["reevaluation"] = {
        **previous,
        "status": final_status,
        "processed_count": int(previous.get("processed_count") or 0) + processed,
        "failed_count": int(previous.get("failed_count") or 0) + failed,
        "cursor": next_cursor,
    }
    run.completeness_json = completeness
    db.add(run)
    db.commit()
    return ReevaluationBatchResult(
        run_id=run_id,
        processed_count=processed,
        failed_count=failed,
        next_cursor=next_cursor,
    )


def _registered_pair(source_name: str):
    connectors = build_builtin_registry()
    mappers = build_builtin_mapper_registry()
    if source_name not in mappers.source_names():
        raise KeyError(f"unknown enrichment source: {source_name}")
    return connectors.get(source_name), mappers.get(source_name)
