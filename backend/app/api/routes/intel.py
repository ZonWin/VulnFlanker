from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.api.deps import require_current_user
from app.core.config import get_settings
from app.db.models import IntelRawEvent, User
from app.schemas.intel import (
    CisaKevMonitorConfigOut,
    CisaKevMonitorConfigUpdate,
    IntelCollectionRunOut,
    IntelCollectionResult,
    IntelCollectRequest,
    IntelEnrichmentCollectRequest,
    IntelEnrichmentSourceConfigUpdate,
    IntelSourceVulnerabilityCleanupRequest,
    IntelSourceVulnerabilityCleanupResult,
    IntelRawEventNormalizeResult,
    IntelRawEventOut,
    IntelSourceStatusOut,
    IntelWebhookAccepted,
    WatchVulnMonitorConfigOut,
    WatchVulnMonitorConfigUpdate,
    WatchVulnWebhookEnvelope,
)
from app.services.cisa_kev_monitor import (
    get_cisa_kev_monitor_status,
    update_cisa_kev_monitor_config,
)
from app.services.intel_ingestion import (
    IngestionStats,
    collect_aliyun_avd,
    collect_cisa_kev,
    ingest_watchvuln_webhook,
)
from app.services.intel_normalization import normalize_raw_event
from app.services.intel_enrichment_orchestration import (
    collect_registered_enrichment_source,
    enrichment_source_names,
    update_enrichment_source_config,
)
from app.services.intel_cleanup import clear_source_vulnerabilities
from app.services.intel_tracking import (
    complete_collection_run,
    create_collection_run,
    get_collection_run,
    get_raw_event,
    list_collection_runs,
    list_raw_events,
    list_source_statuses,
)
from app.services.audit import create_audit_log
from app.services.auth import user_audit_details
from app.services.watchvuln_builtin import collect_watchvuln_builtin
from app.services.watchvuln_monitor import (
    get_watchvuln_monitor_status,
    update_watchvuln_monitor_config,
)
from app.workers.tasks import (
    collect_enrichment_source_task,
    collect_vulnerability_source,
    process_watchvuln_raw_event,
)

router = APIRouter()
CONSOLE_AUTH = [Depends(require_current_user)]


@router.post(
    "/cisa-kev/collect",
    response_model=IntelCollectionResult,
    dependencies=CONSOLE_AUTH,
)
async def collect_cisa_kev_endpoint(
    request: IntelCollectRequest,
    db: Session = Depends(get_db),
) -> IntelCollectionResult:
    return _collect_manual_source("cisa-kev", request, db)


@router.get(
    "/cisa-kev/monitor",
    response_model=CisaKevMonitorConfigOut,
    dependencies=CONSOLE_AUTH,
)
async def get_cisa_kev_monitor_endpoint(
    db: Session = Depends(get_db),
) -> CisaKevMonitorConfigOut:
    return get_cisa_kev_monitor_status(db)


@router.patch(
    "/cisa-kev/monitor",
    response_model=CisaKevMonitorConfigOut,
    dependencies=CONSOLE_AUTH,
)
async def update_cisa_kev_monitor_endpoint(
    request: CisaKevMonitorConfigUpdate,
    db: Session = Depends(get_db),
) -> CisaKevMonitorConfigOut:
    return update_cisa_kev_monitor_config(db, request)


@router.post(
    "/aliyun-avd/collect",
    response_model=IntelCollectionResult,
    dependencies=CONSOLE_AUTH,
)
async def collect_aliyun_avd_endpoint(
    request: IntelCollectRequest,
    db: Session = Depends(get_db),
) -> IntelCollectionResult:
    return _collect_manual_source("aliyun-avd", request, db)


@router.post(
    "/watchvuln/collect",
    response_model=IntelCollectionResult,
    dependencies=CONSOLE_AUTH,
)
async def collect_watchvuln_endpoint(
    request: IntelCollectRequest,
    db: Session = Depends(get_db),
) -> IntelCollectionResult:
    return _collect_manual_source("watchvuln", request, db)


@router.get(
    "/watchvuln/monitor",
    response_model=WatchVulnMonitorConfigOut,
    dependencies=CONSOLE_AUTH,
)
async def get_watchvuln_monitor_endpoint(
    db: Session = Depends(get_db),
) -> WatchVulnMonitorConfigOut:
    return get_watchvuln_monitor_status(db)


@router.patch(
    "/watchvuln/monitor",
    response_model=WatchVulnMonitorConfigOut,
    dependencies=CONSOLE_AUTH,
)
async def update_watchvuln_monitor_endpoint(
    request: WatchVulnMonitorConfigUpdate,
    db: Session = Depends(get_db),
) -> WatchVulnMonitorConfigOut:
    return update_watchvuln_monitor_config(db, request)


def _collect_manual_source(
    source_name: str,
    request: IntelCollectRequest,
    db: Session,
) -> IntelCollectionResult:
    collectors: dict[str, Callable[..., IngestionStats]] = {
        "cisa-kev": collect_cisa_kev,
        "aliyun-avd": collect_aliyun_avd,
        "watchvuln": collect_watchvuln_builtin,
    }
    source_labels = {
        "cisa-kev": "CISA KEV",
        "aliyun-avd": "阿里云漏洞库",
        "watchvuln": "WatchVuln",
    }
    collector = collectors[source_name]
    source_label = source_labels[source_name]
    collect_kwargs = _collect_kwargs(source_name, request)
    normalized_limit = None if request.limit == 0 else request.limit
    latest_only = request.latest_only and not (
        source_name == "cisa-kev" and request.limit == 0
    )
    parameters = {
        "limit": normalized_limit,
        "async_mode": request.async_mode,
        **({"latest_only": latest_only} if source_name == "cisa-kev" else {}),
        **({"min_score": request.min_score} if source_name == "aliyun-avd" else {}),
        **({"mode": "builtin"} if source_name == "watchvuln" else {}),
    }

    fallback_run_id: str | None = None
    if request.async_mode:
        try:
            run = create_collection_run(
                db,
                source_name=source_name,
                trigger_type="manual",
                status="queued",
                parameters=parameters,
            )
            db.commit()
            task = collect_vulnerability_source.delay(
                source_name,
                request.limit,
                run.id,
                request.min_score if source_name == "aliyun-avd" else None,
                latest_only if source_name == "cisa-kev" else False,
            )
            run.task_id = task.id
            db.add(run)
            db.commit()
            return IntelCollectionResult(
                status="queued",
                source_name=source_name,
                run_id=run.id,
                task_id=task.id,
                message=_queued_message(source_name, source_label),
            )
        except Exception:
            fallback_run_id = run.id if "run" in locals() else None
            pass

    sync_run_id = fallback_run_id
    if sync_run_id is None:
        run = create_collection_run(
            db,
            source_name=source_name,
            trigger_type="manual",
            parameters=parameters,
        )
        db.commit()
        sync_run_id = run.id

    try:
        stats = collector(db, run_id=sync_run_id, **collect_kwargs)
    except Exception as exc:
        run_out = get_collection_run(db, sync_run_id)
        return IntelCollectionResult(
            status=run_out.status if run_out else "failed",
            source_name=source_name,
            run_id=sync_run_id,
            fetched_count=run_out.fetched_count if run_out else 0,
            stored_count=run_out.stored_count if run_out else 0,
            processed_count=run_out.processed_count if run_out else 0,
            skipped_count=run_out.skipped_count if run_out else 0,
            failed_count=run_out.failed_count if run_out else 1,
            error_message=(run_out.error_message if run_out else None) or str(exc),
            message=_failed_message(source_name, source_label),
        )
    return IntelCollectionResult(
        status=stats.status,
        source_name=stats.source_name,
        run_id=stats.run_id,
        fetched_count=stats.fetched_count,
        stored_count=stats.stored_count,
        processed_count=stats.processed_count,
        skipped_count=stats.skipped_count,
        failed_count=stats.failed_count,
        error_message=stats.error_message,
        message=_completed_message(source_name, source_label),
    )


def _collect_kwargs(source_name: str, request: IntelCollectRequest) -> dict[str, int | float | bool | None]:
    if source_name == "watchvuln":
        return {"limit": None if request.limit == 0 else request.limit}
    kwargs: dict[str, int | float | bool | None] = {
        "limit": None if request.limit == 0 else request.limit
    }
    if source_name == "cisa-kev":
        kwargs["latest_only"] = request.latest_only and request.limit != 0
    if source_name == "aliyun-avd":
        kwargs["min_score"] = request.min_score
    return kwargs


def _queued_message(source_name: str, source_label: str) -> str:
    if source_name == "watchvuln":
        return "内置 WatchVuln 采集任务已提交到 Celery。"
    return f"{source_label} 采集任务已提交到 Celery。"


def _completed_message(source_name: str, source_label: str) -> str:
    if source_name == "watchvuln":
        return "内置 WatchVuln 采集和归一化已完成。"
    return f"{source_label} 采集和归一化已完成。"


def _failed_message(source_name: str, source_label: str) -> str:
    if source_name == "watchvuln":
        return "内置 WatchVuln 采集失败。"
    return f"{source_label} 采集失败。"


@router.get(
    "/sources",
    response_model=list[IntelSourceStatusOut],
    dependencies=CONSOLE_AUTH,
)
async def get_intel_sources(
    db: Session = Depends(get_db),
) -> list[IntelSourceStatusOut]:
    return list_source_statuses(db)


@router.get(
    "/sources/{source_name}",
    response_model=IntelSourceStatusOut,
    dependencies=CONSOLE_AUTH,
)
async def get_intel_source(
    source_name: str,
    db: Session = Depends(get_db),
) -> IntelSourceStatusOut:
    return _get_source_status(db, source_name)


@router.patch(
    "/sources/{source_name}",
    response_model=IntelSourceStatusOut,
    dependencies=CONSOLE_AUTH,
)
async def update_intel_enrichment_source(
    source_name: str,
    payload: IntelEnrichmentSourceConfigUpdate,
    db: Session = Depends(get_db),
) -> IntelSourceStatusOut:
    if source_name not in enrichment_source_names():
        raise HTTPException(status_code=404, detail="Enrichment source not found")
    try:
        update_enrichment_source_config(
            db,
            source_name,
            **payload.model_dump(exclude_none=True),
        )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _get_source_status(db, source_name)


@router.post(
    "/sources/{source_name}/collect",
    response_model=IntelCollectionResult,
    dependencies=CONSOLE_AUTH,
)
async def collect_intel_enrichment_source(
    source_name: str,
    payload: IntelEnrichmentCollectRequest,
    db: Session = Depends(get_db),
) -> IntelCollectionResult:
    if source_name not in enrichment_source_names():
        raise HTTPException(status_code=404, detail="Enrichment source not found")
    if payload.limit is not None:
        raise HTTPException(
            status_code=400,
            detail=(
                "Enrichment collection must run without a record limit so the "
                "snapshot or incremental window can be activated atomically"
            ),
        )
    if payload.force_baseline and source_name not in {"cve-list-v5", "redhat-csaf"}:
        raise HTTPException(status_code=400, detail="Source does not support forced baseline")
    if payload.async_mode:
        try:
            task = collect_enrichment_source_task.delay(
                source_name,
                "manual",
                payload.limit,
                payload.force_baseline,
            )
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail=f"Failed to queue enrichment collection: {exc}",
            ) from exc
        return IntelCollectionResult(
            status="queued",
            source_name=source_name,
            task_id=task.id,
            message="Enrichment collection task queued.",
        )
    try:
        run = collect_registered_enrichment_source(
            db,
            source_name,
            trigger_type="manual",
            limit=payload.limit,
            force_baseline=payload.force_baseline,
            dispatch_reevaluation=True,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return IntelCollectionResult(
        status=run.status,
        source_name=run.source_name,
        run_id=run.id,
        fetched_count=run.fetched_count,
        stored_count=run.stored_count,
        processed_count=run.processed_count,
        skipped_count=run.skipped_count,
        failed_count=run.failed_count,
        error_message=run.error_message,
        message="Enrichment collection completed.",
    )


def _get_source_status(db: Session, source_name: str) -> IntelSourceStatusOut:
    status_by_name = {item.source_name: item for item in list_source_statuses(db)}
    source_status = status_by_name.get(source_name)
    if source_status is None:
        raise HTTPException(status_code=404, detail="Intel source not found")
    return source_status


@router.delete(
    "/sources/{source_name}/vulnerabilities",
    response_model=IntelSourceVulnerabilityCleanupResult,
    dependencies=CONSOLE_AUTH,
)
async def clear_intel_source_vulnerabilities(
    source_name: str,
    payload: IntelSourceVulnerabilityCleanupRequest,
    current_user: User = Depends(require_current_user),
    db: Session = Depends(get_db),
) -> IntelSourceVulnerabilityCleanupResult:
    if not payload.confirmed:
        raise HTTPException(status_code=400, detail="Cleanup confirmation is required")
    source_statuses = {item.source_name: item for item in list_source_statuses(db)}
    source_status = source_statuses.get(source_name)
    if source_status is None:
        raise HTTPException(status_code=404, detail="Intel source not found")

    try:
        stats = clear_source_vulnerabilities(db, source_name=source_name)
        create_audit_log(
            db,
            action="clear_source_vulnerabilities",
            resource_type="intel_source",
            resource_id=source_name,
            summary=f"Cleared vulnerabilities collected by {source_status.source_label or source_name}",
            actor_type="user",
            actor_id=current_user.id,
            details={
                **user_audit_details(current_user),
                "source_name": source_name,
                "source_label": source_status.source_label,
                **stats.__dict__,
            },
        )
        db.commit()
    except Exception:
        db.rollback()
        raise

    return IntelSourceVulnerabilityCleanupResult(
        source_name=source_name,
        source_label=source_status.source_label,
        **stats.__dict__,
    )


@router.get(
    "/runs",
    response_model=list[IntelCollectionRunOut],
    dependencies=CONSOLE_AUTH,
)
async def get_intel_runs(
    source_name: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[IntelCollectionRunOut]:
    return list_collection_runs(
        db,
        source_name=source_name,
        status=status,
        limit=limit,
    )


@router.get(
    "/runs/{run_id}",
    response_model=IntelCollectionRunOut,
    dependencies=CONSOLE_AUTH,
)
async def get_intel_run(
    run_id: str,
    db: Session = Depends(get_db),
) -> IntelCollectionRunOut:
    run = get_collection_run(db, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Intel collection run not found")
    return run


@router.get(
    "/raw-events",
    response_model=list[IntelRawEventOut],
    dependencies=CONSOLE_AUTH,
)
async def get_intel_raw_events(
    provider: str | None = Query(default=None),
    processing_status: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[IntelRawEventOut]:
    return list_raw_events(
        db,
        provider=provider,
        processing_status=processing_status,
        limit=limit,
    )


@router.get(
    "/raw-events/{raw_event_id}",
    response_model=IntelRawEventOut,
    dependencies=CONSOLE_AUTH,
)
async def get_intel_raw_event(
    raw_event_id: str,
    db: Session = Depends(get_db),
) -> IntelRawEventOut:
    raw_event = get_raw_event(db, raw_event_id)
    if raw_event is None:
        raise HTTPException(status_code=404, detail="Intel raw event not found")
    return raw_event


@router.post(
    "/raw-events/{raw_event_id}/normalize",
    response_model=IntelRawEventNormalizeResult,
    dependencies=CONSOLE_AUTH,
)
async def normalize_intel_raw_event(
    raw_event_id: str,
    db: Session = Depends(get_db),
) -> IntelRawEventNormalizeResult:
    try:
        result = normalize_raw_event(db, raw_event_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Normalization failed: {exc}",
        ) from exc
    return IntelRawEventNormalizeResult(
        raw_event_id=result.raw_event_id,
        status=result.status,
        vulnerability_id=result.vulnerability_id,
        canonical_id=result.canonical_id,
    )


@router.post(
    "/watchvuln/webhook",
    response_model=IntelWebhookAccepted,
    status_code=status.HTTP_202_ACCEPTED,
)
async def receive_watchvuln_webhook(
    request: Request,
    db: Session = Depends(get_db),
    x_vulnflanker_token: Annotated[
        str | None,
        Header(alias="X-VulnFlanker-Token"),
    ] = None,
    token: str | None = Query(default=None),
) -> IntelWebhookAccepted:
    settings = get_settings()
    provided_token = x_vulnflanker_token or token
    if settings.intel_webhook_token and provided_token != settings.intel_webhook_token:
        raise HTTPException(status_code=401, detail="Invalid webhook token")

    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > settings.intel_webhook_max_body_bytes:
        raise HTTPException(status_code=413, detail="Webhook payload too large")

    try:
        body = await request.json()
        envelope = WatchVulnWebhookEnvelope.model_validate(body)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from exc

    raw_event, created = ingest_watchvuln_webhook(db, envelope)
    run = create_collection_run(
        db,
        source_name="watchvuln",
        trigger_type="webhook",
        parameters={
            "event_type": envelope.type,
            "raw_event_id": raw_event.id,
            "deduplicated": not created,
        },
    )
    queued = False
    if created or raw_event.processing_status == "pending":
        queued = _queue_or_process_raw_event(db, raw_event.id, run.id)
        latest_raw_event = db.get(IntelRawEvent, raw_event.id)
        if latest_raw_event is not None:
            raw_event = latest_raw_event
    complete_collection_run(
        db,
        run,
        fetched_count=1,
        stored_count=1 if created else 0,
        processed_count=1 if raw_event.processing_status == "processed" else 0,
        skipped_count=1 if raw_event.processing_status == "skipped" else 0,
        failed_count=1 if raw_event.processing_status == "failed" else 0,
        status="queued" if queued else "completed",
        error_message=raw_event.last_error,
    )
    db.commit()

    return IntelWebhookAccepted(
        raw_event_id=raw_event.id,
        provider=raw_event.provider,
        event_type=raw_event.event_type,
        processing_status=raw_event.processing_status,
        run_id=run.id,
        deduplicated=not created,
        queued=queued,
    )


def _queue_or_process_raw_event(
    db: Session,
    raw_event_id: str,
    run_id: str | None = None,
) -> bool:
    try:
        process_watchvuln_raw_event.delay(raw_event_id, run_id)
        return True
    except Exception:
        normalize_raw_event(db, raw_event_id)
        return False
