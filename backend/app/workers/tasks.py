from sqlalchemy import select

from app.db.models import IntelCollectionRun, IntelSourceConfig
from app.db.session import SessionLocal
from app.services.cisa_kev_monitor import (
    get_cisa_kev_monitor_config,
    should_run_cisa_kev_monitor,
)
from app.services.intel_ingestion import collect_aliyun_avd, collect_cisa_kev
from app.services.intel_enrichment_orchestration import (
    collect_registered_enrichment_source,
    dispatch_enrichment_reevaluation,
    pending_enrichment_reevaluation_runs,
    reevaluate_enrichment_run,
    reserve_due_enrichment_sources,
)
from app.services.intel_normalization import normalize_raw_event
from app.services.intel_tracking import complete_collection_run, fail_collection_run
from app.services.email_alerts import (
    due_email_delivery_ids,
    recover_stale_email_deliveries,
    send_email_delivery,
)
from app.services.notifications import cleanup_expired_notifications
from app.services.vulnerability_ai_enrichment import (
    BASIC_EXTRACTION_PROFILE_KEY,
    EXISTING_DATA_LAYER,
    WEB_ENRICHMENT_LAYER,
    WEB_ENRICHMENT_PROFILE_KEY,
    AUTO_LAYER,
    enrich_vulnerability_auto,
    enrich_vulnerability_from_existing_data,
    enrich_vulnerability_with_web_search,
    run_vulnerability_ai_enrichment_batch,
)
from app.services.verification_orchestrator import run_local_verification_task
from app.services.watchvuln_builtin import collect_watchvuln_builtin
from app.services.watchvuln_monitor import (
    get_watchvuln_monitor_config,
    should_run_watchvuln_monitor,
)
from app.workers.celery_app import celery_app


@celery_app.task(name="vulnflanker.send_email_delivery")
def send_email_delivery_task(delivery_id: str) -> dict[str, str | int | None]:
    with SessionLocal() as db:
        delivery = send_email_delivery(db, delivery_id)
        if delivery is None:
            return {"status": "not_found", "delivery_id": delivery_id}
        return {
            "status": delivery.status,
            "delivery_id": delivery.id,
            "attempt_count": delivery.attempt_count,
            "next_attempt_at": (
                delivery.next_attempt_at.isoformat() if delivery.next_attempt_at else None
            ),
        }


@celery_app.task(name="vulnflanker.dispatch_due_email_deliveries")
def dispatch_due_email_deliveries() -> dict[str, int]:
    with SessionLocal() as db:
        recovered_count = recover_stale_email_deliveries(db)
        delivery_ids = due_email_delivery_ids(db, limit=100)
        processed_count = 0
        for delivery_id in delivery_ids:
            if send_email_delivery(db, delivery_id) is not None:
                processed_count += 1
        return {
            "queued_count": len(delivery_ids),
            "processed_count": processed_count,
            "recovered_count": recovered_count,
        }


@celery_app.task(name="vulnflanker.cleanup_expired_notifications")
def cleanup_expired_notifications_task() -> dict[str, int]:
    with SessionLocal() as db:
        return {"deleted_count": cleanup_expired_notifications(db)}


@celery_app.task(name="vulnflanker.collect_vulnerability_source")
def collect_vulnerability_source(
    source_name: str,
    limit: int | None = None,
    run_id: str | None = None,
    min_score: float | None = None,
    latest_only: bool = False,
) -> dict[str, str | int]:
    if source_name == "cisa-kev":
        collector = collect_cisa_kev
        collect_kwargs = {"limit": limit, "run_id": run_id, "latest_only": latest_only}
    elif source_name == "aliyun-avd":
        collector = collect_aliyun_avd
        collect_kwargs = {"limit": limit, "run_id": run_id, "min_score": min_score}
    elif source_name == "watchvuln":
        collector = collect_watchvuln_builtin
        collect_kwargs = {"limit": limit, "run_id": run_id}
    else:
        return {
            "status": "unsupported",
            "source_name": source_name,
            "message": "当前仅支持 cisa-kev、aliyun-avd 与 watchvuln 漏洞源采集。",
        }

    with SessionLocal() as db:
        stats = collector(db, **collect_kwargs)
        return {
            "status": "completed",
            "source_name": stats.source_name,
            "run_id": stats.run_id or "",
            "fetched_count": stats.fetched_count,
            "stored_count": stats.stored_count,
            "processed_count": stats.processed_count,
            "skipped_count": stats.skipped_count,
            "failed_count": stats.failed_count,
        }


@celery_app.task(name="vulnflanker.collect_enrichment_source")
def collect_enrichment_source_task(
    source_name: str,
    trigger_type: str = "manual",
    limit: int | None = None,
    force_baseline: bool = False,
) -> dict[str, str | int | None]:
    with SessionLocal() as db:
        run = collect_registered_enrichment_source(
            db,
            source_name,
            trigger_type=trigger_type,
            limit=limit,
            force_baseline=force_baseline,
            dispatch_reevaluation=True,
        )
        reevaluation = (run.completeness_json or {}).get("reevaluation") or {}
        return {
            "status": run.status,
            "source_name": run.source_name,
            "run_id": run.id,
            "fetched_count": run.fetched_count,
            "stored_count": run.stored_count,
            "processed_count": run.processed_count,
            "failed_count": run.failed_count,
            "reevaluation_task_id": reevaluation.get("task_id"),
        }


@celery_app.task(name="vulnflanker.dispatch_due_enrichment_sources")
def dispatch_due_enrichment_sources() -> dict[str, object]:
    queued: list[str] = []
    failed: dict[str, str] = {}
    with SessionLocal() as db:
        source_names = reserve_due_enrichment_sources(db)
        for source_name in source_names:
            try:
                collect_enrichment_source_task.delay(
                    source_name,
                    "scheduled",
                    None,
                    False,
                )
                queued.append(source_name)
            except Exception as exc:
                failed[source_name] = str(exc)[:1000]
                config = db.scalar(
                    select(IntelSourceConfig).where(
                        IntelSourceConfig.source_name == source_name
                    )
                )
                if config is not None:
                    config.last_error = failed[source_name]
                    db.add(config)
        db.commit()
    return {"status": "completed", "queued": queued, "failed": failed}


@celery_app.task(name="vulnflanker.dispatch_pending_enrichment_reevaluations")
def dispatch_pending_enrichment_reevaluations() -> dict[str, object]:
    queued: list[str] = []
    with SessionLocal() as db:
        runs = pending_enrichment_reevaluation_runs(db)
        for run in runs:
            if dispatch_enrichment_reevaluation(db, run):
                queued.append(run.id)
    return {"status": "completed", "queued_run_ids": queued}


@celery_app.task(name="vulnflanker.reevaluate_enrichment_run")
def reevaluate_enrichment_run_task(
    run_id: str,
    after_vulnerability_id: str | None = None,
) -> dict[str, str | int | None]:
    with SessionLocal() as db:
        result = reevaluate_enrichment_run(
            db,
            run_id,
            after_vulnerability_id=after_vulnerability_id,
        )
    if result.next_cursor:
        reevaluate_enrichment_run_task.delay(run_id, result.next_cursor)
    return {
        "status": "queued" if result.next_cursor else "completed",
        "run_id": run_id,
        "processed_count": result.processed_count,
        "failed_count": result.failed_count,
        "next_cursor": result.next_cursor,
    }

@celery_app.task(name="vulnflanker.collect_cisa_kev_monitor")
def collect_cisa_kev_monitor() -> dict[str, str | int]:
    with SessionLocal() as db:
        config = get_cisa_kev_monitor_config(db)
        if not config.enabled:
            return {
                "status": "disabled",
                "source_name": "cisa-kev",
                "message": "CISA KEV 定时采集未启用。",
            }
        if not should_run_cisa_kev_monitor(db, config=config):
            return {
                "status": "skipped",
                "source_name": "cisa-kev",
                "message": "CISA KEV 定时采集尚未到达下次执行时间。",
            }
        stats = collect_cisa_kev(
            db,
            limit=config.limit,
            latest_only=config.latest_only,
            trigger_type="scheduled",
        )
        return {
            "status": "completed",
            "source_name": stats.source_name,
            "run_id": stats.run_id or "",
            "fetched_count": stats.fetched_count,
            "stored_count": stats.stored_count,
            "processed_count": stats.processed_count,
            "skipped_count": stats.skipped_count,
            "failed_count": stats.failed_count,
        }


@celery_app.task(name="vulnflanker.collect_watchvuln_monitor")
def collect_watchvuln_monitor() -> dict[str, str | int]:
    with SessionLocal() as db:
        config = get_watchvuln_monitor_config(db)
        if not config.enabled:
            return {
                "status": "disabled",
                "source_name": "watchvuln",
                "message": "内置 WatchVuln 定时监测未启用。",
            }
        if not should_run_watchvuln_monitor(db, config=config):
            return {
                "status": "skipped",
                "source_name": "watchvuln",
                "message": "内置 WatchVuln 定时监测尚未到达下次执行时间。",
            }
        stats = collect_watchvuln_builtin(
            db,
            limit=config.limit,
            trigger_type="scheduled",
        )
        return {
            "status": "completed",
            "source_name": stats.source_name,
            "run_id": stats.run_id or "",
            "fetched_count": stats.fetched_count,
            "stored_count": stats.stored_count,
            "processed_count": stats.processed_count,
            "skipped_count": stats.skipped_count,
            "failed_count": stats.failed_count,
        }


@celery_app.task(name="vulnflanker.process_watchvuln_raw_event")
def process_watchvuln_raw_event(
    raw_event_id: str,
    run_id: str | None = None,
) -> dict[str, str | None]:
    with SessionLocal() as db:
        try:
            result = normalize_raw_event(db, raw_event_id)
        except Exception as exc:
            if run_id:
                run = db.get(IntelCollectionRun, run_id)
                if run is not None:
                    fail_collection_run(db, run, exc)
                    db.commit()
            raise
        if run_id:
            run = db.get(IntelCollectionRun, run_id)
            if run is not None:
                complete_collection_run(
                    db,
                    run,
                    fetched_count=1,
                    processed_count=1 if result.status == "processed" else 0,
                    skipped_count=1 if result.status == "skipped" else 0,
                    status="completed",
                )
                db.commit()
        return {
            "status": result.status,
            "raw_event_id": result.raw_event_id,
            "vulnerability_id": result.vulnerability_id,
            "canonical_id": result.canonical_id,
        }


@celery_app.task(name="vulnflanker.normalize_vulnerability_record")
def normalize_vulnerability_record(raw_event_id: str) -> dict[str, str | None]:
    return process_watchvuln_raw_event(raw_event_id)


@celery_app.task(name="vulnflanker.recompute_match_result")
def recompute_match_result(match_result_id: str) -> dict[str, str]:
    return {
        "status": "queued",
        "match_result_id": match_result_id,
        "message": "匹配重算任务骨架已预留。",
    }


@celery_app.task(name="vulnflanker.ai_enrich_vulnerability")
def ai_enrich_vulnerability(
    vulnerability_id: str,
    layer: str = EXISTING_DATA_LAYER,
    profile_key: str = BASIC_EXTRACTION_PROFILE_KEY,
    allow_web_enrichment: bool = False,
    force_refresh: bool = False,
) -> dict[str, str | float | None]:
    if layer not in {EXISTING_DATA_LAYER, WEB_ENRICHMENT_LAYER, AUTO_LAYER}:
        return {
            "status": "unsupported",
            "vulnerability_id": vulnerability_id,
            "message": "不支持的 AI 补全层级。",
        }
    with SessionLocal() as db:
        if layer == WEB_ENRICHMENT_LAYER:
            enrichment = enrich_vulnerability_with_web_search(
                db,
                vulnerability_id,
                profile_key=profile_key or WEB_ENRICHMENT_PROFILE_KEY,
                force_refresh=force_refresh,
            )
        elif layer == AUTO_LAYER:
            enrichment = enrich_vulnerability_auto(
                db,
                vulnerability_id,
                allow_web_enrichment=allow_web_enrichment,
                force_refresh=force_refresh,
            )
        else:
            enrichment = enrich_vulnerability_from_existing_data(
                db,
                vulnerability_id,
                profile_key=profile_key,
                force_refresh=force_refresh,
            )
        return {
            "status": enrichment.status,
            "vulnerability_id": enrichment.vulnerability_id,
            "enrichment_id": enrichment.id,
            "confidence": enrichment.confidence,
        }


@celery_app.task(name="vulnflanker.ai_enrich_missing_vulnerabilities")
def ai_enrich_missing_vulnerabilities(batch_run_id: str) -> dict[str, str | int | None]:
    with SessionLocal() as db:
        result = run_vulnerability_ai_enrichment_batch(db, batch_run_id)
        return {
            "status": result.status,
            "batch_run_id": result.batch_run_id,
            "selected_count": result.selected_count,
            "skipped_count": result.skipped_count,
            "message": result.message,
        }


@celery_app.task(name="vulnflanker.run_non_intrusive_verification")
def run_non_intrusive_verification(task_id: str) -> dict[str, str | int]:
    with SessionLocal() as db:
        result = run_local_verification_task(db, task_id)
        if result is None:
            return {
                "status": "not_found",
                "task_id": task_id,
                "message": "验证任务不存在。",
            }
        return {
            "status": str(result["status"]),
            "task_id": str(result["task_id"]),
            "evidence_count": int(result["evidence_count"]),
        }
