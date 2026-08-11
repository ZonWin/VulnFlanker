from __future__ import annotations

import hashlib
import json
from typing import Any, Callable

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.connectors.base import CollectorPage, VulnerabilitySourceConnector
from app.db.base import utcnow
from app.db.models import (
    IntelCollectionRun,
    IntelRawEvent,
    IntelSourceConfig,
    VulnerabilityAffectedScope,
    VulnerabilitySourceContribution,
)
from app.services.intel_ingestion import compute_payload_hash
from app.services.intel_tracking import create_collection_run


class IncompleteGenerationError(RuntimeError):
    pass


def get_or_create_source_config(
    db: Session,
    *,
    source_name: str,
    update_mode: str = "snapshot",
    schedule_seconds: int = 86_400,
) -> IntelSourceConfig:
    config = db.scalar(
        select(IntelSourceConfig).where(IntelSourceConfig.source_name == source_name)
    )
    if config is None:
        config = IntelSourceConfig(
            source_name=source_name,
            update_mode=update_mode,
            schedule_seconds=schedule_seconds,
        )
        db.add(config)
        db.flush()
    return config


def begin_generation(
    db: Session,
    connector: VulnerabilitySourceConnector,
    *,
    trigger_type: str = "manual",
    parameters: dict[str, Any] | None = None,
) -> IntelCollectionRun:
    metadata = connector.metadata
    config = get_or_create_source_config(
        db,
        source_name=metadata.source_name,
        update_mode=metadata.update_mode.value,
        schedule_seconds=metadata.default_schedule_seconds,
    )
    run = create_collection_run(
        db,
        source_name=metadata.source_name,
        trigger_type=trigger_type,
        status="staging",
        parameters=parameters,
    )
    run.generation_id = run.id
    run.update_mode = metadata.update_mode.value
    run.cursor_before_json = dict(config.cursor_json or {})
    run.parser_version = metadata.parser_version
    run.completeness_json = {"complete": False, "terminal_page_seen": False}
    config.last_attempt_at = utcnow()
    config.last_error = None
    db.add_all((run, config))
    db.flush()
    return run


def stage_collector_page(
    db: Session,
    run: IntelCollectionRun,
    page: CollectorPage,
) -> tuple[int, int]:
    if run.status != "staging" or not run.generation_id:
        raise ValueError("collection run is not an open staging generation")

    stored = 0
    for record in page.records:
        if record.source_name != run.source_name:
            raise ValueError("collector page contains a record from another source")
        payload_hash = compute_payload_hash(record.payload)
        existing = db.scalar(
            select(IntelRawEvent).where(
                IntelRawEvent.provider == run.source_name,
                IntelRawEvent.generation_id == run.generation_id,
                IntelRawEvent.external_key == record.external_id,
                IntelRawEvent.payload_hash == payload_hash,
            )
        )
        if existing is not None:
            continue
        db.add(
            IntelRawEvent(
                provider=record.source_name,
                event_type=record.event_type,
                external_key=record.external_id,
                source_url=record.source_url,
                payload=record.payload,
                payload_hash=payload_hash,
                processing_status="staged",
                received_at=record.fetched_at,
                generation_id=run.generation_id,
                page_key=page.page_key,
                artifact_uri=page.artifact_uri,
                artifact_hash=page.artifact_hash,
            )
        )
        stored += 1

    run.fetched_count += len(page.records)
    run.stored_count += stored
    if page.artifact_uri:
        run.artifacts_count += 1
    if page.next_cursor is not None:
        run.cursor_after_json = dict(page.next_cursor)
    completeness = dict(run.completeness_json or {})
    completeness.update(page.metadata)
    completeness["terminal_page_seen"] = bool(page.complete)
    completeness["complete"] = bool(page.complete)
    completeness["last_page_key"] = page.page_key
    run.completeness_json = completeness
    db.add(run)
    db.flush()
    return len(page.records), stored


def mark_generation_ready(db: Session, run: IntelCollectionRun) -> IntelCollectionRun:
    completeness = run.completeness_json or {}
    if not completeness.get("complete") or not completeness.get("terminal_page_seen"):
        raise IncompleteGenerationError(
            "collector did not emit a complete terminal page; active data is unchanged"
        )
    run.status = "ready"
    db.add(run)
    db.flush()
    return run


def upsert_source_contribution(
    db: Session,
    *,
    run: IntelCollectionRun,
    vulnerability_id: str,
    external_key: str,
    contribution: dict[str, Any],
    provenance: dict[str, Any] | None = None,
    raw_event_id: str | None = None,
) -> VulnerabilitySourceContribution:
    if run.status not in {"staging", "ready"} or not run.generation_id:
        raise ValueError("contributions can only be written to a staged generation")
    row = db.scalar(
        select(VulnerabilitySourceContribution).where(
            VulnerabilitySourceContribution.vulnerability_id == vulnerability_id,
            VulnerabilitySourceContribution.source_name == run.source_name,
            VulnerabilitySourceContribution.generation_id == run.generation_id,
            VulnerabilitySourceContribution.external_key == external_key,
        )
    )
    fingerprint = compute_fact_fingerprint(contribution)
    if row is None:
        row = VulnerabilitySourceContribution(
            vulnerability_id=vulnerability_id,
            source_name=run.source_name,
            generation_id=run.generation_id,
            external_key=external_key,
            raw_event_id=raw_event_id,
            contribution_json=contribution,
            provenance_json=provenance or {},
            fact_fingerprint=fingerprint,
            is_active=False,
        )
    else:
        row.raw_event_id = raw_event_id or row.raw_event_id
        row.contribution_json = contribution
        row.provenance_json = provenance or {}
        row.fact_fingerprint = fingerprint
    db.add(row)
    db.flush()
    return row


def activate_generation(db: Session, run: IntelCollectionRun) -> IntelCollectionRun:
    if run.status != "ready" or not run.generation_id:
        raise ValueError("only a ready generation can be activated")
    config = db.scalar(
        select(IntelSourceConfig).where(IntelSourceConfig.source_name == run.source_name)
    )
    if config is None:
        raise ValueError(f"source config not found: {run.source_name}")

    previous_generation_id = config.active_generation_id
    now = utcnow()

    # The caller controls the outer commit. A nested transaction ensures that
    # all active flags and the source pointer switch together.
    with db.begin_nested():
        db.execute(
            update(VulnerabilitySourceContribution)
            .where(
                VulnerabilitySourceContribution.source_name == run.source_name,
                VulnerabilitySourceContribution.is_active.is_(True),
            )
            .values(is_active=False)
        )
        db.execute(
            update(VulnerabilitySourceContribution)
            .where(
                VulnerabilitySourceContribution.source_name == run.source_name,
                VulnerabilitySourceContribution.generation_id == run.generation_id,
            )
            .values(is_active=True)
        )
        db.execute(
            update(VulnerabilityAffectedScope)
            .where(
                VulnerabilityAffectedScope.source_name == run.source_name,
                VulnerabilityAffectedScope.is_active.is_(True),
            )
            .values(is_active=False)
        )
        db.execute(
            update(VulnerabilityAffectedScope)
            .where(
                VulnerabilityAffectedScope.source_name == run.source_name,
                VulnerabilityAffectedScope.generation_id == run.generation_id,
            )
            .values(is_active=True)
        )
        if previous_generation_id and previous_generation_id != run.generation_id:
            previous_run = db.scalar(
                select(IntelCollectionRun).where(
                    IntelCollectionRun.source_name == run.source_name,
                    IntelCollectionRun.generation_id == previous_generation_id,
                )
            )
            if previous_run is not None and previous_run.status == "activated":
                previous_run.status = "superseded"
                db.add(previous_run)

        run.status = "activated"
        run.activated_at = now
        run.finished_at = now
        config.active_generation_id = run.generation_id
        config.cursor_json = dict(run.cursor_after_json or run.cursor_before_json or {})
        config.last_success_at = now
        config.last_error = None
        db.add_all((run, config))
        db.flush()
    return run


def fail_generation(
    db: Session,
    run: IntelCollectionRun,
    error: Exception | str,
    *,
    error_code: str = "collection_failed",
) -> IntelCollectionRun:
    message = str(error)[:4000]
    run.status = "failed"
    run.finished_at = utcnow()
    run.failed_count = max(1, run.failed_count)
    run.error_code = error_code
    run.error_message = message
    config = db.scalar(
        select(IntelSourceConfig).where(IntelSourceConfig.source_name == run.source_name)
    )
    if config is not None:
        config.last_error = message
        db.add(config)
    db.add(run)
    db.flush()
    return run


def collect_generation(
    db: Session,
    connector: VulnerabilitySourceConnector,
    *,
    trigger_type: str = "manual",
    parameters: dict[str, Any] | None = None,
    normalize_page: Callable[[Session, IntelCollectionRun, CollectorPage], None] | None = None,
    **fetch_kwargs: Any,
) -> IntelCollectionRun:
    """Run one collector generation while preserving the last active data on failure."""
    run = begin_generation(
        db,
        connector,
        trigger_type=trigger_type,
        parameters=parameters,
    )
    db.commit()
    try:
        for page in connector.fetch_pages(**fetch_kwargs):
            stage_collector_page(db, run, page)
            if normalize_page is not None:
                normalize_page(db, run, page)
            db.commit()
        mark_generation_ready(db, run)
        activate_generation(db, run)
        db.commit()
        return run
    except Exception as exc:
        db.rollback()
        run = db.get(IntelCollectionRun, run.id)
        if run is not None:
            fail_generation(db, run, exc)
            db.commit()
        raise


def compute_fact_fingerprint(document: Any) -> str:
    serialized = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
