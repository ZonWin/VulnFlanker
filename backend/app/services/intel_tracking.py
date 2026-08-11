from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
import re
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session, selectinload

from app.core.config import get_settings
from app.db.base import utcnow
from app.db.models import (
    IntelCollectionRun,
    IntelRawEvent,
    IntelSourceConfig,
    Vulnerability,
    VulnerabilitySource,
)
from app.services.severity import normalize_severity_label
from app.services.vulnerability_product_identity import product_values_conflict
from app.services.vulnerability_review import is_reason_confirmed
from app.services.notifications import create_system_event
from app.schemas.intel import (
    IntelCollectionRunOut,
    IntelNormalizationQualityOut,
    IntelRawEventOut,
    IntelSourceStatusOut,
)


KNOWN_INTEL_SOURCES = ("cisa-kev", "watchvuln", "aliyun-avd")
SOURCE_LABELS = {
    "cisa-kev": "CISA KEV",
    "watchvuln": "WatchVuln",
    "aliyun-avd": "阿里云漏洞库",
    "cve-list-v5": "CVE List V5",
    "nvd": "NVD",
    "canonical-ubuntu": "Canonical Ubuntu Security",
    "debian-security-tracker": "Debian Security Tracker",
    "redhat-csaf": "Red Hat CSAF VEX",
}
WATCHVULN_SOURCE_LABELS = {
    "avd": "阿里云漏洞库",
    "chaitin": "长亭漏洞库",
    "oscs": "OSCS 开源安全情报预警",
    "ti": "奇安信威胁情报中心",
    "threatbook": "微步在线研究响应中心",
    "seebug": "Seebug 漏洞平台",
    "struts2": "Apache Struts2 Security Bulletins",
    "kev": "CISA KEV",
    "venustech": "启明星辰漏洞通告",
}


def create_collection_run(
    db: Session,
    *,
    source_name: str,
    trigger_type: str,
    status: str = "running",
    task_id: str | None = None,
    parameters: dict[str, Any] | None = None,
) -> IntelCollectionRun:
    now = utcnow()
    run = IntelCollectionRun(
        source_name=source_name,
        trigger_type=trigger_type,
        status=status,
        started_at=now,
        finished_at=now if status in {"completed", "failed"} else None,
        task_id=task_id,
        parameters_json=parameters or {},
    )
    db.add(run)
    db.flush()
    if run.status not in {"queued", "running"}:
        _record_collection_event(db, run)
    return run


def complete_collection_run(
    db: Session,
    run: IntelCollectionRun,
    *,
    fetched_count: int = 0,
    stored_count: int = 0,
    processed_count: int = 0,
    skipped_count: int = 0,
    failed_count: int = 0,
    status: str | None = None,
    error_message: str | None = None,
    task_id: str | None = None,
) -> IntelCollectionRun:
    run.status = status or ("failed" if failed_count else "completed")
    run.finished_at = None if run.status in {"queued", "running"} else utcnow()
    run.fetched_count = fetched_count
    run.stored_count = stored_count
    run.processed_count = processed_count
    run.skipped_count = skipped_count
    run.failed_count = failed_count
    run.error_message = error_message
    if task_id:
        run.task_id = task_id
    db.add(run)
    db.flush()
    if run.status not in {"queued", "running"}:
        _record_collection_event(db, run)
    return run


def fail_collection_run(
    db: Session,
    run: IntelCollectionRun,
    error: Exception | str,
) -> IntelCollectionRun:
    return complete_collection_run(
        db,
        run,
        failed_count=1,
        status="failed",
        error_message=str(error),
    )


def _record_collection_event(db: Session, run: IntelCollectionRun) -> None:
    failed = run.status == "failed"
    source_label = SOURCE_LABELS.get(run.source_name, run.source_name)
    status_label = "失败" if failed else "完成"
    create_system_event(
        db,
        event_key=f"intel.collection:{run.id}",
        category="intel",
        event_type=(
            "intel_collection_failed" if failed else "intel_collection_completed"
        ),
        level="error" if failed else "success",
        title=f"{source_label} 情报采集{status_label}",
        summary=(
            f"获取 {run.fetched_count} 条，存储 {run.stored_count} 条，"
            f"处理 {run.processed_count} 条，跳过 {run.skipped_count} 条，"
            f"失败 {run.failed_count} 条。"
        ),
        details={
            "run_id": run.id,
            "source_name": run.source_name,
            "source_label": source_label,
            "trigger_type": run.trigger_type,
            "status": run.status,
            "fetched_count": run.fetched_count,
            "stored_count": run.stored_count,
            "processed_count": run.processed_count,
            "skipped_count": run.skipped_count,
            "failed_count": run.failed_count,
            "error_message": run.error_message,
            "task_id": run.task_id,
        },
        target_type="intel_run",
        target_id=run.id,
        target_query={"run_id": run.id},
        occurred_at=run.finished_at,
    )


def list_collection_runs(
    db: Session,
    *,
    source_name: str | None = None,
    status: str | None = None,
    limit: int = 50,
) -> list[IntelCollectionRunOut]:
    statement = select(IntelCollectionRun).order_by(desc(IntelCollectionRun.started_at))
    if source_name:
        statement = statement.where(IntelCollectionRun.source_name == source_name)
    if status:
        statement = statement.where(IntelCollectionRun.status == status)
    statement = statement.limit(limit)
    return [_to_collection_run_out(run) for run in db.scalars(statement).all()]


def get_collection_run(db: Session, run_id: str) -> IntelCollectionRunOut | None:
    run = db.get(IntelCollectionRun, run_id)
    if run is None:
        return None
    return _to_collection_run_out(run)


def list_source_statuses(db: Session) -> list[IntelSourceStatusOut]:
    raw_counts = _raw_event_counts(db)
    vulnerability_counts = _vulnerability_counts(db)
    configs = {
        config.source_name: config
        for config in db.scalars(select(IntelSourceConfig)).all()
    }
    statuses = []
    for spec in _source_status_specs():
        source_name = spec["source_name"]
        config = configs.get(source_name)
        latest_run = db.scalar(
            select(IntelCollectionRun)
            .where(IntelCollectionRun.source_name == source_name)
            .order_by(desc(IntelCollectionRun.started_at))
        )
        counts = raw_counts[source_name]
        freshness_state, freshness_age = _freshness(config)
        schedule_seconds = (
            config.schedule_seconds if config is not None else spec.get("schedule_seconds")
        )
        statuses.append(
            IntelSourceStatusOut(
                source_name=source_name,
                source_label=spec.get("source_label"),
                parent_source_name=spec.get("parent_source_name"),
                enabled=(
                    config.enabled
                    if config is not None
                    else bool(spec.get("legacy_enabled"))
                ),
                last_run_id=latest_run.id if latest_run else None,
                last_status=latest_run.status if latest_run else None,
                last_started_at=latest_run.started_at if latest_run else None,
                last_finished_at=latest_run.finished_at if latest_run else None,
                last_error=(
                    (latest_run.error_message if latest_run else None)
                    or (config.last_error if config is not None else None)
                ),
                raw_event_count=counts["total"],
                processed_event_count=counts["processed"],
                failed_event_count=counts["failed"],
                vulnerability_count=vulnerability_counts[source_name],
                update_mode=(
                    config.update_mode if config is not None else spec.get("update_mode")
                ),
                schedule_seconds=schedule_seconds,
                stale_after_seconds=(
                    config.stale_after_seconds if config is not None else None
                ),
                expire_after_seconds=(
                    config.expire_after_seconds if config is not None else None
                ),
                parser_version=spec.get("parser_version"),
                supports_cursor=bool(spec.get("supports_cursor")),
                supports_deletions=bool(spec.get("supports_deletions")),
                active_generation_id=(
                    config.active_generation_id if config is not None else None
                ),
                last_success_at=(config.last_success_at if config is not None else None),
                last_attempt_at=(config.last_attempt_at if config is not None else None),
                next_run_at=_next_run_at(config, schedule_seconds),
                freshness_state=freshness_state,
                freshness_age_seconds=freshness_age,
            )
        )
    return statuses


def list_raw_events(
    db: Session,
    *,
    provider: str | None = None,
    processing_status: str | None = None,
    limit: int = 50,
) -> list[IntelRawEventOut]:
    statement = (
        select(IntelRawEvent)
        .options(
            selectinload(IntelRawEvent.vulnerability).selectinload(
                Vulnerability.sources
            ).selectinload(
                VulnerabilitySource.raw_event
            )
        )
        .order_by(desc(IntelRawEvent.received_at), desc(IntelRawEvent.created_at))
        .limit(limit)
    )
    if provider:
        statement = statement.where(IntelRawEvent.provider == provider)
    if processing_status:
        statement = statement.where(IntelRawEvent.processing_status == processing_status)
    return [_to_raw_event_out(raw_event) for raw_event in db.scalars(statement).all()]


def get_raw_event(db: Session, raw_event_id: str) -> IntelRawEventOut | None:
    raw_event = db.scalar(
        select(IntelRawEvent)
        .options(
            selectinload(IntelRawEvent.vulnerability).selectinload(
                Vulnerability.sources
            ).selectinload(
                VulnerabilitySource.raw_event
            )
        )
        .where(IntelRawEvent.id == raw_event_id)
    )
    if raw_event is None:
        return None
    return _to_raw_event_out(raw_event)


def quality_for_vulnerability(
    vulnerability: Vulnerability | None,
) -> IntelNormalizationQualityOut | None:
    return _quality_for_vulnerability(vulnerability)


def _raw_event_counts(db: Session) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = defaultdict(
        lambda: {"total": 0, "processed": 0, "failed": 0}
    )
    rows = db.execute(
        select(
            IntelRawEvent.provider,
            IntelRawEvent.processing_status,
            func.count(IntelRawEvent.id),
        ).group_by(IntelRawEvent.provider, IntelRawEvent.processing_status)
    )
    for provider, status, count in rows:
        counts[provider]["total"] += int(count)
        if status == "processed":
            counts[provider]["processed"] += int(count)
        if status == "failed":
            counts[provider]["failed"] += int(count)
    return counts


def _watchvuln_subsource_raw_counts(db: Session) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = defaultdict(
        lambda: {"total": 0, "processed": 0, "failed": 0}
    )
    raw_events = db.scalars(
        select(IntelRawEvent).where(IntelRawEvent.provider == "watchvuln")
    ).all()
    for raw_event in raw_events:
        source_name = _watchvuln_source_name_from_payload(raw_event.payload)
        if source_name is None:
            continue
        counts[source_name]["total"] += 1
        if raw_event.processing_status == "processed":
            counts[source_name]["processed"] += 1
        if raw_event.processing_status == "failed":
            counts[source_name]["failed"] += 1
    return counts


def _vulnerability_counts(db: Session) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    rows = db.execute(
        select(
            VulnerabilitySource.source_name,
            func.count(func.distinct(VulnerabilitySource.vulnerability_id)),
        ).group_by(VulnerabilitySource.source_name)
    )
    for source_name, count in rows:
        count_value = int(count)
        counts[source_name] = count_value
        if str(source_name).startswith("watchvuln:"):
            counts["watchvuln"] += count_value
    return counts


def _source_status_specs() -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = [
        {
            "source_name": source_name,
            "source_label": SOURCE_LABELS[source_name],
            "parent_source_name": None,
            "legacy_enabled": True,
        }
        for source_name in KNOWN_INTEL_SOURCES
    ]
    from app.connectors.registry import build_builtin_registry
    from app.services.intel_source_collection import build_builtin_mapper_registry

    collectors = build_builtin_registry()
    mapper_names = set(build_builtin_mapper_registry().source_names())
    for source_name in sorted(mapper_names):
        metadata = collectors.get(source_name).metadata
        specs.append(
            {
                "source_name": source_name,
                "source_label": metadata.display_name,
                "parent_source_name": None,
                "legacy_enabled": False,
                "update_mode": metadata.update_mode.value,
                "schedule_seconds": metadata.default_schedule_seconds,
                "parser_version": metadata.parser_version,
                "supports_cursor": metadata.supports_cursor,
                "supports_deletions": metadata.supports_deletions,
            }
        )
    return specs


def _freshness(config: IntelSourceConfig | None) -> tuple[str | None, int | None]:
    if config is None:
        return "never_collected", None
    if config.last_success_at is None:
        return "never_collected", None
    current = utcnow()
    if config.last_success_at.tzinfo is None:
        current = current.replace(tzinfo=None)
    age = max(0, int((current - config.last_success_at).total_seconds()))
    if age >= config.expire_after_seconds:
        return "expired", age
    if age >= config.stale_after_seconds:
        return "stale", age
    return "fresh", age


def _next_run_at(
    config: IntelSourceConfig | None,
    schedule_seconds: int | None,
):
    if config is None or not config.enabled or schedule_seconds is None:
        return None
    anchor = config.last_attempt_at or config.last_success_at
    if anchor is None:
        return utcnow()
    return anchor + timedelta(seconds=schedule_seconds)


def _parse_watchvuln_sources(sources: str) -> list[str]:
    parsed = []
    for source in sources.split(","):
        normalized = _normalize_watchvuln_source(source)
        if normalized and normalized not in parsed:
            parsed.append(normalized)
    return parsed


def _normalize_watchvuln_source(source: str) -> str:
    normalized = source.strip().lower()
    if normalized in {"avd", "aliyun-avd"}:
        return "avd"
    if normalized in {"ti", "nox", "qianxin-ti"}:
        return "ti"
    if normalized in {"struts2", "structs2"}:
        return "struts2"
    return normalized


def _watchvuln_source_name_from_payload(payload: dict[str, Any]) -> str | None:
    content = payload.get("content") if isinstance(payload, dict) else None
    if not isinstance(content, dict):
        return None
    source = content.get("watchvuln_source")
    if not source:
        return None
    normalized = _normalize_watchvuln_source(str(source))
    return f"watchvuln:{normalized}" if normalized else None


def _to_collection_run_out(run: IntelCollectionRun) -> IntelCollectionRunOut:
    return IntelCollectionRunOut(
        id=run.id,
        source_name=run.source_name,
        trigger_type=run.trigger_type,
        status=run.status,
        started_at=run.started_at,
        finished_at=run.finished_at,
        fetched_count=run.fetched_count,
        stored_count=run.stored_count,
        processed_count=run.processed_count,
        skipped_count=run.skipped_count,
        failed_count=run.failed_count,
        error_message=run.error_message,
        task_id=run.task_id,
        parameters=run.parameters_json or {},
        generation_id=run.generation_id,
        update_mode=run.update_mode,
        cursor_before=run.cursor_before_json or {},
        cursor_after=run.cursor_after_json or {},
        completeness=run.completeness_json or {},
        parser_version=run.parser_version,
        artifacts_count=run.artifacts_count,
        activated_at=run.activated_at,
        error_code=run.error_code,
        created_at=run.created_at,
        updated_at=run.updated_at,
    )


def _to_raw_event_out(raw_event: IntelRawEvent) -> IntelRawEventOut:
    vulnerability = raw_event.vulnerability
    return IntelRawEventOut(
        id=raw_event.id,
        provider=raw_event.provider,
        event_type=raw_event.event_type,
        external_key=raw_event.external_key,
        source_url=raw_event.source_url,
        processing_status=raw_event.processing_status,
        received_at=raw_event.received_at,
        processed_at=raw_event.processed_at,
        last_error=raw_event.last_error,
        vulnerability_id=raw_event.vulnerability_id,
        vulnerability_canonical_id=(
            vulnerability.canonical_id if vulnerability is not None else None
        ),
        quality=_quality_for_vulnerability(vulnerability),
        created_at=raw_event.created_at,
        updated_at=raw_event.updated_at,
    )


def _quality_for_vulnerability(
    vulnerability: Vulnerability | None,
) -> IntelNormalizationQualityOut | None:
    if vulnerability is None:
        return None
    sources = list(vulnerability.sources)
    source_url_count = sum(1 for source in sources if source.source_url)
    reference_count = sum(len(source.references_json or []) for source in sources)
    quality_flags = {
        "canonical_id": bool(vulnerability.canonical_id),
        "product": bool(vulnerability.product),
        "affected_versions": bool(vulnerability.affected_versions),
        "fixed_versions": bool(vulnerability.fixed_versions),
        "severity": bool(vulnerability.severity_cvss or vulnerability.severity_label),
        "exploitation_signal": bool(
            vulnerability.kev_status
            or vulnerability.poc_status
            or vulnerability.wild_exploitation_status
            or vulnerability.epss is not None
        ),
        "source_url": source_url_count > 0,
        "references": reference_count > 0,
    }
    missing_fields = [
        field_name
        for field_name, is_present in quality_flags.items()
        if not is_present
    ]
    conflict_fields = _source_conflict_fields(vulnerability)
    issue_codes = [f"missing_{field_name}" for field_name in missing_fields]
    issue_codes.extend(f"source_conflict_{field_name}" for field_name in conflict_fields)
    return IntelNormalizationQualityOut(
        has_canonical_id=quality_flags["canonical_id"],
        has_product=quality_flags["product"],
        has_affected_version=quality_flags["affected_versions"],
        has_fixed_version=quality_flags["fixed_versions"],
        has_severity=quality_flags["severity"],
        has_exploitation_signal=quality_flags["exploitation_signal"],
        source_url_count=source_url_count,
        reference_count=reference_count,
        missing_fields=missing_fields,
        issue_codes=issue_codes,
        conflict_fields=conflict_fields,
        source_conflict_count=len(conflict_fields),
        needs_ai_enrichment=any(
            issue in issue_codes
            for issue in (
                "missing_product",
                "missing_affected_versions",
                "missing_fixed_versions",
                "missing_references",
            )
        ),
        needs_human_review=any(
            issue in issue_codes
            for issue in (
                "missing_canonical_id",
                "missing_source_url",
            )
        )
        or bool(conflict_fields),
    )


def _source_conflict_fields(vulnerability: Vulnerability) -> list[str]:
    conflicts: set[str] = set()
    comparable_fields = (
        "product",
        "affected_versions",
        "fixed_versions",
        "severity",
    )
    for source in vulnerability.sources:
        for field_name in comparable_fields:
            source_value = _source_field_value(source, field_name)
            current_value = _vulnerability_field_value(vulnerability, field_name)
            if not source_value or not current_value:
                continue
            if is_reason_confirmed(
                vulnerability,
                f"source_conflict_{field_name}",
            ):
                continue
            if field_name == "product":
                if _cisa_source_has_multiple_affected_scopes(vulnerability, source):
                    continue
                if product_values_conflict(source_value, current_value):
                    conflicts.add(field_name)
            elif _normalize_compare_text(source_value) != _normalize_compare_text(current_value):
                conflicts.add(field_name)
    return sorted(conflicts)


def _cisa_source_has_multiple_affected_scopes(
    vulnerability: Vulnerability,
    source: VulnerabilitySource,
) -> bool:
    if source.source_name != "cisa-kev" or not source.raw_event_id:
        return False
    return (
        sum(
            scope.raw_event_id == source.raw_event_id
            for scope in vulnerability.affected_scopes
        )
        > 1
    )


def _vulnerability_field_value(vulnerability: Vulnerability, field_name: str) -> str | None:
    if field_name == "severity":
        if vulnerability.severity_label:
            return vulnerability.severity_label
        if vulnerability.severity_cvss is not None:
            score = vulnerability.severity_cvss
            if score >= 9:
                return "critical"
            if score >= 7:
                return "high"
            if score >= 4:
                return "medium"
            return "low"
    value = getattr(vulnerability, field_name, None)
    return _clean_text(value)


def _source_field_value(source: VulnerabilitySource, field_name: str) -> str | None:
    raw_event = source.raw_event
    payload = raw_event.payload if raw_event is not None else {}
    if not isinstance(payload, dict):
        return None
    content = payload.get("content") if isinstance(payload.get("content"), dict) else payload
    record = payload.get("record") if isinstance(payload.get("record"), dict) else payload

    if source.source_name == "cisa-kev":
        if field_name == "product":
            return _first_clean_text(record, "product")
        if field_name == "fixed_versions":
            return _extract_fixed_version(_first_clean_text(record, "requiredAction"))
        return None

    if source.source_name == "aliyun-avd":
        if field_name == "severity":
            return _normalize_severity_compare_value(_first_clean_text(record, "severity"))
        return _first_clean_text(
            record,
            field_name,
            _camel_case(field_name),
            field_name.rstrip("s"),
        )

    if source.source_name == "watchvuln" or source.source_name.startswith("watchvuln:"):
        if field_name == "severity":
            return _normalize_severity_compare_value(_first_clean_text(content, "severity"))
        if field_name == "product":
            return _first_clean_text(content, "product", "affected_product", "component")
        if field_name == "affected_versions":
            return _first_clean_text(
                content,
                "affected_versions",
                "affectedVersion",
                "affected_version",
                "influence",
                "scope",
            )
        if field_name == "fixed_versions":
            return _first_clean_text(
                content,
                "fixed_versions",
                "fixedVersion",
                "fixed_version",
            )
    return None


def _first_clean_text(payload: dict[str, Any], *field_names: str) -> str | None:
    for field_name in field_names:
        value = _clean_text(payload.get(field_name))
        if value:
            return value
    lowered = {key.lower(): value for key, value in payload.items()}
    for field_name in field_names:
        value = _clean_text(lowered.get(field_name.lower()))
        if value:
            return value
    return None


def _clean_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list | tuple | set):
        return ", ".join(str(item).strip() for item in value if str(item).strip()) or None
    text = str(value).strip()
    return text or None


def _normalize_compare_text(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().lower())


def _normalize_severity_compare_value(value: str | None) -> str | None:
    if not value:
        return None
    return normalize_severity_label(value) or value


def _camel_case(value: str) -> str:
    parts = value.split("_")
    return parts[0] + "".join(part.capitalize() for part in parts[1:])


def _extract_fixed_version(value: str | None) -> str | None:
    if not value:
        return None
    match = re.search(r"(?:version|v)\s*([0-9][0-9A-Za-z.\-_+]*)", value, re.IGNORECASE)
    return match.group(1) if match else value
