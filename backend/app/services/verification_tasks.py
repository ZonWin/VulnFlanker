from __future__ import annotations

from datetime import timedelta

from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.core.config import get_settings
from app.db.base import utcnow
from app.db.models import Asset, MatchResult, VerificationEvidence, VerificationTask, Vulnerability
from app.matching.utils import normalize_name
from app.schemas.verification import (
    AgentTaskEvidenceIn,
    AgentTaskOut,
    AgentTaskPollOut,
    AgentTaskResultIn,
    AgentTaskResultOut,
    VerificationEvidenceOut,
    VerificationEvidenceSummaryOut,
    VerificationTaskActionIn,
    VerificationTaskCreateIn,
    VerificationTaskDetailOut,
    VerificationTaskListPage,
    VerificationTaskOut,
    VerificationTaskSummaryOut,
    VerificationTaskTimelineEvent,
)
from app.services.agent_status import record_agent_task_poll, record_agent_task_result
from app.services.audit import create_audit_log
from app.services.verification_orchestrator import apply_verification_result_to_match_result
from app.verification.package_version_check import build_package_absence_evidence


ALLOWED_AGENT_TASK_TYPES = {"package_version_check"}
RETRYABLE_TASK_STATUSES = {"failed", "rejected", "cancelled"}


def list_verification_tasks(
    db: Session,
    *,
    status: str | None = None,
    agent_id: str | None = None,
    asset_id: str | None = None,
    vulnerability_id: str | None = None,
    match_result_id: str | None = None,
    task_type: str | None = None,
    limit: int = 100,
) -> list[VerificationTaskSummaryOut]:
    page = list_verification_tasks_page(
        db,
        status=status,
        agent_id=agent_id,
        asset_id=asset_id,
        vulnerability_id=vulnerability_id,
        match_result_id=match_result_id,
        task_type=task_type,
        offset=0,
        limit=limit,
    )
    return page.items


def list_verification_tasks_page(
    db: Session,
    *,
    status: str | None = None,
    agent_id: str | None = None,
    asset_id: str | None = None,
    vulnerability_id: str | None = None,
    match_result_id: str | None = None,
    task_type: str | None = None,
    offset: int = 0,
    limit: int = 60,
) -> VerificationTaskListPage:
    mark_timed_out_verification_tasks(db)
    statement = _task_context_statement().order_by(
        desc(VerificationTask.created_at),
        desc(VerificationTask.updated_at),
    )
    if status:
        statement = statement.where(VerificationTask.status == status)
    if agent_id:
        statement = statement.where(Asset.agent_id == agent_id)
    if asset_id:
        statement = statement.where(or_(VerificationTask.asset_id == asset_id, Asset.agent_id == asset_id))
    if vulnerability_id:
        statement = statement.where(
            or_(
                MatchResult.vulnerability_id == vulnerability_id,
                Vulnerability.canonical_id == vulnerability_id,
            )
        )
    if match_result_id:
        statement = statement.where(VerificationTask.match_result_id == match_result_id)
    if task_type:
        statement = statement.where(VerificationTask.task_type == task_type)
    stats = _task_list_stats(db, statement)
    statement = statement.offset(offset).limit(limit + 1)

    tasks = list(db.scalars(statement).all())
    visible_tasks = tasks[:limit]
    retry_counts = _retry_counts(db, [task.id for task in visible_tasks])
    return VerificationTaskListPage(
        items=[
            _to_task_summary_out(task, retry_counts.get(task.id, 0))
            for task in visible_tasks
        ],
        offset=offset,
        limit=limit,
        has_more=len(tasks) > limit,
        total=stats["total"],
        active_count=stats["active"],
        failed_count=stats["failed"],
        evidence_count=stats["evidence"],
    )


def get_verification_task(
    db: Session,
    task_id: str,
) -> VerificationTaskDetailOut | None:
    mark_timed_out_verification_tasks(db)
    task = db.scalar(_task_context_statement().where(VerificationTask.id == task_id))
    if task is None:
        return None
    return _to_task_detail_out(task, _retry_count(db, task.id))


def list_verification_evidence(
    db: Session,
    *,
    verification_task_id: str | None = None,
    match_result_id: str | None = None,
    asset_id: str | None = None,
    vulnerability_id: str | None = None,
    evidence_type: str | None = None,
    limit: int = 100,
) -> list[VerificationEvidenceSummaryOut]:
    statement = (
        select(VerificationEvidence)
        .join(VerificationEvidence.verification_task)
        .join(VerificationTask.asset)
        .join(VerificationEvidence.match_result)
        .join(MatchResult.vulnerability)
        .options(
            selectinload(VerificationEvidence.verification_task).selectinload(
                VerificationTask.asset
            ),
            selectinload(VerificationEvidence.match_result).selectinload(
                MatchResult.vulnerability
            ),
        )
        .order_by(desc(VerificationEvidence.created_at))
    )
    if verification_task_id:
        statement = statement.where(VerificationEvidence.verification_task_id == verification_task_id)
    if match_result_id:
        statement = statement.where(VerificationEvidence.match_result_id == match_result_id)
    if asset_id:
        statement = statement.where(or_(VerificationTask.asset_id == asset_id, Asset.agent_id == asset_id))
    if vulnerability_id:
        statement = statement.where(
            or_(
                MatchResult.vulnerability_id == vulnerability_id,
                Vulnerability.canonical_id == vulnerability_id,
            )
        )
    if evidence_type:
        statement = statement.where(VerificationEvidence.evidence_type == evidence_type)
    statement = statement.limit(limit)
    return [_to_evidence_summary_out(item) for item in db.scalars(statement).all()]


def cancel_verification_task(
    db: Session,
    task_id: str,
    payload: VerificationTaskActionIn,
    *,
    actor_details: dict[str, object | None] | None = None,
) -> VerificationTaskDetailOut | None:
    mark_timed_out_verification_tasks(db)
    task = db.scalar(_task_context_statement().where(VerificationTask.id == task_id))
    if task is None:
        return None

    now = utcnow()
    actor_id = payload.requested_by
    if task.status == "queued":
        task.status = "cancelled"
        task.completed_at = now
        task.cancel_requested_at = now
        task.error_code = "cancelled_by_operator"
        task.error_message = "Verification task was cancelled before assignment."
        action = "verification_task.cancelled"
        summary = f"Cancelled {task.task_type} verification task before assignment."
    elif task.status == "in_progress":
        task.status = "cancel_requested"
        task.cancel_requested_at = now
        task.error_code = "cancel_requested"
        task.error_message = "Cancellation was requested while the task was in progress."
        action = "verification_task.cancel_requested"
        summary = f"Requested cancellation for in-progress {task.task_type} verification task."
    else:
        raise ValueError(f"Cannot cancel verification task in {task.status} status.")

    create_audit_log(
        db,
        action=action,
        resource_type="verification_task",
        resource_id=task.id,
        actor_type="user" if actor_id else "system",
        actor_id=actor_id,
        outcome=task.status,
        summary=summary,
        details={
            **(actor_details or {}),
            "asset_id": task.asset_id,
            "match_result_id": task.match_result_id,
            "task_type": task.task_type,
            "previous_status": "queued" if action.endswith("cancelled") else "in_progress",
            "new_status": task.status,
        },
    )
    apply_verification_result_to_match_result(
        db,
        task,
        actor_type="user" if actor_id else "system",
        actor_id=actor_id,
    )
    db.commit()
    db.refresh(task)
    return get_verification_task(db, task.id)


def retry_verification_task(
    db: Session,
    task_id: str,
    payload: VerificationTaskActionIn,
    *,
    actor_details: dict[str, object | None] | None = None,
) -> VerificationTaskOut | None:
    mark_timed_out_verification_tasks(db)
    task = db.scalar(_task_context_statement().where(VerificationTask.id == task_id))
    if task is None:
        return None
    if task.status not in RETRYABLE_TASK_STATUSES:
        raise ValueError(
            "Only failed, rejected, or cancelled verification tasks can be retried."
        )

    retry = VerificationTask(
        asset_id=task.asset_id,
        match_result_id=task.match_result_id,
        task_type=task.task_type,
        status="queued",
        parameters=dict(task.parameters or {}),
        requested_by=payload.requested_by or task.requested_by,
        previous_task_id=task.id,
    )
    db.add(retry)
    db.flush()
    create_audit_log(
        db,
        action="verification_task.retried",
        resource_type="verification_task",
        resource_id=retry.id,
        actor_type="user" if payload.requested_by else "system",
        actor_id=payload.requested_by,
        outcome="success",
        summary=f"Retried {task.task_type} verification task.",
        details={
            **(actor_details or {}),
            "previous_task_id": task.id,
            "previous_status": task.status,
            "asset_id": task.asset_id,
            "match_result_id": task.match_result_id,
            "task_type": task.task_type,
        },
    )
    db.commit()
    db.refresh(retry)
    return _to_task_out(retry)


def mark_timed_out_verification_tasks(db: Session) -> int:
    settings = get_settings()
    now = utcnow()
    queued_before = now - timedelta(seconds=settings.verification_queued_timeout_seconds)
    in_progress_before = now - timedelta(
        seconds=settings.verification_in_progress_timeout_seconds
    )

    timed_out = list(
        db.scalars(
            select(VerificationTask).where(
                or_(
                    (VerificationTask.status == "queued")
                    & (VerificationTask.created_at < queued_before),
                    (VerificationTask.status == "in_progress")
                    & (VerificationTask.assigned_at.is_not(None))
                    & (VerificationTask.assigned_at < in_progress_before),
                )
            )
        ).all()
    )
    for task in timed_out:
        previous_status = task.status
        task.status = "failed"
        task.completed_at = now
        task.error_code = (
            "queued_timeout" if previous_status == "queued" else "in_progress_timeout"
        )
        task.error_message = (
            "Verification task stayed queued beyond the configured timeout."
            if previous_status == "queued"
            else "Verification task stayed in progress beyond the configured timeout."
        )
        create_audit_log(
            db,
            action="verification_task.timed_out",
            resource_type="verification_task",
            resource_id=task.id,
            actor_type="system",
            actor_id=None,
            outcome="failed",
            summary=f"Marked {task.task_type} verification task as timed out.",
            details={
                "asset_id": task.asset_id,
                "match_result_id": task.match_result_id,
                "task_type": task.task_type,
                "previous_status": previous_status,
                "new_status": task.status,
                "error_code": task.error_code,
            },
        )
        apply_verification_result_to_match_result(db, task)

    if timed_out:
        db.commit()
    return len(timed_out)


def create_verification_task(
    db: Session,
    payload: VerificationTaskCreateIn,
    *,
    previous_task_id: str | None = None,
    actor_details: dict[str, object | None] | None = None,
) -> VerificationTaskOut | None:
    if payload.task_type not in ALLOWED_AGENT_TASK_TYPES:
        create_audit_log(
            db,
            action="verification_task.rejected",
            resource_type="verification_task",
            resource_id=payload.match_result_id,
            actor_type="user" if payload.requested_by else "system",
            actor_id=payload.requested_by,
            outcome="rejected",
            summary=f"Rejected unsupported verification task type {payload.task_type}.",
            details={
                **(actor_details or {}),
                "match_result_id": payload.match_result_id,
                "task_type": payload.task_type,
            },
        )
        db.commit()
        raise ValueError(f"Unsupported verification task type: {payload.task_type}")

    match_result = db.scalar(
        select(MatchResult)
        .options(
            selectinload(MatchResult.asset),
            selectinload(MatchResult.vulnerability),
            selectinload(MatchResult.evidence),
        )
        .where(MatchResult.id == payload.match_result_id)
    )
    if match_result is None:
        create_audit_log(
            db,
            action="verification_task.create_failed",
            resource_type="match_result",
            resource_id=payload.match_result_id,
            actor_type="user" if payload.requested_by else "system",
            actor_id=payload.requested_by,
            outcome="not_found",
            summary="Verification task creation failed because match result was not found.",
            details={
                **(actor_details or {}),
                "match_result_id": payload.match_result_id,
                "task_type": payload.task_type,
            },
        )
        db.commit()
        return None

    parameters = {
        **_default_parameters(match_result, payload.task_type),
        **payload.parameters,
    }
    task = VerificationTask(
        asset_id=match_result.asset_id,
        match_result_id=match_result.id,
        task_type=payload.task_type,
        status="queued",
        parameters=parameters,
        requested_by=payload.requested_by,
        previous_task_id=previous_task_id,
    )
    db.add(task)
    db.flush()
    create_audit_log(
        db,
        action="verification_task.created",
        resource_type="verification_task",
        resource_id=task.id,
        actor_type="user" if payload.requested_by else "system",
        actor_id=payload.requested_by,
        outcome="success",
        summary=f"Created {task.task_type} verification task.",
        details={
            **(actor_details or {}),
            "asset_id": task.asset_id,
            "match_result_id": task.match_result_id,
            "task_type": task.task_type,
            "parameters": task.parameters or {},
        },
    )
    db.commit()
    db.refresh(task)
    return _to_task_out(task)


def poll_next_agent_task(db: Session, agent_id: str) -> AgentTaskPollOut:
    polled_at = utcnow()
    record_agent_task_poll(db, agent_id, seen_at=polled_at)

    asset = db.scalar(select(Asset).where(Asset.agent_id == agent_id))
    if asset is None:
        db.commit()
        return AgentTaskPollOut(task=None)

    task = db.scalar(
        select(VerificationTask)
        .where(
            VerificationTask.asset_id == asset.id,
            VerificationTask.status == "queued",
        )
        .order_by(VerificationTask.created_at)
    )
    if task is None:
        db.commit()
        return AgentTaskPollOut(task=None)

    task.status = "in_progress"
    task.assigned_at = polled_at
    create_audit_log(
        db,
        action="verification_task.assigned",
        resource_type="verification_task",
        resource_id=task.id,
        actor_type="agent",
        actor_id=agent_id,
        outcome="success",
        summary=f"Assigned {task.task_type} verification task to agent.",
        details={
            "asset_id": asset.id,
            "match_result_id": task.match_result_id,
            "task_type": task.task_type,
        },
    )
    db.commit()
    db.refresh(task)
    return AgentTaskPollOut(task=_to_agent_task_out(task))


def submit_agent_task_result(
    db: Session,
    *,
    agent_id: str,
    task_id: str,
    payload: AgentTaskResultIn,
) -> AgentTaskResultOut | None:
    task = db.scalar(
        select(VerificationTask)
        .options(
            selectinload(VerificationTask.asset),
            selectinload(VerificationTask.evidence),
        )
        .where(VerificationTask.id == task_id)
    )
    if task is None or task.asset.agent_id != agent_id:
        return None

    legacy_package_absence = (
        task.task_type == "package_version_check"
        and payload.status == "failed"
        and payload.error_code == "package_not_found"
    )
    task.status = "completed" if legacy_package_absence else payload.status
    task.completed_at = payload.completed_at or utcnow()
    task.error_code = None if legacy_package_absence else payload.error_code
    task.error_message = None if legacy_package_absence else payload.error_message
    task.evidence.clear()
    evidence_items = list(payload.evidence)
    if legacy_package_absence and not any(
        item.evidence_type == "package_absence" for item in evidence_items
    ):
        package_name = str((task.parameters or {}).get("package_name") or "package")
        evidence_items.append(
            AgentTaskEvidenceIn.model_validate(
                build_package_absence_evidence(
                    package_name,
                    source="agent_package_inventory",
                )
            )
        )
    for item in evidence_items:
        task.evidence.append(_build_evidence(task, item))
    apply_verification_result_to_match_result(
        db,
        task,
        actor_type="agent",
        actor_id=agent_id,
    )
    record_agent_task_result(
        db,
        agent_id,
        result_status=task.status,
        error_message=task.error_message,
    )
    create_audit_log(
        db,
        action="verification_task.result_received",
        resource_type="verification_task",
        resource_id=task.id,
        actor_type="agent",
        actor_id=agent_id,
        outcome=task.status,
        summary=f"Received {task.status} result for {task.task_type} verification task.",
        details={
            "asset_id": task.asset_id,
            "match_result_id": task.match_result_id,
            "task_type": task.task_type,
            "evidence_count": len(evidence_items),
            "error_code": task.error_code,
            "reported_status": payload.status,
            "reported_error_code": payload.error_code,
            "normalized_package_absence": legacy_package_absence,
        },
    )

    db.commit()
    db.refresh(task)
    return AgentTaskResultOut(
        status=task.status,
        task_id=task.id,
        evidence_count=len(task.evidence),
    )


def _default_parameters(match_result: MatchResult, task_type: str) -> dict[str, object]:
    if task_type != "package_version_check":
        return {}
    vulnerability = match_result.vulnerability
    parameters: dict[str, object] = {}
    package_name = _matched_component_name(match_result) or vulnerability.product
    if package_name:
        parameters["package_name"] = package_name
        component_type = _component_type_for_product(package_name)
        if component_type is None and vulnerability.product:
            component_type = _component_type_for_product(vulnerability.product)
        if component_type:
            parameters["component_type"] = component_type
    if vulnerability.fixed_versions:
        parameters["expected_version"] = vulnerability.fixed_versions
    return parameters


def _matched_component_name(match_result: MatchResult) -> str | None:
    for evidence in match_result.evidence:
        if evidence.evidence_type not in {"product_match", "package_version"}:
            continue
        details = evidence.details_json or {}
        if evidence.evidence_type == "product_match" and details.get("kind") != "component":
            continue
        name = str(details.get("name") or "").strip()
        if name:
            return name
    return None


def _component_type_for_product(product: str | None) -> str | None:
    product_key = normalize_name(product)
    if product_key in {
        "linuxkernel",
        "kernel",
        "linuximage",
        "linuximagegeneric",
        "linuxheaders",
    }:
        return "kernel"
    if product_key in {
        "ubuntu",
        "ubuntulinux",
        "debian",
        "debianlinux",
        "redhatenterpriselinux",
        "rhel",
        "redhat",
        "redhatlinux",
        "centos",
        "centoslinux",
        "rockylinux",
        "rocky",
        "almalinux",
        "amazonlinux",
        "amzn",
        "amzn2",
    }:
        return "operating_system"
    return None


def _build_evidence(
    task: VerificationTask,
    item: AgentTaskEvidenceIn,
) -> VerificationEvidence:
    return VerificationEvidence(
        verification_task_id=task.id,
        match_result_id=task.match_result_id,
        evidence_type=item.evidence_type,
        summary=item.summary,
        raw_ref=item.raw_ref,
        confidence=item.confidence,
        details_json=item.details,
    )


def _task_context_statement():
    return (
        select(VerificationTask)
        .join(VerificationTask.asset)
        .join(VerificationTask.match_result)
        .join(MatchResult.vulnerability)
        .options(
            selectinload(VerificationTask.asset),
            selectinload(VerificationTask.match_result).selectinload(
                MatchResult.vulnerability
            ),
            selectinload(VerificationTask.evidence),
        )
    )


def _task_list_stats(db: Session, statement) -> dict[str, int]:
    task_rows = (
        statement.with_only_columns(VerificationTask.id, VerificationTask.status)
        .order_by(None)
        .subquery()
    )
    task_ids = select(task_rows.c.id)
    evidence_count = db.scalar(
        select(func.count(VerificationEvidence.id)).where(
            VerificationEvidence.verification_task_id.in_(task_ids)
        )
    )
    rows = db.execute(
        select(task_rows.c.status, func.count(task_rows.c.id)).group_by(
            task_rows.c.status
        )
    ).all()
    counts = {status: int(count) for status, count in rows}
    return {
        "total": sum(counts.values()),
        "active": counts.get("queued", 0) + counts.get("in_progress", 0),
        "failed": counts.get("failed", 0) + counts.get("rejected", 0),
        "evidence": int(evidence_count or 0),
    }


def _to_task_out(task: VerificationTask) -> VerificationTaskOut:
    return VerificationTaskOut(
        id=task.id,
        asset_id=task.asset_id,
        match_result_id=task.match_result_id,
        task_type=task.task_type,
        status=task.status,
        parameters=task.parameters or {},
        requested_by=task.requested_by,
        previous_task_id=task.previous_task_id,
        assigned_at=task.assigned_at,
        cancel_requested_at=task.cancel_requested_at,
        completed_at=task.completed_at,
        error_code=task.error_code,
        error_message=task.error_message,
        created_at=task.created_at,
        updated_at=task.updated_at,
    )


def _to_task_summary_out(
    task: VerificationTask,
    retry_count: int,
) -> VerificationTaskSummaryOut:
    match_result = task.match_result
    vulnerability = match_result.vulnerability if match_result is not None else None
    return VerificationTaskSummaryOut(
        **_to_task_out(task).model_dump(),
        asset_hostname=task.asset.hostname if task.asset is not None else None,
        asset_agent_id=task.asset.agent_id if task.asset is not None else None,
        vulnerability_id=vulnerability.id if vulnerability is not None else None,
        vulnerability_canonical_id=(
            vulnerability.canonical_id if vulnerability is not None else None
        ),
        vulnerability_title=vulnerability.title if vulnerability is not None else None,
        evidence_count=len(task.evidence),
        retry_count=retry_count,
    )


def _to_task_detail_out(
    task: VerificationTask,
    retry_count: int,
) -> VerificationTaskDetailOut:
    return VerificationTaskDetailOut(
        **_to_task_summary_out(task, retry_count).model_dump(),
        evidence=[_to_evidence_out(item) for item in task.evidence],
        timeline=_task_timeline(task),
    )


def _to_evidence_out(evidence: VerificationEvidence) -> VerificationEvidenceOut:
    return VerificationEvidenceOut(
        id=evidence.id,
        verification_task_id=evidence.verification_task_id,
        evidence_type=evidence.evidence_type,
        summary=evidence.summary,
        raw_ref=evidence.raw_ref,
        confidence=evidence.confidence,
        details=evidence.details_json or {},
        created_at=evidence.created_at,
    )


def _to_evidence_summary_out(
    evidence: VerificationEvidence,
) -> VerificationEvidenceSummaryOut:
    base = _to_evidence_out(evidence).model_dump()
    task = evidence.verification_task
    match_result = evidence.match_result
    vulnerability = match_result.vulnerability if match_result is not None else None
    return VerificationEvidenceSummaryOut(
        **base,
        match_result_id=evidence.match_result_id,
        asset_id=task.asset_id if task is not None else None,
        asset_hostname=task.asset.hostname if task is not None and task.asset else None,
        vulnerability_id=vulnerability.id if vulnerability is not None else None,
        vulnerability_canonical_id=(
            vulnerability.canonical_id if vulnerability is not None else None
        ),
        vulnerability_title=vulnerability.title if vulnerability is not None else None,
    )


def _task_timeline(task: VerificationTask) -> list[VerificationTaskTimelineEvent]:
    events = [
        VerificationTaskTimelineEvent(
            status="queued",
            occurred_at=task.created_at,
            summary="Verification task was created.",
        )
    ]
    if task.assigned_at is not None:
        events.append(
            VerificationTaskTimelineEvent(
                status="in_progress",
                occurred_at=task.assigned_at,
                summary="Verification task was assigned.",
            )
        )
    if task.cancel_requested_at is not None:
        events.append(
            VerificationTaskTimelineEvent(
                status="cancel_requested",
                occurred_at=task.cancel_requested_at,
                summary="Cancellation was requested.",
            )
        )
    if task.completed_at is not None:
        events.append(
            VerificationTaskTimelineEvent(
                status=task.status,
                occurred_at=task.completed_at,
                summary=f"Verification task entered {task.status} status.",
            )
        )
    events.sort(key=lambda event: event.occurred_at)
    return events


def _retry_counts(db: Session, task_ids: list[str]) -> dict[str, int]:
    if not task_ids:
        return {}
    rows = db.execute(
        select(VerificationTask.previous_task_id, func.count(VerificationTask.id))
        .where(VerificationTask.previous_task_id.in_(task_ids))
        .group_by(VerificationTask.previous_task_id)
    ).all()
    return {str(previous_task_id): count for previous_task_id, count in rows}


def _retry_count(db: Session, task_id: str) -> int:
    return db.scalar(
        select(func.count(VerificationTask.id)).where(
            VerificationTask.previous_task_id == task_id
        )
    ) or 0


def _to_agent_task_out(task: VerificationTask) -> AgentTaskOut:
    return AgentTaskOut(
        id=task.id,
        task_type=task.task_type,
        match_result_id=task.match_result_id,
        parameters=task.parameters or {},
        created_at=task.created_at,
    )
