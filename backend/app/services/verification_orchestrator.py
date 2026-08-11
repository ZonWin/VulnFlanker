from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.db.base import utcnow
from app.db.models import Asset, MatchResult, VerificationEvidence, VerificationTask
from app.services.audit import create_audit_log
from app.services.risk_snapshot import apply_risk_snapshot
from app.verification.package_version_check import (
    TASK_TYPE as PACKAGE_VERSION_CHECK,
    decide_package_version_match_update,
    execute_package_version_check,
)


def apply_verification_result_to_match_result(
    db: Session,
    task: VerificationTask,
    *,
    actor_type: str = "system",
    actor_id: str | None = None,
) -> None:
    match_result = _load_match_result(db, task.match_result_id)
    if match_result is None:
        return

    previous_status = match_result.status
    previous_confidence = match_result.confidence
    previous_risk_score = match_result.risk_score
    decision = _decision_for_task(task, match_result)
    if (
        _has_authoritative_not_affected_status(match_result)
        and decision.match_status not in {None, "not_affected"}
    ):
        decision.match_status = None
        decision.reason = (
            "Verification evidence was recorded but cannot override an applicable "
            "distribution not-affected status."
        )
        decision.reason_code = "verification.distribution_status_preserved"
    _annotate_verification_evidence(task, decision)
    if decision.match_status is not None:
        match_result.status = decision.match_status
    if decision.confidence is not None:
        match_result.confidence = round(decision.confidence, 2)
    if decision.reason:
        match_result.match_reason = _merge_verification_reason(
            match_result.match_reason,
            decision.reason,
        )

    apply_risk_snapshot(match_result)
    match_result.last_evaluated_at = utcnow()
    create_audit_log(
        db,
        action="match_result.verification_updated",
        resource_type="match_result",
        resource_id=match_result.id,
        actor_type=actor_type,
        actor_id=actor_id,
        outcome="success",
        summary="Updated match result from verification evidence.",
        details={
            "verification_task_id": task.id,
            "task_type": task.task_type,
            "task_status": task.status,
            "previous_status": previous_status,
            "new_status": match_result.status,
            "previous_confidence": previous_confidence,
            "new_confidence": match_result.confidence,
            "previous_risk_score": previous_risk_score,
            "new_risk_score": match_result.risk_score,
            "reason": decision.reason,
            "reason_code": decision.reason_code,
        },
    )


def run_local_verification_task(
    db: Session,
    task_id: str,
) -> dict[str, str | int] | None:
    task = db.scalar(
        select(VerificationTask)
        .options(
            selectinload(VerificationTask.asset).selectinload(Asset.components),
            selectinload(VerificationTask.evidence),
        )
        .where(VerificationTask.id == task_id)
    )
    if task is None:
        return None

    if task.task_type != PACKAGE_VERSION_CHECK:
        task.status = "rejected"
        task.completed_at = utcnow()
        task.error_code = "unsupported_task_type"
        task.error_message = f"Unsupported verification task type: {task.task_type}"
        create_audit_log(
            db,
            action="verification_task.rejected",
            resource_type="verification_task",
            resource_id=task.id,
            actor_type="worker",
            actor_id="local-worker",
            outcome="rejected",
            summary=f"Rejected unsupported verification task type {task.task_type}.",
            details={
                "asset_id": task.asset_id,
                "match_result_id": task.match_result_id,
                "task_type": task.task_type,
            },
        )
        apply_verification_result_to_match_result(
            db,
            task,
            actor_type="worker",
            actor_id="local-worker",
        )
        db.commit()
        return {
            "status": task.status,
            "task_id": task.id,
            "evidence_count": 0,
        }

    task.status = "in_progress"
    task.assigned_at = task.assigned_at or utcnow()
    create_audit_log(
        db,
        action="verification_task.assigned",
        resource_type="verification_task",
        resource_id=task.id,
        actor_type="worker",
        actor_id="local-worker",
        outcome="success",
        summary=f"Assigned {task.task_type} verification task to local worker.",
        details={
            "asset_id": task.asset_id,
            "match_result_id": task.match_result_id,
            "task_type": task.task_type,
        },
    )
    execution = execute_package_version_check(
        task.parameters or {},
        [*list(task.asset.components), *_asset_platform_components(task.asset)],
    )
    task.status = execution.status
    task.completed_at = utcnow()
    task.error_code = execution.error_code
    task.error_message = execution.error_message
    task.evidence.clear()
    for item in execution.evidence:
        task.evidence.append(_build_evidence(task, item))

    apply_verification_result_to_match_result(
        db,
        task,
        actor_type="worker",
        actor_id="local-worker",
    )
    create_audit_log(
        db,
        action="verification_task.result_received",
        resource_type="verification_task",
        resource_id=task.id,
        actor_type="worker",
        actor_id="local-worker",
        outcome=task.status,
        summary=f"Recorded {task.status} result for {task.task_type} verification task.",
        details={
            "asset_id": task.asset_id,
            "match_result_id": task.match_result_id,
            "task_type": task.task_type,
            "evidence_count": len(task.evidence),
            "error_code": task.error_code,
        },
    )
    db.commit()
    db.refresh(task)
    return {
        "status": task.status,
        "task_id": task.id,
        "evidence_count": len(task.evidence),
    }


def _decision_for_task(task: VerificationTask, match_result: MatchResult):
    parameters = task.parameters or {}
    if task.task_type == PACKAGE_VERSION_CHECK:
        return decide_package_version_match_update(
            task_status=task.status,
            error_code=task.error_code,
            evidence_items=list(task.evidence),
            affected_versions=_parameter_or_default(
                parameters,
                "constraint_affected_versions",
                match_result.vulnerability.affected_versions,
            ),
            fixed_versions=_parameter_or_default(
                parameters,
                "constraint_fixed_versions",
                match_result.vulnerability.fixed_versions,
            ),
            expected_package_name=_parameter_text(
                parameters,
                "expected_product_identity",
            ),
            constraint_version_scheme=_parameter_text(
                parameters,
                "constraint_version_scheme",
            ),
            source_authority=_parameter_text(parameters, "source_authority"),
            authority_score=_parameter_int(parameters, "authority_score"),
        )
    return decide_package_version_match_update(
        task_status="rejected",
        error_code="unsupported_task_type",
        evidence_items=[],
        affected_versions=None,
        fixed_versions=None,
        expected_package_name=None,
    )


def _load_match_result(db: Session, match_result_id: str) -> MatchResult | None:
    return db.scalar(
        select(MatchResult)
        .options(
            selectinload(MatchResult.asset).selectinload(Asset.exposures),
            selectinload(MatchResult.verification_tasks),
            selectinload(MatchResult.vulnerability),
            selectinload(MatchResult.evidence),
        )
        .where(MatchResult.id == match_result_id)
    )


def _build_evidence(
    task: VerificationTask,
    item: dict[str, object],
) -> VerificationEvidence:
    details = {**dict(item.get("details") or {}), "evidence_origin": "local_worker"}
    return VerificationEvidence(
        verification_task_id=task.id,
        match_result_id=task.match_result_id,
        evidence_type=str(item.get("evidence_type") or "verification_evidence"),
        summary=str(item.get("summary") or ""),
        raw_ref=item.get("raw_ref"),
        confidence=float(item.get("confidence") or 0.0),
        details_json=details,
    )


def _asset_platform_components(asset: Asset) -> list[dict[str, object]]:
    components: list[dict[str, object]] = []
    if asset.os_family or asset.platform or asset.os_version:
        os_name = str(asset.os_family or asset.platform or "operating system")
        components.append(
            {
                "id": f"{asset.id}:os",
                "component_name": os_name,
                "component_type": "operating_system",
                "version": asset.os_version,
                "source_type": "os-release",
                "ecosystem": "deb" if str(asset.os_family or "").lower() in {"ubuntu", "debian"} else None,
                "distro": str(asset.os_family or "").lower() or None,
                "distro_release": asset.os_version,
                "architecture": asset.architecture,
                "version_scheme": "generic",
                "install_path": " ".join(
                    str(value)
                    for value in (asset.os_family, asset.os_version)
                    if value
                )
                or None,
            }
        )
    if asset.kernel_version:
        components.append(
            {
                "id": f"{asset.id}:kernel",
                "component_name": "Linux Kernel",
                "component_type": "kernel",
                "version": asset.kernel_version,
                "source_type": "uname",
                "ecosystem": "deb" if str(asset.os_family or "").lower() in {"ubuntu", "debian"} else None,
                "distro": str(asset.os_family or "").lower() or None,
                "distro_release": asset.os_version,
                "source_package": "linux" if str(asset.os_family or "").lower() in {"ubuntu", "debian"} else "kernel",
                "architecture": asset.architecture,
                "version_scheme": (
                    "ubuntu_kernel"
                    if str(asset.os_family or "").lower() == "ubuntu"
                    else "generic"
                ),
                "install_path": " ".join(
                    str(value)
                    for value in (asset.platform, asset.kernel_version)
                    if value
                )
                or None,
            }
        )
    return components


def _merge_verification_reason(current_reason: str | None, verification_reason: str) -> str:
    if not current_reason:
        return verification_reason
    return f"{current_reason} | Verification: {verification_reason}"


def _annotate_verification_evidence(task: VerificationTask, decision) -> None:
    for evidence in task.evidence:
        if evidence.evidence_type not in {
            "package_version",
            "kernel_version",
            "os_version",
            "package_absence",
        }:
            continue
        evidence.details_json = {
            **(evidence.details_json or {}),
            "decision_status": decision.match_status,
            "decision_reason_code": decision.reason_code,
            "server_evaluation": decision.details,
        }


def _has_authoritative_not_affected_status(match_result: MatchResult) -> bool:
    if match_result.status != "not_affected":
        return False
    for evidence in match_result.evidence:
        if evidence.evidence_type != "distro_status":
            continue
        details = evidence.details_json or {}
        if (
            details.get("declared_status") in {"not_affected", "package_not_present"}
            and details.get("authority") == "distribution"
        ):
            return True
    return False


def _parameter_or_default(
    parameters: dict,
    key: str,
    default: str | None,
) -> str | None:
    if key not in parameters:
        return default
    value = parameters.get(key)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _parameter_text(parameters: dict, key: str) -> str | None:
    value = parameters.get(key)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _parameter_int(parameters: dict, key: str) -> int | None:
    value = parameters.get(key)
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
