from __future__ import annotations

from sqlalchemy import desc, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.deployment import deployment_profile
from app.db.base import utcnow
from app.db.models import MatchEvaluationRun
from app.schemas.match_result import MatchEvaluationRequest, MatchEvaluationResponse
from app.services.matching import (
    evaluate_match_batch,
    iter_match_pair_batches,
    prepare_match_evaluation,
)
from app.services.risk_notifications import (
    RiskChange,
    enqueue_evaluation_deliveries,
    process_risk_evaluation_changes,
)


ACTIVE_STATUSES = ("queued", "running")
FULL_SCOPE_KEY = "full"
MAX_SAMPLE_RESULT_IDS = 8


def create_match_evaluation_run(
    db: Session,
    request: MatchEvaluationRequest,
    *,
    actor_id: str | None = None,
) -> tuple[MatchEvaluationRun, bool]:
    is_full = not request.asset_id and not request.vulnerability_id
    if is_full:
        active = _active_full_run(db)
        if active is not None:
            return active, False

    run = MatchEvaluationRun(
        status="queued",
        trigger_type="manual",
        asset_id=request.asset_id,
        vulnerability_id=request.vulnerability_id,
        requested_by=actor_id,
        active_scope_key=FULL_SCOPE_KEY if is_full else None,
        sample_result_ids_json=[],
    )
    db.add(run)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        if is_full and (active := _active_full_run(db)) is not None:
            return active, False
        raise
    db.refresh(run)
    return run, True


def set_match_evaluation_task_id(
    db: Session,
    run_id: str,
    task_id: str,
) -> MatchEvaluationRun | None:
    run = db.get(MatchEvaluationRun, run_id)
    if run is None:
        return None
    run.task_id = task_id
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def fail_match_evaluation_enqueue(
    db: Session,
    run_id: str,
    error: Exception,
) -> MatchEvaluationRun | None:
    run = db.get(MatchEvaluationRun, run_id)
    if run is None:
        return None
    _finish_failed(run, error)
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def get_match_evaluation_run(
    db: Session,
    run_id: str,
) -> MatchEvaluationResponse | None:
    run = db.get(MatchEvaluationRun, run_id)
    return to_match_evaluation_response(run) if run is not None else None


def list_match_evaluation_runs(
    db: Session,
    *,
    limit: int = 20,
) -> list[MatchEvaluationResponse]:
    statement = (
        select(MatchEvaluationRun)
        .order_by(desc(MatchEvaluationRun.created_at))
        .limit(limit)
    )
    return [to_match_evaluation_response(run) for run in db.scalars(statement).all()]


def run_match_evaluation(
    db: Session,
    run_id: str,
) -> MatchEvaluationResponse:
    run = db.get(MatchEvaluationRun, run_id)
    if run is None:
        raise ValueError("Match evaluation run not found.")
    if run.status not in ACTIVE_STATUSES:
        return to_match_evaluation_response(run)

    run.status = "running"
    run.started_at = run.started_at or utcnow()
    run.recent_error = None
    db.add(run)
    db.commit()

    all_changes: list[RiskChange] = []
    delivery_ids: list[str] = []
    try:
        assets, vulnerabilities, skipped_vulnerabilities, numeric_config = (
            prepare_match_evaluation(
                db,
                asset_id=run.asset_id,
                vulnerability_id=run.vulnerability_id,
            )
        )
        run = _require_run(db, run_id)
        run.total_count = len(assets) * (
            len(vulnerabilities) + skipped_vulnerabilities
        )
        run.skipped_count = len(assets) * skipped_vulnerabilities
        run.processed_count = run.skipped_count
        db.add(run)
        db.commit()

        batch_size = deployment_profile(get_settings()).matching_batch_size
        for pair_batch in iter_match_pair_batches(
            assets,
            vulnerabilities,
            batch_size=batch_size,
        ):
            try:
                batch_results, batch_changes = evaluate_match_batch(
                    db,
                    pair_batch,
                    numeric_config=numeric_config,
                )
                run = _require_run(db, run_id)
                run.processed_count += len(pair_batch)
                run.evaluated_count += len(batch_results)
                sample_ids = list(run.sample_result_ids_json or [])
                for result in batch_results:
                    if len(sample_ids) >= MAX_SAMPLE_RESULT_IDS:
                        break
                    sample_ids.append(result.id)
                run.sample_result_ids_json = sample_ids
                db.add(run)
                db.commit()
                all_changes.extend(batch_changes)
            except Exception as exc:
                db.rollback()
                run = _require_run(db, run_id)
                run.processed_count += len(pair_batch)
                run.failed_count += len(pair_batch)
                run.recent_error = _compact_error(exc)
                db.add(run)
                db.commit()

        if all_changes:
            outcome = process_risk_evaluation_changes(
                db,
                changes=all_changes,
                trigger_type=run.trigger_type,
                evaluation_event_id=run.id,
                occurred_at=run.started_at,
            )
            delivery_ids = outcome.delivery_ids
            db.commit()

        run = _require_run(db, run_id)
        run.status = (
            "completed" if run.failed_count == 0 else "completed_with_errors"
        )
        run.finished_at = utcnow()
        run.active_scope_key = None
        db.add(run)
        db.commit()
        db.refresh(run)
        enqueue_evaluation_deliveries(delivery_ids)
        return to_match_evaluation_response(run)
    except Exception as exc:
        db.rollback()
        run = _require_run(db, run_id)
        _finish_failed(run, exc)
        db.add(run)
        db.commit()
        db.refresh(run)
        return to_match_evaluation_response(run)


def to_match_evaluation_response(
    run: MatchEvaluationRun,
) -> MatchEvaluationResponse:
    return MatchEvaluationResponse(
        run_id=run.id,
        task_id=run.task_id,
        status=run.status,
        asset_id=run.asset_id,
        vulnerability_id=run.vulnerability_id,
        total_count=run.total_count,
        processed_count=run.processed_count,
        evaluated_count=run.evaluated_count,
        skipped_count=run.skipped_count,
        failed_count=run.failed_count,
        sample_result_ids=list(run.sample_result_ids_json or []),
        recent_error=run.recent_error,
        started_at=run.started_at,
        finished_at=run.finished_at,
        created_at=run.created_at,
        updated_at=run.updated_at,
    )


def _active_full_run(db: Session) -> MatchEvaluationRun | None:
    return db.scalar(
        select(MatchEvaluationRun)
        .where(
            MatchEvaluationRun.active_scope_key == FULL_SCOPE_KEY,
            MatchEvaluationRun.status.in_(ACTIVE_STATUSES),
        )
        .order_by(desc(MatchEvaluationRun.created_at))
    )


def _require_run(db: Session, run_id: str) -> MatchEvaluationRun:
    run = db.get(MatchEvaluationRun, run_id)
    if run is None:
        raise ValueError("Match evaluation run not found.")
    return run


def _finish_failed(run: MatchEvaluationRun, error: Exception) -> None:
    run.status = "failed"
    run.recent_error = _compact_error(error)
    run.finished_at = utcnow()
    run.active_scope_key = None


def _compact_error(error: Exception) -> str:
    message = str(error).strip() or error.__class__.__name__
    return message[:2000]
