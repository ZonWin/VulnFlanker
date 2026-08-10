from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_current_user, require_superuser
from app.db.models import User
from app.schemas.match_result import (
    AssetRiskRanking,
    MatchEvaluationRequest,
    MatchEvaluationResponse,
    MatchResultListPage,
    MatchRuleTraceOut,
    MatchResultDetail,
    MatchResultHandlingReopenIn,
    MatchResultHandlingUpdateIn,
    MatchResultSummary,
    RiskConfigOut,
    VulnerabilityRiskRanking,
)
from app.schemas.verification import (
    VerificationTaskCreateIn,
    VerificationTaskOut,
    VerificationTaskRequestIn,
)
from app.services.match_results import (
    get_match_result,
    get_match_result_trace,
    list_asset_risk_rankings,
    list_match_results,
    list_match_results_page,
    list_risk_queue,
    list_risk_queue_page,
    list_vulnerability_risk_rankings,
)
from app.services.risk import current_risk_config
from app.services.rule_numeric_config import get_rule_numeric_config_values
from app.services.matching import (
    VulnerabilityNotReadyForMatching,
    reevaluate_match_result,
)
from app.services.match_evaluation_runs import (
    create_match_evaluation_run,
    fail_match_evaluation_enqueue,
    get_match_evaluation_run,
    list_match_evaluation_runs,
    set_match_evaluation_task_id,
    to_match_evaluation_response,
)
from app.workers.tasks import run_match_evaluation_task
from app.schemas.email_alert import EmailActionOut
from app.services.match_result_handling import (
    HANDLING_STATUSES,
    reopen_match_result_handling,
    update_match_result_handling,
)
from app.services.verification_tasks import create_verification_task
from app.services.auth import user_audit_details
from app.services.risk_notifications import create_manual_risk_email

router = APIRouter()


@router.post(
    "/evaluate",
    response_model=MatchEvaluationResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def evaluate_match_results(
    request: MatchEvaluationRequest,
    current_user: User = Depends(require_current_user),
    db: Session = Depends(get_db),
) -> MatchEvaluationResponse:
    try:
        run, created = create_match_evaluation_run(
            db,
            request,
            actor_id=current_user.id,
        )
    except VulnerabilityNotReadyForMatching as exc:
        raise _readiness_http_error(exc) from exc
    if not created:
        return to_match_evaluation_response(run)
    try:
        task = run_match_evaluation_task.delay(run.id)
        updated = set_match_evaluation_task_id(db, run.id, task.id)
        return to_match_evaluation_response(updated or run)
    except Exception as exc:
        fail_match_evaluation_enqueue(db, run.id, exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="风险匹配评估任务暂时无法进入队列，请稍后重试。",
        ) from exc


@router.get(
    "/evaluations",
    response_model=list[MatchEvaluationResponse],
)
async def get_match_evaluation_runs(
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
) -> list[MatchEvaluationResponse]:
    return list_match_evaluation_runs(db, limit=limit)


@router.get(
    "/evaluations/{run_id}",
    response_model=MatchEvaluationResponse,
)
async def get_match_evaluation_run_detail(
    run_id: str,
    db: Session = Depends(get_db),
) -> MatchEvaluationResponse:
    run = get_match_evaluation_run(db, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Match evaluation run not found")
    return run


@router.get("", response_model=MatchResultListPage | list[MatchResultSummary])
async def get_match_results(
    status: str | None = Query(default=None),
    asset_id: str | None = Query(default=None),
    vulnerability_id: str | None = Query(default=None),
    risk_code: str | None = Query(default=None, max_length=32),
    paged: bool = Query(default=False),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=30, ge=1, le=300),
    db: Session = Depends(get_db),
) -> MatchResultListPage | list[MatchResultSummary]:
    if not paged:
        return list_match_results(
            db,
            status=status,
            asset_id=asset_id,
            vulnerability_id=vulnerability_id,
            risk_code=risk_code,
        )
    return list_match_results_page(
        db,
        status=status,
        asset_id=asset_id,
        vulnerability_id=vulnerability_id,
        risk_code=risk_code,
        offset=offset,
        limit=limit,
    )


@router.get("/risk-queue", response_model=MatchResultListPage | list[MatchResultSummary])
async def get_risk_queue(
    status: str | None = Query(default=None),
    min_risk_score: float | None = Query(default=None, ge=0.0, le=10.0),
    risk_priority: str | None = Query(
        default=None,
        pattern="^(critical|high|medium|low|none)$",
    ),
    asset_criticality: str | None = Query(default=None),
    exposure_type: str | None = Query(default=None),
    business_system_id: str | None = Query(default=None, max_length=36),
    responsible_person_id: str | None = Query(default=None, max_length=36),
    responsibility_team_id: str | None = Query(default=None, max_length=36),
    kev_only: bool | None = Query(default=None),
    verification_state: str | None = Query(
        default=None,
        pattern="^(verified|unverified|has_task|no_task)$",
    ),
    agent_status: str | None = Query(
        default=None,
        pattern="^(online|offline|unknown)$",
    ),
    asset_freshness: str | None = Query(default=None, pattern="^(fresh|stale)$"),
    handling_status: str | None = Query(
        default=None,
        pattern=f"^({'|'.join(HANDLING_STATUSES)})$",
    ),
    handling_scope: str = Query(default="open", pattern="^(open|closed|all)$"),
    risk_code: str | None = Query(default=None, max_length=32),
    paged: bool = Query(default=False),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
) -> MatchResultListPage | list[MatchResultSummary]:
    if not paged:
        return list_risk_queue(
            db,
            status=status,
            min_risk_score=min_risk_score,
            risk_priority=risk_priority,
            asset_criticality=asset_criticality,
            exposure_type=exposure_type,
            business_system_id=business_system_id,
            responsible_person_id=responsible_person_id,
            responsibility_team_id=responsibility_team_id,
            kev_only=kev_only,
            verification_state=verification_state,
            agent_status=agent_status,
            asset_freshness=asset_freshness,
            handling_status=handling_status,
            handling_scope=handling_scope,
            risk_code=risk_code,
            limit=limit,
        )
    return list_risk_queue_page(
        db,
        status=status,
        min_risk_score=min_risk_score,
        risk_priority=risk_priority,
        asset_criticality=asset_criticality,
        exposure_type=exposure_type,
        business_system_id=business_system_id,
        responsible_person_id=responsible_person_id,
        responsibility_team_id=responsibility_team_id,
        kev_only=kev_only,
        verification_state=verification_state,
        agent_status=agent_status,
        asset_freshness=asset_freshness,
        handling_status=handling_status,
        handling_scope=handling_scope,
        risk_code=risk_code,
        offset=offset,
        limit=limit,
    )


@router.get("/risk-config", response_model=RiskConfigOut)
async def get_risk_config(db: Session = Depends(get_db)) -> RiskConfigOut:
    return RiskConfigOut(**current_risk_config(get_rule_numeric_config_values(db)))


@router.get("/rankings/vulnerabilities", response_model=list[VulnerabilityRiskRanking])
async def get_vulnerability_risk_rankings(
    status: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[VulnerabilityRiskRanking]:
    return list_vulnerability_risk_rankings(db, status=status, limit=limit)


@router.get("/rankings/assets", response_model=list[AssetRiskRanking])
async def get_asset_risk_rankings(
    status: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[AssetRiskRanking]:
    return list_asset_risk_rankings(db, status=status, limit=limit)


@router.post("/{match_result_id}/reevaluate", response_model=MatchResultDetail)
async def reevaluate_single_match_result(
    match_result_id: str,
    current_user: User = Depends(require_current_user),
    db: Session = Depends(get_db),
) -> MatchResultDetail:
    try:
        result = reevaluate_match_result(
            db,
            match_result_id,
            actor_id=current_user.id,
            actor_details=user_audit_details(current_user),
        )
    except VulnerabilityNotReadyForMatching as exc:
        raise _readiness_http_error(exc) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Match result not found")
    detail = get_match_result(db, result.id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Match result not found")
    return detail


@router.patch("/{match_result_id}/handling", response_model=MatchResultDetail)
async def update_single_match_result_handling(
    match_result_id: str,
    payload: MatchResultHandlingUpdateIn,
    current_user: User = Depends(require_superuser),
    db: Session = Depends(get_db),
) -> MatchResultDetail:
    result = update_match_result_handling(
        db,
        match_result_id,
        payload,
        actor_id=current_user.id,
        actor_details=user_audit_details(current_user),
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Match result not found")
    detail = get_match_result(db, result.id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Match result not found")
    return detail


@router.post("/{match_result_id}/handling/reopen", response_model=MatchResultDetail)
async def reopen_single_match_result_handling(
    match_result_id: str,
    payload: MatchResultHandlingReopenIn,
    current_user: User = Depends(require_superuser),
    db: Session = Depends(get_db),
) -> MatchResultDetail:
    try:
        result = reopen_match_result_handling(
            db,
            match_result_id,
            payload,
            actor_id=current_user.id,
            actor_details=user_audit_details(current_user),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Match result not found")
    detail = get_match_result(db, result.id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Match result not found")
    return detail


@router.get("/{match_result_id}/trace", response_model=list[MatchRuleTraceOut])
async def get_single_match_result_trace(
    match_result_id: str,
    db: Session = Depends(get_db),
) -> list[MatchRuleTraceOut]:
    trace = get_match_result_trace(db, match_result_id)
    if trace is None:
        raise HTTPException(status_code=404, detail="Match result not found")
    return trace


@router.post(
    "/{match_result_id}/verification-tasks",
    response_model=VerificationTaskOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_verification_task_for_match_result(
    match_result_id: str,
    payload: VerificationTaskRequestIn,
    current_user: User = Depends(require_current_user),
    db: Session = Depends(get_db),
) -> VerificationTaskOut:
    try:
        task = create_verification_task(
            db,
            VerificationTaskCreateIn(
                match_result_id=match_result_id,
                task_type=payload.task_type,
                parameters=payload.parameters,
                requested_by=current_user.id,
            ),
            actor_details=user_audit_details(current_user),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if task is None:
        raise HTTPException(status_code=404, detail="Match result not found")
    return task


@router.post("/{match_result_id}/email-alert", response_model=EmailActionOut)
async def send_match_result_email_alert(
    match_result_id: str,
    current_user: User = Depends(require_superuser),
    db: Session = Depends(get_db),
) -> EmailActionOut:
    try:
        return create_manual_risk_email(
            db,
            match_result_id,
            actor_id=current_user.id,
            actor_details=user_audit_details(current_user),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{match_result_id}", response_model=MatchResultDetail)
async def get_match_result_detail(
    match_result_id: str,
    db: Session = Depends(get_db),
) -> MatchResultDetail:
    result = get_match_result(db, match_result_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Match result not found")
    return result


def _readiness_http_error(exc: VulnerabilityNotReadyForMatching) -> HTTPException:
    readiness = exc.readiness
    return HTTPException(
        status_code=400,
        detail={
            "message": str(exc),
            "vulnerability_id": exc.vulnerability.id,
            "canonical_id": exc.vulnerability.canonical_id,
            "information_completeness": readiness.information_completeness,
            "match_readiness": readiness.match_readiness,
            "reasons": readiness.reasons,
            "missing_fields": readiness.missing_fields,
            "rule_version": readiness.rule_version,
        },
    )
