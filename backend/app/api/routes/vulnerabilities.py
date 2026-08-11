import json

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_current_user
from app.db.models import User
from app.schemas.ai import (
    VulnerabilityAIEnrichmentOut,
    VulnerabilityAIEnrichmentRunResponse,
    VulnerabilityAIEnrichmentTriggerRequest,
)
from app.schemas.vulnerability import (
    UbuntuSecuritySyncOut,
    VulnerabilityCreate,
    VulnerabilityDetail,
    VulnerabilityListPage,
    VulnerabilityReadinessStats,
    VulnerabilityUpdate,
)
from app.services.audit import create_audit_log
from app.services.ubuntu_security import sync_ubuntu_security_statuses
from app.services.vulnerability_catalog import (
    DuplicateVulnerabilityError,
    create_vulnerability,
    get_vulnerability,
    get_vulnerability_readiness_stats,
    list_vulnerabilities_page,
    update_vulnerability,
)
from app.services.auth import user_audit_details
from app.services.vulnerability_ai_enrichment import (
    BASIC_EXTRACTION_PROFILE_KEY,
    WEB_ENRICHMENT_PROFILE_KEY,
    enrich_vulnerability_auto,
    enrich_vulnerability_from_existing_data,
    enrich_vulnerability_with_web_search,
    list_vulnerability_ai_enrichments,
)
from app.workers.tasks import ai_enrich_vulnerability

router = APIRouter()


@router.get("", response_model=VulnerabilityListPage)
async def get_vulnerabilities(
    match_readiness: str | None = None,
    information_completeness: str | None = None,
    search: str | None = Query(default=None, max_length=256),
    severity_labels: str | None = Query(default=None, max_length=256),
    kev_status: bool | None = None,
    ai_enrichment_status: str | None = Query(default=None, max_length=64),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=30, ge=1, le=300),
    db: Session = Depends(get_db),
) -> VulnerabilityListPage:
    try:
        return list_vulnerabilities_page(
            db,
            match_readiness=match_readiness,
            information_completeness=information_completeness,
            search=search,
            severity_labels=severity_labels,
            kev_status=kev_status,
            ai_enrichment_status=ai_enrichment_status,
            offset=offset,
            limit=limit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/readiness/stats", response_model=VulnerabilityReadinessStats)
async def get_vulnerability_readiness_statistics(
    db: Session = Depends(get_db),
) -> VulnerabilityReadinessStats:
    return get_vulnerability_readiness_stats(db)


@router.post("", response_model=VulnerabilityDetail, status_code=status.HTTP_201_CREATED)
async def post_vulnerability(
    payload: VulnerabilityCreate,
    current_user: User = Depends(require_current_user),
    db: Session = Depends(get_db),
) -> VulnerabilityDetail:
    try:
        return create_vulnerability(
            db,
            payload,
            actor_id=current_user.id,
            actor_details=user_audit_details(current_user),
        )
    except DuplicateVulnerabilityError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{vulnerability_id}", response_model=VulnerabilityDetail)
async def get_vulnerability_detail(
    vulnerability_id: str,
    db: Session = Depends(get_db),
) -> VulnerabilityDetail:
    vulnerability = get_vulnerability(db, vulnerability_id)
    if vulnerability is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return vulnerability


@router.get(
    "/{vulnerability_id}/ai-enrichments",
    response_model=list[VulnerabilityAIEnrichmentOut],
)
async def get_vulnerability_ai_enrichments(
    vulnerability_id: str,
    db: Session = Depends(get_db),
) -> list[VulnerabilityAIEnrichmentOut]:
    try:
        return list_vulnerability_ai_enrichments(db, vulnerability_id)
    except ValueError as exc:
        raise _ai_enrichment_http_error(exc) from exc


@router.post(
    "/{vulnerability_id}/ai-enrichments",
    response_model=VulnerabilityAIEnrichmentRunResponse,
)
async def post_vulnerability_ai_enrichment(
    vulnerability_id: str,
    payload: VulnerabilityAIEnrichmentTriggerRequest,
    current_user: User = Depends(require_current_user),
    db: Session = Depends(get_db),
) -> VulnerabilityAIEnrichmentRunResponse:
    profile_key = payload.profile_key or (
        WEB_ENRICHMENT_PROFILE_KEY
        if payload.layer == "web_enrichment"
        else BASIC_EXTRACTION_PROFILE_KEY
    )
    if payload.async_mode:
        try:
            task = ai_enrich_vulnerability.delay(
                vulnerability_id,
                payload.layer,
                profile_key,
                payload.allow_web_enrichment,
                payload.force_refresh,
            )
            return VulnerabilityAIEnrichmentRunResponse(
                async_queued=True,
                task_id=task.id,
            )
        except Exception:
            pass

    try:
        if payload.layer == "web_enrichment":
            enrichment = enrich_vulnerability_with_web_search(
                db,
                vulnerability_id,
                profile_key=profile_key,
                actor_id=current_user.id,
                actor_details=user_audit_details(current_user),
                force_refresh=payload.force_refresh,
            )
        elif payload.layer == "auto":
            enrichment = enrich_vulnerability_auto(
                db,
                vulnerability_id,
                allow_web_enrichment=payload.allow_web_enrichment,
                actor_id=current_user.id,
                actor_details=user_audit_details(current_user),
                force_refresh=payload.force_refresh,
            )
        else:
            enrichment = enrich_vulnerability_from_existing_data(
                db,
                vulnerability_id,
                profile_key=profile_key,
                actor_id=current_user.id,
                actor_details=user_audit_details(current_user),
                force_refresh=payload.force_refresh,
            )
    except ValueError as exc:
        raise _ai_enrichment_http_error(exc) from exc
    return VulnerabilityAIEnrichmentRunResponse(enrichment=enrichment)


@router.post(
    "/{vulnerability_id}/ubuntu-security-sync",
    response_model=UbuntuSecuritySyncOut,
)
async def post_ubuntu_security_sync(
    vulnerability_id: str,
    current_user: User = Depends(require_current_user),
    db: Session = Depends(get_db),
) -> UbuntuSecuritySyncOut:
    try:
        result = sync_ubuntu_security_statuses(db, vulnerability_id)
    except ValueError as exc:
        detail = str(exc)
        status_code = 404 if detail == "Vulnerability not found" else 400
        raise HTTPException(status_code=status_code, detail=detail) from exc
    except (OSError, TimeoutError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Ubuntu security data could not be loaded: {exc}",
        ) from exc
    create_audit_log(
        db,
        action="vulnerability.ubuntu_security_synced",
        resource_type="vulnerability",
        resource_id=result.vulnerability_id,
        actor_type="user",
        actor_id=current_user.id,
        outcome="success",
        summary=f"Imported {result.scope_count} Ubuntu security scopes.",
        details={
            **user_audit_details(current_user),
            "canonical_id": result.canonical_id,
            "status_counts": result.status_counts,
        },
    )
    db.commit()
    return UbuntuSecuritySyncOut(
        vulnerability_id=result.vulnerability_id,
        canonical_id=result.canonical_id,
        scope_count=result.scope_count,
        status_counts=result.status_counts,
    )


@router.patch("/{vulnerability_id}", response_model=VulnerabilityDetail)
async def patch_vulnerability_detail(
    vulnerability_id: str,
    payload: VulnerabilityUpdate,
    current_user: User = Depends(require_current_user),
    db: Session = Depends(get_db),
) -> VulnerabilityDetail:
    try:
        vulnerability = update_vulnerability(
            db,
            vulnerability_id,
            payload,
            actor_id=current_user.id,
            actor_details=user_audit_details(current_user),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if vulnerability is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return vulnerability


def _ai_enrichment_http_error(exc: ValueError) -> HTTPException:
    detail = str(exc)
    if "Vulnerability not found" in detail:
        return HTTPException(status_code=404, detail=detail)
    return HTTPException(status_code=400, detail=detail)
