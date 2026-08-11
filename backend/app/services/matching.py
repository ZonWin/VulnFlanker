from __future__ import annotations

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session, selectinload

from app.db.base import utcnow
from app.db.models import (
    Asset,
    IntelSourceConfig,
    MatchEvidence,
    MatchResult,
    RiskQueueEvent,
    Vulnerability,
    VulnerabilityAffectedScope,
)
from app.matching.base import MatchContext
from app.matching.pipeline import PipelineResult, evaluate_pipeline
from app.matching.scope_resolver import ScopeResolution, resolve_affected_scopes
from app.matching.utils import extract_conditions
from app.services.audit import create_audit_log
from app.services.platform_settings import (
    get_platform_settings,
    is_product_only_matching_enabled,
)
from app.services.rule_numeric_config import (
    RuleNumericConfigValues,
    get_rule_numeric_config_values,
)
from app.services.risk_snapshot import apply_risk_snapshot
from app.services.risk_codes import RISK_CODE_STATUSES, allocate_risk_code
from app.services.risk_notifications import (
    capture_risk_state,
    classify_risk_change,
    enqueue_evaluation_deliveries,
    process_risk_evaluation_changes,
)
from app.services.vulnerability_readiness import (
    MATCH_READY,
    VulnerabilityReadiness,
    evaluate_vulnerability_readiness,
)
from app.services.vulnerability_review import is_vulnerability_excluded_from_matching


class VulnerabilityNotReadyForMatching(ValueError):
    def __init__(
        self,
        vulnerability: Vulnerability,
        readiness: VulnerabilityReadiness,
    ) -> None:
        self.vulnerability = vulnerability
        self.readiness = readiness
        super().__init__(
            f"Vulnerability {vulnerability.canonical_id} is not ready for matching: "
            f"{readiness.match_readiness}"
        )


def evaluate_matches(
    db: Session,
    *,
    asset_id: str | None = None,
    vulnerability_id: str | None = None,
    raise_if_vulnerability_blocked: bool | None = None,
    trigger_type: str = "manual",
) -> list[MatchResult]:
    assets = _load_assets(db, asset_id)
    vulnerabilities = _load_vulnerabilities(db, vulnerability_id)
    numeric_config = get_rule_numeric_config_values(db)
    results: list[MatchResult] = []
    changes = []
    should_raise_if_blocked = (
        bool(vulnerability_id)
        if raise_if_vulnerability_blocked is None
        else raise_if_vulnerability_blocked
    )

    for vulnerability in vulnerabilities:
        if is_vulnerability_excluded_from_matching(vulnerability):
            continue
        if not _ensure_vulnerability_ready(
            db,
            vulnerability,
            raise_if_blocked=should_raise_if_blocked,
        ):
            continue
        for asset in assets:
            previous_result = db.scalar(
                select(MatchResult).where(
                    and_(
                        MatchResult.asset_id == asset.id,
                        MatchResult.vulnerability_id == vulnerability.id,
                    )
                )
            )
            previous = capture_risk_state(previous_result)
            result = evaluate_asset_vulnerability(
                db,
                asset,
                vulnerability,
                numeric_config=numeric_config,
            )
            results.append(result)
            change = classify_risk_change(result, previous)
            if change is not None:
                changes.append(change)

    outcome = process_risk_evaluation_changes(
        db,
        changes=changes,
        trigger_type=trigger_type,
    )
    db.commit()
    for result in results:
        db.refresh(result)
    enqueue_evaluation_deliveries(outcome.delivery_ids)
    return results


def evaluate_asset_vulnerability(
    db: Session,
    asset: Asset,
    vulnerability: Vulnerability,
    *,
    numeric_config: RuleNumericConfigValues | None = None,
) -> MatchResult:
    if is_vulnerability_excluded_from_matching(vulnerability):
        raise VulnerabilityNotReadyForMatching(
            vulnerability,
            evaluate_vulnerability_readiness(
                vulnerability,
                allow_product_only_match=is_product_only_matching_enabled(
                    get_platform_settings(db)
                ),
            ),
        )
    _ensure_vulnerability_ready(db, vulnerability, raise_if_blocked=True)
    numeric_config = numeric_config or get_rule_numeric_config_values(db)
    scopes = vulnerability.affected_scopes
    if scopes:
        source_freshness = _source_freshness_for_scopes(db, scopes)
        scope_resolution = resolve_affected_scopes(asset, scopes)
        if scope_resolution.selected:
            pipeline_result = _aggregate_scope_pipeline_results(
                [
                    (
                        scope,
                        _evaluate_affected_scope(
                            asset,
                            vulnerability,
                            scope,
                            numeric_config=numeric_config,
                            freshness=source_freshness.get(scope.source_name),
                        ),
                    )
                    for scope in scope_resolution.selected
                ],
                resolution=scope_resolution,
            )
        else:
            pipeline_result = _no_applicable_scope_result(scope_resolution)
    else:
        context = build_match_context(asset, vulnerability, numeric_config=numeric_config)
        pipeline_result = evaluate_pipeline(context)
    match_result = _get_or_create_match_result(db, asset, vulnerability)
    previous_status = match_result.status
    match_result.asset = asset
    match_result.vulnerability = vulnerability
    _apply_pipeline_result(
        match_result,
        pipeline_result,
        numeric_config=numeric_config,
    )
    transition_at = utcnow()
    previously_in_queue = previous_status in RISK_CODE_STATUSES
    currently_in_queue = match_result.status in RISK_CODE_STATUSES
    if not previously_in_queue and currently_in_queue:
        if match_result.risk_entered_at is None:
            match_result.risk_entered_at = transition_at
        db.add(
            RiskQueueEvent(
                match_result=match_result,
                event_type="entered",
                from_status=previous_status,
                to_status=match_result.status,
                created_at=transition_at,
                updated_at=transition_at,
            )
        )
    elif previously_in_queue and not currently_in_queue:
        db.add(
            RiskQueueEvent(
                match_result=match_result,
                event_type="exited",
                from_status=previous_status,
                to_status=match_result.status,
                created_at=transition_at,
                updated_at=transition_at,
            )
        )
    if match_result.risk_code is None and currently_in_queue:
        match_result.risk_code = allocate_risk_code(db, created_at=transition_at)
    _replace_evidence(match_result, pipeline_result)
    db.add(match_result)
    db.flush()
    return match_result


def reevaluate_match_result(
    db: Session,
    match_result_id: str,
    *,
    actor_id: str | None = None,
    actor_details: dict[str, object | None] | None = None,
) -> MatchResult | None:
    match_result = db.scalar(
        select(MatchResult)
        .options(
            selectinload(MatchResult.asset).selectinload(Asset.components),
            selectinload(MatchResult.asset).selectinload(Asset.exposures),
            selectinload(MatchResult.verification_tasks),
            selectinload(MatchResult.vulnerability).selectinload(
                Vulnerability.affected_scopes
            ),
            selectinload(MatchResult.evidence),
        )
        .where(MatchResult.id == match_result_id)
    )
    if match_result is None:
        return None

    previous_status = match_result.status
    previous_risk_score = match_result.risk_score
    previous_risk_priority = match_result.risk_priority
    previous = capture_risk_state(match_result)
    numeric_config = get_rule_numeric_config_values(db)
    result = evaluate_asset_vulnerability(
        db,
        match_result.asset,
        match_result.vulnerability,
        numeric_config=numeric_config,
    )
    change = classify_risk_change(result, previous)
    outcome = process_risk_evaluation_changes(
        db,
        changes=[change] if change is not None else [],
        trigger_type="manual",
    )
    create_audit_log(
        db,
        action="match_result.reevaluated",
        resource_type="match_result",
        resource_id=result.id,
        actor_type="user" if actor_id else "system",
        actor_id=actor_id,
        outcome="success",
        summary="Reevaluated match result with current matching rules.",
        details={
            **(actor_details or {}),
            "asset_id": result.asset_id,
            "vulnerability_id": result.vulnerability_id,
            "previous_status": previous_status,
            "new_status": result.status,
            "previous_risk_score": previous_risk_score,
            "new_risk_score": result.risk_score,
            "previous_risk_priority": previous_risk_priority,
            "new_risk_priority": result.risk_priority,
            "rule_version": result.rule_version,
        },
    )
    db.commit()
    db.refresh(result)
    enqueue_evaluation_deliveries(outcome.delivery_ids)
    return result


def build_match_context(
    asset: Asset,
    vulnerability: Vulnerability,
    *,
    numeric_config: RuleNumericConfigValues | None = None,
    affected_scope: VulnerabilityAffectedScope | None = None,
) -> MatchContext:
    scope_product = affected_scope.product if affected_scope else vulnerability.product
    scope_vendor = affected_scope.vendor if affected_scope else vulnerability.vendor
    scope_affected_versions = (
        affected_scope.affected_versions
        if affected_scope
        else vulnerability.affected_versions
    )
    scope_fixed_versions = (
        affected_scope.fixed_versions if affected_scope else vulnerability.fixed_versions
    )
    return MatchContext(
        asset_id=asset.id,
        vulnerability_id=vulnerability.id,
        asset={
            "id": asset.id,
            "agent_id": asset.agent_id,
            "hostname": asset.hostname,
            "platform": asset.platform,
            "os_family": asset.os_family,
            "os_version": asset.os_version,
            "kernel_version": asset.kernel_version,
            "environment_type": asset.environment_type,
            "exposure_type": asset.exposure_type,
            "criticality": asset.criticality,
        },
        vulnerability={
            "id": vulnerability.id,
            "canonical_id": vulnerability.canonical_id,
            "title": vulnerability.title,
            "vendor": scope_vendor,
            "product": scope_product,
            "severity_cvss": vulnerability.severity_cvss,
            "epss": vulnerability.epss,
            "kev_status": vulnerability.kev_status,
            "poc_status": vulnerability.poc_status,
            "wild_exploitation_status": vulnerability.wild_exploitation_status,
            "affected_versions": scope_affected_versions,
            "fixed_versions": scope_fixed_versions,
            "affected_scope": (
                {
                    "id": affected_scope.id,
                    "vendor": affected_scope.vendor,
                    "product": affected_scope.product,
                    "ecosystem": affected_scope.ecosystem,
                    "distro": affected_scope.distro,
                    "distro_release": affected_scope.distro_release,
                    "source_package": affected_scope.source_package,
                    "binary_package": affected_scope.binary_package,
                    "architecture": affected_scope.architecture,
                    "flavor": affected_scope.flavor,
                    "version_scheme": affected_scope.version_scheme,
                    "version_type": affected_scope.version_type,
                    "status": affected_scope.status,
                    "default_status": affected_scope.default_status,
                    "source_authority": affected_scope.source_authority,
                    "authority_score": affected_scope.authority_score,
                    "purl": affected_scope.purl,
                    "cpe": affected_scope.cpe,
                    "platforms": affected_scope.platforms_json or [],
                    "structured_versions": affected_scope.structured_versions_json or [],
                    "affected_versions": affected_scope.affected_versions,
                    "fixed_versions": affected_scope.fixed_versions,
                    "source_name": affected_scope.source_name,
                    "source_url": affected_scope.source_url,
                }
                if affected_scope
                else None
            ),
        },
        asset_components=[
            {
                "id": component.id,
                "component_name": component.component_name,
                "component_type": component.component_type,
                "version": component.version,
                "source_type": component.source_type,
                "ecosystem": component.ecosystem,
                "distro": component.distro,
                "distro_release": component.distro_release,
                "source_package": component.source_package,
                "binary_package": component.binary_package,
                "architecture": component.architecture,
                "flavor": component.flavor,
                "version_scheme": component.version_scheme,
                "purl": component.purl,
                "cpe": component.cpe,
                "install_path": component.install_path,
                "evidence_ref": component.evidence_ref,
            }
            for component in asset.components
        ],
        asset_exposures=[
            {
                "id": exposure.id,
                "exposure_kind": exposure.exposure_kind,
                "address": exposure.address,
                "port": exposure.port,
                "protocol": exposure.protocol,
                "service_name": exposure.service_name,
                "product": exposure.product,
                "version": exposure.version,
                "state": exposure.state,
                "is_public": exposure.is_public,
                "banner": exposure.banner,
                "evidence_ref": exposure.evidence_ref,
            }
            for exposure in asset.exposures
        ],
        vulnerability_conditions=extract_conditions(vulnerability.notes),
        rule_confidences=(
            numeric_config.matching_confidences if numeric_config is not None else {}
        ),
    )


def _load_assets(db: Session, asset_id: str | None) -> list[Asset]:
    statement = select(Asset).options(
        selectinload(Asset.components),
        selectinload(Asset.exposures),
    )
    if asset_id:
        statement = statement.where(or_(Asset.id == asset_id, Asset.agent_id == asset_id))
    return list(db.scalars(statement).all())


def _load_vulnerabilities(
    db: Session,
    vulnerability_id: str | None,
) -> list[Vulnerability]:
    statement = select(Vulnerability).options(
        selectinload(Vulnerability.sources),
        selectinload(Vulnerability.affected_scopes),
        selectinload(Vulnerability.review_resolutions),
    )
    if vulnerability_id:
        statement = statement.where(
            or_(
                Vulnerability.id == vulnerability_id,
                Vulnerability.canonical_id == vulnerability_id,
            )
        )
    return list(db.scalars(statement).all())


def _aggregate_scope_pipeline_results(
    scope_results: list[tuple[VulnerabilityAffectedScope, PipelineResult]],
    *,
    resolution: ScopeResolution | None = None,
) -> PipelineResult:
    affected = [item for item in scope_results if item[1].status == "affected"]
    reviews = [item for item in scope_results if item[1].status == "needs_review"]
    selected = affected or reviews or scope_results
    status = "affected" if affected else "needs_review" if reviews else "not_affected"
    confidences = [result.confidence for _, result in selected]
    confidence = min(confidences) if status != "not_affected" else max(confidences)
    evidence: list[dict] = []
    rule_results = []
    rule_trace: list[dict] = []
    for scope, result in scope_results:
        scope_summary = _scope_summary(scope)
        for item in result.evidence:
            evidence.append(
                {
                    **item,
                    "details": {
                        **(item.get("details") or {}),
                        "source_authority": scope.source_authority,
                        "authority_score": scope.authority_score,
                        "affected_scope": scope_summary,
                    },
                }
            )
        for item in result.rule_trace:
            rule_trace.append({**item, "affected_scope": scope_summary})
        rule_results.extend(result.rule_results)
    if resolution is not None:
        evidence.append(
            {
                "type": "scope_resolution",
                "summary": (
                    f"Selected {len(resolution.selected)} of "
                    f"{len(resolution.applicable)} applicable affected scopes."
                ),
                "confidence": confidence,
                "details": {
                    "selected_scope_ids": [
                        str(scope.id) for scope in resolution.selected
                    ],
                    "excluded_scopes": resolution.excluded,
                },
            }
        )
    return PipelineResult(
        status=status,
        confidence=round(confidence, 2),
        reason="; ".join(result.reason for _, result in selected),
        rule_version="match-scope-pipeline-v1",
        evidence=evidence,
        rule_results=rule_results,
        rule_trace=_deduplicate_scope_rule_trace(rule_trace),
    )


def _deduplicate_scope_rule_trace(rule_trace: list[dict]) -> list[dict]:
    consolidated: dict[tuple[object, ...], dict] = {}
    for item in rule_trace:
        key = (
            item.get("rule_name"),
            item.get("status"),
            item.get("reason_code"),
        )
        existing = consolidated.get(key)
        scope = item.get("affected_scope") or {}
        scope_id = scope.get("scope_id") if isinstance(scope, dict) else None
        if existing is None:
            existing = {**item, "affected_scope_ids": []}
            consolidated[key] = existing
        if scope_id and scope_id not in existing["affected_scope_ids"]:
            existing["affected_scope_ids"].append(scope_id)
    return list(consolidated.values())


def _evaluate_affected_scope(
    asset: Asset,
    vulnerability: Vulnerability,
    scope: VulnerabilityAffectedScope,
    *,
    numeric_config: RuleNumericConfigValues,
    freshness: dict[str, object] | None = None,
) -> PipelineResult:
    if freshness and freshness.get("state") == "expired":
        return _expired_source_scope_result(scope, freshness)
    declared = _declared_scope_result(scope)
    if declared is not None:
        return _apply_source_freshness(declared, freshness)
    result = evaluate_pipeline(
        build_match_context(
            asset,
            vulnerability,
            numeric_config=numeric_config,
            affected_scope=scope,
        )
    )
    return _apply_source_freshness(result, freshness)


def _source_freshness_for_scopes(
    db: Session,
    scopes: list[VulnerabilityAffectedScope],
) -> dict[str, dict[str, object]]:
    source_names = {scope.source_name for scope in scopes}
    configs = db.scalars(
        select(IntelSourceConfig).where(IntelSourceConfig.source_name.in_(source_names))
    ).all()
    states: dict[str, dict[str, object]] = {}
    for config in configs:
        if config.last_success_at is None:
            continue
        current = utcnow()
        if config.last_success_at.tzinfo is None:
            current = current.replace(tzinfo=None)
        age = max(0, int((current - config.last_success_at).total_seconds()))
        state = (
            "expired"
            if age >= config.expire_after_seconds
            else "stale" if age >= config.stale_after_seconds else "fresh"
        )
        states[config.source_name] = {
            "state": state,
            "age_seconds": age,
            "stale_after_seconds": config.stale_after_seconds,
            "expire_after_seconds": config.expire_after_seconds,
            "last_success_at": config.last_success_at.isoformat(),
        }
    return states


def _expired_source_scope_result(
    scope: VulnerabilityAffectedScope,
    freshness: dict[str, object],
) -> PipelineResult:
    reason = (
        f"{scope.source_name} evidence is expired and cannot support an "
        "authoritative affectedness decision."
    )
    return PipelineResult(
        status="needs_review",
        confidence=0.5,
        reason=reason,
        rule_version="match-source-freshness-v1",
        evidence=[
            {
                "type": "source_freshness",
                "summary": reason,
                "confidence": 0.5,
                "details": freshness,
            }
        ],
        rule_trace=[
            {
                "rule_name": "source_freshness_rule",
                "rule_version": "v1",
                "executed": True,
                "status": "needs_review",
                "confidence": 0.5,
                "reason": reason,
                "reason_code": "source_freshness.expired",
                "uncertain_reason": reason,
                "input_summary": freshness,
                "evidence_count": 1,
            }
        ],
    )


def _apply_source_freshness(
    result: PipelineResult,
    freshness: dict[str, object] | None,
) -> PipelineResult:
    if not freshness or freshness.get("state") != "stale":
        return result
    summary = "The source data is stale but has not reached its expiry threshold."
    result.confidence = min(result.confidence, 0.75)
    result.evidence.append(
        {
            "type": "source_freshness",
            "summary": summary,
            "confidence": 0.75,
            "details": freshness,
        }
    )
    result.rule_trace.append(
        {
            "rule_name": "source_freshness_rule",
            "rule_version": "v1",
            "executed": True,
            "status": result.status,
            "confidence": result.confidence,
            "reason": summary,
            "reason_code": "source_freshness.stale",
            "uncertain_reason": summary,
            "input_summary": freshness,
            "evidence_count": 1,
        }
    )
    return result


def _declared_scope_result(
    scope: VulnerabilityAffectedScope,
) -> PipelineResult | None:
    status_key = str(scope.status or "affected").strip().lower().replace("-", "_")
    if status_key not in {
        "not_affected",
        "package_not_present",
        "needs_review",
        "under_investigation",
    }:
        if not (
            scope.source_name
            in {
                "ubuntu-security",
                "canonical-ubuntu",
                "debian-security-tracker",
                "redhat-csaf",
            }
            and status_key == "affected"
        ):
            return None

    status = (
        "not_affected"
        if status_key in {"not_affected", "package_not_present"}
        else "needs_review" if status_key == "under_investigation" else status_key
    )
    confidence = max(0.5, min(float(scope.authority_score or 0) / 100, 0.99))
    summary = (
        f"{scope.source_name} declares {scope.distro or 'the target platform'} "
        f"{scope.distro_release or ''} package {scope.source_package or scope.product} "
        f"as {status.replace('_', ' ')}."
    )
    evidence = {
        "type": "distro_status",
        "summary": summary,
        "confidence": confidence,
        "details": {
            "declared_status": scope.status,
            "source_status": scope.default_status,
            "authority": scope.source_authority,
            "authority_score": scope.authority_score,
            "affected_scope": _scope_summary(scope),
        },
    }
    return PipelineResult(
        status=status,
        confidence=round(confidence, 2),
        reason=summary,
        rule_version="match-distro-status-v1",
        evidence=[evidence],
        rule_trace=[
            {
                "rule_name": "distro_status_rule",
                "rule_version": "v1",
                "executed": True,
                "status": status,
                "confidence": round(confidence, 2),
                "reason": summary,
                "reason_code": f"distro_status.{status}",
                "uncertain_reason": summary if status == "needs_review" else None,
                "input_summary": _scope_summary(scope),
                "evidence_count": 1,
            }
        ],
    )


def _no_applicable_scope_result(resolution: ScopeResolution) -> PipelineResult:
    reason = "No vulnerability affected scope applies to this asset identity."
    return PipelineResult(
        status="not_affected",
        confidence=0.9,
        reason=reason,
        rule_version="match-scope-pipeline-v2",
        evidence=[
            {
                "type": "scope_no_match",
                "summary": reason,
                "confidence": 0.9,
                "details": {"excluded_scopes": resolution.excluded},
            }
        ],
        rule_trace=[
            {
                "rule_name": "scope_resolver",
                "rule_version": "v1",
                "executed": True,
                "status": "not_affected",
                "confidence": 0.9,
                "reason": reason,
                "reason_code": "scope_resolver.not_affected.no_applicable_scope",
                "uncertain_reason": None,
                "input_summary": {"excluded_scopes": resolution.excluded},
                "evidence_count": 1,
            }
        ],
    )


def _scope_summary(scope: VulnerabilityAffectedScope) -> dict[str, object]:
    return {
        "scope_id": scope.id,
        "source_name": scope.source_name,
        "vendor": scope.vendor,
        "product": scope.product,
        "ecosystem": scope.ecosystem,
        "distro": scope.distro,
        "distro_release": scope.distro_release,
        "source_package": scope.source_package,
        "binary_package": scope.binary_package,
        "architecture": scope.architecture,
        "flavor": scope.flavor,
        "version_scheme": scope.version_scheme,
        "version_type": scope.version_type,
        "status": scope.status,
        "default_status": scope.default_status,
        "source_authority": scope.source_authority,
        "authority_score": scope.authority_score,
        "purl": scope.purl,
        "cpe": scope.cpe,
        "platforms": scope.platforms_json or [],
        "affected_versions": scope.affected_versions,
        "fixed_versions": scope.fixed_versions,
        "source_url": scope.source_url,
    }


def _ensure_vulnerability_ready(
    db: Session,
    vulnerability: Vulnerability,
    *,
    raise_if_blocked: bool,
) -> bool:
    readiness = evaluate_vulnerability_readiness(
        vulnerability,
        allow_product_only_match=is_product_only_matching_enabled(
            get_platform_settings(db)
        ),
    )
    if readiness.match_readiness == MATCH_READY:
        return True
    if raise_if_blocked:
        raise VulnerabilityNotReadyForMatching(vulnerability, readiness)
    return False


def _get_or_create_match_result(
    db: Session,
    asset: Asset,
    vulnerability: Vulnerability,
) -> MatchResult:
    match_result = db.scalar(
        select(MatchResult)
        .options(
            selectinload(MatchResult.evidence),
            selectinload(MatchResult.verification_tasks),
        )
        .where(
            and_(
                MatchResult.asset_id == asset.id,
                MatchResult.vulnerability_id == vulnerability.id,
            )
        )
    )
    if match_result is not None:
        return match_result
    return MatchResult(asset_id=asset.id, vulnerability_id=vulnerability.id)


def _apply_pipeline_result(
    match_result: MatchResult,
    pipeline_result: PipelineResult,
    *,
    numeric_config: RuleNumericConfigValues,
) -> None:
    match_result.status = pipeline_result.status
    match_result.confidence = pipeline_result.confidence
    apply_risk_snapshot(match_result, numeric_config=numeric_config)
    match_result.match_reason = pipeline_result.reason
    match_result.rule_version = pipeline_result.rule_version
    match_result.last_evaluated_at = utcnow()


def _replace_evidence(
    match_result: MatchResult,
    pipeline_result: PipelineResult,
) -> None:
    match_result.evidence.clear()
    for evidence in pipeline_result.evidence:
        match_result.evidence.append(
            MatchEvidence(
                evidence_type=str(evidence.get("type") or "rule_evidence"),
                summary=str(evidence.get("summary") or ""),
                raw_ref=evidence.get("raw_ref"),
                confidence=float(evidence.get("confidence") or pipeline_result.confidence),
                details_json={
                    "rule_name": evidence.get("rule_name"),
                    **(evidence.get("details") or {}),
                },
            )
        )
    for trace_item in pipeline_result.rule_trace:
        match_result.evidence.append(
            MatchEvidence(
                evidence_type="rule_trace",
                summary=(
                    f"{trace_item.get('rule_name')} -> "
                    f"{trace_item.get('status')}: {trace_item.get('reason')}"
                ),
                confidence=float(trace_item.get("confidence") or 0.0),
                details_json=trace_item,
            )
        )

