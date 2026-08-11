from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping

from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.db.models import (
    AgentStatus,
    Asset,
    AssetSnapshot,
    BusinessSystem,
    MatchEvidence,
    MatchResult,
    Person,
    Vulnerability,
)
from app.matching.utils import extract_conditions
from app.schemas.match_result import (
    AssetRiskRanking,
    MatchEvidenceOut,
    MatchResultListPage,
    MatchRuleTraceOut,
    MatchResultDetail,
    MatchResultHandlingRecordOut,
    MatchResultSummary,
    VulnerabilityRiskRanking,
)
from app.schemas.verification import VerificationEvidenceOut
from app.services.agent_status import build_asset_freshness, compute_agent_status
from app.services.asset_catalog import build_asset_ownership
from app.services.risk import calculate_match_risk, risk_priority, risk_priority_bounds
from app.services.match_result_handling import (
    CLOSED_HANDLING_STATUSES,
    DEFAULT_HANDLING_STATUS,
    OPEN_HANDLING_STATUSES,
)
from app.services.rule_numeric_config import get_rule_numeric_config_values


RISK_QUEUE_STATUSES = ("verified", "affected", "needs_review")


def list_match_results(
    db: Session,
    *,
    status: str | None = None,
    asset_id: str | None = None,
    vulnerability_id: str | None = None,
    risk_code: str | None = None,
) -> list[MatchResultSummary]:
    page = list_match_results_page(
        db,
        status=status,
        asset_id=asset_id,
        vulnerability_id=vulnerability_id,
        risk_code=risk_code,
        offset=0,
        limit=1_000_000,
    )
    return page.items


def list_match_results_page(
    db: Session,
    *,
    status: str | None = None,
    asset_id: str | None = None,
    vulnerability_id: str | None = None,
    risk_code: str | None = None,
    offset: int = 0,
    limit: int = 30,
) -> MatchResultListPage:
    statement = (
        select(MatchResult)
        .join(MatchResult.asset)
        .join(MatchResult.vulnerability)
        .options(
            selectinload(MatchResult.asset).selectinload(Asset.exposures),
            selectinload(MatchResult.asset).selectinload(Asset.snapshots),
            selectinload(MatchResult.asset)
            .selectinload(Asset.business_system_record)
            .selectinload(BusinessSystem.responsible_person)
            .selectinload(Person.team),
            selectinload(MatchResult.vulnerability),
            selectinload(MatchResult.verification_tasks),
            selectinload(MatchResult.verification_evidence),
        )
        .order_by(desc(MatchResult.risk_score), desc(MatchResult.updated_at))
    )
    if status:
        statement = statement.where(MatchResult.status == status)
    if asset_id:
        statement = statement.where(or_(Asset.id == asset_id, Asset.agent_id == asset_id))
    if vulnerability_id:
        statement = statement.where(
            or_(
                Vulnerability.id == vulnerability_id,
                Vulnerability.canonical_id == vulnerability_id,
            )
        )

    if risk_code and risk_code.strip():
        statement = statement.where(
            MatchResult.risk_code.ilike(f"%{risk_code.strip()}%")
        )

    total = int(
        db.scalar(select(func.count()).select_from(statement.order_by(None).subquery()))
        or 0
    )
    results = db.scalars(statement.offset(offset).limit(limit + 1)).all()
    return MatchResultListPage(
        items=_to_match_result_summaries(db, list(results[:limit])),
        offset=offset,
        limit=limit,
        has_more=len(results) > limit,
        total=total,
    )


def list_risk_queue(
    db: Session,
    *,
    status: str | None = None,
    min_risk_score: float | None = None,
    risk_priority: str | None = None,
    asset_criticality: str | None = None,
    exposure_type: str | None = None,
    business_system_id: str | None = None,
    responsible_person_id: str | None = None,
    responsibility_team_id: str | None = None,
    kev_only: bool | None = None,
    verification_state: str | None = None,
    agent_status: str | None = None,
    asset_freshness: str | None = None,
    handling_status: str | None = None,
    handling_scope: str = "open",
    risk_code: str | None = None,
    limit: int = 50,
) -> list[MatchResultSummary]:
    page = list_risk_queue_page(
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
        offset=0,
        limit=limit,
    )
    return page.items


def list_risk_queue_page(
    db: Session,
    *,
    status: str | None = None,
    min_risk_score: float | None = None,
    risk_priority: str | None = None,
    asset_criticality: str | None = None,
    exposure_type: str | None = None,
    business_system_id: str | None = None,
    responsible_person_id: str | None = None,
    responsibility_team_id: str | None = None,
    kev_only: bool | None = None,
    verification_state: str | None = None,
    agent_status: str | None = None,
    asset_freshness: str | None = None,
    handling_status: str | None = None,
    handling_scope: str = "open",
    risk_code: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> MatchResultListPage:
    statuses = (status,) if status else RISK_QUEUE_STATUSES
    needs_python_filters = any((verification_state, agent_status, asset_freshness))
    numeric_config = get_rule_numeric_config_values(db)
    if needs_python_filters:
        chunk_size = min(max(limit * 3, 100), 300)
        db_offset = 0
        matched_count = 0
        page_results: list[MatchResult] = []
        critical_count = 0
        unverified_count = 0
        stale_asset_count = 0
        while True:
            candidates = _load_operational_results(
                db,
                statuses=statuses,
                min_risk_score=min_risk_score,
                risk_priority=risk_priority,
                asset_criticality=asset_criticality,
                exposure_type=exposure_type,
                business_system_id=business_system_id,
                responsible_person_id=responsible_person_id,
                responsibility_team_id=responsibility_team_id,
                kev_only=kev_only,
                handling_status=handling_status,
                handling_scope=handling_scope,
                risk_code=risk_code,
                offset=db_offset,
                limit=chunk_size,
                priority_thresholds=numeric_config.risk_priority_thresholds,
                include_ownership=True,
            )
            if not candidates:
                break
            db_offset += chunk_size
            agent_status_by_id = _agent_status_map(db, candidates)
            filtered = _filter_operational_results(
                candidates,
                agent_status_by_id=agent_status_by_id,
                verification_state=verification_state,
                agent_status=agent_status,
                asset_freshness=asset_freshness,
            )
            for result in filtered:
                if _is_critical_risk(result):
                    critical_count += 1
                if _is_unverified_risk(result):
                    unverified_count += 1
                if _asset_freshness_for_result(result) == "stale":
                    stale_asset_count += 1
                if matched_count >= offset and len(page_results) < limit + 1:
                    page_results.append(result)
                matched_count += 1
        agent_status_by_id = _agent_status_map(db, page_results)
        return MatchResultListPage(
            items=[
                _to_match_result_summary(result, agent_status_by_id=agent_status_by_id)
                for result in page_results[:limit]
            ],
            offset=offset,
            limit=limit,
            has_more=len(page_results) > limit,
            total=matched_count,
            critical_count=critical_count,
            unverified_count=unverified_count,
            stale_asset_count=stale_asset_count,
        )

    all_results = _load_operational_results(
        db,
        statuses=statuses,
        min_risk_score=min_risk_score,
        risk_priority=risk_priority,
        asset_criticality=asset_criticality,
        exposure_type=exposure_type,
        business_system_id=business_system_id,
        responsible_person_id=responsible_person_id,
        responsibility_team_id=responsibility_team_id,
        kev_only=kev_only,
        handling_status=handling_status,
        handling_scope=handling_scope,
        risk_code=risk_code,
        offset=0,
        limit=None,
        priority_thresholds=numeric_config.risk_priority_thresholds,
        include_ownership=True,
    )
    results = all_results[offset : offset + limit + 1]
    agent_status_by_id = _agent_status_map(db, results)
    stats = _risk_queue_stats(all_results)
    return MatchResultListPage(
        items=[
            _to_match_result_summary(result, agent_status_by_id=agent_status_by_id)
            for result in results[:limit]
        ],
        offset=offset,
        limit=limit,
        has_more=len(results) > limit,
        total=stats["total"],
        critical_count=stats["critical"],
        unverified_count=stats["unverified"],
        stale_asset_count=stats["stale"],
    )


def list_vulnerability_risk_rankings(
    db: Session,
    *,
    status: str | None = None,
    limit: int = 50,
) -> list[VulnerabilityRiskRanking]:
    statuses = (status,) if status else RISK_QUEUE_STATUSES
    numeric_config = get_rule_numeric_config_values(db)
    results = _load_operational_results(db, statuses=statuses)
    grouped: dict[str, list[MatchResult]] = defaultdict(list)
    for result in results:
        grouped[result.vulnerability_id].append(result)

    rankings = [
        _to_vulnerability_ranking(
            group_results,
            priority_thresholds=numeric_config.risk_priority_thresholds,
        )
        for group_results in grouped.values()
    ]
    rankings.sort(
        key=lambda ranking: (
            ranking.max_risk_score,
            ranking.total_risk_score,
            ranking.affected_count,
        ),
        reverse=True,
    )
    return rankings[:limit]


def list_asset_risk_rankings(
    db: Session,
    *,
    status: str | None = None,
    limit: int = 50,
) -> list[AssetRiskRanking]:
    statuses = (status,) if status else RISK_QUEUE_STATUSES
    numeric_config = get_rule_numeric_config_values(db)
    results = _load_operational_results(db, statuses=statuses)
    grouped: dict[str, list[MatchResult]] = defaultdict(list)
    for result in results:
        grouped[result.asset_id].append(result)

    rankings = [
        _to_asset_ranking(
            group_results,
            priority_thresholds=numeric_config.risk_priority_thresholds,
        )
        for group_results in grouped.values()
    ]
    rankings.sort(
        key=lambda ranking: (
            ranking.max_risk_score,
            ranking.total_risk_score,
            ranking.affected_count,
        ),
        reverse=True,
    )
    return rankings[:limit]


def get_match_result(db: Session, match_result_id: str) -> MatchResultDetail | None:
    result = db.scalar(
        select(MatchResult)
        .options(
            selectinload(MatchResult.asset).selectinload(Asset.exposures),
            selectinload(MatchResult.asset).selectinload(Asset.snapshots),
            selectinload(MatchResult.asset)
            .selectinload(Asset.business_system_record)
            .selectinload(BusinessSystem.responsible_person)
            .selectinload(Person.team),
            selectinload(MatchResult.vulnerability),
            selectinload(MatchResult.evidence),
            selectinload(MatchResult.handling_records),
            selectinload(MatchResult.verification_tasks),
            selectinload(MatchResult.verification_evidence),
        )
        .where(MatchResult.id == match_result_id)
    )
    if result is None:
        return None
    agent_status_by_id = _agent_status_map(db, [result])
    return MatchResultDetail(
        **_to_match_result_summary(
            result,
            agent_status_by_id=agent_status_by_id,
        ).model_dump(),
        evidence=[
            _to_match_evidence(evidence)
            for evidence in result.evidence
            if evidence.evidence_type != "rule_trace"
        ],
        matching_trace=[
            _to_match_rule_trace(evidence, vulnerability=result.vulnerability)
            for evidence in result.evidence
            if evidence.evidence_type == "rule_trace"
        ],
        verification_evidence=[
            _to_verification_evidence(evidence)
            for evidence in result.verification_evidence
        ],
        handling_records=[
            _to_handling_record(record)
            for record in sorted(
                result.handling_records,
                key=lambda item: item.created_at,
                reverse=True,
            )
        ],
    )


def get_match_result_trace(
    db: Session,
    match_result_id: str,
) -> list[MatchRuleTraceOut] | None:
    result = db.scalar(
        select(MatchResult)
        .options(
            selectinload(MatchResult.evidence),
            selectinload(MatchResult.vulnerability),
        )
        .where(MatchResult.id == match_result_id)
    )
    if result is None:
        return None
    return [
        _to_match_rule_trace(evidence, vulnerability=result.vulnerability)
        for evidence in result.evidence
        if evidence.evidence_type == "rule_trace"
    ]


def _to_match_result_summaries(
    db: Session,
    results: list[MatchResult],
) -> list[MatchResultSummary]:
    agent_status_by_id = _agent_status_map(db, results)
    return [
        _to_match_result_summary(result, agent_status_by_id=agent_status_by_id)
        for result in results
    ]


def _to_match_result_summary(
    result: MatchResult,
    *,
    agent_status_by_id: dict[str, AgentStatus] | None = None,
) -> MatchResultSummary:
    risk = _risk_breakdown_for_result(result)
    latest_task = _latest_verification_task(result)
    latest_snapshot = _latest_asset_snapshot(result.asset)
    freshness = build_asset_freshness(latest_snapshot)
    agent_status_model = (
        agent_status_by_id.get(result.asset.agent_id)
        if agent_status_by_id is not None and result.asset.agent_id
        else None
    )
    computed_agent_status = (
        compute_agent_status(agent_status_model) if agent_status_model is not None else None
    )
    return MatchResultSummary(
        id=result.id,
        risk_code=result.risk_code,
        vulnerability_id=result.vulnerability_id,
        vulnerability_canonical_id=result.vulnerability.canonical_id,
        vulnerability_title=result.vulnerability.title,
        vulnerability_product=result.vulnerability.product,
        vulnerability_kev_status=result.vulnerability.kev_status,
        asset_id=result.asset_id,
        asset_hostname=result.asset.hostname,
        asset_agent_id=result.asset.agent_id,
        asset_agent_status=computed_agent_status,
        asset_last_seen_at=result.asset.last_seen_at,
        asset_snapshot_age_seconds=freshness.snapshot_age_seconds,
        asset_is_stale=freshness.is_stale,
        asset_exposure_type=result.asset.exposure_type,
        asset_criticality=result.asset.criticality,
        asset_has_public_exposure=any(
            exposure.is_public for exposure in result.asset.exposures
        ),
        ownership=build_asset_ownership(result.asset),
        status=result.status,
        confidence=result.confidence,
        risk_score=result.risk_score,
        risk_priority=risk.priority,
        risk_model_version=risk.model_version,
        risk_factors=risk.factor_dicts(),
        risk_explanation=risk.explanation,
        handling_status=result.handling_status or DEFAULT_HANDLING_STATUS,
        handling_note=result.handling_note,
        handling_updated_by=result.handling_updated_by,
        handling_updated_at=result.handling_updated_at,
        handling_closed_at=result.handling_closed_at,
        match_reason=result.match_reason,
        rule_version=result.rule_version,
        last_evaluated_at=result.last_evaluated_at,
        latest_verification_task_id=latest_task.id if latest_task is not None else None,
        latest_verification_task_status=(
            latest_task.status if latest_task is not None else None
        ),
        verification_task_count=len(result.verification_tasks),
        verification_evidence_count=len(result.verification_evidence),
    )


def _to_match_evidence(evidence: MatchEvidence) -> MatchEvidenceOut:
    return MatchEvidenceOut(
        id=evidence.id,
        evidence_type=evidence.evidence_type,
        summary=evidence.summary,
        raw_ref=evidence.raw_ref,
        confidence=evidence.confidence,
        details=evidence.details_json or {},
    )


def _latest_verification_task(result: MatchResult):
    if not result.verification_tasks:
        return None
    return max(result.verification_tasks, key=lambda task: task.created_at)


def _latest_asset_snapshot(asset: Asset) -> AssetSnapshot | None:
    if not asset.snapshots:
        return None
    return max(
        asset.snapshots,
        key=lambda snapshot: (snapshot.collected_at, snapshot.received_at),
    )


def _agent_status_map(
    db: Session,
    results: list[MatchResult],
) -> dict[str, AgentStatus]:
    agent_ids = {
        result.asset.agent_id
        for result in results
        if result.asset is not None and result.asset.agent_id
    }
    if not agent_ids:
        return {}
    statuses = db.scalars(
        select(AgentStatus).where(AgentStatus.agent_id.in_(agent_ids))
    ).all()
    return {status.agent_id: status for status in statuses}


def _to_match_rule_trace(
    evidence: MatchEvidence,
    *,
    vulnerability: Vulnerability,
) -> MatchRuleTraceOut:
    details = evidence.details_json or {}
    input_summary = details.get("input_summary") if isinstance(details, dict) else {}
    if not isinstance(input_summary, dict):
        input_summary = {}
    return MatchRuleTraceOut(
        rule_name=str(details.get("rule_name") or ""),
        rule_version=str(details.get("rule_version") or "v1"),
        executed=bool(details.get("executed")),
        status=str(details.get("status") or "unknown"),
        confidence=float(details.get("confidence") or evidence.confidence or 0.0),
        reason=str(details.get("reason") or evidence.summary),
        reason_code=(
            str(details.get("reason_code"))
            if details.get("reason_code") is not None
            else None
        ),
        uncertain_reason=(
            str(details.get("uncertain_reason"))
            if details.get("uncertain_reason") is not None
            else None
        ),
        input_summary=input_summary,
        risk_scope=_trace_risk_scope(details, input_summary, vulnerability),
        asset_context=_trace_asset_context(input_summary),
        evidence_count=int(details.get("evidence_count") or 0),
    )


def _trace_risk_scope(
    details: Mapping[str, object],
    input_summary: Mapping[str, object],
    vulnerability: Vulnerability,
) -> dict[str, object]:
    affected_scope = details.get("affected_scope")
    if not isinstance(affected_scope, Mapping):
        affected_scope = {}
    conditions = extract_conditions(vulnerability.notes)
    return _compact_trace_context(
        {
            "scope_id": affected_scope.get("scope_id"),
            "vendor": affected_scope.get("vendor") or vulnerability.vendor,
            "product": (
                affected_scope.get("product")
                or input_summary.get("expected_product")
                or vulnerability.product
            ),
            "aliases": input_summary.get("aliases"),
            "affected_versions": (
                affected_scope.get("affected_versions")
                or input_summary.get("affected_versions")
                or vulnerability.affected_versions
            ),
            "fixed_versions": (
                affected_scope.get("fixed_versions")
                or input_summary.get("fixed_versions")
                or vulnerability.fixed_versions
            ),
            "affected_os": input_summary.get("affected_os")
            or conditions.get("affected_os"),
            "requires_module": input_summary.get("requires_module")
            or conditions.get("requires_module"),
            "requires_feature_flag": input_summary.get("requires_feature_flag")
            or conditions.get("requires_feature_flag"),
            "requires_public_access": (
                input_summary.get("requires_public_access")
                if input_summary.get("requires_public_access") is not None
                else conditions.get("requires_public_access")
            ),
            "source_url": affected_scope.get("source_url"),
        }
    )


def _trace_asset_context(input_summary: Mapping[str, object]) -> dict[str, object]:
    context = {
        key: input_summary.get(key)
        for key in (
            "matched_components",
            "matched_versions",
            "public_exposure_count",
            "matching_public_exposure_count",
        )
    }
    asset_os = input_summary.get("asset_os")
    if isinstance(asset_os, list):
        for key, value in zip(
            ("platform", "os_family", "os_version", "kernel_version"),
            asset_os,
            strict=False,
        ):
            context[key] = value
    return _compact_trace_context(context)


def _compact_trace_context(values: Mapping[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in values.items()
        if value is not None and value != "" and value != [] and value != {}
    }


def _to_verification_evidence(evidence) -> VerificationEvidenceOut:
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


def _to_handling_record(record) -> MatchResultHandlingRecordOut:
    return MatchResultHandlingRecordOut(
        id=record.id,
        match_result_id=record.match_result_id,
        action=record.action,
        from_status=record.from_status,
        to_status=record.to_status,
        note=record.note,
        actor_id=record.actor_id,
        actor_username=record.actor_username,
        actor_display_name=record.actor_display_name,
        created_at=record.created_at,
    )


def _load_operational_results(
    db: Session,
    *,
    statuses: tuple[str, ...],
    min_risk_score: float | None = None,
    risk_priority: str | None = None,
    asset_criticality: str | None = None,
    exposure_type: str | None = None,
    business_system_id: str | None = None,
    responsible_person_id: str | None = None,
    responsibility_team_id: str | None = None,
    kev_only: bool | None = None,
    handling_status: str | None = None,
    handling_scope: str = "open",
    risk_code: str | None = None,
    offset: int = 0,
    limit: int | None = None,
    priority_thresholds: Mapping[str, float] | None = None,
    include_ownership: bool = False,
) -> list[MatchResult]:
    asset_load_options = [
        selectinload(MatchResult.asset).selectinload(Asset.exposures),
        selectinload(MatchResult.asset).selectinload(Asset.snapshots),
    ]
    if include_ownership:
        asset_load_options.append(
            selectinload(MatchResult.asset)
            .selectinload(Asset.business_system_record)
            .selectinload(BusinessSystem.responsible_person)
            .selectinload(Person.team)
        )
    statement = (
        select(MatchResult)
        .join(MatchResult.asset)
        .join(MatchResult.vulnerability)
        .options(
            *asset_load_options,
            selectinload(MatchResult.vulnerability),
            selectinload(MatchResult.verification_tasks),
            selectinload(MatchResult.verification_evidence),
        )
        .where(MatchResult.status.in_(statuses))
        .order_by(desc(MatchResult.risk_score), desc(MatchResult.updated_at))
    )
    if min_risk_score is not None:
        statement = statement.where(MatchResult.risk_score >= min_risk_score)
    if risk_priority:
        minimum_score, maximum_score = risk_priority_bounds(
            risk_priority,
            thresholds=priority_thresholds,
        )
        statement = statement.where(MatchResult.risk_score >= minimum_score)
        if maximum_score is not None:
            statement = statement.where(MatchResult.risk_score < maximum_score)
    if asset_criticality:
        statement = statement.where(Asset.criticality == asset_criticality)
    if exposure_type:
        statement = statement.where(Asset.exposure_type == exposure_type)
    if business_system_id:
        statement = statement.where(Asset.business_system_id == business_system_id)
    if responsible_person_id:
        statement = statement.where(
            Asset.business_system_record.has(
                BusinessSystem.responsible_person_id == responsible_person_id
            )
        )
    if responsibility_team_id:
        statement = statement.where(
            Asset.business_system_record.has(
                BusinessSystem.responsible_person.has(
                    Person.team_id == responsibility_team_id
                )
            )
        )
    if kev_only:
        statement = statement.where(Vulnerability.kev_status.is_(True))
    if risk_code and risk_code.strip():
        statement = statement.where(
            MatchResult.risk_code.ilike(f"%{risk_code.strip()}%")
        )
    if handling_status:
        statement = statement.where(MatchResult.handling_status == handling_status)
    elif handling_scope == "open":
        statement = statement.where(MatchResult.handling_status.in_(OPEN_HANDLING_STATUSES))
    elif handling_scope == "closed":
        statement = statement.where(MatchResult.handling_status.in_(CLOSED_HANDLING_STATUSES))
    if offset:
        statement = statement.offset(offset)
    if limit is not None:
        statement = statement.limit(limit)
    return list(db.scalars(statement).all())


def _filter_operational_results(
    results: list[MatchResult],
    *,
    agent_status_by_id: dict[str, AgentStatus],
    verification_state: str | None,
    agent_status: str | None,
    asset_freshness: str | None,
) -> list[MatchResult]:
    filtered = results
    if verification_state:
        filtered = [
            result
            for result in filtered
            if _matches_verification_state(result, verification_state)
        ]
    if agent_status:
        filtered = [
            result
            for result in filtered
            if _agent_status_for_result(result, agent_status_by_id) == agent_status
        ]
    if asset_freshness:
        filtered = [
            result
            for result in filtered
            if _asset_freshness_for_result(result) == asset_freshness
        ]
    return filtered


def _risk_queue_stats(results: list[MatchResult]) -> dict[str, int]:
    return {
        "total": len(results),
        "critical": sum(1 for result in results if _is_critical_risk(result)),
        "unverified": sum(1 for result in results if _is_unverified_risk(result)),
        "stale": sum(
            1 for result in results if _asset_freshness_for_result(result) == "stale"
        ),
    }


def _is_critical_risk(result: MatchResult) -> bool:
    return _risk_breakdown_for_result(result).priority == "critical"


def _is_unverified_risk(result: MatchResult) -> bool:
    return result.status != "verified" and not result.verification_evidence


def _matches_verification_state(result: MatchResult, verification_state: str) -> bool:
    is_verified = result.status == "verified" or bool(result.verification_evidence)
    has_task = bool(result.verification_tasks)
    if verification_state == "verified":
        return is_verified
    if verification_state == "unverified":
        return not is_verified
    if verification_state == "has_task":
        return has_task
    if verification_state == "no_task":
        return not has_task
    return True


def _agent_status_for_result(
    result: MatchResult,
    agent_status_by_id: dict[str, AgentStatus],
) -> str:
    if not result.asset.agent_id:
        return "unknown"
    status = agent_status_by_id.get(result.asset.agent_id)
    if status is None:
        return "unknown"
    return compute_agent_status(status)


def _asset_freshness_for_result(result: MatchResult) -> str:
    freshness = build_asset_freshness(_latest_asset_snapshot(result.asset))
    return "stale" if freshness.is_stale else "fresh"


def _risk_breakdown_for_result(result: MatchResult):
    if result.risk_model_version and result.risk_factors_json:
        return _StoredRiskBreakdown(
            score=result.risk_score,
            priority=result.risk_priority,
            model_version=result.risk_model_version,
            factors=result.risk_factors_json,
            explanation=result.risk_explanation,
        )
    return calculate_match_risk(
        status=result.status,
        severity_cvss=result.vulnerability.severity_cvss,
        kev_status=result.vulnerability.kev_status,
        poc_status=result.vulnerability.poc_status,
        wild_exploitation_status=result.vulnerability.wild_exploitation_status,
        epss=result.vulnerability.epss,
        exposure_type=result.asset.exposure_type,
        has_public_exposure=any(exposure.is_public for exposure in result.asset.exposures),
        asset_criticality=result.asset.criticality,
        confidence=result.confidence,
    )


class _StoredRiskBreakdown:
    def __init__(
        self,
        *,
        score: float,
        priority: str,
        model_version: str,
        factors: list[dict],
        explanation: str | None,
    ) -> None:
        self.score = score
        self.priority = priority or risk_priority(score)
        self.model_version = model_version
        self.factors = factors
        self.explanation = explanation or ""

    def factor_dicts(self) -> list[dict[str, object]]:
        return list(self.factors)


def _to_vulnerability_ranking(
    results: list[MatchResult],
    *,
    priority_thresholds: Mapping[str, float] | None = None,
) -> VulnerabilityRiskRanking:
    ordered_results = sorted(results, key=lambda result: result.risk_score, reverse=True)
    top_result = ordered_results[0]
    vulnerability = top_result.vulnerability
    scores = [result.risk_score for result in results]
    return VulnerabilityRiskRanking(
        vulnerability_id=vulnerability.id,
        vulnerability_canonical_id=vulnerability.canonical_id,
        vulnerability_title=vulnerability.title,
        risk_priority=risk_priority(max(scores), thresholds=priority_thresholds),
        max_risk_score=round(max(scores), 2),
        average_risk_score=round(sum(scores) / len(scores), 2),
        total_risk_score=round(sum(scores), 2),
        result_count=len(results),
        affected_count=sum(1 for result in results if result.status == "affected"),
        needs_review_count=sum(1 for result in results if result.status == "needs_review"),
        top_asset_id=top_result.asset_id,
        top_asset_hostname=top_result.asset.hostname,
    )


def _to_asset_ranking(
    results: list[MatchResult],
    *,
    priority_thresholds: Mapping[str, float] | None = None,
) -> AssetRiskRanking:
    ordered_results = sorted(results, key=lambda result: result.risk_score, reverse=True)
    top_result = ordered_results[0]
    asset = top_result.asset
    vulnerability = top_result.vulnerability
    scores = [result.risk_score for result in results]
    return AssetRiskRanking(
        asset_id=asset.id,
        asset_hostname=asset.hostname,
        asset_criticality=asset.criticality,
        asset_exposure_type=asset.exposure_type,
        business_system=asset.business_system,
        risk_priority=risk_priority(max(scores), thresholds=priority_thresholds),
        max_risk_score=round(max(scores), 2),
        average_risk_score=round(sum(scores) / len(scores), 2),
        total_risk_score=round(sum(scores), 2),
        result_count=len(results),
        affected_count=sum(1 for result in results if result.status == "affected"),
        needs_review_count=sum(1 for result in results if result.status == "needs_review"),
        top_vulnerability_id=vulnerability.id,
        top_vulnerability_canonical_id=vulnerability.canonical_id,
        top_vulnerability_title=vulnerability.title,
    )
