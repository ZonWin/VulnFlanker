from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.asset import AssetOwnership
from app.schemas.verification import VerificationEvidenceOut


class MatchEvaluationRequest(BaseModel):
    asset_id: str | None = None
    vulnerability_id: str | None = None


class MatchEvaluationResponse(BaseModel):
    run_id: str
    task_id: str | None = None
    status: str
    asset_id: str | None = None
    vulnerability_id: str | None = None
    total_count: int = 0
    processed_count: int = 0
    evaluated_count: int
    skipped_count: int = 0
    failed_count: int = 0
    sample_result_ids: list[str] = Field(default_factory=list)
    recent_error: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class MatchEvidenceOut(BaseModel):
    id: str
    evidence_type: str
    summary: str
    raw_ref: str | None = None
    confidence: float
    details: dict[str, object] = Field(default_factory=dict)


class MatchRuleTraceOut(BaseModel):
    rule_name: str
    rule_version: str
    executed: bool
    status: str
    confidence: float
    reason: str
    reason_code: str | None = None
    uncertain_reason: str | None = None
    input_summary: dict[str, object] = Field(default_factory=dict)
    risk_scope: dict[str, object] = Field(default_factory=dict)
    asset_context: dict[str, object] = Field(default_factory=dict)
    evidence_count: int = 0


class RiskFactorOut(BaseModel):
    name: str
    label: str
    value: float
    weight: float
    weighted_score: float
    evidence: list[str] = Field(default_factory=list)


class RiskConfigOut(BaseModel):
    model_version: str
    weights: dict[str, float]
    priority_thresholds: dict[str, float]
    weight_total: float
    warnings: list[str] = Field(default_factory=list)


MatchHandlingStatus = Literal[
    "unprocessed",
    "notified",
    "remediating",
    "pending_review",
    "resolved",
    "false_positive",
    "risk_accepted",
]


class MatchResultHandlingUpdateIn(BaseModel):
    handling_status: MatchHandlingStatus
    note: str | None = Field(default=None, max_length=4000)


class MatchResultHandlingReopenIn(BaseModel):
    note: str | None = Field(default=None, max_length=4000)


class MatchResultHandlingRecordOut(BaseModel):
    id: str
    match_result_id: str
    action: str
    from_status: MatchHandlingStatus | None = None
    to_status: MatchHandlingStatus
    note: str | None = None
    actor_id: str | None = None
    actor_username: str | None = None
    actor_display_name: str | None = None
    created_at: datetime


class MatchResultSummary(BaseModel):
    id: str
    risk_code: str | None = None
    vulnerability_id: str
    vulnerability_canonical_id: str
    vulnerability_title: str
    vulnerability_product: str | None = None
    vulnerability_kev_status: bool = False
    asset_id: str
    asset_hostname: str
    asset_agent_id: str | None = None
    asset_agent_status: str | None = None
    asset_last_seen_at: datetime | None = None
    asset_snapshot_age_seconds: int | None = None
    asset_is_stale: bool = True
    asset_exposure_type: str | None = None
    asset_criticality: str | None = None
    asset_has_public_exposure: bool = False
    ownership: AssetOwnership
    status: str
    confidence: float
    risk_score: float
    risk_priority: str = "none"
    risk_model_version: str = "risk-v1"
    risk_factors: list[RiskFactorOut] = Field(default_factory=list)
    risk_explanation: str | None = None
    handling_status: MatchHandlingStatus = "unprocessed"
    handling_note: str | None = None
    handling_updated_by: str | None = None
    handling_updated_at: datetime | None = None
    handling_closed_at: datetime | None = None
    match_reason: str | None = None
    rule_version: str
    last_evaluated_at: datetime | None = None
    latest_verification_task_id: str | None = None
    latest_verification_task_status: str | None = None
    verification_task_count: int = 0
    verification_evidence_count: int = 0


class MatchResultListPage(BaseModel):
    items: list[MatchResultSummary] = Field(default_factory=list)
    offset: int = 0
    limit: int
    has_more: bool = False
    total: int = 0
    critical_count: int = 0
    unverified_count: int = 0
    stale_asset_count: int = 0


class MatchResultDetail(MatchResultSummary):
    evidence: list[MatchEvidenceOut] = Field(default_factory=list)
    matching_trace: list[MatchRuleTraceOut] = Field(default_factory=list)
    verification_evidence: list[VerificationEvidenceOut] = Field(default_factory=list)
    handling_records: list[MatchResultHandlingRecordOut] = Field(default_factory=list)


class VulnerabilityRiskRanking(BaseModel):
    vulnerability_id: str
    vulnerability_canonical_id: str
    vulnerability_title: str
    risk_priority: str
    max_risk_score: float
    average_risk_score: float
    total_risk_score: float
    result_count: int
    affected_count: int
    needs_review_count: int
    top_asset_id: str | None = None
    top_asset_hostname: str | None = None


class AssetRiskRanking(BaseModel):
    asset_id: str
    asset_hostname: str
    asset_criticality: str
    asset_exposure_type: str
    business_system: str | None = None
    risk_priority: str
    max_risk_score: float
    average_risk_score: float
    total_risk_score: float
    result_count: int
    affected_count: int
    needs_review_count: int
    top_vulnerability_id: str | None = None
    top_vulnerability_canonical_id: str | None = None
    top_vulnerability_title: str | None = None
