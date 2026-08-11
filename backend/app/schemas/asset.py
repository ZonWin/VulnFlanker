from __future__ import annotations

from datetime import datetime

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.agent import AgentStatusOut


class AssetComponentOut(BaseModel):
    id: str
    component_name: str
    component_type: str
    version: str | None = None
    source_type: str | None = None
    ecosystem: str | None = None
    distro: str | None = None
    distro_release: str | None = None
    source_package: str | None = None
    binary_package: str | None = None
    architecture: str | None = None
    flavor: str | None = None
    version_scheme: str | None = None
    purl: str | None = None
    cpe: str | None = None
    install_path: str | None = None
    evidence_ref: str | None = None


class AssetExposureOut(BaseModel):
    id: str
    exposure_kind: str
    address: str | None = None
    port: int | None = None
    protocol: str
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    state: str
    is_public: bool
    banner: str | None = None
    evidence_ref: str | None = None


class AssetSnapshotSummary(BaseModel):
    id: str
    agent_id: str
    agent_version: str | None = None
    platform: str | None = None
    collected_at: datetime
    received_at: datetime
    payload_hash: str
    component_count: int
    exposure_count: int
    firewall_count: int = 0
    firewall_rule_count: int = 0


class AssetOwnershipBusinessSystem(BaseModel):
    id: str
    code: str
    name: str
    status: str


class AssetOwnershipPerson(BaseModel):
    id: str
    name: str
    email: str | None = None
    status: str


class AssetOwnershipTeam(BaseModel):
    id: str
    code: str
    name: str
    status: str


class AssetOwnership(BaseModel):
    status: Literal["complete", "unassigned", "system_incomplete"]
    source: str | None = None
    updated_at: datetime | None = None
    business_system: AssetOwnershipBusinessSystem | None = None
    responsible_person: AssetOwnershipPerson | None = None
    responsibility_team: AssetOwnershipTeam | None = None


class AssetSummary(BaseModel):
    id: str
    agent_id: str | None = None
    hostname: str
    display_name: str | None = None
    primary_ip: str | None = None
    platform: str | None = None
    os_family: str | None = None
    os_version: str | None = None
    architecture: str | None = None
    criticality: str
    environment_type: str
    exposure_type: str
    last_seen_at: datetime | None = None
    component_count: int
    exposure_count: int
    ownership: AssetOwnership


class AssetListPage(BaseModel):
    items: list[AssetSummary] = Field(default_factory=list)
    offset: int = 0
    limit: int
    has_more: bool = False
    total: int = 0
    high_criticality_count: int = 0
    public_exposure_count: int = 0
    incomplete_ownership_count: int = 0


class AssetFirewallOut(BaseModel):
    id: str
    engine: str
    role: str
    backend: str | None = None
    managed_by: str | None = None
    effective: bool
    installed: bool
    runtime_state: str
    service_enabled: bool | None = None
    collection_status: str
    error_code: str | None = None
    error_message: str | None = None
    runtime_rule_count: int
    permanent_rule_count: int
    last_attempt_at: datetime
    last_success_at: datetime | None = None


class AssetFirewallList(BaseModel):
    items: list[AssetFirewallOut]
    total: int


class AssetFirewallRuleOut(BaseModel):
    id: str
    firewall_id: str
    engine: str
    scope: str
    family: str | None = None
    table: str | None = None
    chain: str | None = None
    zone: str | None = None
    order: int
    rule_kind: str
    action: str | None = None
    protocol: str | None = None
    source: str | None = None
    destination: str | None = None
    source_port: str | None = None
    destination_port: str | None = None
    in_interface: str | None = None
    out_interface: str | None = None
    state_match: str | None = None
    comment: str | None = None
    raw_rule: str


class AssetFirewallRuleList(BaseModel):
    items: list[AssetFirewallRuleOut]
    total: int
    page: int
    page_size: int


class AssetFirewallRawOut(BaseModel):
    engine: str
    scope: Literal["runtime", "permanent"]
    content: str | None = None
    collection_status: str
    last_success_at: datetime | None = None


class AssetFreshnessOut(BaseModel):
    last_snapshot_at: datetime | None = None
    snapshot_age_seconds: int | None = None
    stale_after_seconds: int
    is_stale: bool


class AssetDetail(AssetSummary):
    kernel_version: str | None = None
    business_system: str | None = None
    owner_team: str | None = None
    owner_person: str | None = None
    allow_auto_verify: bool
    allow_auto_remediate: bool
    snapshots_count: int
    latest_snapshot: AssetSnapshotSummary | None = None
    agent_status: AgentStatusOut | None = None
    freshness: AssetFreshnessOut
    components: list[AssetComponentOut]
    exposures: list[AssetExposureOut]


class AssetMetadataUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_name: str | None = Field(default=None, max_length=255)
    environment_type: str | None = Field(default=None, min_length=1, max_length=32)
    exposure_type: str | None = Field(default=None, min_length=1, max_length=32)
    criticality: str | None = Field(default=None, min_length=1, max_length=32)
    allow_auto_verify: bool | None = None
    allow_auto_remediate: bool | None = None


class AssetDeleteRequest(BaseModel):
    delete_agent: bool = False


class AssetBusinessSystemBinding(BaseModel):
    business_system_id: str | None = Field(default=None, max_length=36)


class AssetBusinessSystemBulkBinding(AssetBusinessSystemBinding):
    asset_ids: list[str] = Field(min_length=1, max_length=500)

    @field_validator("asset_ids")
    @classmethod
    def validate_unique_asset_ids(cls, value: list[str]) -> list[str]:
        cleaned = [asset_id.strip() for asset_id in value if asset_id.strip()]
        if len(cleaned) != len(value):
            raise ValueError("asset_ids cannot contain empty values")
        if len(set(cleaned)) != len(cleaned):
            raise ValueError("asset_ids cannot contain duplicates")
        return cleaned


class AssetBusinessSystemBulkBindingOut(BaseModel):
    updated_count: int
    asset_ids: list[str]
    business_system_id: str | None = None
