from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.version import APP_VERSION


class AgentHeartbeatIn(BaseModel):
    agent_id: str = Field(..., description="Agent 唯一标识")
    hostname: str
    platform: str
    version: str


class AgentHeartbeatOut(BaseModel):
    status: str
    message: str


class AgentEnrollIn(BaseModel):
    enrollment_token: str
    agent_id: str | None = None
    hostname: str
    platform: str = "linux"
    version: str = APP_VERSION


class AgentEnrollOut(BaseModel):
    agent_id: str
    agent_secret: str
    agent_api_prefix: str


class AgentEnrollmentTokenCreateIn(BaseModel):
    name: str = "default"
    expires_at: datetime | None = None
    max_uses: int | None = Field(default=1, ge=1)


class AgentEnrollmentTokenCreateOut(BaseModel):
    id: str
    name: str
    enrollment_token: str
    token_preview: str | None = None
    status: str
    expires_at: datetime | None = None
    max_uses: int | None = None
    used_count: int
    created_by: str | None = None
    created_by_display: str | None = None
    revoked_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class AgentEnrollmentTokenOut(BaseModel):
    id: str
    name: str
    token_preview: str | None = None
    status: str
    expires_at: datetime | None = None
    max_uses: int | None = None
    used_count: int
    created_by: str | None = None
    created_by_display: str | None = None
    revoked_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class AgentTaskStats(BaseModel):
    queued: int = 0
    in_progress: int = 0
    cancel_requested: int = 0
    cancelled: int = 0
    completed: int = 0
    failed: int = 0
    rejected: int = 0
    total: int = 0


class AgentStatusOut(BaseModel):
    agent_id: str
    hostname: str | None = None
    platform: str | None = None
    version: str | None = None
    status: str
    last_heartbeat_at: datetime | None = None
    last_snapshot_at: datetime | None = None
    last_task_poll_at: datetime | None = None
    last_error: str | None = None
    created_at: datetime
    updated_at: datetime


class AgentSummary(AgentStatusOut):
    asset_id: str | None = None
    asset_hostname: str | None = None
    asset_primary_ip: str | None = None
    asset_last_seen_at: datetime | None = None
    task_stats: AgentTaskStats = Field(default_factory=AgentTaskStats)


class AgentDetail(AgentSummary):
    pass


class LifecycleActionOut(BaseModel):
    status: str
    agent_id: str | None = None
    asset_id: str | None = None
    asset_deleted: bool = False
    agent_deleted: bool = False
    agent_disabled: bool = False
    match_results_deleted: int = 0
    verification_tasks_deleted: int = 0


class AssetComponentIn(BaseModel):
    component_name: str
    component_type: str
    version: str | None = None
    source_type: str | None = None
    ecosystem: str | None = Field(default=None, max_length=32)
    distro: str | None = Field(default=None, max_length=64)
    distro_release: str | None = Field(default=None, max_length=64)
    source_package: str | None = Field(default=None, max_length=255)
    binary_package: str | None = Field(default=None, max_length=255)
    architecture: str | None = Field(default=None, max_length=64)
    flavor: str | None = Field(default=None, max_length=64)
    version_scheme: str | None = Field(default=None, max_length=32)
    purl: str | None = Field(default=None, max_length=512)
    cpe: str | None = Field(default=None, max_length=512)
    install_path: str | None = None
    evidence_ref: str | None = None


class AssetExposureIn(BaseModel):
    exposure_kind: str
    address: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    protocol: str = "tcp"
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    state: str = "open"
    is_public: bool = False
    banner: str | None = None
    evidence_ref: str | None = None


FirewallEngine = Literal["firewalld", "ufw", "iptables", "nftables"]
FirewallRole = Literal["manager", "backend", "compatibility", "standalone"]
FirewallRuntimeState = Literal["active", "inactive", "configured", "unknown"]
FirewallCollectionStatus = Literal[
    "success",
    "partial",
    "unsupported",
    "permission_denied",
    "timeout",
    "error",
]
FirewallRuleScope = Literal["runtime", "permanent"]


class AssetFirewallRuleIn(BaseModel):
    scope: FirewallRuleScope = "runtime"
    family: str | None = Field(default=None, max_length=16)
    table: str | None = Field(default=None, max_length=128)
    chain: str | None = Field(default=None, max_length=128)
    zone: str | None = Field(default=None, max_length=128)
    order: int = Field(default=0, ge=0)
    rule_kind: str = Field(default="rule", max_length=32)
    action: str | None = Field(default=None, max_length=64)
    protocol: str | None = Field(default=None, max_length=32)
    source: str | None = Field(default=None, max_length=4096)
    destination: str | None = Field(default=None, max_length=4096)
    source_port: str | None = Field(default=None, max_length=128)
    destination_port: str | None = Field(default=None, max_length=128)
    in_interface: str | None = Field(default=None, max_length=128)
    out_interface: str | None = Field(default=None, max_length=128)
    state_match: str | None = Field(default=None, max_length=255)
    comment: str | None = Field(default=None, max_length=4096)
    raw_rule: str = Field(min_length=1, max_length=262_144)


class AssetFirewallIn(BaseModel):
    engine: FirewallEngine
    role: FirewallRole = "standalone"
    backend: str | None = Field(default=None, max_length=32)
    managed_by: str | None = Field(default=None, max_length=32)
    effective: bool = False
    installed: bool = True
    runtime_state: FirewallRuntimeState = "unknown"
    service_enabled: bool | None = None
    collection_status: FirewallCollectionStatus = "success"
    error_code: str | None = Field(default=None, max_length=64)
    error_message: str | None = Field(default=None, max_length=1024)
    raw_runtime: str | None = Field(default=None, max_length=1_048_576)
    raw_permanent: str | None = Field(default=None, max_length=1_048_576)
    rules: list[AssetFirewallRuleIn] = Field(default_factory=list, max_length=20_000)


class AssetSnapshotIn(BaseModel):
    model_config = ConfigDict(extra="allow")

    agent_id: str
    agent_version: str | None = None
    hostname: str
    primary_ip: str | None = None
    platform: str = "linux"
    os_family: str | None = None
    os_version: str | None = None
    kernel_version: str | None = None
    architecture: str | None = None
    environment_type: str = "production"
    exposure_type: str = "internal"
    business_system: str | None = None
    owner_team: str | None = None
    owner_person: str | None = None
    criticality: str = "medium"
    allow_auto_verify: bool = False
    allow_auto_remediate: bool = False
    collected_at: datetime | None = None
    components: list[AssetComponentIn] = Field(default_factory=list)
    exposures: list[AssetExposureIn] = Field(default_factory=list)
    firewalls: list[AssetFirewallIn] | None = Field(default=None, max_length=16)

    @model_validator(mode="after")
    def validate_unique_firewall_engines(self) -> "AssetSnapshotIn":
        if self.firewalls is None:
            return self
        engines = [firewall.engine.strip().lower() for firewall in self.firewalls]
        if len(engines) != len(set(engines)):
            raise ValueError("firewalls cannot contain duplicate engines")
        return self


class AssetSnapshotSubmissionOut(BaseModel):
    status: str
    asset_id: str
    snapshot_id: str
    asset_action: str
    snapshot_action: str
    component_count: int
    exposure_count: int
    firewall_count: int = 0
    firewall_rule_count: int = 0
