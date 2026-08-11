from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, utcnow


class Asset(TimestampMixin, Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    agent_id: Mapped[str | None] = mapped_column(String(128), unique=True, index=True, nullable=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    primary_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    platform: Mapped[str | None] = mapped_column(String(64), nullable=True)
    os_family: Mapped[str | None] = mapped_column(String(64), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    kernel_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    architecture: Mapped[str | None] = mapped_column(String(64), nullable=True)
    environment_type: Mapped[str] = mapped_column(String(32), default="production")
    exposure_type: Mapped[str] = mapped_column(String(32), default="internal")
    business_system: Mapped[str | None] = mapped_column(String(255), nullable=True)
    owner_team: Mapped[str | None] = mapped_column(String(255), nullable=True)
    owner_person: Mapped[str | None] = mapped_column(String(255), nullable=True)
    business_system_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("business_systems.id", ondelete="RESTRICT"),
        index=True,
        nullable=True,
    )
    ownership_source: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ownership_updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    criticality: Mapped[str] = mapped_column(String(32), default="medium")
    allow_auto_verify: Mapped[bool] = mapped_column(Boolean, default=False)
    allow_auto_remediate: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    components: Mapped[list["AssetComponent"]] = relationship(
        back_populates="asset",
        cascade="all, delete-orphan",
    )
    exposures: Mapped[list["AssetExposure"]] = relationship(
        back_populates="asset",
        cascade="all, delete-orphan",
    )
    firewalls: Mapped[list["AssetFirewall"]] = relationship(
        back_populates="asset",
        cascade="all, delete-orphan",
    )
    snapshots: Mapped[list["AssetSnapshot"]] = relationship(
        back_populates="asset",
        cascade="all, delete-orphan",
    )
    match_results: Mapped[list["MatchResult"]] = relationship(back_populates="asset")
    verification_tasks: Mapped[list["VerificationTask"]] = relationship(back_populates="asset")
    business_system_record: Mapped["BusinessSystem | None"] = relationship(
        back_populates="assets"
    )


class AssetComponent(TimestampMixin, Base):
    __tablename__ = "asset_components"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    component_name: Mapped[str] = mapped_column(String(255), index=True)
    component_type: Mapped[str] = mapped_column(String(64), index=True)
    version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    source_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ecosystem: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    distro: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    distro_release: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_package: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    binary_package: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    architecture: Mapped[str | None] = mapped_column(String(64), nullable=True)
    flavor: Mapped[str | None] = mapped_column(String(64), nullable=True)
    version_scheme: Mapped[str | None] = mapped_column(String(32), nullable=True)
    purl: Mapped[str | None] = mapped_column(String(512), nullable=True)
    cpe: Mapped[str | None] = mapped_column(String(512), nullable=True)
    install_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_ref: Mapped[str | None] = mapped_column(Text, nullable=True)

    asset: Mapped["Asset"] = relationship(back_populates="components")


class AssetExposure(TimestampMixin, Base):
    __tablename__ = "asset_exposures"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    exposure_kind: Mapped[str] = mapped_column(String(64), index=True)
    address: Mapped[str | None] = mapped_column(String(128), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(16), default="tcp")
    service_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    state: Mapped[str] = mapped_column(String(32), default="open")
    is_public: Mapped[bool] = mapped_column(Boolean, default=False)
    banner: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_ref: Mapped[str | None] = mapped_column(Text, nullable=True)

    asset: Mapped["Asset"] = relationship(back_populates="exposures")


class AssetFirewall(TimestampMixin, Base):
    __tablename__ = "asset_firewalls"
    __table_args__ = (
        UniqueConstraint(
            "asset_id",
            "engine",
            name="uq_asset_firewalls_asset_engine",
        ),
        CheckConstraint(
            "engine IN ('firewalld', 'ufw', 'iptables', 'nftables')",
            name="ck_asset_firewalls_engine",
        ),
        CheckConstraint(
            "role IN ('manager', 'backend', 'compatibility', 'standalone')",
            name="ck_asset_firewalls_role",
        ),
        CheckConstraint(
            "runtime_state IN ('active', 'inactive', 'configured', 'unknown')",
            name="ck_asset_firewalls_runtime_state",
        ),
        CheckConstraint(
            "collection_status IN ('success', 'partial', 'unsupported', "
            "'permission_denied', 'timeout', 'error')",
            name="ck_asset_firewalls_collection_status",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    asset_id: Mapped[str] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"),
        index=True,
    )
    engine: Mapped[str] = mapped_column(String(32), index=True)
    role: Mapped[str] = mapped_column(String(32), default="standalone")
    backend: Mapped[str | None] = mapped_column(String(32), nullable=True)
    managed_by: Mapped[str | None] = mapped_column(String(32), nullable=True)
    effective: Mapped[bool] = mapped_column(Boolean, default=False)
    installed: Mapped[bool] = mapped_column(Boolean, default=True)
    runtime_state: Mapped[str] = mapped_column(String(32), default="unknown")
    service_enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    collection_status: Mapped[str] = mapped_column(String(32), default="success")
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    runtime_rule_count: Mapped[int] = mapped_column(Integer, default=0)
    permanent_rule_count: Mapped[int] = mapped_column(Integer, default=0)
    raw_runtime: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_permanent: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )
    last_success_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    asset: Mapped["Asset"] = relationship(back_populates="firewalls")
    rules: Mapped[list["AssetFirewallRule"]] = relationship(
        back_populates="firewall",
        cascade="all, delete-orphan",
        order_by="AssetFirewallRule.rule_order",
    )


class AssetFirewallRule(TimestampMixin, Base):
    __tablename__ = "asset_firewall_rules"
    __table_args__ = (
        CheckConstraint(
            "scope IN ('runtime', 'permanent')",
            name="ck_asset_firewall_rules_scope",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    firewall_id: Mapped[str] = mapped_column(
        ForeignKey("asset_firewalls.id", ondelete="CASCADE"),
        index=True,
    )
    scope: Mapped[str] = mapped_column(String(32), index=True)
    family: Mapped[str | None] = mapped_column(String(16), nullable=True)
    table_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    chain_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    zone: Mapped[str | None] = mapped_column(String(128), nullable=True)
    rule_order: Mapped[int] = mapped_column(Integer, default=0)
    rule_kind: Mapped[str] = mapped_column(String(32), default="rule")
    action: Mapped[str | None] = mapped_column(String(64), nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(32), nullable=True)
    source: Mapped[str | None] = mapped_column(Text, nullable=True)
    destination: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_port: Mapped[str | None] = mapped_column(String(128), nullable=True)
    destination_port: Mapped[str | None] = mapped_column(String(128), nullable=True)
    in_interface: Mapped[str | None] = mapped_column(String(128), nullable=True)
    out_interface: Mapped[str | None] = mapped_column(String(128), nullable=True)
    state_match: Mapped[str | None] = mapped_column(String(255), nullable=True)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_rule: Mapped[str] = mapped_column(Text)

    firewall: Mapped["AssetFirewall"] = relationship(back_populates="rules")


class AssetSnapshot(TimestampMixin, Base):
    __tablename__ = "asset_snapshots"
    __table_args__ = (
        UniqueConstraint(
            "asset_id",
            "payload_hash",
            name="uq_asset_snapshots_asset_payload_hash",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    agent_id: Mapped[str] = mapped_column(String(128), index=True)
    agent_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    platform: Mapped[str | None] = mapped_column(String(64), nullable=True)
    hostname: Mapped[str] = mapped_column(String(255))
    primary_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    os_family: Mapped[str | None] = mapped_column(String(64), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    kernel_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    architecture: Mapped[str | None] = mapped_column(String(64), nullable=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_payload: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    component_count: Mapped[int] = mapped_column(Integer, default=0)
    exposure_count: Mapped[int] = mapped_column(Integer, default=0)
    firewall_count: Mapped[int] = mapped_column(Integer, default=0)
    firewall_rule_count: Mapped[int] = mapped_column(Integer, default=0)

    asset: Mapped["Asset"] = relationship(back_populates="snapshots")
