from __future__ import annotations

import hashlib
import json
import re
import unicodedata

from sqlalchemy import desc, select
from sqlalchemy.orm import Session, selectinload

from app.db.base import utcnow
from app.db.models import (
    Asset,
    AssetComponent,
    AssetExposure,
    AssetFirewall,
    AssetFirewallRule,
    AssetSnapshot,
    BusinessSystem,
    Person,
)
from app.schemas.agent import (
    AgentHeartbeatIn,
    AgentHeartbeatOut,
    AssetComponentIn,
    AssetExposureIn,
    AssetFirewallIn,
    AssetFirewallRuleIn,
    AssetSnapshotIn,
    AssetSnapshotSubmissionOut,
)
from app.services.agent_status import record_agent_heartbeat, record_agent_snapshot
from app.services.audit import create_audit_log
from app.services.auto_matching import maybe_auto_match_new_asset
from app.services.notifications import create_system_event


def register_heartbeat(db: Session, payload: AgentHeartbeatIn) -> AgentHeartbeatOut:
    record_agent_heartbeat(db, payload)
    db.commit()
    return AgentHeartbeatOut(
        status="accepted",
        message=f"heartbeat received from {payload.hostname}",
    )


def ingest_asset_snapshot(
    db: Session,
    payload: AssetSnapshotIn,
) -> AssetSnapshotSubmissionOut:
    normalized_payload = payload.model_dump(mode="json", exclude_none=True)
    payload_hash = _compute_payload_hash(normalized_payload)
    collected_at = payload.collected_at or utcnow()
    received_at = utcnow()

    asset = db.scalar(select(Asset).where(Asset.agent_id == payload.agent_id))
    asset_action = "updated"
    should_initialize_metadata = False
    if asset is None:
        asset = Asset(
            agent_id=payload.agent_id,
            hostname=payload.hostname,
        )
        db.add(asset)
        db.flush()
        asset_action = "created"
        should_initialize_metadata = True

    snapshot = db.scalar(
        select(AssetSnapshot)
        .where(
            AssetSnapshot.asset_id == asset.id,
            AssetSnapshot.payload_hash == payload_hash,
        )
        .order_by(desc(AssetSnapshot.received_at))
    )
    snapshot_action = "deduplicated"
    if snapshot is None:
        _apply_asset_profile(
            asset,
            payload,
            collected_at,
            update_metadata=should_initialize_metadata,
        )
        if should_initialize_metadata:
            _apply_ownership_hint(db, asset, payload)
        asset.components = [_build_component(component) for component in payload.components]
        asset.exposures = [_build_exposure(exposure) for exposure in payload.exposures]
        if payload.firewalls is not None:
            _sync_firewalls(asset, payload.firewalls, collected_at)
        firewall_count = len(payload.firewalls or [])
        firewall_rule_count = sum(
            len(firewall.rules) for firewall in (payload.firewalls or [])
        )
        snapshot = AssetSnapshot(
            asset_id=asset.id,
            agent_id=payload.agent_id,
            agent_version=payload.agent_version,
            platform=payload.platform,
            hostname=payload.hostname,
            primary_ip=payload.primary_ip,
            os_family=payload.os_family,
            os_version=payload.os_version,
            kernel_version=payload.kernel_version,
            architecture=payload.architecture,
            collected_at=collected_at,
            received_at=received_at,
            payload_hash=payload_hash,
            raw_payload=normalized_payload,
            component_count=len(payload.components),
            exposure_count=len(payload.exposures),
            firewall_count=firewall_count,
            firewall_rule_count=firewall_rule_count,
        )
        db.add(snapshot)
        snapshot_action = "created"
    else:
        _apply_asset_profile(
            asset,
            payload,
            collected_at,
            update_metadata=should_initialize_metadata,
        )
        snapshot.received_at = received_at

    record_agent_snapshot(db, payload, received_at=received_at)

    if asset_action == "created":
        create_system_event(
            db,
            event_key=f"asset.created:{asset.id}",
            category="asset",
            event_type="asset_created",
            level="success",
            title="新增资产",
            summary=f"本次资产同步新增 1 台资产：{asset.hostname}。",
            details={
                "created_count": 1,
                "asset_ids": [asset.id],
                "assets": [
                    {
                        "asset_id": asset.id,
                        "agent_id": asset.agent_id,
                        "hostname": asset.hostname,
                        "primary_ip": asset.primary_ip,
                    }
                ],
                "source": "agent_snapshot",
            },
            target_type="asset",
            target_id=asset.id,
            occurred_at=received_at,
        )

    db.commit()
    if asset_action == "created":
        maybe_auto_match_new_asset(db, asset.id)

    return AssetSnapshotSubmissionOut(
        status="stored",
        asset_id=asset.id,
        snapshot_id=snapshot.id,
        asset_action=asset_action,
        snapshot_action=snapshot_action,
        component_count=len(payload.components),
        exposure_count=len(payload.exposures),
        firewall_count=len(payload.firewalls or []),
        firewall_rule_count=sum(
            len(firewall.rules) for firewall in (payload.firewalls or [])
        ),
    )


def _compute_payload_hash(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _apply_asset_profile(
    asset: Asset,
    payload: AssetSnapshotIn,
    collected_at,
    *,
    update_metadata: bool,
) -> None:
    asset.hostname = payload.hostname
    asset.primary_ip = payload.primary_ip
    asset.platform = payload.platform
    asset.os_family = payload.os_family
    asset.os_version = payload.os_version
    asset.kernel_version = payload.kernel_version
    asset.architecture = payload.architecture
    if update_metadata:
        asset.environment_type = payload.environment_type
        asset.exposure_type = payload.exposure_type
        asset.business_system = payload.business_system
        asset.owner_team = payload.owner_team
        asset.owner_person = payload.owner_person
        asset.criticality = payload.criticality
        asset.allow_auto_verify = payload.allow_auto_verify
        asset.allow_auto_remediate = payload.allow_auto_remediate
    asset.last_seen_at = collected_at


def _build_component(component: AssetComponentIn) -> AssetComponent:
    return AssetComponent(
        component_name=component.component_name,
        component_type=component.component_type,
        version=component.version,
        source_type=component.source_type,
        ecosystem=component.ecosystem,
        distro=component.distro,
        distro_release=component.distro_release,
        source_package=component.source_package,
        binary_package=component.binary_package,
        architecture=component.architecture,
        flavor=component.flavor,
        version_scheme=component.version_scheme,
        purl=component.purl,
        cpe=component.cpe,
        install_path=component.install_path,
        evidence_ref=component.evidence_ref,
    )


def _build_exposure(exposure: AssetExposureIn) -> AssetExposure:
    return AssetExposure(
        exposure_kind=exposure.exposure_kind,
        address=exposure.address,
        port=exposure.port,
        protocol=exposure.protocol,
        service_name=exposure.service_name,
        product=exposure.product,
        version=exposure.version,
        state=exposure.state,
        is_public=exposure.is_public,
        banner=exposure.banner,
        evidence_ref=exposure.evidence_ref,
    )


def _sync_firewalls(
    asset: Asset,
    incoming_firewalls: list[AssetFirewallIn],
    collected_at,
) -> None:
    current_by_engine = {firewall.engine: firewall for firewall in asset.firewalls}
    incoming_engines = {firewall.engine for firewall in incoming_firewalls}

    asset.firewalls = [
        firewall
        for firewall in asset.firewalls
        if firewall.engine in incoming_engines
    ]

    for incoming in incoming_firewalls:
        firewall = current_by_engine.get(incoming.engine)
        is_new = firewall is None
        if firewall is None:
            firewall = AssetFirewall(
                asset_id=asset.id,
                engine=incoming.engine,
            )
            asset.firewalls.append(firewall)

        firewall.role = incoming.role
        firewall.backend = incoming.backend
        firewall.managed_by = incoming.managed_by
        firewall.effective = incoming.effective
        firewall.installed = incoming.installed
        firewall.runtime_state = incoming.runtime_state
        firewall.service_enabled = incoming.service_enabled
        firewall.collection_status = incoming.collection_status
        firewall.error_code = incoming.error_code
        firewall.error_message = incoming.error_message
        firewall.last_attempt_at = collected_at

        if incoming.collection_status == "success" or is_new:
            firewall.raw_runtime = incoming.raw_runtime
            firewall.raw_permanent = incoming.raw_permanent
            firewall.rules = [
                _build_firewall_rule(rule) for rule in incoming.rules
            ]
            firewall.runtime_rule_count = sum(
                rule.scope == "runtime" for rule in incoming.rules
            )
            firewall.permanent_rule_count = sum(
                rule.scope == "permanent" for rule in incoming.rules
            )
            if incoming.collection_status == "success":
                firewall.last_success_at = collected_at


def _build_firewall_rule(rule: AssetFirewallRuleIn) -> AssetFirewallRule:
    return AssetFirewallRule(
        scope=rule.scope,
        family=rule.family,
        table_name=rule.table,
        chain_name=rule.chain,
        zone=rule.zone,
        rule_order=rule.order,
        rule_kind=rule.rule_kind,
        action=rule.action,
        protocol=rule.protocol,
        source=rule.source,
        destination=rule.destination,
        source_port=rule.source_port,
        destination_port=rule.destination_port,
        in_interface=rule.in_interface,
        out_interface=rule.out_interface,
        state_match=rule.state_match,
        comment=rule.comment,
        raw_rule=rule.raw_rule,
    )


def _apply_ownership_hint(
    db: Session,
    asset: Asset,
    payload: AssetSnapshotIn,
) -> None:
    system_name = _normalize_hint(payload.business_system)
    if system_name is None or asset.business_system_id is not None:
        return
    systems = list(
        db.scalars(
            select(BusinessSystem)
            .options(
                selectinload(BusinessSystem.responsible_person).selectinload(Person.team)
            )
            .where(
                BusinessSystem.normalized_name == system_name,
                BusinessSystem.status == "active",
            )
        ).all()
    )
    matching_systems = [
        system
        for system in systems
        if _hint_matches_person_and_team(system, payload)
    ]
    if len(matching_systems) != 1:
        return
    system = matching_systems[0]
    person = system.responsible_person
    if (
        person is None
        or person.status != "active"
        or person.team.status != "active"
    ):
        return
    asset.business_system_record = system
    asset.ownership_source = "agent_match"
    asset.ownership_updated_at = utcnow()
    create_audit_log(
        db,
        action="ownership.asset.assigned",
        resource_type="asset",
        resource_id=asset.id,
        actor_type="agent",
        actor_id=payload.agent_id,
        summary=f"Matched new asset {asset.hostname} to {system.code} from Agent ownership hints.",
        details={
            "asset_id": asset.id,
            "business_system_id": system.id,
            "business_system_name": system.name,
            "source": "agent_match",
        },
    )


def _hint_matches_person_and_team(
    system: BusinessSystem,
    payload: AssetSnapshotIn,
) -> bool:
    person = system.responsible_person
    if person is None:
        return False
    person_hint = _normalize_hint(payload.owner_person)
    team_hint = _normalize_hint(payload.owner_team)
    if person_hint is not None and _normalize_hint(person.name) != person_hint:
        return False
    if team_hint is not None and _normalize_hint(person.team.name) != team_hint:
        return False
    return True


def _normalize_hint(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = re.sub(r"\s+", "", unicodedata.normalize("NFKC", value)).casefold()
    return normalized or None
