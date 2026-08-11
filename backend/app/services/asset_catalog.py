from __future__ import annotations

from sqlalchemy import and_, desc, func, not_, or_, select
from sqlalchemy.orm import Session, selectinload

from app.db.models import (
    Asset,
    AssetComponent,
    AssetExposure,
    AssetFirewall,
    AssetFirewallRule,
    AssetSnapshot,
    BusinessSystem,
    Person,
    ResponsibilityTeam,
)
from app.schemas.asset import (
    AssetComponentOut,
    AssetDetail,
    AssetExposureOut,
    AssetFirewallList,
    AssetFirewallOut,
    AssetFirewallRawOut,
    AssetFirewallRuleList,
    AssetFirewallRuleOut,
    AssetListPage,
    AssetMetadataUpdate,
    AssetOwnership,
    AssetOwnershipBusinessSystem,
    AssetOwnershipPerson,
    AssetOwnershipTeam,
    AssetSnapshotSummary,
    AssetSummary,
)
from app.services.agent_status import build_asset_freshness, get_asset_agent_status


def list_assets(
    db: Session,
    *,
    business_system_id: str | None = None,
    responsible_person_id: str | None = None,
    responsibility_team_id: str | None = None,
    ownership_status: str | None = None,
    search: str | None = None,
    criticality: str | None = None,
    environment_type: str | None = None,
    exposure_type: str | None = None,
    platform: str | None = None,
    os_family: str | None = None,
) -> list[AssetSummary]:
    page = list_assets_page(
        db,
        business_system_id=business_system_id,
        responsible_person_id=responsible_person_id,
        responsibility_team_id=responsibility_team_id,
        ownership_status=ownership_status,
        search=search,
        criticality=criticality,
        environment_type=environment_type,
        exposure_type=exposure_type,
        platform=platform,
        os_family=os_family,
        offset=0,
        limit=1_000_000,
        include_stats=False,
    )
    return page.items


def list_assets_page(
    db: Session,
    *,
    business_system_id: str | None = None,
    responsible_person_id: str | None = None,
    responsibility_team_id: str | None = None,
    ownership_status: str | None = None,
    search: str | None = None,
    criticality: str | None = None,
    environment_type: str | None = None,
    exposure_type: str | None = None,
    platform: str | None = None,
    os_family: str | None = None,
    offset: int = 0,
    limit: int = 30,
    include_stats: bool = True,
) -> AssetListPage:
    conditions, complete_relationship = _asset_list_conditions(
        business_system_id=business_system_id,
        responsible_person_id=responsible_person_id,
        responsibility_team_id=responsibility_team_id,
        ownership_status=ownership_status,
        search=search,
        criticality=criticality,
        environment_type=environment_type,
        exposure_type=exposure_type,
        platform=platform,
        os_family=os_family,
    )

    assets = db.scalars(
        select(Asset)
        .options(*_asset_summary_load_options())
        .where(*conditions)
        .order_by(desc(Asset.last_seen_at), desc(Asset.updated_at), Asset.hostname)
        .offset(offset)
        .limit(limit + 1)
    ).all()
    page_assets = assets[:limit]
    component_counts = _count_asset_children(db, AssetComponent.asset_id, page_assets)
    exposure_counts = _count_asset_children(db, AssetExposure.asset_id, page_assets)
    stats = (
        {
            "total": _count_assets(db, conditions),
            "high_criticality_count": _count_assets(
                db,
                [*conditions, Asset.criticality.in_(("critical", "high"))],
            ),
            "public_exposure_count": _count_assets(
                db,
                [
                    *conditions,
                    Asset.exposure_type.in_(("internet", "public", "external", "dmz")),
                ],
            ),
            "incomplete_ownership_count": _count_assets(
                db,
                [*conditions, not_(complete_relationship)],
            ),
        }
        if include_stats
        else {}
    )
    return AssetListPage(
        items=[
            _to_asset_summary(
                asset,
                component_count=component_counts.get(asset.id, 0),
                exposure_count=exposure_counts.get(asset.id, 0),
            )
            for asset in page_assets
        ],
        offset=offset,
        limit=limit,
        has_more=len(assets) > limit,
        **stats,
    )


def _asset_list_conditions(
    *,
    business_system_id: str | None = None,
    responsible_person_id: str | None = None,
    responsibility_team_id: str | None = None,
    ownership_status: str | None = None,
    search: str | None = None,
    criticality: str | None = None,
    environment_type: str | None = None,
    exposure_type: str | None = None,
    platform: str | None = None,
    os_family: str | None = None,
):
    complete_relationship = Asset.business_system_record.has(
        and_(
            BusinessSystem.status == "active",
            BusinessSystem.responsible_person.has(
                and_(
                    Person.status == "active",
                    Person.team.has(ResponsibilityTeam.status == "active"),
                )
            ),
        )
    )
    conditions = []
    if business_system_id:
        conditions.append(Asset.business_system_id == business_system_id)
    if responsible_person_id:
        conditions.append(
            Asset.business_system_record.has(
                BusinessSystem.responsible_person_id == responsible_person_id
            )
        )
    if responsibility_team_id:
        conditions.append(
            Asset.business_system_record.has(
                BusinessSystem.responsible_person.has(
                    Person.team_id == responsibility_team_id
                )
            )
        )
    if ownership_status == "unassigned":
        conditions.append(Asset.business_system_id.is_(None))
    elif ownership_status == "complete":
        conditions.append(complete_relationship)
    elif ownership_status == "system_incomplete":
        conditions.extend(
            [Asset.business_system_id.is_not(None), not_(complete_relationship)]
        )
    if search and search.strip():
        terms = [term for term in search.strip().split() if term]
        for term in terms:
            pattern = f"%{term}%"
            conditions.append(
                or_(
                    Asset.id.ilike(pattern),
                    Asset.agent_id.ilike(pattern),
                    Asset.display_name.ilike(pattern),
                    Asset.hostname.ilike(pattern),
                    Asset.primary_ip.ilike(pattern),
                    Asset.platform.ilike(pattern),
                    Asset.os_family.ilike(pattern),
                    Asset.os_version.ilike(pattern),
                    Asset.architecture.ilike(pattern),
                    Asset.business_system_record.has(
                        or_(
                            BusinessSystem.code.ilike(pattern),
                            BusinessSystem.name.ilike(pattern),
                            BusinessSystem.responsible_person.has(
                                or_(
                                    Person.name.ilike(pattern),
                                    Person.email.ilike(pattern),
                                    Person.team.has(
                                        or_(
                                            ResponsibilityTeam.code.ilike(pattern),
                                            ResponsibilityTeam.name.ilike(pattern),
                                        )
                                    ),
                                )
                            ),
                        )
                    ),
                )
            )
    exact_filters = {
        Asset.criticality: criticality,
        Asset.environment_type: environment_type,
        Asset.exposure_type: exposure_type,
        Asset.platform: platform,
        Asset.os_family: os_family,
    }
    for column, value in exact_filters.items():
        if value:
            conditions.append(column == value)
    return conditions, complete_relationship


def _count_assets(db: Session, conditions) -> int:
    return int(db.scalar(select(func.count(Asset.id)).where(*conditions)) or 0)


def _count_asset_children(
    db: Session,
    asset_id_column,
    assets: list[Asset],
) -> dict[str, int]:
    asset_ids = [asset.id for asset in assets]
    if not asset_ids:
        return {}
    rows = db.execute(
        select(asset_id_column, func.count())
        .where(asset_id_column.in_(asset_ids))
        .group_by(asset_id_column)
    ).all()
    return {asset_id: int(count) for asset_id, count in rows}


def get_asset(db: Session, asset_id: str) -> AssetDetail | None:
    asset = db.scalar(
        select(Asset)
        .options(*_asset_load_options())
        .where(
            or_(
                Asset.id == asset_id,
                Asset.agent_id == asset_id,
            )
        )
    )
    if asset is None:
        return None

    latest_snapshot = db.scalar(
        select(AssetSnapshot)
        .where(AssetSnapshot.asset_id == asset.id)
        .order_by(
            desc(AssetSnapshot.collected_at),
            desc(AssetSnapshot.received_at),
        )
    )
    snapshots_count = db.scalar(
        select(func.count(AssetSnapshot.id)).where(AssetSnapshot.asset_id == asset.id)
    ) or 0

    ownership = build_asset_ownership(asset)
    return AssetDetail(
        **_to_asset_summary(asset).model_dump(),
        kernel_version=asset.kernel_version,
        business_system=(
            ownership.business_system.name if ownership.business_system else None
        ),
        owner_team=(
            ownership.responsibility_team.name
            if ownership.responsibility_team
            else None
        ),
        owner_person=(
            ownership.responsible_person.name
            if ownership.responsible_person
            else None
        ),
        allow_auto_verify=asset.allow_auto_verify,
        allow_auto_remediate=asset.allow_auto_remediate,
        snapshots_count=snapshots_count,
        latest_snapshot=(
            _to_asset_snapshot_summary(latest_snapshot)
            if latest_snapshot is not None
            else None
        ),
        agent_status=get_asset_agent_status(db, asset),
        freshness=build_asset_freshness(latest_snapshot),
        components=[_to_asset_component(component) for component in asset.components],
        exposures=[_to_asset_exposure(exposure) for exposure in asset.exposures],
    )


def list_asset_firewalls(
    db: Session,
    asset_id: str,
) -> AssetFirewallList | None:
    asset = _find_asset(db, asset_id)
    if asset is None:
        return None
    firewalls = list(
        db.scalars(
            select(AssetFirewall).where(AssetFirewall.asset_id == asset.id)
        ).all()
    )
    engine_order = {"firewalld": 0, "ufw": 1, "iptables": 2, "nftables": 3}
    firewalls.sort(key=lambda item: engine_order.get(item.engine, 99))
    return AssetFirewallList(
        items=[_to_asset_firewall(firewall) for firewall in firewalls],
        total=len(firewalls),
    )


def list_asset_firewall_rules(
    db: Session,
    asset_id: str,
    engine: str,
    *,
    scope: str | None = None,
    family: str | None = None,
    action: str | None = None,
    protocol: str | None = None,
    search: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> AssetFirewallRuleList | None:
    firewall = _find_asset_firewall(db, asset_id, engine)
    if firewall is None:
        return None

    conditions = [AssetFirewallRule.firewall_id == firewall.id]
    if scope:
        conditions.append(AssetFirewallRule.scope == scope)
    if family:
        conditions.append(func.lower(AssetFirewallRule.family) == family.lower())
    if action:
        conditions.append(func.lower(AssetFirewallRule.action) == action.lower())
    if protocol:
        conditions.append(func.lower(AssetFirewallRule.protocol) == protocol.lower())
    if search and search.strip():
        pattern = f"%{search.strip()}%"
        conditions.append(
            or_(
                AssetFirewallRule.table_name.ilike(pattern),
                AssetFirewallRule.chain_name.ilike(pattern),
                AssetFirewallRule.zone.ilike(pattern),
                AssetFirewallRule.source.ilike(pattern),
                AssetFirewallRule.destination.ilike(pattern),
                AssetFirewallRule.source_port.ilike(pattern),
                AssetFirewallRule.destination_port.ilike(pattern),
                AssetFirewallRule.comment.ilike(pattern),
                AssetFirewallRule.raw_rule.ilike(pattern),
            )
        )

    total = db.scalar(
        select(func.count(AssetFirewallRule.id)).where(*conditions)
    ) or 0
    rules = db.scalars(
        select(AssetFirewallRule)
        .where(*conditions)
        .order_by(
            AssetFirewallRule.scope,
            AssetFirewallRule.rule_order,
            AssetFirewallRule.id,
        )
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return AssetFirewallRuleList(
        items=[_to_asset_firewall_rule(firewall.engine, rule) for rule in rules],
        total=total,
        page=page,
        page_size=page_size,
    )


def get_asset_firewall_raw(
    db: Session,
    asset_id: str,
    engine: str,
    scope: str,
) -> AssetFirewallRawOut | None:
    firewall = _find_asset_firewall(db, asset_id, engine)
    if firewall is None:
        return None
    return AssetFirewallRawOut(
        engine=firewall.engine,
        scope=scope,
        content=(
            firewall.raw_runtime if scope == "runtime" else firewall.raw_permanent
        ),
        collection_status=firewall.collection_status,
        last_success_at=firewall.last_success_at,
    )


def _find_asset(db: Session, asset_id: str) -> Asset | None:
    return db.scalar(
        select(Asset).where(
            or_(
                Asset.id == asset_id,
                Asset.agent_id == asset_id,
            )
        )
    )


def _find_asset_firewall(
    db: Session,
    asset_id: str,
    engine: str,
) -> AssetFirewall | None:
    asset = _find_asset(db, asset_id)
    if asset is None:
        return None
    return db.scalar(
        select(AssetFirewall).where(
            AssetFirewall.asset_id == asset.id,
            AssetFirewall.engine == engine,
        )
    )


def update_asset_metadata(
    db: Session,
    asset_id: str,
    payload: AssetMetadataUpdate,
) -> AssetDetail | None:
    asset = db.scalar(
        select(Asset).where(
            or_(
                Asset.id == asset_id,
                Asset.agent_id == asset_id,
            )
        )
    )
    if asset is None:
        return None

    nullable_text_fields = ("display_name",)
    required_text_fields = (
        "environment_type",
        "exposure_type",
        "criticality",
    )
    boolean_fields = (
        "allow_auto_verify",
        "allow_auto_remediate",
    )

    provided_fields = payload.model_fields_set
    for field_name in nullable_text_fields:
        if field_name in provided_fields:
            setattr(asset, field_name, _clean_optional_text(getattr(payload, field_name)))

    for field_name in required_text_fields:
        if field_name in provided_fields:
            value = _clean_optional_text(getattr(payload, field_name))
            if value is not None:
                setattr(asset, field_name, value)

    for field_name in boolean_fields:
        if field_name in provided_fields:
            value = getattr(payload, field_name)
            if value is not None:
                setattr(asset, field_name, value)

    db.commit()
    db.refresh(asset)
    return get_asset(db, asset.id)


def _to_asset_summary(
    asset: Asset,
    *,
    component_count: int | None = None,
    exposure_count: int | None = None,
) -> AssetSummary:
    return AssetSummary(
        id=asset.id,
        agent_id=asset.agent_id,
        hostname=asset.hostname,
        display_name=asset.display_name,
        primary_ip=asset.primary_ip,
        platform=asset.platform,
        os_family=asset.os_family,
        os_version=asset.os_version,
        architecture=asset.architecture,
        criticality=asset.criticality,
        environment_type=asset.environment_type,
        exposure_type=asset.exposure_type,
        last_seen_at=asset.last_seen_at,
        component_count=(
            component_count if component_count is not None else len(asset.components)
        ),
        exposure_count=(
            exposure_count if exposure_count is not None else len(asset.exposures)
        ),
        ownership=build_asset_ownership(asset),
    )


def build_asset_ownership(asset: Asset) -> AssetOwnership:
    system = asset.business_system_record
    if system is None:
        return AssetOwnership(
            status="unassigned",
            source=asset.ownership_source,
            updated_at=asset.ownership_updated_at,
        )

    person = system.responsible_person
    team = person.team if person is not None else None
    is_complete = (
        system.status == "active"
        and person is not None
        and person.status == "active"
        and team is not None
        and team.status == "active"
    )
    return AssetOwnership(
        status="complete" if is_complete else "system_incomplete",
        source=asset.ownership_source,
        updated_at=asset.ownership_updated_at,
        business_system=AssetOwnershipBusinessSystem(
            id=system.id,
            code=system.code,
            name=system.name,
            status=system.status,
        ),
        responsible_person=(
            AssetOwnershipPerson(
                id=person.id,
                name=person.name,
                email=person.email,
                status=person.status,
            )
            if person is not None
            else None
        ),
        responsibility_team=(
            AssetOwnershipTeam(
                id=team.id,
                code=team.code,
                name=team.name,
                status=team.status,
            )
            if team is not None
            else None
        ),
    )


def _asset_load_options():
    return (
        selectinload(Asset.components),
        selectinload(Asset.exposures),
        *_asset_summary_load_options(),
    )


def _asset_summary_load_options():
    return (
        selectinload(Asset.business_system_record)
        .selectinload(BusinessSystem.responsible_person)
        .selectinload(Person.team),
    )


def _clean_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _to_asset_component(component: AssetComponent) -> AssetComponentOut:
    return AssetComponentOut(
        id=component.id,
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


def _to_asset_exposure(exposure: AssetExposure) -> AssetExposureOut:
    return AssetExposureOut(
        id=exposure.id,
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


def _to_asset_firewall(firewall: AssetFirewall) -> AssetFirewallOut:
    return AssetFirewallOut(
        id=firewall.id,
        engine=firewall.engine,
        role=firewall.role,
        backend=firewall.backend,
        managed_by=firewall.managed_by,
        effective=firewall.effective,
        installed=firewall.installed,
        runtime_state=firewall.runtime_state,
        service_enabled=firewall.service_enabled,
        collection_status=firewall.collection_status,
        error_code=firewall.error_code,
        error_message=firewall.error_message,
        runtime_rule_count=firewall.runtime_rule_count,
        permanent_rule_count=firewall.permanent_rule_count,
        last_attempt_at=firewall.last_attempt_at,
        last_success_at=firewall.last_success_at,
    )


def _to_asset_firewall_rule(
    engine: str,
    rule: AssetFirewallRule,
) -> AssetFirewallRuleOut:
    return AssetFirewallRuleOut(
        id=rule.id,
        firewall_id=rule.firewall_id,
        engine=engine,
        scope=rule.scope,
        family=rule.family,
        table=rule.table_name,
        chain=rule.chain_name,
        zone=rule.zone,
        order=rule.rule_order,
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


def _to_asset_snapshot_summary(snapshot: AssetSnapshot) -> AssetSnapshotSummary:
    return AssetSnapshotSummary(
        id=snapshot.id,
        agent_id=snapshot.agent_id,
        agent_version=snapshot.agent_version,
        platform=snapshot.platform,
        collected_at=snapshot.collected_at,
        received_at=snapshot.received_at,
        payload_hash=snapshot.payload_hash,
        component_count=snapshot.component_count,
        exposure_count=snapshot.exposure_count,
        firewall_count=snapshot.firewall_count,
        firewall_rule_count=snapshot.firewall_rule_count,
    )
