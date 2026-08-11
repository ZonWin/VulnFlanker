from __future__ import annotations

from sqlalchemy import event, func, select

from app.db.models import AgentStatus, Asset, AssetComponent, AssetExposure, AssetSnapshot


def build_linux_snapshot(
    *,
    nginx_version: str = "1.24.0",
    exposure_port: int = 443,
    collected_at: str = "2026-05-05T12:00:00Z",
) -> dict[str, object]:
    return {
        "agent_id": "agent-linux-001",
        "agent_version": "0.1.0",
        "hostname": "web-01.prod.local",
        "primary_ip": "10.10.20.15",
        "platform": "linux",
        "os_family": "ubuntu",
        "os_version": "22.04",
        "kernel_version": "5.15.0-105-generic",
        "architecture": "x86_64",
        "environment_type": "production",
        "exposure_type": "internet",
        "business_system": "payments",
        "owner_team": "sre",
        "owner_person": "alice",
        "criticality": "high",
        "allow_auto_verify": True,
        "components": [
            {
                "component_name": "nginx",
                "component_type": "package",
                "version": nginx_version,
                "source_type": "dpkg",
                "ecosystem": "deb",
                "distro": "ubuntu",
                "distro_release": "22.04",
                "source_package": "nginx",
                "binary_package": "nginx",
                "architecture": "amd64",
                "version_scheme": "debian",
                "install_path": "/usr/sbin/nginx",
            },
            {
                "component_name": "openssl",
                "component_type": "package",
                "version": "3.0.2",
                "source_type": "dpkg",
                "ecosystem": "deb",
                "distro": "ubuntu",
                "distro_release": "22.04",
                "source_package": "openssl",
                "binary_package": "openssl",
                "architecture": "amd64",
                "version_scheme": "debian",
            },
        ],
        "exposures": [
            {
                "exposure_kind": "network_service",
                "address": "203.0.113.20",
                "port": exposure_port,
                "protocol": "tcp",
                "service_name": "https",
                "product": "nginx",
                "version": nginx_version,
                "state": "open",
                "is_public": True,
                "banner": "nginx",
            }
        ],
        "collected_at": collected_at,
    }


def test_asset_snapshot_endpoint_persists_asset_profile(client, db_session) -> None:
    response = client.post("/api/v1/agents/snapshots", json=build_linux_snapshot())

    assert response.status_code == 202
    payload = response.json()
    assert payload["status"] == "stored"
    assert payload["asset_action"] == "created"
    assert payload["snapshot_action"] == "created"
    assert payload["component_count"] == 2
    assert payload["exposure_count"] == 1

    asset = db_session.scalar(
        select(Asset).where(Asset.agent_id == "agent-linux-001")
    )
    assert asset is not None
    assert asset.hostname == "web-01.prod.local"
    assert asset.platform == "linux"
    assert asset.architecture == "x86_64"
    assert len(asset.components) == 2
    assert len(asset.exposures) == 1
    nginx = next(item for item in asset.components if item.component_name == "nginx")
    assert nginx.ecosystem == "deb"
    assert nginx.distro == "ubuntu"
    assert nginx.distro_release == "22.04"
    assert nginx.source_package == "nginx"
    assert nginx.binary_package == "nginx"
    assert nginx.architecture == "amd64"
    assert nginx.version_scheme == "debian"

    detail_response = client.get(f"/api/v1/assets/{asset.id}")
    assert detail_response.status_code == 200
    detail_nginx = next(
        item
        for item in detail_response.json()["components"]
        if item["component_name"] == "nginx"
    )
    assert detail_nginx["ecosystem"] == "deb"
    assert detail_nginx["distro"] == "ubuntu"
    assert detail_nginx["source_package"] == "nginx"
    assert detail_nginx["binary_package"] == "nginx"
    assert detail_nginx["version_scheme"] == "debian"

    snapshot = db_session.scalar(
        select(AssetSnapshot).where(AssetSnapshot.asset_id == asset.id)
    )
    assert snapshot is not None
    assert snapshot.component_count == 2
    assert snapshot.exposure_count == 1
    assert snapshot.raw_payload["hostname"] == "web-01.prod.local"


def test_asset_snapshot_reingestion_updates_in_place_without_dirty_rows(
    client,
    db_session,
) -> None:
    first_response = client.post("/api/v1/agents/snapshots", json=build_linux_snapshot())
    assert first_response.status_code == 202

    second_response = client.post(
        "/api/v1/agents/snapshots",
        json=build_linux_snapshot(
            nginx_version="1.26.1",
            exposure_port=8443,
            collected_at="2026-05-05T12:30:00Z",
        ),
    )
    assert second_response.status_code == 202
    second_payload = second_response.json()
    assert second_payload["asset_action"] == "updated"
    assert second_payload["snapshot_action"] == "created"

    asset = db_session.scalar(
        select(Asset).where(Asset.agent_id == "agent-linux-001")
    )
    assert asset is not None
    assert len(asset.components) == 2
    assert len(asset.exposures) == 1
    assert {component.component_name: component.version for component in asset.components}[
        "nginx"
    ] == "1.26.1"
    assert asset.exposures[0].port == 8443

    exposures_count = db_session.scalar(select(func.count(AssetExposure.id)))
    snapshots_count = db_session.scalar(select(func.count(AssetSnapshot.id)))
    assert exposures_count == 1
    assert snapshots_count == 2


def test_identical_asset_snapshot_is_deduplicated(client, db_session) -> None:
    first_response = client.post("/api/v1/agents/snapshots", json=build_linux_snapshot())
    assert first_response.status_code == 202

    second_response = client.post("/api/v1/agents/snapshots", json=build_linux_snapshot())
    assert second_response.status_code == 202
    second_payload = second_response.json()
    assert second_payload["snapshot_action"] == "deduplicated"

    snapshots_count = db_session.scalar(select(func.count(AssetSnapshot.id)))
    exposures_count = db_session.scalar(select(func.count(AssetExposure.id)))
    assert snapshots_count == 1
    assert exposures_count == 1


def test_assets_endpoints_return_latest_asset_profile(client) -> None:
    ingest_response = client.post("/api/v1/agents/snapshots", json=build_linux_snapshot())
    asset_id = ingest_response.json()["asset_id"]

    list_response = client.get("/api/v1/assets")
    assert list_response.status_code == 200
    list_payload = list_response.json()
    assert len(list_payload) == 1
    assert list_payload[0]["agent_id"] == "agent-linux-001"
    assert list_payload[0]["display_name"] is None
    assert list_payload[0]["component_count"] == 2
    assert list_payload[0]["exposure_count"] == 1

    detail_response = client.get(f"/api/v1/assets/{asset_id}")
    assert detail_response.status_code == 200
    detail_payload = detail_response.json()
    assert detail_payload["hostname"] == "web-01.prod.local"
    assert detail_payload["display_name"] is None
    assert detail_payload["latest_snapshot"]["agent_version"] == "0.1.0"
    assert detail_payload["agent_status"]["status"] == "online"
    assert detail_payload["agent_status"]["last_snapshot_at"] is not None
    assert detail_payload["freshness"]["is_stale"] is False
    assert detail_payload["components"][0]["component_type"] == "package"
    assert detail_payload["exposures"][0]["service_name"] == "https"


def test_paged_asset_list_stats_count_full_result_set(client, db_session) -> None:
    db_session.add_all(
        [
            Asset(
                hostname=f"paged-stats-{index}.example.test",
                criticality="critical" if index % 2 == 0 else "medium",
                exposure_type="internet" if index % 3 == 0 else "internal",
            )
            for index in range(35)
        ]
    )
    db_session.commit()

    response = client.get("/api/v1/assets?paged=true&offset=0&limit=30")

    assert response.status_code == 200
    payload = response.json()
    assert len(payload["items"]) == 30
    assert payload["has_more"] is True
    assert payload["total"] == 35
    assert payload["high_criticality_count"] == 18
    assert payload["public_exposure_count"] == 12
    assert payload["incomplete_ownership_count"] == 35


def test_paged_asset_list_uses_aggregate_child_counts(client, db_session) -> None:
    asset = Asset(
        hostname="component-heavy.example.test",
        criticality="high",
        exposure_type="internet",
    )
    db_session.add(asset)
    db_session.flush()
    db_session.add_all(
        [
            AssetComponent(
                asset_id=asset.id,
                component_name=f"package-{index}",
                component_type="package",
            )
            for index in range(25)
        ]
    )
    db_session.add_all(
        [
            AssetExposure(
                asset_id=asset.id,
                exposure_kind="network_service",
                protocol="tcp",
                state="open",
                is_public=True,
            )
            for _ in range(3)
        ]
    )
    db_session.commit()

    statements: list[str] = []

    def capture_sql(conn, cursor, statement, parameters, context, executemany) -> None:
        statements.append(" ".join(statement.lower().split()))

    event.listen(db_session.bind, "before_cursor_execute", capture_sql)
    try:
        response = client.get("/api/v1/assets?paged=true&offset=0&limit=10")
    finally:
        event.remove(db_session.bind, "before_cursor_execute", capture_sql)

    assert response.status_code == 200
    payload = response.json()
    assert payload["items"][0]["component_count"] == 25
    assert payload["items"][0]["exposure_count"] == 3

    detail_component_queries = [
        statement
        for statement in statements
        if "from asset_components" in statement and "group by" not in statement
    ]
    detail_exposure_queries = [
        statement
        for statement in statements
        if "from asset_exposures" in statement and "group by" not in statement
    ]
    assert detail_component_queries == []
    assert detail_exposure_queries == []


def test_asset_metadata_can_be_edited_and_survives_reingestion(
    client,
    db_session,
) -> None:
    ingest_response = client.post("/api/v1/agents/snapshots", json=build_linux_snapshot())
    asset_id = ingest_response.json()["asset_id"]

    update_response = client.patch(
        f"/api/v1/assets/{asset_id}",
        json={
            "display_name": "支付业务生产服务器",
            "environment_type": "staging",
            "exposure_type": "internal",
            "criticality": "critical",
            "allow_auto_remediate": True,
        },
    )
    assert update_response.status_code == 200
    updated_payload = update_response.json()
    assert updated_payload["display_name"] == "支付业务生产服务器"
    assert updated_payload["hostname"] == "web-01.prod.local"
    assert updated_payload["business_system"] is None
    assert updated_payload["owner_team"] is None
    assert updated_payload["owner_person"] is None
    assert updated_payload["environment_type"] == "staging"
    assert updated_payload["exposure_type"] == "internal"
    assert updated_payload["criticality"] == "critical"
    assert updated_payload["allow_auto_remediate"] is True

    next_snapshot = build_linux_snapshot(
        nginx_version="1.26.2",
        collected_at="2026-05-05T13:00:00Z",
    )
    next_snapshot["hostname"] = "web-01-renamed.prod.local"
    next_snapshot["business_system"] = "agent-overwrite-attempt"
    next_snapshot["owner_team"] = "agent-team"
    next_snapshot["owner_person"] = "agent-owner"
    next_snapshot["environment_type"] = "production"
    next_snapshot["exposure_type"] = "internet"
    next_snapshot["criticality"] = "low"
    next_snapshot["allow_auto_remediate"] = False

    reingest_response = client.post("/api/v1/agents/snapshots", json=next_snapshot)
    assert reingest_response.status_code == 202

    asset = db_session.scalar(
        select(Asset).where(Asset.agent_id == "agent-linux-001")
    )
    assert asset is not None
    assert asset.hostname == "web-01-renamed.prod.local"
    assert asset.display_name == "支付业务生产服务器"
    assert asset.business_system == "payments"
    assert asset.owner_team == "sre"
    assert asset.owner_person == "alice"
    assert asset.environment_type == "staging"
    assert asset.exposure_type == "internal"
    assert asset.criticality == "critical"
    assert asset.allow_auto_remediate is True


def test_agent_heartbeat_endpoint_persists_agent_status(client, db_session) -> None:
    response = client.post(
        "/api/v1/agents/heartbeat",
        json={
            "agent_id": "agent-heartbeat-001",
            "hostname": "worker-01.prod.local",
            "platform": "linux",
            "version": "0.2.0",
        },
    )

    assert response.status_code == 202
    status = db_session.scalar(
        select(AgentStatus).where(AgentStatus.agent_id == "agent-heartbeat-001")
    )
    assert status is not None
    assert status.hostname == "worker-01.prod.local"
    assert status.last_heartbeat_at is not None

    list_response = client.get("/api/v1/agents")
    assert list_response.status_code == 200
    payload = list_response.json()
    assert len(payload) == 1
    assert payload[0]["agent_id"] == "agent-heartbeat-001"
    assert payload[0]["asset_primary_ip"] is None
    assert payload[0]["status"] == "online"
    assert payload[0]["task_stats"]["total"] == 0
