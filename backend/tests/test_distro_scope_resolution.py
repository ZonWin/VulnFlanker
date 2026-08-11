from __future__ import annotations

from sqlalchemy import select

from app.db.models import (
    Asset,
    AssetComponent,
    Vulnerability,
    VulnerabilityAffectedScope,
    VulnerabilitySource,
    VerificationEvidence,
)
from app.matching.scope_resolver import resolve_affected_scopes
from app.services.matching import evaluate_asset_vulnerability
from app.services.ubuntu_security import (
    UbuntuSecuritySyncResult,
    parse_ubuntu_cve_scopes,
    sync_ubuntu_security_statuses,
)


def _scope(scope_id: str, **overrides: object) -> dict[str, object]:
    return {
        "id": scope_id,
        "source_authority": "unknown",
        "authority_score": 10,
        **overrides,
    }


def _asset() -> dict[str, object]:
    return {
        "os_family": "Ubuntu",
        "os_version": "22.04 LTS",
        "architecture": "x86_64",
        "kernel_version": "5.15.0-120-generic",
        "components": [
            {
                "component_name": "linux-image-5.15.0-120-generic",
                "source_package": "linux",
                "binary_package": "linux-image-5.15.0-120-generic",
                "ecosystem": "deb",
                "architecture": "amd64",
                "flavor": "generic",
            }
        ],
    }


def test_distribution_scope_supersedes_generic_upstream_scope() -> None:
    generic = _scope("generic", status="affected")
    jammy = _scope(
        "jammy",
        distro="ubuntu",
        distro_release="jammy",
        source_package="linux",
        status="not_affected",
        source_authority="distribution",
        authority_score=100,
    )

    resolution = resolve_affected_scopes(_asset(), [generic, jammy])

    assert resolution.selected == [jammy]
    assert resolution.excluded == [
        {
            "scope_id": "generic",
            "reason": "superseded_by_more_authoritative_specific_scope",
        }
    ]


def test_scope_resolver_rejects_wrong_release_package_and_architecture() -> None:
    scopes = [
        _scope("noble", distro="ubuntu", distro_release="noble"),
        _scope("package", source_package="linux-gke"),
        _scope("architecture", architecture="arm64"),
        _scope("platform", platforms_json=["Microsoft Windows"]),
    ]

    resolution = resolve_affected_scopes(_asset(), scopes)

    assert resolution.selected == []
    assert {item["reason"] for item in resolution.excluded} == {
        "distro_release_mismatch",
        "source_package_mismatch",
        "architecture_mismatch",
        "platform_mismatch",
    }


def test_ubuntu_payload_preserves_status_and_fixed_boundary() -> None:
    scopes = parse_ubuntu_cve_scopes(
        {
            "id": "CVE-2026-12345",
            "packages": [
                {
                    "name": "linux",
                    "statuses": [
                        {
                            "release_codename": "jammy",
                            "status": "released",
                            "description": "5.15.0-100.110",
                            "pocket": "security",
                        },
                        {
                            "release_codename": "noble",
                            "status": "not-affected",
                            "description": "6.8.0-31.31",
                        },
                        {
                            "release_codename": "upstream",
                            "status": "released",
                            "description": "6.9",
                        },
                    ],
                }
            ],
        }
    )

    assert len(scopes) == 2
    assert scopes[0]["status"] == "fixed"
    assert scopes[0]["fixed_versions"] == "5.15.0-100.110"
    assert scopes[0]["default_status"] == "released"
    assert scopes[1]["status"] == "not_affected"
    assert scopes[1]["fixed_versions"] is None


def test_ubuntu_ambiguous_and_vulnerable_statuses_fail_safely() -> None:
    scopes = parse_ubuntu_cve_scopes(
        {
            "id": "CVE-2026-12349",
            "packages": [
                {
                    "name": "openssl",
                    "statuses": [
                        {"release_codename": "jammy", "status": "needed"},
                        {"release_codename": "noble", "status": "deferred"},
                        {"release_codename": "focal", "status": "ignored"},
                        {"release_codename": "bionic", "status": "needs-triage"},
                        {"release_codename": "xenial", "status": "DNE"},
                    ],
                }
            ],
        }
    )

    assert {
        scope["distro_release"]: scope["status"] for scope in scopes
    } == {
        "jammy": "affected",
        "noble": "affected",
        "focal": "needs_review",
        "bionic": "needs_review",
        "xenial": "not_affected",
    }


def test_ubuntu_sync_replaces_only_official_scopes(db_session) -> None:
    vulnerability = _vulnerability(db_session, "CVE-2026-12346")
    db_session.add(
        VulnerabilityAffectedScope(
            vulnerability_id=vulnerability.id,
            source_name="cve-record",
            scope_key="generic",
            product="Linux Kernel",
            status="affected",
        )
    )
    db_session.commit()
    payload = {
        "id": vulnerability.canonical_id,
        "packages": [
            {
                "name": "linux",
                "statuses": [
                    {
                        "release_codename": "jammy",
                        "status": "not-affected",
                        "description": "5.15.0-120.130",
                    }
                ],
            }
        ],
    }

    first = sync_ubuntu_security_statuses(
        db_session,
        vulnerability.id,
        fetcher=lambda _: payload,
    )
    second = sync_ubuntu_security_statuses(
        db_session,
        vulnerability.id,
        fetcher=lambda _: payload,
    )
    db_session.commit()

    scopes = list(
        db_session.scalars(
            select(VulnerabilityAffectedScope).where(
                VulnerabilityAffectedScope.vulnerability_id == vulnerability.id
            )
        )
    )
    assert first.scope_count == second.scope_count == 1
    assert first.status_counts == {"not_affected": 1}
    assert {scope.source_name for scope in scopes} == {
        "cve-record",
        "ubuntu-security",
    }


def test_manual_ubuntu_security_sync_endpoint(
    client,
    db_session,
    monkeypatch,
) -> None:
    vulnerability = _vulnerability(db_session, "CVE-2026-12350")

    def fake_sync(db, vulnerability_id: str) -> UbuntuSecuritySyncResult:
        assert db is db_session
        assert vulnerability_id == vulnerability.id
        return UbuntuSecuritySyncResult(
            vulnerability_id=vulnerability.id,
            canonical_id=vulnerability.canonical_id,
            scope_count=2,
            status_counts={"fixed": 1, "not_affected": 1},
        )

    monkeypatch.setattr(
        "app.api.routes.vulnerabilities.sync_ubuntu_security_statuses",
        fake_sync,
    )

    response = client.post(
        f"/api/v1/vulnerabilities/{vulnerability.id}/ubuntu-security-sync"
    )

    assert response.status_code == 200
    assert response.json() == {
        "vulnerability_id": vulnerability.id,
        "canonical_id": vulnerability.canonical_id,
        "scope_count": 2,
        "status_counts": {"fixed": 1, "not_affected": 1},
    }


def test_jammy_not_affected_overrides_generic_upstream_range(client, db_session) -> None:
    asset = _database_asset(db_session)
    vulnerability = _vulnerability(db_session, "CVE-2026-12347")
    db_session.add_all(
        [
            VulnerabilityAffectedScope(
                vulnerability_id=vulnerability.id,
                source_name="cve-record",
                scope_key="upstream",
                product="Linux Kernel",
                status="affected",
                affected_versions="< 6.0",
                source_authority="upstream",
                authority_score=20,
            ),
            VulnerabilityAffectedScope(
                vulnerability_id=vulnerability.id,
                source_name="ubuntu-security",
                scope_key="jammy",
                vendor="Canonical",
                product="linux",
                ecosystem="deb",
                distro="ubuntu",
                distro_release="jammy",
                source_package="linux",
                version_scheme="ubuntu_kernel",
                status="not_affected",
                default_status="not-affected",
                source_authority="distribution",
                authority_score=100,
            ),
        ]
    )
    db_session.commit()

    result = evaluate_asset_vulnerability(db_session, asset, vulnerability)

    assert result.status == "not_affected"
    assert {item.evidence_type for item in result.evidence} >= {
        "distro_status",
        "scope_resolution",
    }

    task_response = client.post(
        "/api/v1/verification-tasks",
        json={
            "match_result_id": result.id,
            "parameters": {
                "constraint_affected_versions": "< 99.0",
                "source_authority": "untrusted-override",
            },
        },
    )
    assert task_response.status_code == 201
    task_payload = task_response.json()
    assert task_payload["parameters"]["source_authority"] == "distribution"
    assert task_payload["parameters"].get("constraint_affected_versions") is None

    poll_response = client.get("/api/v1/agents/agent-jammy-kernel/tasks/next")
    assert poll_response.status_code == 200
    result_response = client.post(
        f"/api/v1/agents/agent-jammy-kernel/tasks/{task_payload['id']}/results",
        json={
            "status": "completed",
            "evidence": [
                {
                    "evidence_type": "kernel_version",
                    "summary": "Agent reported an older kernel.",
                    "confidence": 0.99,
                    "details": {
                        "package_name": "Linux Kernel",
                        "component_type": "kernel",
                        "observed_version": "5.15.0-90-generic",
                        "distro": "ubuntu",
                        "source": "uname",
                    },
                }
            ],
        },
    )
    assert result_response.status_code == 202
    db_session.refresh(result)
    assert result.status == "not_affected"
    verification = db_session.scalar(
        select(VerificationEvidence).where(
            VerificationEvidence.verification_task_id == task_payload["id"]
        )
    )
    assert verification is not None
    assert verification.details_json["decision_reason_code"] == (
        "verification.distribution_status_preserved"
    )


def test_released_jammy_fix_uses_kernel_abi_boundary(db_session) -> None:
    asset = _database_asset(db_session)
    vulnerability = _vulnerability(db_session, "CVE-2026-12348")
    db_session.add(
        VulnerabilityAffectedScope(
            vulnerability_id=vulnerability.id,
            source_name="ubuntu-security",
            scope_key="jammy-fixed",
            vendor="Canonical",
            product="linux",
            ecosystem="deb",
            distro="ubuntu",
            distro_release="jammy",
            source_package="linux",
            version_scheme="ubuntu_kernel",
            status="fixed",
            default_status="released",
            fixed_versions="5.15.0-100.110",
            source_authority="distribution",
            authority_score=100,
        )
    )
    db_session.commit()

    result = evaluate_asset_vulnerability(db_session, asset, vulnerability)

    assert result.status == "not_affected"
    version_evidence = next(
        item for item in result.evidence if item.evidence_type == "kernel_version"
    )
    comparison = version_evidence.details_json["comparisons"][0]
    assert comparison["comparator"] == "ubuntu_kernel_abi"
    assert comparison["compare_result"] == 1


def _vulnerability(db_session, canonical_id: str) -> Vulnerability:
    vulnerability = Vulnerability(
        canonical_id=canonical_id,
        title=f"{canonical_id} Linux kernel vulnerability",
        vendor="Linux",
        product="Linux Kernel",
        affected_versions="< 6.0",
        severity_label="high",
        severity_cvss=8.0,
    )
    db_session.add(vulnerability)
    db_session.flush()
    db_session.add(
        VulnerabilitySource(
            vulnerability_id=vulnerability.id,
            source_name="test-source",
            external_id=canonical_id,
            source_url=f"https://example.test/{canonical_id}",
            title=vulnerability.title,
            last_payload_hash=f"hash-{canonical_id}",
        )
    )
    db_session.commit()
    return vulnerability


def _database_asset(db_session) -> Asset:
    asset = Asset(
        agent_id="agent-jammy-kernel",
        hostname="jammy-host",
        platform="linux",
        os_family="ubuntu",
        os_version="22.04",
        kernel_version="5.15.0-120-generic",
        architecture="x86_64",
    )
    db_session.add(asset)
    db_session.flush()
    db_session.add(
        AssetComponent(
            asset_id=asset.id,
            component_name="linux-image-5.15.0-120-generic",
            component_type="package",
            version="5.15.0-120.130",
            source_type="dpkg-query",
            ecosystem="deb",
            distro="ubuntu",
            distro_release="22.04",
            source_package="linux",
            binary_package="linux-image-5.15.0-120-generic",
            architecture="amd64",
            flavor="generic",
            version_scheme="ubuntu_kernel",
        )
    )
    db_session.commit()
    return asset
