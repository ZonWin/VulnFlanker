from __future__ import annotations

from dataclasses import dataclass

import pytest

from app.db.models import (
    Asset,
    AssetComponent,
    VulnerabilityAffectedScope,
)
from app.services.matching import evaluate_asset_vulnerability
from app.services.ubuntu_security import sync_ubuntu_security_statuses
from test_matching_engine import create_vulnerability


@dataclass(frozen=True, slots=True)
class AuditedRiskCase:
    risk_suffix: str
    cve_id: str
    package: str
    ubuntu_status: str
    fixed_version: str | None
    expected_status: str
    expected_comparator: str | None
    expected_reason_code: str


AUDITED_RISK_CASES = (
    AuditedRiskCase("000001", "CVE-2022-0492", "linux", "not-affected", None, "not_affected", None, "distro_status.not_affected"),
    AuditedRiskCase("000002", "CVE-2026-31431", "linux", "released", "5.15.0-179.189", "affected", "ubuntu_kernel_abi", "version.affected_range"),
    AuditedRiskCase("000003", "CVE-2018-14634", "linux", "not-affected", None, "not_affected", None, "distro_status.not_affected"),
    AuditedRiskCase("000004", "CVE-2021-22555", "linux", "not-affected", None, "not_affected", None, "distro_status.not_affected"),
    AuditedRiskCase("000005", "CVE-2025-32463", "sudo", "not-affected", None, "not_affected", None, "distro_status.not_affected"),
    AuditedRiskCase("000006", "CVE-2025-38352", "linux", "released", "5.15.0-156.166", "affected", "ubuntu_kernel_abi", "version.affected_range"),
    AuditedRiskCase("000007", "CVE-2025-48384", "git", "released", "1:2.34.1-1ubuntu1.13", "affected", "debian_policy", "version.affected_range"),
    AuditedRiskCase("000010", "CVE-2023-0386", "linux", "released", "5.15.0-70.77", "not_affected", "ubuntu_kernel_abi", "version.safe_range"),
    AuditedRiskCase("000011", "CVE-2024-53150", "linux", "released", "5.15.0-135.146", "affected", "ubuntu_kernel_abi", "version.affected_range"),
    AuditedRiskCase("000012", "CVE-2024-53197", "linux", "released", "5.15.0-135.146", "affected", "ubuntu_kernel_abi", "version.affected_range"),
    AuditedRiskCase("000014", "CVE-2024-53104", "linux", "released", "5.15.0-133.144", "affected", "ubuntu_kernel_abi", "version.affected_range"),
    AuditedRiskCase("000015", "CVE-2024-36971", "linux", "released", "5.15.0-121.131", "affected", "ubuntu_kernel_abi", "version.affected_range"),
    AuditedRiskCase("000016", "CVE-2022-2586", "linux", "released", "5.15.0-46.49", "not_affected", "ubuntu_kernel_abi", "version.safe_range"),
    AuditedRiskCase("000017", "CVE-2024-1086", "linux", "released", "5.15.0-101.111", "not_affected", "ubuntu_kernel_abi", "version.safe_range"),
    AuditedRiskCase("000018", "CVE-2023-0266", "linux", "released", "5.15.0-69.76", "not_affected", "ubuntu_kernel_abi", "version.safe_range"),
    AuditedRiskCase("000019", "CVE-2021-3493", "linux", "not-affected", None, "not_affected", None, "distro_status.not_affected"),
    AuditedRiskCase("000020", "CVE-2022-0847", "linux", "not-affected", None, "not_affected", None, "distro_status.not_affected"),
    AuditedRiskCase("000022", "CVE-2021-22600", "linux", "not-affected", None, "not_affected", None, "distro_status.not_affected"),
)


@pytest.mark.parametrize(
    "case",
    AUDITED_RISK_CASES,
    ids=lambda case: f"risk-{case.risk_suffix}-{case.cve_id}",
)
def test_audited_jammy_risk_has_authoritative_status_and_evidence(
    db_session,
    case: AuditedRiskCase,
) -> None:
    asset = _audited_asset(db_session)
    product = "Linux Kernel" if case.package == "linux" else case.package
    vulnerability = create_vulnerability(
        db_session,
        canonical_id=case.cve_id,
        vendor="Linux" if case.package == "linux" else case.package,
        product=product,
        affected_versions=_invalid_upstream_constraint(case.package),
        fixed_versions="",
    )
    db_session.add(
        VulnerabilityAffectedScope(
            vulnerability_id=vulnerability.id,
            source_name="cve-record",
            scope_key=f"upstream-{case.cve_id}",
            vendor=vulnerability.vendor,
            product=product,
            affected_versions=_invalid_upstream_constraint(case.package),
            status="affected",
            source_authority="upstream",
            authority_score=20,
        )
    )
    db_session.commit()

    sync_ubuntu_security_statuses(
        db_session,
        vulnerability.id,
        fetcher=lambda _: _ubuntu_payload(case),
    )
    db_session.commit()
    db_session.refresh(vulnerability)

    result = evaluate_asset_vulnerability(db_session, asset, vulnerability)

    assert result.status == case.expected_status
    evidence_types = {item.evidence_type for item in result.evidence}
    assert "scope_resolution" in evidence_types
    trace = [
        item.details_json
        for item in result.evidence
        if item.evidence_type == "rule_trace"
    ]
    assert case.expected_reason_code in {
        item.get("reason_code") for item in trace
    }

    decisive = [
        item
        for item in result.evidence
        if item.evidence_type in {"distro_status", "kernel_version", "package_version"}
    ]
    assert decisive
    assert all(
        item.details_json.get("source_authority") == "distribution"
        for item in decisive
    )
    assert all(item.details_json.get("authority_score") == 100 for item in decisive)

    if case.expected_comparator is None:
        assert {item.evidence_type for item in decisive} == {"distro_status"}
        assert decisive[0].details_json["declared_status"] == "not_affected"
        return

    assert len(decisive) == 1
    comparisons = decisive[0].details_json["comparisons"]
    assert comparisons
    assert {item["comparator"] for item in comparisons} == {
        case.expected_comparator
    }
    assert all(item["reason_code"] is None for item in comparisons)


def test_audited_fixture_contains_exactly_the_18_reviewed_risks() -> None:
    assert len(AUDITED_RISK_CASES) == 18
    assert len({case.cve_id for case in AUDITED_RISK_CASES}) == 18
    assert {case.expected_status for case in AUDITED_RISK_CASES} == {
        "affected",
        "not_affected",
    }


def _audited_asset(db_session) -> Asset:
    asset = Asset(
        agent_id="audited-jammy-agent",
        hostname="audited-jammy-host",
        platform="linux",
        os_family="ubuntu",
        os_version="22.04",
        kernel_version="5.15.0-119-generic",
        architecture="amd64",
    )
    db_session.add(asset)
    db_session.flush()
    db_session.add_all(
        [
            AssetComponent(
                asset_id=asset.id,
                component_name="linux-image-5.15.0-119-generic",
                component_type="package",
                version="5.15.0-119.129",
                source_type="dpkg",
            ),
            AssetComponent(
                asset_id=asset.id,
                component_name="linux-image-generic",
                component_type="package",
                version="5.15.0.119.119",
                source_type="dpkg",
            ),
            AssetComponent(
                asset_id=asset.id,
                component_name="sudo",
                component_type="package",
                version="1.9.9-1ubuntu2.4",
                source_type="dpkg",
            ),
            AssetComponent(
                asset_id=asset.id,
                component_name="git",
                component_type="package",
                version="1:2.34.1-1ubuntu1.11",
                source_type="dpkg",
            ),
        ]
    )
    db_session.commit()
    return asset


def _ubuntu_payload(case: AuditedRiskCase) -> dict[str, object]:
    status = {
        "release_codename": "jammy",
        "status": case.ubuntu_status,
    }
    if case.fixed_version:
        status["description"] = case.fixed_version
    return {
        "id": case.cve_id,
        "packages": [{"name": case.package, "statuses": [status]}],
    }


def _invalid_upstream_constraint(package: str) -> str:
    if package == "linux":
        return ">= 0bddb0050557, < 78a498c3a227"
    if package == "git":
        return ">= 9f250a618c, < f4e52d6f27"
    return ">= 1.9.14, < 1.9.17"
