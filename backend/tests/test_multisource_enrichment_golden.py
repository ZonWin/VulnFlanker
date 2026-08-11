from __future__ import annotations

from types import SimpleNamespace

from app.db.models import (
    Asset,
    AssetComponent,
    Vulnerability,
    VulnerabilityAffectedScope,
    VulnerabilitySource,
)
from app.services.intel_authority import merge_contribution_documents
from app.services.intel_enrichment_orchestration import enrichment_source_names
from app.services.matching import evaluate_asset_vulnerability


def _contribution(source_name: str, document: dict, key: str = "CVE-2026-9800"):
    return SimpleNamespace(
        source_name=source_name,
        generation_id=f"generation-{source_name}",
        external_key=key,
        contribution_json=document,
        provenance_json={"source": source_name},
        is_active=True,
    )


def test_multisource_field_authority_keeps_conflicts_without_role_leakage() -> None:
    merged = merge_contribution_documents(
        [
            _contribution(
                "cisa-kev",
                {
                    "known_exploited": True,
                    "required_action": "Apply mitigations.",
                    "description": "KEV must not own generic description.",
                },
            ),
            _contribution(
                "cve-list-v5",
                {
                    "title": "CNA title",
                    "description": "CNA authoritative description",
                    "references": ["https://vendor.example/advisory"],
                },
            ),
            _contribution(
                "nvd",
                {
                    "description": "NVD analysis description",
                    "nvd_metrics": {"cvssMetricV31": [{"baseScore": 9.8}]},
                },
            ),
            _contribution(
                "canonical-ubuntu",
                {
                    "description": "Distribution source must not replace CNA text.",
                    "ubuntu_vex": {"status_counts": {"not_affected": 1}},
                },
            ),
        ]
    )

    assert merged["known_exploited"].source_name == "cisa-kev"
    assert merged["description"].source_name == "cve-list-v5"
    assert merged["description"].value == "CNA authoritative description"
    assert merged["description"].has_conflict is True
    assert {item.source_name for item in merged["description"].candidates} == {
        "cve-list-v5",
        "nvd",
    }
    assert "description" not in {
        field
        for field, value in merged.items()
        if value.source_name == "canonical-ubuntu"
    }


def test_ubuntu_distribution_scope_wins_without_cross_distro_leakage(db_session) -> None:
    asset = Asset(
        agent_id="agent-golden-ubuntu",
        hostname="golden-ubuntu",
        platform="linux",
        os_family="ubuntu",
        os_version="22.04",
        architecture="x86_64",
    )
    vulnerability = Vulnerability(
        canonical_id="CVE-2026-9801",
        title="OpenSSL multi-source golden",
        vendor="OpenSSL",
        product="OpenSSL",
        affected_versions="< 99.0",
        severity_label="high",
        severity_cvss=8.0,
    )
    db_session.add_all((asset, vulnerability))
    db_session.flush()
    db_session.add_all(
        [
            AssetComponent(
                asset_id=asset.id,
                component_name="libssl3",
                component_type="package",
                version="3.0.2-0ubuntu1.20",
                source_type="dpkg-query",
                ecosystem="deb",
                distro="ubuntu",
                distro_release="22.04",
                source_package="openssl",
                binary_package="libssl3",
                architecture="amd64",
                version_scheme="debian",
            ),
            VulnerabilitySource(
                vulnerability_id=vulnerability.id,
                source_name="cve-list-v5",
                external_id=vulnerability.canonical_id,
                title=vulnerability.title,
                source_url="https://www.cve.org/CVERecord?id=CVE-2026-9801",
                last_payload_hash="golden-cve-hash",
            ),
            VulnerabilityAffectedScope(
                vulnerability_id=vulnerability.id,
                source_name="nvd",
                scope_key="nvd-upstream",
                vendor="OpenSSL",
                product="OpenSSL",
                status="affected",
                affected_versions="< 99.0",
                source_authority="upstream",
                authority_score=80,
            ),
            VulnerabilityAffectedScope(
                vulnerability_id=vulnerability.id,
                source_name="canonical-ubuntu",
                scope_key="canonical-jammy",
                vendor="Canonical",
                product="libssl3",
                ecosystem="deb",
                distro="ubuntu",
                distro_release="jammy",
                source_package="openssl",
                binary_package="libssl3",
                status="not_affected",
                default_status="not_affected",
                source_authority="distribution",
                authority_score=100,
            ),
            VulnerabilityAffectedScope(
                vulnerability_id=vulnerability.id,
                source_name="debian-security-tracker",
                scope_key="debian-bookworm",
                vendor="Debian",
                product="openssl",
                ecosystem="deb",
                distro="debian",
                distro_release="bookworm",
                source_package="openssl",
                status="affected",
                default_status="open",
                source_authority="distribution",
                authority_score=100,
            ),
            VulnerabilityAffectedScope(
                vulnerability_id=vulnerability.id,
                source_name="redhat-csaf",
                scope_key="redhat-nine",
                vendor="Red Hat",
                product="openssl",
                ecosystem="rpm",
                distro="rhel",
                distro_release="9",
                binary_package="openssl",
                status="affected",
                default_status="known_affected",
                source_authority="distribution",
                authority_score=100,
            ),
        ]
    )
    db_session.commit()

    result = evaluate_asset_vulnerability(db_session, asset, vulnerability)

    assert result.status == "not_affected"
    distro_status = next(
        evidence for evidence in result.evidence if evidence.evidence_type == "distro_status"
    )
    assert distro_status.details_json["affected_scope"]["source_name"] == (
        "canonical-ubuntu"
    )
    resolution = next(
        evidence
        for evidence in result.evidence
        if evidence.evidence_type == "scope_resolution"
    )
    excluded_reasons = {
        item["reason"] for item in resolution.details_json["excluded_scopes"]
    }
    assert "distro_mismatch" in excluded_reasons
    assert "superseded_by_more_authoritative_specific_scope" in excluded_reasons


def test_all_formal_enrichment_collectors_remain_independent_registry_entries() -> None:
    assert enrichment_source_names() == (
        "canonical-ubuntu",
        "cve-list-v5",
        "debian-security-tracker",
        "nvd",
        "redhat-csaf",
    )
