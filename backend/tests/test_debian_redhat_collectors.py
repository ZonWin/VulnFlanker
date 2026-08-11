from __future__ import annotations

import io
import json
import tarfile
from datetime import datetime, timezone

import pytest
import zstandard
from sqlalchemy import select

from app.connectors.debian_security_tracker import (
    DebianSecurityTrackerConnector,
    iter_debian_tracker_records,
)
from app.connectors.http_client import SourceDownloadError
from app.connectors.redhat_csaf import (
    RedHatCsafConnector,
    iter_redhat_archive_records,
    select_redhat_delta_actions,
)
from app.db.base import utcnow
from app.db.models import IntelSourceConfig, Vulnerability, VulnerabilityAffectedScope
from app.matching.scope_resolver import scope_applies_to_asset
from app.services.debian_security_normalization import DebianSecurityTrackerMapper
from app.services.intel_source_collection import collect_enrichment_source
from app.services.redhat_csaf_normalization import (
    CsafProduct,
    RedHatCsafMapper,
    rhel_release,
)


def _debian_feed(cve_id: str = "CVE-2026-9400") -> dict:
    return {
        "openssl": {
            cve_id: {
                "description": "Debian tracker description",
                "scope": "remote",
                "releases": {
                    "bookworm": {
                        "status": "resolved",
                        "repositories": {"bookworm": "3.0.17-1~deb12u2"},
                        "fixed_version": "3.0.17-1~deb12u2",
                        "urgency": "high**",
                    },
                    "bullseye": {
                        "status": "open",
                        "repositories": {"bullseye": "1.1.1w-0+deb11u3"},
                        "fixed_version": "0",
                        "urgency": "high**",
                    },
                    "trixie": {
                        "status": "undetermined",
                        "repositories": {"trixie": "3.5.1-1"},
                        "fixed_version": "0",
                        "urgency": "not yet assigned",
                    },
                    "buster": {
                        "status": "resolved",
                        "repositories": {"buster": "1.1.1n-0+deb10u6"},
                        "fixed_version": "0",
                        "urgency": "unimportant",
                    },
                },
            }
        }
    }


def _redhat_vex(cve_id: str = "CVE-2026-9500") -> dict:
    platform = {
        "category": "product_name",
        "name": "Red Hat Enterprise Linux AppStream EUS (v.9.4)",
        "product": {
            "name": "Red Hat Enterprise Linux AppStream EUS (v.9.4)",
            "product_id": "AppStream-9.4.0.Z.EUS",
            "product_identification_helper": {
                "cpe": "cpe:/a:redhat:rhel_eus:9.4::appstream"
            },
        },
    }
    components = [
        (
            "openssl-fixed",
            "openssl-3.2.2-6.el9_4.1.x86_64",
            "pkg:rpm/redhat/openssl@3.2.2-6.el9_4.1?arch=x86_64",
        ),
        ("openssl", "openssl", "pkg:rpm/redhat/openssl"),
        ("bash", "bash", "pkg:rpm/redhat/bash"),
        ("curl", "curl", "pkg:rpm/redhat/curl"),
    ]
    component_branches = [
        {
            "category": "product_version",
            "name": name,
            "product": {
                "name": name,
                "product_id": product_id,
                "product_identification_helper": {"purl": purl},
            },
        }
        for product_id, name, purl in components
    ]
    relationships = [
        {
            "category": "default_component_of",
            "full_product_name": {
                "name": f"{component_id} as a component of RHEL 9.4",
                "product_id": f"AppStream-9.4.0.Z.EUS:{component_id}",
            },
            "product_reference": component_id,
            "relates_to_product_reference": "AppStream-9.4.0.Z.EUS",
        }
        for component_id, _name, _purl in components
    ]
    return {
        "document": {
            "category": "csaf_vex",
            "publisher": {"name": "Red Hat Product Security"},
            "tracking": {
                "id": cve_id,
                "current_release_date": "2026-08-11T00:00:00Z",
            },
        },
        "product_tree": {
            "branches": [
                {
                    "category": "vendor",
                    "name": "Red Hat",
                    "branches": [platform, *component_branches],
                }
            ],
            "relationships": relationships,
        },
        "vulnerabilities": [
            {
                "cve": cve_id,
                "notes": [
                    {"category": "description", "text": "Red Hat description"}
                ],
                "references": [
                    {
                        "category": "external",
                        "url": f"https://access.redhat.com/security/cve/{cve_id}",
                    }
                ],
                "product_status": {
                    "fixed": ["AppStream-9.4.0.Z.EUS:openssl-fixed"],
                    "known_affected": ["AppStream-9.4.0.Z.EUS:openssl"],
                    "known_not_affected": ["AppStream-9.4.0.Z.EUS:bash"],
                    "under_investigation": ["AppStream-9.4.0.Z.EUS:curl"],
                },
            }
        ],
    }


def _redhat_archive(documents: dict[str, dict], *, unsafe: bool = False) -> bytes:
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w") as archive:
        for path, document in documents.items():
            payload = json.dumps(document).encode("utf-8")
            member_path = f"../{path}" if unsafe else f"csaf-vex/{path}"
            info = tarfile.TarInfo(member_path)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return zstandard.ZstdCompressor().compress(tar_buffer.getvalue())


def test_debian_mapper_preserves_release_status_semantics() -> None:
    records = list(
        iter_debian_tracker_records(
            io.BytesIO(json.dumps(_debian_feed()).encode()),
            fetched_at=utcnow(),
            source_url="https://security-tracker.debian.org/tracker/data/json",
        )
    )
    normalized = DebianSecurityTrackerMapper().map_record(records[0])
    statuses = {scope.distro_release: scope for scope in normalized.scopes}

    assert statuses["bookworm"].status == "fixed"
    assert statuses["bookworm"].fixed_versions == "3.0.17-1~deb12u2"
    assert statuses["bullseye"].status == "affected"
    assert statuses["trixie"].status == "under_investigation"
    assert statuses["buster"].status == "not_affected"
    assert statuses["buster"].fixed_versions is None


def test_debian_connector_activates_complete_snapshot(db_session) -> None:
    feed_url = "https://security-tracker.debian.org/tracker/data/json"
    connector = DebianSecurityTrackerConnector(
        feed_url=feed_url,
        page_size=1,
        download_artifact=lambda _url: (
            io.BytesIO(json.dumps(_debian_feed()).encode()),
            "debian-hash",
        ),
    )
    run = collect_enrichment_source(
        db_session,
        connector=connector,
        mapper=DebianSecurityTrackerMapper(),
    )
    db_session.expire_all()

    assert run.status == "activated"
    vulnerability = db_session.scalar(
        select(Vulnerability).where(Vulnerability.canonical_id == "CVE-2026-9400")
    )
    assert vulnerability is not None
    assert len(vulnerability.affected_scopes) == 4
    assert all(
        scope.source_name == "debian-security-tracker"
        for scope in vulnerability.affected_scopes
    )


def test_debian_release_codename_matches_numeric_asset_version() -> None:
    asset = {
        "os_family": "debian",
        "os_version": "12",
        "components": [
            {"component_name": "openssl", "ecosystem": "deb"}
        ],
    }
    scope = {
        "distro": "debian",
        "distro_release": "bookworm",
        "ecosystem": "deb",
        "source_package": "openssl",
        "platforms_json": [],
    }
    assert scope_applies_to_asset(asset, scope) == (True, None)


def test_redhat_mapper_resolves_relationships_and_rpm_purls() -> None:
    record = next(
        iter_redhat_archive_records(
            io.BytesIO(
                _redhat_archive({"2026/cve-2026-9500.json": _redhat_vex()})
            ),
            fetched_at=utcnow(),
            base_url="https://security.access.redhat.com/data/csaf/v2/vex/",
        )
    )
    normalized = RedHatCsafMapper().map_record(record)
    statuses = {(scope.binary_package, scope.status): scope for scope in normalized.scopes}

    fixed = statuses[("openssl", "fixed")]
    assert fixed.distro_release == "9.4"
    assert fixed.architecture == "x86_64"
    assert fixed.fixed_versions == "3.2.2-6.el9_4.1"
    assert statuses[("openssl", "affected")].fixed_versions is None
    assert statuses[("bash", "not_affected")].status == "not_affected"
    assert statuses[("curl", "under_investigation")].status == "under_investigation"
    assert normalized.provenance["license"] == "CC BY 4.0"


def test_redhat_delta_prefers_latest_action_and_preserves_cursor_order() -> None:
    changes = io.BytesIO(
        b'"2026/cve-2026-9500.json","2026-08-11T01:00:00+00:00"\n'
        b'"2026/cve-2026-9600.json","2026-08-11T02:00:00+00:00"\n'
    )
    deletions = io.BytesIO(
        b'"2026/cve-2026-9500.json","2026-08-11T03:00:00+00:00"\n'
    )
    actions, latest = select_redhat_delta_actions(
        changes,
        deletions,
        since=datetime(2026, 8, 11, tzinfo=timezone.utc),
    )

    assert [item["action"] for item in actions] == ["update", "delete"]
    assert actions[-1]["path"] == "2026/cve-2026-9500.json"
    assert latest == datetime(2026, 8, 11, 3, tzinfo=timezone.utc)


def test_redhat_archive_rejects_path_traversal() -> None:
    archive = _redhat_archive(
        {"2026/cve-2026-9500.json": _redhat_vex()},
        unsafe=True,
    )
    with pytest.raises(SourceDownloadError, match="unsafe member"):
        list(
            iter_redhat_archive_records(
                io.BytesIO(archive),
                fetched_at=utcnow(),
                base_url="https://security.access.redhat.com/data/csaf/v2/vex/",
            )
        )


def test_redhat_deletion_delta_deactivates_previous_scopes(db_session) -> None:
    base_url = "https://security.access.redhat.com/data/csaf/v2/vex/"
    archive_name = "csaf_vex_2026-08-09.tar.zst"
    artifacts = {
        f"{base_url}archive_latest.txt": (archive_name.encode(), "pointer-hash"),
        f"{base_url}{archive_name}": (
            _redhat_archive({"2026/cve-2026-9500.json": _redhat_vex()}),
            "archive-hash",
        ),
    }

    def baseline_download(url: str):
        payload, digest = artifacts[url]
        return io.BytesIO(payload), digest

    connector = RedHatCsafConnector(
        base_url=base_url,
        page_size=10,
        download_artifact=baseline_download,
    )
    baseline = collect_enrichment_source(
        db_session,
        connector=connector,
        mapper=RedHatCsafMapper(),
    )
    assert baseline.status == "activated"
    assert db_session.scalars(
        select(VulnerabilityAffectedScope).where(
            VulnerabilityAffectedScope.source_name == "redhat-csaf",
            VulnerabilityAffectedScope.is_active.is_(True),
        )
    ).all()

    delta_artifacts = {
        f"{base_url}changes.csv": (b"", "changes-hash"),
        f"{base_url}deletions.csv": (
            b'"2026/cve-2026-9500.json","2026-08-11T03:00:00+00:00"\n',
            "deletions-hash",
        ),
    }

    def delta_download(url: str):
        payload, digest = delta_artifacts[url]
        return io.BytesIO(payload), digest

    connector.download_artifact = delta_download
    delta = collect_enrichment_source(
        db_session,
        connector=connector,
        mapper=RedHatCsafMapper(),
    )
    db_session.expire_all()

    assert delta.status == "activated"
    assert db_session.scalars(
        select(VulnerabilityAffectedScope).where(
            VulnerabilityAffectedScope.source_name == "redhat-csaf",
            VulnerabilityAffectedScope.is_active.is_(True),
        )
    ).all() == []
    config = db_session.scalar(
        select(IntelSourceConfig).where(IntelSourceConfig.source_name == "redhat-csaf")
    )
    assert config is not None
    assert config.cursor_json["feed_timestamp"] == "2026-08-11T03:00:00+00:00"


def test_rhel_major_scope_matches_minor_asset_but_minor_scopes_stay_exact() -> None:
    asset = {
        "os_family": "rhel",
        "os_version": "9.4",
        "components": [{"component_name": "openssl", "ecosystem": "rpm"}],
    }
    common = {
        "distro": "rhel",
        "ecosystem": "rpm",
        "binary_package": "openssl",
        "platforms_json": [],
    }
    assert scope_applies_to_asset(asset, {**common, "distro_release": "9"}) == (
        True,
        None,
    )
    assert scope_applies_to_asset(asset, {**common, "distro_release": "9.6"}) == (
        False,
        "distro_release_mismatch",
    )


def test_redhat_release_parser_does_not_treat_e4s_digit_as_release() -> None:
    platform = CsafProduct(
        product_id="AppStream-8.8.0.Z.E4S",
        name="Red Hat Enterprise Linux AppStream E4S (v.8.8)",
        purl=None,
        cpe="cpe:/a:redhat:rhel_e4s:8.8::appstream",
        branch_path=(),
    )
    assert rhel_release(platform) == "8.8"
