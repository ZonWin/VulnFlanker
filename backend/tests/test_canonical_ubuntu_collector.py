from __future__ import annotations

import bz2
import io
import json
import tarfile

import pytest
from sqlalchemy import select

from app.connectors.canonical_ubuntu import (
    CanonicalUbuntuConnector,
    canonical_artifact_identity,
    canonical_oval_status,
    decompress_bz2_bounded,
    iter_canonical_oval_records,
    iter_canonical_vex_records,
)
from app.connectors.http_client import SourceDownloadError
from app.db.models import (
    IntelSourceConfig,
    Vulnerability,
    VulnerabilityAffectedScope,
    VulnerabilitySourceContribution,
)
from app.services.canonical_ubuntu_normalization import (
    CanonicalUbuntuMapper,
    parse_ubuntu_purl,
)
from app.services.intel_source_collection import collect_enrichment_source


def _vex_document(cve_id: str = "CVE-2026-9300") -> dict:
    vulnerability = {
        "@id": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "name": cve_id,
        "description": "Canonical VEX description",
        "aliases": [
            f"https://www.cve.org/CVERecord?id={cve_id}",
            f"https://ubuntu.com/security/{cve_id}",
        ],
    }
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://canonical.example/{cve_id}",
        "author": "Canonical Ltd.",
        "timestamp": "2026-08-11T00:00:00Z",
        "version": 2,
        "statements": [
            {
                "vulnerability": vulnerability,
                "status": "not_affected",
                "justification": "vulnerable_code_not_present",
                "impact_statement": "The package is not affected.",
                "products": [
                    {
                        "@id": "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1?arch=source&distro=jammy"
                    },
                    {
                        "@id": "pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1?arch=amd64&distro=jammy"
                    },
                ],
            },
            {
                "vulnerability": vulnerability,
                "status": "fixed",
                "status_notes": "A fix has been published.",
                "products": [
                    {
                        "@id": "pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.5?arch=source&distro=noble"
                    },
                    {
                        "@id": "pkg:deb/ubuntu/libssl3t64@3.0.13-0ubuntu3.5?arch=amd64&distro=noble"
                    },
                ],
            },
            {
                "vulnerability": vulnerability,
                "status": "under_investigation",
                "products": [
                    {
                        "@id": "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1?arch=source&distro=focal"
                    }
                ],
            },
        ],
    }


def _vex_tar(document: dict, *, unsafe: bool = False) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:xz") as archive:
        payload = json.dumps(document).encode("utf-8")
        name = (
            "../vex/cve/2026/CVE-2026-9300.json"
            if unsafe
            else "ubuntu-security-notices/vex/cve/2026/CVE-2026-9300.json"
        )
        info = tarfile.TarInfo(name)
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    return output.getvalue()


def _oval_xml(cve_id: str = "CVE-2026-9300") -> bytes:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
 xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
  <definitions>
    <definition class="vulnerability" id="oval:com.ubuntu.jammy:def:1" version="1">
      <metadata>
        <title>{cve_id} on Ubuntu 22.04 LTS</title>
        <description>Canonical OVAL description</description>
        <reference source="CVE" ref_id="{cve_id}" ref_url="https://www.cve.org/CVERecord?id={cve_id}"/>
      </metadata>
      <criteria operator="OR">
        <criteria operator="AND">
          <criterion test_ref="oval:com.ubuntu.jammy:tst:1" comment="openssl package in jammy was vulnerable but has been fixed (note: '3.0.2-0ubuntu1.20')."/>
          <criterion test_ref="oval:com.ubuntu.jammy:tst:1" comment="duplicate ref"/>
        </criteria>
      </criteria>
    </definition>
  </definitions>
  <tests>
    <linux-def:dpkginfo_test id="oval:com.ubuntu.jammy:tst:1" version="1" check_existence="at_least_one_exists" check="at least one">
      <linux-def:object object_ref="oval:com.ubuntu.jammy:obj:1"/>
      <linux-def:state state_ref="oval:com.ubuntu.jammy:ste:1"/>
    </linux-def:dpkginfo_test>
  </tests>
  <objects>
    <linux-def:dpkginfo_object id="oval:com.ubuntu.jammy:obj:1" version="1">
      <linux-def:name var_ref="oval:com.ubuntu.jammy:var:1" var_check="at least one"/>
    </linux-def:dpkginfo_object>
  </objects>
  <states>
    <linux-def:dpkginfo_state id="oval:com.ubuntu.jammy:ste:1" version="1">
      <linux-def:evr datatype="debian_evr_string" operation="less than">0:3.0.2-0ubuntu1.20</linux-def:evr>
    </linux-def:dpkginfo_state>
  </states>
  <variables>
    <constant_variable id="oval:com.ubuntu.jammy:var:1" version="1" datatype="string">
      <value>openssl</value>
      <value>libssl3</value>
    </constant_variable>
  </variables>
</oval_definitions>""".encode("utf-8")


def test_parse_ubuntu_purl_extracts_release_arch_and_version() -> None:
    assert parse_ubuntu_purl(
        "pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.20?arch=amd64&distro=jammy"
    ) == {
        "purl": "pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.20?arch=amd64&distro=jammy",
        "name": "libssl3",
        "version": "3.0.2-0ubuntu1.20",
        "distro_release": "jammy",
        "architecture": "amd64",
    }
    assert parse_ubuntu_purl("pkg:rpm/redhat/openssl@1") is None


def test_canonical_artifact_identity_keeps_flavor_separate() -> None:
    assert canonical_artifact_identity("jammy") == ("jammy", None)
    assert canonical_artifact_identity("realtime/jammy") == ("jammy", "realtime")


def test_canonical_oval_status_never_infers_not_affected_from_missing_state() -> None:
    assert canonical_oval_status("package is not affected", {}) == (
        "not_affected",
        "not-affected",
    )
    assert canonical_oval_status("package decision has been made to ignore", {}) == (
        "affected",
        "ignored",
    )
    assert canonical_oval_status(None, {}) == ("under_investigation", "unknown")


def test_canonical_vex_archive_rejects_path_traversal() -> None:
    artifact = io.BytesIO(_vex_tar(_vex_document(), unsafe=True))
    with pytest.raises(SourceDownloadError, match="unsafe path"):
        list(
            iter_canonical_vex_records(
                artifact,
                fetched_at=datetime_now(),
                source_url="https://security-metadata.canonical.com/vex/vex-all.tar.xz",
            )
        )


def test_canonical_oval_decompression_rejects_doctype() -> None:
    artifact = io.BytesIO(bz2.compress(b"<!DOCTYPE foo><root/>"))
    with pytest.raises(SourceDownloadError, match="forbidden declaration"):
        decompress_bz2_bounded(artifact)


def test_canonical_oval_parser_resolves_test_object_state_and_variable() -> None:
    records = list(
        iter_canonical_oval_records(
            io.BytesIO(_oval_xml()),
            artifact_release="jammy",
            fetched_at=datetime_now(),
            source_url="https://security-metadata.canonical.com/oval/jammy",
        )
    )

    assert len(records) == 1
    facts = records[0].payload["facts"]
    assert len(facts) == 2
    assert {fact["binary_package"] for fact in facts} == {"openssl", "libssl3"}
    assert {fact["source_package"] for fact in facts} == {"openssl"}
    assert {fact["fixed_version"] for fact in facts} == {"3.0.2-0ubuntu1.20"}
    assert {fact["status"] for fact in facts} == {"fixed"}


def test_canonical_mapper_preserves_explicit_vex_statuses() -> None:
    record = next(
        iter_canonical_vex_records(
            io.BytesIO(_vex_tar(_vex_document())),
            fetched_at=datetime_now(),
            source_url="https://security-metadata.canonical.com/vex/vex-all.tar.xz",
        )
    )

    normalized = CanonicalUbuntuMapper().map_record(record)

    statuses = {(scope.distro_release, scope.status) for scope in normalized.scopes}
    assert ("jammy", "not_affected") in statuses
    assert ("noble", "fixed") in statuses
    assert ("focal", "under_investigation") in statuses
    noble_binary = next(
        scope
        for scope in normalized.scopes
        if scope.distro_release == "noble" and scope.binary_package == "libssl3t64"
    )
    assert noble_binary.source_package == "openssl"
    assert noble_binary.fixed_versions == "3.0.13-0ubuntu3.5"


def test_canonical_connector_activates_vex_and_oval_in_one_generation(db_session) -> None:
    vex_url = "https://security-metadata.canonical.com/vex/vex-all.tar.xz"
    oval_url = (
        "https://security-metadata.canonical.com/oval/"
        "com.ubuntu.jammy.cve.oval.xml.bz2"
    )
    artifacts = {
        vex_url: (_vex_tar(_vex_document()), "vex-hash"),
        oval_url: (bz2.compress(_oval_xml()), "oval-hash"),
    }

    def download(url: str):
        payload, digest = artifacts[url]
        return io.BytesIO(payload), digest

    connector = CanonicalUbuntuConnector(
        vex_url=vex_url,
        releases=["jammy"],
        page_size=10,
        download_artifact=download,
    )
    run = collect_enrichment_source(
        db_session,
        connector=connector,
        mapper=CanonicalUbuntuMapper(),
    )
    db_session.expire_all()

    vulnerability = db_session.scalar(
        select(Vulnerability).where(Vulnerability.canonical_id == "CVE-2026-9300")
    )
    assert run.status == "activated"
    assert run.update_mode == "snapshot"
    assert run.completeness_json["artifact_count"] == 2
    assert vulnerability is not None
    scopes = vulnerability.affected_scopes
    assert any(
        scope.distro_release == "jammy"
        and scope.binary_package == "libssl3"
        and scope.status == "not_affected"
        for scope in scopes
    )
    assert any(
        scope.distro_release == "jammy"
        and scope.binary_package == "libssl3"
        and scope.status == "fixed"
        and scope.fixed_versions == "3.0.2-0ubuntu1.20"
        for scope in scopes
    )
    assert all(scope.source_name == "canonical-ubuntu" for scope in scopes)
    assert {scope.source_authority for scope in scopes} == {"distribution"}

    contributions = db_session.scalars(
        select(VulnerabilitySourceContribution).where(
            VulnerabilitySourceContribution.vulnerability_id == vulnerability.id,
            VulnerabilitySourceContribution.is_active.is_(True),
        )
    ).all()
    assert len(contributions) == 2
    assert {row.external_key.split(":", 1)[0] for row in contributions} == {"vex", "oval"}
    config = db_session.scalar(
        select(IntelSourceConfig).where(
            IntelSourceConfig.source_name == "canonical-ubuntu"
        )
    )
    assert config is not None
    assert config.cursor_json["artifacts"] == {
        "openvex": "vex-hash",
        "oval:jammy": "oval-hash",
    }


def test_canonical_limit_does_not_activate_partial_snapshot(db_session) -> None:
    vex_url = "https://security-metadata.canonical.com/vex/vex-all.tar.xz"
    oval_url = (
        "https://security-metadata.canonical.com/oval/"
        "com.ubuntu.jammy.cve.oval.xml.bz2"
    )
    artifacts = {
        vex_url: (_vex_tar(_vex_document()), "vex-hash"),
        oval_url: (bz2.compress(_oval_xml()), "oval-hash"),
    }
    connector = CanonicalUbuntuConnector(
        vex_url=vex_url,
        releases=["jammy"],
        download_artifact=lambda url: (io.BytesIO(artifacts[url][0]), artifacts[url][1]),
    )

    with pytest.raises(Exception, match="complete terminal page"):
        collect_enrichment_source(
            db_session,
            connector=connector,
            mapper=CanonicalUbuntuMapper(),
            limit=1,
        )

    assert db_session.scalars(
        select(VulnerabilityAffectedScope).where(
            VulnerabilityAffectedScope.source_name == "canonical-ubuntu",
            VulnerabilityAffectedScope.is_active.is_(True),
        )
    ).all() == []


def datetime_now():
    from app.db.base import utcnow

    return utcnow()
