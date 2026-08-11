from __future__ import annotations

import json
import re
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Callable
from urllib.request import Request, urlopen

from sqlalchemy import delete, or_, select
from sqlalchemy.orm import Session, selectinload

from app.db.models import Vulnerability, VulnerabilityAffectedScope


UBUNTU_SECURITY_SOURCE = "ubuntu-security"
UBUNTU_SECURITY_AUTHORITY_SCORE = 100
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


@dataclass(slots=True)
class UbuntuSecuritySyncResult:
    vulnerability_id: str
    canonical_id: str
    scope_count: int
    status_counts: dict[str, int]


def fetch_ubuntu_cve_payload(canonical_id: str) -> dict[str, Any]:
    cve_id = _validated_cve_id(canonical_id)
    url = f"https://ubuntu.com/security/cves/{cve_id}.json"
    request = Request(url, headers={"Accept": "application/json"})
    with urlopen(request, timeout=30) as response:  # noqa: S310 - fixed trusted host
        payload = response.read(20 * 1024 * 1024 + 1)
    if len(payload) > 20 * 1024 * 1024:
        raise ValueError("Ubuntu security response exceeded 20 MiB")
    parsed = json.loads(payload.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("Ubuntu security response must be a JSON object")
    return parsed


def parse_ubuntu_cve_scopes(payload: dict[str, Any]) -> list[dict[str, Any]]:
    canonical_id = _validated_cve_id(str(payload.get("id") or ""))
    source_url = f"https://ubuntu.com/security/cves/{canonical_id}.json"
    scopes: dict[str, dict[str, Any]] = {}
    for package in payload.get("packages") or []:
        if not isinstance(package, dict):
            continue
        package_name = _clean_text(package.get("name"))
        if not package_name:
            continue
        for release_status in package.get("statuses") or []:
            if not isinstance(release_status, dict):
                continue
            release = _clean_text(release_status.get("release_codename"))
            raw_status = _clean_text(release_status.get("status"))
            if not release or not raw_status or release.lower() == "upstream":
                continue
            status = _normalized_ubuntu_status(raw_status)
            if status is None:
                status = "needs_review"
            description = _clean_text(release_status.get("description"))
            fixed_version = description if status == "fixed" and description else None
            scope = {
                "source_name": UBUNTU_SECURITY_SOURCE,
                "vendor": "Canonical",
                "product": package_name,
                "ecosystem": "deb",
                "distro": "ubuntu",
                "distro_release": release.lower(),
                "source_package": package_name,
                "binary_package": None,
                "architecture": None,
                "flavor": _kernel_flavor(package_name),
                "version_scheme": (
                    "ubuntu_kernel" if package_name.startswith("linux") else "debian"
                ),
                "version_type": "ubuntu-package",
                "status": status,
                "default_status": raw_status,
                "source_authority": "distribution",
                "authority_score": UBUNTU_SECURITY_AUTHORITY_SCORE,
                "purl": None,
                "cpe": None,
                "platforms": [f"Ubuntu {release.lower()}"],
                "structured_versions": [
                    {
                        "release": release.lower(),
                        "status": raw_status,
                        "description": description,
                        "pocket": _clean_text(release_status.get("pocket")),
                        "component": _clean_text(release_status.get("component")),
                    }
                ],
                "affected_versions": None,
                "fixed_versions": fixed_version,
                "source_url": source_url,
            }
            scope["scope_key"] = _scope_key(scope)
            scopes[scope["scope_key"]] = scope
    return list(scopes.values())


def sync_ubuntu_security_statuses(
    db: Session,
    vulnerability_id: str,
    *,
    fetcher: Callable[[str], dict[str, Any]] = fetch_ubuntu_cve_payload,
) -> UbuntuSecuritySyncResult:
    vulnerability = db.scalar(
        select(Vulnerability)
        .options(selectinload(Vulnerability.affected_scopes))
        .where(
            or_(
                Vulnerability.id == vulnerability_id,
                Vulnerability.canonical_id == vulnerability_id,
            )
        )
    )
    if vulnerability is None:
        raise ValueError("Vulnerability not found")
    payload = fetcher(vulnerability.canonical_id)
    payload_id = _validated_cve_id(str(payload.get("id") or ""))
    if payload_id != vulnerability.canonical_id.upper():
        raise ValueError(
            f"Ubuntu security response ID {payload_id} does not match "
            f"{vulnerability.canonical_id}"
        )
    scopes = parse_ubuntu_cve_scopes(payload)

    db.execute(
        delete(VulnerabilityAffectedScope).where(
            VulnerabilityAffectedScope.vulnerability_id == vulnerability.id,
            VulnerabilityAffectedScope.source_name == UBUNTU_SECURITY_SOURCE,
        )
    )
    status_counts: dict[str, int] = {}
    for item in scopes:
        status_counts[item["status"]] = status_counts.get(item["status"], 0) + 1
        db.add(
            VulnerabilityAffectedScope(
                vulnerability_id=vulnerability.id,
                source_name=item["source_name"],
                scope_key=item["scope_key"],
                vendor=item["vendor"],
                product=item["product"],
                ecosystem=item["ecosystem"],
                distro=item["distro"],
                distro_release=item["distro_release"],
                source_package=item["source_package"],
                binary_package=item["binary_package"],
                architecture=item["architecture"],
                flavor=item["flavor"],
                version_scheme=item["version_scheme"],
                version_type=item["version_type"],
                status=item["status"],
                default_status=item["default_status"],
                source_authority=item["source_authority"],
                authority_score=item["authority_score"],
                purl=item["purl"],
                cpe=item["cpe"],
                platforms_json=item["platforms"],
                structured_versions_json=item["structured_versions"],
                affected_versions=item["affected_versions"],
                fixed_versions=item["fixed_versions"],
                source_url=item["source_url"],
            )
        )
    db.flush()
    return UbuntuSecuritySyncResult(
        vulnerability_id=vulnerability.id,
        canonical_id=vulnerability.canonical_id,
        scope_count=len(scopes),
        status_counts=status_counts,
    )


def _normalized_ubuntu_status(value: str) -> str | None:
    status = value.strip().lower().replace("_", "-")
    if status == "released":
        return "fixed"
    if status in {"not-affected", "dne"}:
        return "not_affected"
    if status in {"needed", "deferred", "pending"}:
        return "affected"
    if status in {"ignored", "needs-triage"}:
        return "needs_review"
    return None


def _kernel_flavor(package_name: str) -> str | None:
    if not package_name.startswith("linux-"):
        return None
    known_flavors = (
        "aws",
        "azure",
        "gcp",
        "gke",
        "ibm",
        "lowlatency",
        "nvidia",
        "oem",
        "oracle",
        "raspi",
        "realtime",
    )
    return next((flavor for flavor in known_flavors if flavor in package_name), None)


def _scope_key(scope: dict[str, Any]) -> str:
    identity = {
        key: scope.get(key)
        for key in (
            "distro",
            "distro_release",
            "source_package",
            "binary_package",
            "architecture",
            "flavor",
            "status",
            "default_status",
            "fixed_versions",
        )
    }
    identity["structured_versions"] = scope.get("structured_versions")
    return sha256(
        json.dumps(identity, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()


def _validated_cve_id(value: str) -> str:
    candidate = value.strip().upper()
    if not _CVE_PATTERN.fullmatch(candidate):
        raise ValueError(f"Invalid CVE ID: {value}")
    return candidate


def _clean_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
