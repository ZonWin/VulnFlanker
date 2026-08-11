from __future__ import annotations

from collections import Counter
from typing import Any

from app.connectors.base import RawIntelRecord
from app.connectors.http_client import SourceDownloadError
from app.services.intel_enrichment import EnrichmentRecord, EnrichmentScope


class DebianSecurityTrackerMapper:
    source_name = "debian-security-tracker"

    def map_record(self, record: RawIntelRecord) -> EnrichmentRecord:
        payload = record.payload
        cve_id = _text(payload.get("cve_id")) if isinstance(payload, dict) else None
        source_package = (
            _text(payload.get("source_package")) if isinstance(payload, dict) else None
        )
        tracker = payload.get("tracker") if isinstance(payload, dict) else None
        if not cve_id or not source_package or not isinstance(tracker, dict):
            raise SourceDownloadError("invalid Debian tracker package record")
        if not record.external_id.startswith(f"{cve_id}:"):
            raise SourceDownloadError("Debian tracker CVE id does not match raw event")

        releases = tracker.get("releases")
        scopes: list[EnrichmentScope] = []
        status_counts: Counter[str] = Counter()
        if isinstance(releases, dict):
            for release, release_fact in sorted(releases.items()):
                if not isinstance(release, str) or not isinstance(release_fact, dict):
                    continue
                tracker_status = (_text(release_fact.get("status")) or "undetermined").lower()
                fixed_version = _text(release_fact.get("fixed_version"))
                status = _map_debian_status(tracker_status, fixed_version)
                status_counts[tracker_status] += 1
                effective_fixed = (
                    fixed_version
                    if status == "fixed" and fixed_version not in {None, "0"}
                    else None
                )
                structured_versions = []
                if effective_fixed:
                    structured_versions.append(
                        {
                            "version": "0",
                            "lessThan": effective_fixed,
                            "status": "affected",
                            "versionType": "debian",
                        }
                    )
                scopes.append(
                    EnrichmentScope(
                        vendor="Debian",
                        product=source_package,
                        ecosystem="deb",
                        distro="debian",
                        distro_release=release.lower(),
                        source_package=source_package,
                        version_scheme="debian",
                        version_type="debian-package",
                        status=status,
                        default_status=tracker_status,
                        purl=f"pkg:deb/debian/{source_package}",
                        platforms=[f"Debian {release}"],
                        structured_versions=structured_versions,
                        affected_versions=(
                            f"< {effective_fixed}" if effective_fixed else None
                        ),
                        fixed_versions=effective_fixed,
                        source_authority="distribution",
                        authority_score=100,
                        provenance={
                            "release": release,
                            "urgency": release_fact.get("urgency"),
                            "repositories": release_fact.get("repositories"),
                            "nodsa": release_fact.get("nodsa"),
                            "nodsa_reason": release_fact.get("nodsa_reason"),
                            "fixed_version": fixed_version,
                        },
                    )
                )

        description = _text(tracker.get("description"))
        return EnrichmentRecord(
            canonical_id=cve_id,
            title=cve_id,
            description=description,
            contribution={
                "debian_scopes": {
                    "source_package": source_package,
                    "scope": tracker.get("scope"),
                    "release_count": len(scopes),
                    "status_counts": dict(status_counts),
                }
            },
            scopes=scopes,
            provenance={"source_package": source_package, "scope": tracker.get("scope")},
        )


def _map_debian_status(status: str, fixed_version: str | None) -> str:
    if status == "resolved":
        if fixed_version == "0":
            return "not_affected"
        return "fixed" if fixed_version else "under_investigation"
    if status == "open":
        return "affected"
    if status in {"undetermined", "unknown"}:
        return "under_investigation"
    return "under_investigation"


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
