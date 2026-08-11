from __future__ import annotations

from collections import Counter
from typing import Any
from urllib.parse import parse_qsl, unquote

from app.connectors.base import RawIntelRecord
from app.connectors.canonical_ubuntu import canonical_vex_cve_id
from app.connectors.http_client import SourceDownloadError
from app.services.intel_enrichment import EnrichmentRecord, EnrichmentScope


class CanonicalUbuntuMapper:
    source_name = "canonical-ubuntu"

    def map_record(self, record: RawIntelRecord) -> EnrichmentRecord:
        payload = record.payload
        artifact_type = payload.get("artifact_type") if isinstance(payload, dict) else None
        if artifact_type == "openvex":
            return self._map_vex(record)
        if artifact_type == "oval":
            return self._map_oval(record)
        raise SourceDownloadError(f"unknown Canonical artifact type: {artifact_type}")

    def _map_vex(self, record: RawIntelRecord) -> EnrichmentRecord:
        document = record.payload.get("document")
        cve_id = canonical_vex_cve_id(document)
        statements = document.get("statements")
        scopes: list[EnrichmentScope] = []
        descriptions: list[str] = []
        references: list[str] = []
        status_counts: Counter[str] = Counter()
        for statement_index, statement in enumerate(statements):
            if not isinstance(statement, dict):
                continue
            vulnerability = statement.get("vulnerability")
            if isinstance(vulnerability, dict):
                description = _text(vulnerability.get("description"))
                if description and description not in descriptions:
                    descriptions.append(description)
                for alias in vulnerability.get("aliases") or []:
                    if isinstance(alias, str) and alias.startswith("https://") and alias not in references:
                        references.append(alias)
            vex_status = (_text(statement.get("status")) or "under_investigation").lower()
            status = _normalized_vex_status(vex_status)
            status_counts[vex_status] += 1
            products = [
                parsed
                for item in statement.get("products") or []
                if isinstance(item, dict)
                and (product_id := _text(item.get("@id")))
                and (parsed := parse_ubuntu_purl(product_id)) is not None
            ]
            source_packages = {
                (product["distro_release"], product["version"]): product["name"]
                for product in products
                if product["architecture"] == "source"
            }
            for product_index, product in enumerate(products):
                source_package = source_packages.get(
                    (product["distro_release"], product["version"])
                )
                if product["architecture"] == "source":
                    source_package = product["name"]
                    binary_package = None
                    architecture = None
                else:
                    binary_package = product["name"]
                    architecture = product["architecture"]
                fixed_version = product["version"] if status == "fixed" else None
                scopes.append(
                    EnrichmentScope(
                        vendor="Canonical",
                        product=product["name"],
                        ecosystem="deb",
                        distro="ubuntu",
                        distro_release=product["distro_release"],
                        source_package=source_package,
                        binary_package=binary_package,
                        architecture=architecture,
                        flavor=_kernel_flavor(product["name"]),
                        version_scheme=(
                            "ubuntu_kernel"
                            if product["name"].startswith("linux")
                            else "debian"
                        ),
                        version_type="ubuntu-package",
                        status=status,
                        default_status=vex_status,
                        purl=product["purl"],
                        platforms=[f"Ubuntu {product['distro_release']}"],
                        structured_versions=[
                            {
                                "release": product["distro_release"],
                                "status": vex_status,
                                "version": product["version"],
                                "architecture": product["architecture"],
                                "justification": statement.get("justification"),
                                "impact_statement": statement.get("impact_statement"),
                                "action_statement": statement.get("action_statement"),
                            }
                        ],
                        fixed_versions=fixed_version,
                        source_authority="distribution",
                        authority_score=100,
                        provenance={
                            "artifact": "openvex",
                            "statement_index": statement_index,
                            "product_index": product_index,
                            "statement_timestamp": statement.get("timestamp"),
                            "status_notes": statement.get("status_notes"),
                            "justification": statement.get("justification"),
                        },
                    )
                )
        return EnrichmentRecord(
            canonical_id=cve_id,
            title=cve_id,
            description=descriptions[0] if descriptions else None,
            contribution={
                "references": references,
                "ubuntu_vex": {
                    "document_id": document.get("@id"),
                    "timestamp": document.get("timestamp"),
                    "version": document.get("version"),
                    "statement_count": len(statements),
                    "status_counts": dict(status_counts),
                }
            },
            references=references,
            scopes=_dedupe_scopes(scopes),
            provenance={
                "artifact": "openvex",
                "artifact_member": record.payload.get("artifact_member"),
                "context": document.get("@context"),
                "author": document.get("author"),
            },
        )

    def _map_oval(self, record: RawIntelRecord) -> EnrichmentRecord:
        payload = record.payload
        cve_id = _text(payload.get("cve_id"))
        if not cve_id or cve_id not in record.external_id:
            raise SourceDownloadError("Canonical OVAL CVE id does not match raw event")
        scopes: list[EnrichmentScope] = []
        status_counts: Counter[str] = Counter()
        facts = payload.get("facts") if isinstance(payload.get("facts"), list) else []
        for fact_index, fact in enumerate(facts):
            if not isinstance(fact, dict):
                continue
            status = _text(fact.get("status")) or "under_investigation"
            status_counts[status] += 1
            fixed_version = _text(fact.get("fixed_version"))
            structured_versions = []
            if fixed_version:
                structured_versions.append(
                    {
                        "version": "0",
                        "lessThan": fixed_version,
                        "status": "affected",
                        "versionType": "debian",
                    }
                )
            scopes.append(
                EnrichmentScope(
                    vendor="Canonical",
                    product=_text(fact.get("binary_package"))
                    or _text(fact.get("source_package"))
                    or "ubuntu-package",
                    ecosystem="deb",
                    distro="ubuntu",
                    distro_release=_text(fact.get("release")),
                    source_package=_text(fact.get("source_package")),
                    binary_package=_text(fact.get("binary_package")),
                    architecture=None,
                    flavor=_text(fact.get("flavor"))
                    or _kernel_flavor(_text(fact.get("source_package")) or ""),
                    version_scheme=(
                        "ubuntu_kernel"
                        if (_text(fact.get("source_package")) or "").startswith("linux")
                        else "debian"
                    ),
                    version_type="ubuntu-package",
                    status=status,
                    default_status=_text(fact.get("default_status")),
                    platforms=[f"Ubuntu {fact.get('release')}"],
                    structured_versions=structured_versions,
                    affected_versions=(f"< {fixed_version}" if fixed_version else None),
                    fixed_versions=fixed_version,
                    source_authority="distribution",
                    authority_score=100,
                    provenance={
                        "artifact": "oval",
                        "artifact_release": payload.get("artifact_release"),
                        "fact_index": fact_index,
                        "definition_id": fact.get("definition_id"),
                        "test_ref": fact.get("test_ref"),
                        "comment": fact.get("comment"),
                        "operation": fact.get("operation"),
                        "datatype": fact.get("datatype"),
                    },
                )
            )
        return EnrichmentRecord(
            canonical_id=cve_id,
            title=_text(payload.get("title")) or cve_id,
            description=_text(payload.get("description")),
            contribution={
                "title": _text(payload.get("title")) or cve_id,
                "description": _text(payload.get("description")),
                "ubuntu_oval": {
                    "artifact_release": payload.get("artifact_release"),
                    "release": payload.get("release"),
                    "flavor": payload.get("flavor"),
                    "fact_count": len(facts),
                    "status_counts": dict(status_counts),
                }
            },
            scopes=_dedupe_scopes(scopes),
            provenance={
                "artifact": "oval",
                "artifact_release": payload.get("artifact_release"),
            },
        )


def parse_ubuntu_purl(value: str) -> dict[str, str] | None:
    if not value.startswith("pkg:deb/ubuntu/"):
        return None
    body = value[len("pkg:deb/ubuntu/") :]
    path, _, query = body.partition("?")
    name_part, separator, version_part = path.rpartition("@")
    if not separator:
        return None
    qualifiers = dict(parse_qsl(query, keep_blank_values=True))
    name = unquote(name_part)
    version = unquote(version_part)
    release = unquote(qualifiers.get("distro", ""))
    architecture = unquote(qualifiers.get("arch", ""))
    if not name or not version or not release or not architecture:
        return None
    return {
        "purl": value,
        "name": name,
        "version": version,
        "distro_release": release.lower(),
        "architecture": architecture.lower(),
    }


def _normalized_vex_status(value: str) -> str:
    if value in {"not_affected", "fixed", "affected", "under_investigation"}:
        return value
    return "under_investigation"


def _dedupe_scopes(scopes: list[EnrichmentScope]) -> list[EnrichmentScope]:
    deduped: dict[tuple[Any, ...], EnrichmentScope] = {}
    for scope in scopes:
        key = (
            scope.distro_release,
            scope.source_package,
            scope.binary_package,
            scope.architecture,
            scope.flavor,
            scope.status,
            scope.default_status,
            scope.fixed_versions,
        )
        deduped[key] = scope
    return list(deduped.values())


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


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
