from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, unquote

from app.connectors.base import RawIntelRecord
from app.connectors.http_client import SourceDownloadError
from app.services.intel_enrichment import EnrichmentRecord, EnrichmentScope


@dataclass(frozen=True, slots=True)
class CsafProduct:
    product_id: str
    name: str
    purl: str | None
    cpe: str | None
    branch_path: tuple[str, ...]


class RedHatCsafMapper:
    source_name = "redhat-csaf"

    def map_record(self, record: RawIntelRecord) -> EnrichmentRecord:
        payload = record.payload
        if not isinstance(payload, dict):
            raise SourceDownloadError("invalid Red Hat CSAF raw event")
        if payload.get("deleted") is True:
            cve_id = _text(payload.get("cve_id"))
            if not cve_id or cve_id.upper() != record.external_id.upper():
                raise SourceDownloadError("Red Hat deletion CVE id does not match raw event")
            return EnrichmentRecord(
                canonical_id=cve_id.upper(),
                title=cve_id.upper(),
                description=None,
                contribution={
                    "redhat_scopes": {
                        "deleted": True,
                        "deleted_at": payload.get("deleted_at"),
                        "path": payload.get("path"),
                    }
                },
                scopes=[],
                provenance={"deleted": True, "path": payload.get("path")},
            )

        vulnerabilities = payload.get("vulnerabilities")
        vulnerability = next(
            (
                item
                for item in vulnerabilities or []
                if isinstance(item, dict)
                and (_text(item.get("cve")) or "").upper()
                == record.external_id.upper()
            ),
            None,
        )
        if vulnerability is None:
            raise SourceDownloadError("Red Hat CSAF CVE id does not match raw event")

        products = index_csaf_products(payload.get("product_tree"))
        relationships = index_csaf_relationships(payload.get("product_tree"))
        scopes: list[EnrichmentScope] = []
        status_counts: Counter[str] = Counter()
        ignored_non_rhel = 0
        product_status = vulnerability.get("product_status")
        if isinstance(product_status, dict):
            for csaf_status, product_ids in product_status.items():
                status = _map_redhat_status(str(csaf_status))
                if status is None or not isinstance(product_ids, list):
                    continue
                for product_id in product_ids:
                    relation = relationships.get(str(product_id))
                    if relation is None:
                        continue
                    component = products.get(relation[0])
                    platform = products.get(relation[1])
                    if component is None or platform is None:
                        continue
                    release = rhel_release(platform)
                    if release is None:
                        ignored_non_rhel += 1
                        continue
                    package = parse_redhat_rpm_product(component)
                    if package is None:
                        continue
                    status_counts[str(csaf_status)] += 1
                    fixed_version = package["version"] if status == "fixed" else None
                    structured_versions = []
                    if fixed_version:
                        structured_versions.append(
                            {
                                "version": "0",
                                "lessThan": fixed_version,
                                "status": "affected",
                                "versionType": "rpm",
                            }
                        )
                    is_source = package["architecture"] == "src"
                    scopes.append(
                        EnrichmentScope(
                            vendor="Red Hat",
                            product=package["name"],
                            ecosystem="rpm",
                            distro="rhel",
                            distro_release=release,
                            source_package=package["name"] if is_source else None,
                            binary_package=None if is_source else package["name"],
                            architecture=(
                                None if is_source else package["architecture"]
                            ),
                            version_scheme="rpm",
                            version_type="rpm-evr",
                            status=status,
                            default_status=str(csaf_status),
                            purl=package["purl"],
                            cpe=platform.cpe,
                            platforms=[platform.name],
                            structured_versions=structured_versions,
                            affected_versions=(
                                f"< {fixed_version}" if fixed_version else None
                            ),
                            fixed_versions=fixed_version,
                            source_authority="distribution",
                            authority_score=100,
                            provenance={
                                "relationship_id": product_id,
                                "relationship_category": relation[2],
                                "component_product_id": component.product_id,
                                "platform_product_id": platform.product_id,
                                "platform_name": platform.name,
                                "csaf_status": csaf_status,
                            },
                        )
                    )

        references = [
            url
            for item in vulnerability.get("references") or []
            if isinstance(item, dict) and (url := _text(item.get("url")))
        ]
        descriptions = [
            text
            for note in vulnerability.get("notes") or []
            if isinstance(note, dict)
            and note.get("category") in {"description", "summary"}
            and (text := _text(note.get("text")))
        ]
        return EnrichmentRecord(
            canonical_id=record.external_id.upper(),
            title=record.external_id.upper(),
            description=descriptions[0] if descriptions else None,
            contribution={
                "redhat_scopes": {
                    "document_tracking_id": _nested(payload, "document", "tracking", "id"),
                    "document_revision": _nested(
                        payload, "document", "tracking", "current_release_date"
                    ),
                    "status_counts": dict(status_counts),
                    "rhel_scope_count": len(scopes),
                    "ignored_non_rhel_products": ignored_non_rhel,
                    "attribution": "Red Hat security data, CC BY 4.0",
                }
            },
            references=references,
            scopes=_dedupe_scopes(scopes),
            provenance={
                "document_category": _nested(payload, "document", "category"),
                "publisher": _nested(payload, "document", "publisher", "name"),
                "license": "CC BY 4.0",
                "attribution_url": "https://access.redhat.com/security/data",
            },
        )


def index_csaf_products(product_tree: Any) -> dict[str, CsafProduct]:
    if not isinstance(product_tree, dict):
        return {}
    products: dict[str, CsafProduct] = {}

    def visit(branches: Any, path: tuple[str, ...] = ()) -> None:
        if not isinstance(branches, list):
            return
        for branch in branches:
            if not isinstance(branch, dict):
                continue
            name = _text(branch.get("name")) or ""
            branch_path = (*path, name)
            product = branch.get("product")
            if isinstance(product, dict):
                product_id = _text(product.get("product_id"))
                product_name = _text(product.get("name"))
                helper = product.get("product_identification_helper")
                if product_id and product_name:
                    products[product_id] = CsafProduct(
                        product_id=product_id,
                        name=product_name,
                        purl=_text(helper.get("purl")) if isinstance(helper, dict) else None,
                        cpe=_text(helper.get("cpe")) if isinstance(helper, dict) else None,
                        branch_path=branch_path,
                    )
            visit(branch.get("branches"), branch_path)

    visit(product_tree.get("branches"))
    return products


def index_csaf_relationships(product_tree: Any) -> dict[str, tuple[str, str, str]]:
    if not isinstance(product_tree, dict):
        return {}
    relationships: dict[str, tuple[str, str, str]] = {}
    for item in product_tree.get("relationships") or []:
        if not isinstance(item, dict):
            continue
        full_product = item.get("full_product_name")
        relationship_id = (
            _text(full_product.get("product_id"))
            if isinstance(full_product, dict)
            else None
        )
        component_id = _text(item.get("product_reference"))
        platform_id = _text(item.get("relates_to_product_reference"))
        if relationship_id and component_id and platform_id:
            relationships[relationship_id] = (
                component_id,
                platform_id,
                _text(item.get("category")) or "unknown",
            )
    return relationships


def parse_redhat_rpm_product(product: CsafProduct) -> dict[str, str | None] | None:
    if product.purl and product.purl.startswith("pkg:rpm/redhat/"):
        body = product.purl[len("pkg:rpm/redhat/") :]
        path, _, query = body.partition("?")
        name_part, separator, version_part = path.rpartition("@")
        name = unquote(name_part if separator else path)
        version = unquote(version_part) if separator else None
        qualifiers = dict(parse_qsl(query, keep_blank_values=True))
        architecture = unquote(qualifiers.get("arch", "")) or None
        if name:
            return {
                "name": name,
                "version": version,
                "architecture": architecture,
                "purl": product.purl,
            }
    name = product.name.strip()
    if not name:
        return None
    if name.endswith(".src"):
        return {
            "name": name[:-4],
            "version": None,
            "architecture": "src",
            "purl": product.purl,
        }
    if re.fullmatch(r"[A-Za-z0-9+_.-]+", name):
        return {
            "name": name,
            "version": None,
            "architecture": None,
            "purl": product.purl,
        }
    return None


def rhel_release(platform: CsafProduct) -> str | None:
    if "coreos" in platform.name.lower() or "openshift" in platform.name.lower():
        return None
    if platform.cpe and (
        match := re.search(
            r"(?:enterprise_linux|rhel(?:_[a-z0-9_]+)?):(\d+(?:\.\d+)?)",
            platform.cpe,
            re.I,
        )
    ):
        return match.group(1)
    for pattern in (
        r"\(v\.\s*(\d+(?:\.\d+)?)\)",
        r"enterprise linux\s+(\d+(?:\.\d+)?)\s*$",
        r"enterprise_linux_(\d+(?:\.\d+)?)",
    ):
        for candidate in (platform.name, platform.product_id):
            if match := re.search(pattern, candidate, re.I):
                return match.group(1)
    return None


def _map_redhat_status(status: str) -> str | None:
    return {
        "known_affected": "affected",
        "fixed": "fixed",
        "known_not_affected": "not_affected",
        "under_investigation": "under_investigation",
    }.get(status.lower())


def _dedupe_scopes(scopes: list[EnrichmentScope]) -> list[EnrichmentScope]:
    deduped: dict[tuple[Any, ...], EnrichmentScope] = {}
    for scope in scopes:
        key = (
            scope.distro_release,
            scope.source_package,
            scope.binary_package,
            scope.architecture,
            scope.status,
            scope.fixed_versions,
            scope.cpe,
        )
        deduped[key] = scope
    return list(deduped.values())


def _nested(value: Any, *keys: str) -> Any:
    current = value
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
