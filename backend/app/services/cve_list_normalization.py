from __future__ import annotations

from typing import Any

from app.connectors.base import RawIntelRecord
from app.connectors.http_client import SourceDownloadError
from app.services.intel_enrichment import (
    EnrichmentRecord,
    EnrichmentScope,
)


class CveListV5Mapper:
    source_name = "cve-list-v5"

    def map_record(self, record: RawIntelRecord) -> EnrichmentRecord:
        payload = record.payload
        metadata = payload.get("cveMetadata") if isinstance(payload, dict) else None
        containers = payload.get("containers") if isinstance(payload, dict) else None
        if not isinstance(metadata, dict) or not isinstance(containers, dict):
            raise SourceDownloadError("CVE record is missing metadata or containers")
        cve_id = _text(metadata.get("cveId"))
        if not cve_id or cve_id != record.external_id:
            raise SourceDownloadError("CVE record id does not match raw event")
        data_version = _text(payload.get("dataVersion")) or ""
        if not data_version.startswith("5."):
            raise SourceDownloadError(f"unsupported CVE dataVersion: {data_version}")
        cna = containers.get("cna")
        if not isinstance(cna, dict):
            raise SourceDownloadError("CVE record has no CNA container")
        adp = [item for item in containers.get("adp", []) if isinstance(item, dict)]
        state = (_text(metadata.get("state")) or "PUBLISHED").upper()
        description = _preferred_description(cna.get("descriptions"))
        if state == "REJECTED" and not description:
            description = _preferred_description(cna.get("rejectedReasons"))
        title = _text(cna.get("title")) or description or cve_id
        references, reference_provenance = _collect_references(cna, adp)
        products, scopes = _collect_affected(cna.get("affected"))
        contribution = {
            "canonical_id": cve_id,
            "cve_state": state.lower(),
            "title": title,
            "description": description,
            "products": products,
            "upstream_scopes": [scope.provenance for scope in scopes],
            "references": references,
            "cna_metrics": cna.get("metrics") if isinstance(cna.get("metrics"), list) else [],
        }
        return EnrichmentRecord(
            canonical_id=cve_id,
            title=title,
            description=description,
            contribution=contribution,
            references=references,
            scopes=scopes,
            provenance={
                "data_version": data_version,
                "state": state,
                "containers": {
                    "cna": _provider_name(cna),
                    "adp": [_provider_name(item) for item in adp],
                },
                "reference_provenance": reference_provenance,
            },
        )


def _collect_affected(value: Any) -> tuple[list[dict[str, Any]], list[EnrichmentScope]]:
    if not isinstance(value, list):
        return [], []
    products: list[dict[str, Any]] = []
    scopes: list[EnrichmentScope] = []
    for index, affected in enumerate(value):
        if not isinstance(affected, dict):
            continue
        vendor = _text(affected.get("vendor"))
        product = _text(affected.get("product") or affected.get("packageName"))
        if not product:
            continue
        versions = [
            _normalize_cve_version(item)
            for item in affected.get("versions", [])
            if isinstance(item, dict)
        ]
        versions = [item for item in versions if item]
        platforms = _string_list(affected.get("platforms"))
        purl = _first_purl(affected.get("packageURL"))
        default_status = (_text(affected.get("defaultStatus")) or "unknown").lower()
        product_fact = {
            "vendor": vendor,
            "product": product,
            "package_name": _text(affected.get("packageName")),
            "purl": purl,
            "platforms": platforms,
            "versions": versions,
            "default_status": default_status,
        }
        products.append(product_fact)
        scopes.append(
            EnrichmentScope(
                vendor=vendor,
                product=product,
                version_scheme=_text(affected.get("collectionURL")) and "generic",
                status="affected",
                default_status=default_status,
                purl=purl,
                platforms=platforms,
                structured_versions=versions,
                affected_versions=_render_version_ranges(versions),
                source_authority="cna",
                authority_score=85,
                provenance={"container": "cna", "affected_index": index, **product_fact},
            )
        )
    return products, scopes


def _normalize_cve_version(value: dict[str, Any]) -> dict[str, Any]:
    normalized = {
        key: value[key]
        for key in (
            "version",
            "status",
            "versionType",
            "lessThan",
            "lessThanOrEqual",
            "changes",
        )
        if value.get(key) is not None
    }
    if "status" in normalized:
        normalized["status"] = str(normalized["status"]).lower()
    return normalized


def _collect_references(
    cna: dict[str, Any],
    adp: list[dict[str, Any]],
) -> tuple[list[str], list[dict[str, Any]]]:
    urls: list[str] = []
    provenance: list[dict[str, Any]] = []
    containers = [("cna", cna), *[(f"adp:{index}", item) for index, item in enumerate(adp)]]
    for container_name, container in containers:
        references = container.get("references")
        if not isinstance(references, list):
            continue
        for reference in references:
            url = _text(reference.get("url")) if isinstance(reference, dict) else None
            if not url:
                continue
            if url not in urls:
                urls.append(url)
            provenance.append(
                {
                    "url": url,
                    "container": container_name,
                    "provider": _provider_name(container),
                    "tags": _string_list(reference.get("tags")),
                }
            )
    return urls, provenance


def _preferred_description(value: Any) -> str | None:
    if not isinstance(value, list):
        return None
    descriptions = [item for item in value if isinstance(item, dict)]
    for language in ("en", "en-US", "en-GB"):
        for item in descriptions:
            if item.get("lang") == language and (text := _text(item.get("value"))):
                return text
    return next((_text(item.get("value")) for item in descriptions if _text(item.get("value"))), None)


def _render_version_ranges(versions: list[dict[str, Any]]) -> str | None:
    rendered: list[str] = []
    for version in versions:
        if version.get("status") != "affected":
            continue
        start = _text(version.get("version"))
        if end := _text(version.get("lessThan")):
            rendered.append(f">= {start}, < {end}" if start else f"< {end}")
        elif end := _text(version.get("lessThanOrEqual")):
            rendered.append(f">= {start}, <= {end}" if start else f"<= {end}")
        elif start:
            rendered.append(start)
    return "; ".join(rendered) or None


def _first_purl(value: Any) -> str | None:
    if isinstance(value, str):
        return _text(value)
    if isinstance(value, list):
        return next((_text(item) for item in value if _text(item)), None)
    return None


def _provider_name(container: dict[str, Any]) -> str | None:
    metadata = container.get("providerMetadata")
    if not isinstance(metadata, dict):
        return None
    return _text(metadata.get("shortName") or metadata.get("orgId"))


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return list(dict.fromkeys(text for item in value if (text := _text(item))))


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
