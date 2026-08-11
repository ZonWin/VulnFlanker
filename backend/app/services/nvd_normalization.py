from __future__ import annotations

from typing import Any

from app.connectors.base import RawIntelRecord
from app.connectors.http_client import SourceDownloadError
from app.services.intel_enrichment import EnrichmentRecord, EnrichmentScope


class NvdCveMapper:
    source_name = "nvd"

    def map_record(self, record: RawIntelRecord) -> EnrichmentRecord:
        payload = record.payload
        cve_id = _text(payload.get("id")) if isinstance(payload, dict) else None
        if not cve_id or cve_id != record.external_id:
            raise SourceDownloadError("NVD CVE id does not match raw event")
        description = _preferred_description(payload.get("descriptions"))
        references = _reference_urls(payload.get("references"))
        metrics = payload.get("metrics") if isinstance(payload.get("metrics"), dict) else {}
        weaknesses = _weakness_values(payload.get("weaknesses"))
        configurations = (
            payload.get("configurations")
            if isinstance(payload.get("configurations"), list)
            else []
        )
        scopes = _nvd_cpe_scopes(configurations)
        contribution = {
            "description": description,
            "nvd_metrics": metrics,
            "weaknesses": weaknesses,
            "cpe_configurations": configurations,
            "references": references,
            "nvd_status": _text(payload.get("vulnStatus")),
        }
        return EnrichmentRecord(
            canonical_id=cve_id,
            title=cve_id,
            description=description,
            contribution=contribution,
            references=references,
            scopes=scopes,
            provenance={
                "source_identifier": _text(payload.get("sourceIdentifier")),
                "published": _text(payload.get("published")),
                "last_modified": _text(payload.get("lastModified")),
                "format": "NVD_CVE_API_2.0",
            },
        )


def _nvd_cpe_scopes(configurations: list[Any]) -> list[EnrichmentScope]:
    scopes: list[EnrichmentScope] = []
    for configuration_index, configuration in enumerate(configurations):
        if not isinstance(configuration, dict):
            continue
        nodes = configuration.get("nodes")
        if not isinstance(nodes, list):
            continue
        for node_index, node in enumerate(nodes):
            scopes.extend(
                _scopes_from_node(
                    node,
                    path=[configuration_index, node_index],
                    constrained=False,
                )
            )
    return scopes


def _scopes_from_node(
    node: Any,
    *,
    path: list[int],
    constrained: bool,
) -> list[EnrichmentScope]:
    if not isinstance(node, dict) or node.get("negate") is True:
        return []
    operator = str(node.get("operator") or "OR").upper()
    constrained = constrained or operator == "AND"
    scopes: list[EnrichmentScope] = []
    matches = node.get("cpeMatch")
    if isinstance(matches, list) and not constrained:
        for match_index, match in enumerate(matches):
            scope = _scope_from_cpe_match(match, path=[*path, match_index], operator=operator)
            if scope is not None:
                scopes.append(scope)
    children = node.get("children")
    if isinstance(children, list):
        for child_index, child in enumerate(children):
            scopes.extend(
                _scopes_from_node(
                    child,
                    path=[*path, child_index],
                    constrained=constrained,
                )
            )
    return scopes


def _scope_from_cpe_match(
    match: Any,
    *,
    path: list[int],
    operator: str,
) -> EnrichmentScope | None:
    if not isinstance(match, dict) or match.get("vulnerable") is not True:
        return None
    criteria = _text(match.get("criteria"))
    components = _split_cpe23(criteria) if criteria else []
    if len(components) < 6:
        return None
    vendor = _cpe_value(components[3])
    product = _cpe_value(components[4])
    version = _cpe_value(components[5])
    if not product:
        return None
    structured: dict[str, Any] = {"status": "affected", "versionType": "cpe"}
    if version:
        structured["version"] = version
    boundary_map = {
        "versionStartIncluding": "versionStartIncluding",
        "versionStartExcluding": "versionStartExcluding",
        "versionEndIncluding": "versionEndIncluding",
        "versionEndExcluding": "versionEndExcluding",
    }
    for source_key, target_key in boundary_map.items():
        if value := _text(match.get(source_key)):
            structured[target_key] = value
    return EnrichmentScope(
        vendor=vendor,
        product=product,
        version_scheme="cpe",
        cpe=criteria,
        structured_versions=[structured],
        affected_versions=_render_cpe_range(structured),
        source_authority="nvd",
        authority_score=65,
        provenance={
            "configuration_path": path,
            "operator": operator,
            "match_criteria_id": _text(match.get("matchCriteriaId")),
            "criteria": criteria,
        },
    )


def _split_cpe23(value: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for character in value:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            parts.append("".join(current))
            current = []
        else:
            current.append(character)
    current.append("\\") if escaped else None
    parts.append("".join(current))
    return parts


def _cpe_value(value: str) -> str | None:
    return None if value in {"", "*", "-"} else value


def _render_cpe_range(version: dict[str, Any]) -> str | None:
    parts: list[str] = []
    if value := version.get("versionStartIncluding"):
        parts.append(f">= {value}")
    if value := version.get("versionStartExcluding"):
        parts.append(f"> {value}")
    if value := version.get("versionEndIncluding"):
        parts.append(f"<= {value}")
    if value := version.get("versionEndExcluding"):
        parts.append(f"< {value}")
    if not parts and (value := version.get("version")):
        parts.append(str(value))
    return ", ".join(parts) or None


def _preferred_description(value: Any) -> str | None:
    if not isinstance(value, list):
        return None
    descriptions = [item for item in value if isinstance(item, dict)]
    for item in descriptions:
        if item.get("lang") == "en" and (text := _text(item.get("value"))):
            return text
    return next((_text(item.get("value")) for item in descriptions if _text(item.get("value"))), None)


def _reference_urls(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return list(
        dict.fromkeys(
            url
            for item in value
            if isinstance(item, dict) and (url := _text(item.get("url")))
        )
    )


def _weakness_values(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    weaknesses: list[str] = []
    for item in value:
        descriptions = item.get("description") if isinstance(item, dict) else None
        if not isinstance(descriptions, list):
            continue
        for description in descriptions:
            weakness = _text(description.get("value")) if isinstance(description, dict) else None
            if weakness and weakness not in weaknesses:
                weaknesses.append(weakness)
    return weaknesses


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
