from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
import json
import re
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.db.models import (
    IntelRawEvent,
    Vulnerability,
    VulnerabilityAffectedScope,
    VulnerabilitySource,
)
from app.services.vulnerability_product_identity import is_placeholder_value
from app.services.severity import (
    is_known_exploited_marker,
    normalize_severity_label,
)


WATCHVULN_VULNINFO_TYPE = "watchvuln-vulninfo"
ALIYUN_AVD_HIGH_RISK_TYPE = "aliyun-avd-high-risk"


@dataclass(slots=True)
class NormalizedVulnerabilityRecord:
    canonical_id: str
    title: str
    source_name: str
    event_type: str
    external_id: str
    vendor: str | None = None
    product: str | None = None
    description: str | None = None
    severity_label: str | None = None
    severity_cvss: float | None = None
    kev_status: bool = False
    kev_date_added: datetime | None = None
    kev_due_date: datetime | None = None
    known_ransomware_campaign_use: str | None = None
    poc_status: bool = False
    wild_exploitation_status: bool = False
    affected_versions: str | None = None
    fixed_versions: str | None = None
    remediation: str | None = None
    published_at: datetime | None = None
    notes: str | None = None
    source_url: str | None = None
    references: list[str] | None = None
    tags: list[str] | None = None
    affected_scopes: list["NormalizedAffectedScope"] = field(default_factory=list)


@dataclass(slots=True)
class NormalizedAffectedScope:
    vendor: str | None
    product: str
    ecosystem: str | None = None
    distro: str | None = None
    distro_release: str | None = None
    source_package: str | None = None
    binary_package: str | None = None
    architecture: str | None = None
    flavor: str | None = None
    version_scheme: str | None = None
    version_type: str | None = None
    status: str = "affected"
    default_status: str | None = None
    source_authority: str = "unknown"
    authority_score: int = 0
    purl: str | None = None
    cpe: str | None = None
    platforms: list[str] = field(default_factory=list)
    structured_versions: list[dict[str, object]] = field(default_factory=list)
    affected_versions: str | None = None
    fixed_versions: str | None = None
    source_name: str = "cve-record"
    source_url: str | None = None


@dataclass(slots=True)
class NormalizationResult:
    raw_event_id: str
    status: str
    vulnerability_id: str | None = None
    canonical_id: str | None = None


def normalize_raw_event(db: Session, raw_event_or_id: IntelRawEvent | str) -> NormalizationResult:
    raw_event = _resolve_raw_event(db, raw_event_or_id)
    if raw_event is None:
        raise ValueError("raw intel event not found")

    if raw_event.processing_status == "processed" and raw_event.vulnerability_id:
        vulnerability = db.get(Vulnerability, raw_event.vulnerability_id)
        return NormalizationResult(
            raw_event_id=raw_event.id,
            status=raw_event.processing_status,
            vulnerability_id=raw_event.vulnerability_id,
            canonical_id=vulnerability.canonical_id if vulnerability else None,
        )

    try:
        normalized = _map_raw_event(raw_event)
        if normalized is None:
            raw_event.processing_status = "skipped"
            raw_event.processed_at = utcnow()
            raw_event.last_error = None
            db.add(raw_event)
            db.commit()
            return NormalizationResult(raw_event_id=raw_event.id, status="skipped")

        was_new_vulnerability = db.scalar(
            select(Vulnerability.id).where(
                Vulnerability.canonical_id == normalized.canonical_id
            )
        ) is None
        vulnerability = _upsert_vulnerability(db, normalized)
        _upsert_vulnerability_source(db, raw_event, vulnerability, normalized)
        _replace_affected_scopes(db, raw_event, vulnerability, normalized)
        raw_event.processing_status = "processed"
        raw_event.processed_at = utcnow()
        raw_event.last_error = None
        raw_event.vulnerability_id = vulnerability.id
        db.add(raw_event)
        db.commit()
        if was_new_vulnerability:
            _maybe_run_auto_vulnerability_matching(db, vulnerability.id)
        _maybe_enqueue_ai_auto_enrichment(db, vulnerability)
        return NormalizationResult(
            raw_event_id=raw_event.id,
            status="processed",
            vulnerability_id=vulnerability.id,
            canonical_id=vulnerability.canonical_id,
        )
    except Exception as exc:
        raw_event.processing_status = "failed"
        raw_event.processed_at = utcnow()
        raw_event.last_error = str(exc)
        db.add(raw_event)
        db.commit()
        raise


def _resolve_raw_event(db: Session, raw_event_or_id: IntelRawEvent | str) -> IntelRawEvent | None:
    if isinstance(raw_event_or_id, IntelRawEvent):
        return raw_event_or_id
    return db.get(IntelRawEvent, raw_event_or_id)


def _map_raw_event(raw_event: IntelRawEvent) -> NormalizedVulnerabilityRecord | None:
    if raw_event.provider == "cisa-kev":
        return _map_cisa_kev_event(raw_event)
    if raw_event.provider == "watchvuln":
        return _map_watchvuln_event(raw_event)
    if raw_event.provider == "aliyun-avd":
        return _map_aliyun_avd_event(raw_event)
    return None


def _maybe_enqueue_ai_auto_enrichment(db: Session, vulnerability: Vulnerability) -> None:
    try:
        from app.services.platform_settings import get_platform_settings
        from app.workers.tasks import ai_enrich_vulnerability

        settings = get_platform_settings(db)
        if not (
            settings.ai_enabled
            and settings.ai_auto_enrich_enabled
            and _vulnerability_needs_ai_enrichment(vulnerability)
        ):
            return
        ai_enrich_vulnerability.delay(
            vulnerability.id,
            "auto",
            "basic_extraction_profile",
            settings.ai_allow_web_enrichment_default,
        )
    except Exception:
        return


def _maybe_run_auto_vulnerability_matching(db: Session, vulnerability_id: str) -> None:
    try:
        from app.services.auto_matching import maybe_auto_match_new_vulnerability

        maybe_auto_match_new_vulnerability(db, vulnerability_id)
    except Exception:
        return


def _vulnerability_needs_ai_enrichment(vulnerability: Vulnerability) -> bool:
    return any(
        not _clean_text(getattr(vulnerability, field))
        for field in ("product", "affected_versions", "fixed_versions")
    )


def _map_cisa_kev_event(raw_event: IntelRawEvent) -> NormalizedVulnerabilityRecord:
    record = raw_event.payload.get("record", raw_event.payload)
    cve_id = _clean_text(record.get("cveID")) or raw_event.external_key
    required_action = _clean_text(record.get("requiredAction"))
    affected_versions, fixed_versions = _extract_cisa_kev_versions(
        _clean_text(record.get("shortDescription")),
        required_action,
    )
    cve_record = raw_event.payload.get("cve_record")
    cve_details = _extract_cve_record_details(cve_record)
    cve_scopes = _extract_cve_affected_scopes(
        cve_record,
        source_url=_clean_text(raw_event.payload.get("cve_record_url")),
    )
    cwes = _dedupe_strings(
        [*_normalize_string_list(record.get("cwes")), *cve_details["cwes"]]
    )
    references = _dedupe_strings(
        [
            *_split_semicolon_list(record.get("notes")),
            *cve_details["references"],
            _clean_text(raw_event.payload.get("cve_record_url")),
        ]
    )
    return NormalizedVulnerabilityRecord(
        canonical_id=cve_id,
        title=_clean_text(record.get("vulnerabilityName")) or cve_id,
        source_name="cisa-kev",
        event_type=raw_event.event_type,
        external_id=raw_event.external_key,
        vendor=cve_details["vendor"] or _clean_text(record.get("vendorProject")),
        product=cve_details["product"] or _clean_text(record.get("product")),
        description=cve_details["description"] or _clean_text(record.get("shortDescription")),
        severity_label=cve_details["severity_label"],
        severity_cvss=cve_details["severity_cvss"],
        kev_status=True,
        kev_date_added=_parse_datetime(record.get("dateAdded")),
        kev_due_date=_parse_datetime(record.get("dueDate")),
        known_ransomware_campaign_use=_clean_text(record.get("knownRansomwareCampaignUse")),
        wild_exploitation_status=True,
        affected_versions=cve_details["affected_versions"] or affected_versions,
        fixed_versions=fixed_versions,
        remediation=required_action,
        published_at=cve_details["published_at"] or _parse_datetime(record.get("dateAdded")),
        notes=_clean_text(record.get("notes")),
        source_url=raw_event.source_url,
        references=references,
        tags=_dedupe_strings(
            [
                cve_details["vendor"] or _clean_text(record.get("vendorProject")),
                cve_details["product"] or _clean_text(record.get("product")),
                *cwes,
                "kev",
            ]
        ),
        affected_scopes=cve_scopes,
    )


def _map_watchvuln_event(raw_event: IntelRawEvent) -> NormalizedVulnerabilityRecord | None:
    if raw_event.event_type != WATCHVULN_VULNINFO_TYPE:
        return None

    content = raw_event.payload.get("content", raw_event.payload)
    cve_id = _clean_text(content.get("cve"))
    source_url = _clean_text(content.get("from")) or raw_event.source_url
    tags = _normalize_string_list(content.get("tags"))
    reason = _normalize_string_list(content.get("reason"))
    references = _normalize_reference_list(content.get("references"))
    external_id = _clean_text(content.get("unique_key")) or raw_event.external_key
    canonical_id = cve_id or external_id
    raw_severity = _clean_text(content.get("severity"))
    kev_status = _looks_like_kev(
        external_id,
        source_url,
        tags,
    ) or is_known_exploited_marker(raw_severity)
    source_name = _watchvuln_source_name(content)

    return NormalizedVulnerabilityRecord(
        canonical_id=canonical_id,
        title=_clean_text(content.get("title")) or canonical_id,
        source_name=source_name,
        event_type=raw_event.event_type,
        external_id=external_id,
        vendor=_first_clean_text(content, "vendor", "vendorProject", "vendor_project"),
        product=_first_clean_text(content, "product", "affected_product", "component"),
        description=_clean_text(content.get("description")),
        severity_label=normalize_severity_label(raw_severity),
        kev_status=kev_status,
        kev_date_added=_parse_datetime(content.get("disclosure")) if kev_status else None,
        published_at=_parse_datetime(content.get("disclosure")),
        known_ransomware_campaign_use="Known" if kev_status else None,
        poc_status=_contains_any(tags, "poc", "exp"),
        affected_versions=_first_clean_text(
            content,
            "affected_versions",
            "affectedVersion",
            "affected_version",
            "influence",
            "scope",
        ),
        fixed_versions=_first_clean_text(
            content,
            "fixed_versions",
            "fixedVersion",
            "fixed_version",
        ),
        remediation=_clean_text(content.get("solutions")),
        wild_exploitation_status=kev_status or any(tag == "在野利用" for tag in tags),
        notes="; ".join(reason) if reason else None,
        source_url=source_url,
        references=references,
        tags=tags,
    )


def _map_aliyun_avd_event(raw_event: IntelRawEvent) -> NormalizedVulnerabilityRecord | None:
    if raw_event.event_type != ALIYUN_AVD_HIGH_RISK_TYPE:
        return None

    record = raw_event.payload.get("record", raw_event.payload)
    avd_id = _clean_text(record.get("avd_id")) or raw_event.external_key
    cve_id = _first_cve(record.get("cve_id"))
    canonical_id = cve_id or avd_id
    tags = _normalize_string_list(record.get("tags"))
    severity_cvss = _parse_float(record.get("score"))
    severity_label = normalize_severity_label(record.get("severity")) or _severity_label_for_score(
        severity_cvss
    )
    references = _normalize_reference_list(record.get("references"))

    return NormalizedVulnerabilityRecord(
        canonical_id=canonical_id,
        title=_clean_text(record.get("title")) or canonical_id,
        source_name="aliyun-avd",
        event_type=raw_event.event_type,
        external_id=avd_id,
        vendor=_clean_text(record.get("vendor")),
        product=_clean_text(record.get("product")),
        description=_clean_text(record.get("description")),
        severity_label=severity_label,
        severity_cvss=severity_cvss,
        poc_status=_contains_any(tags, "poc", "exp"),
        wild_exploitation_status=_contains_any(tags, "在野利用", "wild exploitation"),
        affected_versions=_clean_text(record.get("affected_versions")),
        fixed_versions=_clean_text(record.get("fixed_versions")),
        remediation=_clean_text(record.get("remediation")),
        published_at=_parse_datetime(record.get("published_at")),
        source_url=_clean_text(record.get("source_url")) or raw_event.source_url,
        references=references,
        tags=tags,
    )


def _upsert_vulnerability(
    db: Session,
    record: NormalizedVulnerabilityRecord,
) -> Vulnerability:
    vulnerability = db.scalar(
        select(Vulnerability).where(Vulnerability.canonical_id == record.canonical_id)
    )
    authoritative = record.source_name == "cisa-kev"

    if vulnerability is None:
        vulnerability = Vulnerability(
            canonical_id=record.canonical_id,
            title=record.title,
            vendor=record.vendor,
            product=record.product,
            description=record.description,
            severity_label=record.severity_label,
            severity_cvss=record.severity_cvss,
            kev_status=record.kev_status,
            kev_date_added=record.kev_date_added,
            kev_due_date=record.kev_due_date,
            known_ransomware_campaign_use=record.known_ransomware_campaign_use,
            poc_status=record.poc_status,
            wild_exploitation_status=record.wild_exploitation_status,
            affected_versions=record.affected_versions,
            fixed_versions=record.fixed_versions,
            remediation=record.remediation,
            published_at=record.published_at,
            notes=record.notes,
        )
        db.add(vulnerability)
        db.flush()
        return vulnerability

    if is_known_exploited_marker(vulnerability.severity_label):
        vulnerability.severity_label = None
        vulnerability.kev_status = True

    if record.title and (not vulnerability.title or authoritative):
        vulnerability.title = record.title

    for field_name in (
        "vendor",
        "product",
        "description",
        "severity_label",
        "affected_versions",
        "fixed_versions",
        "remediation",
        "notes",
        "known_ransomware_campaign_use",
    ):
        incoming = getattr(record, field_name)
        current = getattr(vulnerability, field_name)
        allow_authoritative_override = authoritative and field_name not in {
            "severity_label",
            "affected_versions",
            "fixed_versions",
        }
        if incoming and (not current or allow_authoritative_override):
            setattr(vulnerability, field_name, incoming)

    if record.severity_cvss is not None and vulnerability.severity_cvss is None:
        vulnerability.severity_cvss = record.severity_cvss

    vulnerability.kev_status = vulnerability.kev_status or record.kev_status
    vulnerability.poc_status = vulnerability.poc_status or record.poc_status
    vulnerability.wild_exploitation_status = (
        vulnerability.wild_exploitation_status or record.wild_exploitation_status
    )

    if record.kev_date_added and (
        vulnerability.kev_date_added is None or authoritative
    ):
        vulnerability.kev_date_added = record.kev_date_added
    if record.kev_due_date and (vulnerability.kev_due_date is None or authoritative):
        vulnerability.kev_due_date = record.kev_due_date
    if record.published_at and (
        vulnerability.published_at is None
        or _datetime_before(record.published_at, vulnerability.published_at)
    ):
        vulnerability.published_at = record.published_at

    db.add(vulnerability)
    db.flush()
    return vulnerability


def _upsert_vulnerability_source(
    db: Session,
    raw_event: IntelRawEvent,
    vulnerability: Vulnerability,
    record: NormalizedVulnerabilityRecord,
) -> VulnerabilitySource:
    source = db.scalar(
        select(VulnerabilitySource).where(
            VulnerabilitySource.source_name == record.source_name,
            VulnerabilitySource.external_id == record.external_id,
        )
    )
    references = record.references or []
    tags = record.tags or []

    if source is None:
        source = VulnerabilitySource(
            vulnerability_id=vulnerability.id,
            raw_event_id=raw_event.id,
            source_name=record.source_name,
            event_type=record.event_type,
            external_id=record.external_id,
            source_url=record.source_url,
            title=record.title,
            description=record.description,
            severity_raw=record.severity_label,
            published_at=record.published_at,
            references_json=references,
            tags_json=tags,
            last_payload_hash=raw_event.payload_hash,
            last_seen_at=utcnow(),
        )
        db.add(source)
        db.flush()
        return source

    source.vulnerability_id = vulnerability.id
    source.raw_event_id = raw_event.id
    source.event_type = record.event_type
    source.source_url = record.source_url or source.source_url
    source.title = record.title or source.title
    source.description = record.description or source.description
    source.severity_raw = record.severity_label or source.severity_raw
    source.published_at = record.published_at or source.published_at
    source.references_json = references
    source.tags_json = tags
    source.last_payload_hash = raw_event.payload_hash
    source.last_seen_at = utcnow()
    db.add(source)
    db.flush()
    return source


def _replace_affected_scopes(
    db: Session,
    raw_event: IntelRawEvent,
    vulnerability: Vulnerability,
    record: NormalizedVulnerabilityRecord,
) -> None:
    if record.source_name != "cisa-kev":
        return
    db.execute(
        delete(VulnerabilityAffectedScope).where(
            VulnerabilityAffectedScope.vulnerability_id == vulnerability.id,
            VulnerabilityAffectedScope.source_name == "cve-record",
        )
    )
    for scope in record.affected_scopes:
        identity_values = [
            scope.vendor or "",
            scope.product,
            scope.ecosystem or "",
            scope.distro or "",
            scope.distro_release or "",
            scope.source_package or "",
            scope.binary_package or "",
            scope.architecture or "",
            scope.flavor or "",
            scope.version_scheme or "",
            scope.status,
            scope.default_status or "",
            scope.affected_versions or "",
            scope.fixed_versions or "",
            json.dumps(scope.platforms, ensure_ascii=False, sort_keys=True),
            json.dumps(scope.structured_versions, ensure_ascii=False, sort_keys=True),
        ]
        scope_key = sha256(
            "\x1f".join(identity_values).encode("utf-8")
        ).hexdigest()
        db.add(
            VulnerabilityAffectedScope(
                vulnerability_id=vulnerability.id,
                raw_event_id=raw_event.id,
                source_name=scope.source_name,
                scope_key=scope_key,
                vendor=scope.vendor,
                product=scope.product,
                ecosystem=scope.ecosystem,
                distro=scope.distro,
                distro_release=scope.distro_release,
                source_package=scope.source_package,
                binary_package=scope.binary_package,
                architecture=scope.architecture,
                flavor=scope.flavor,
                version_scheme=scope.version_scheme,
                version_type=scope.version_type,
                status=scope.status,
                default_status=scope.default_status,
                source_authority=scope.source_authority,
                authority_score=scope.authority_score,
                purl=scope.purl,
                cpe=scope.cpe,
                platforms_json=scope.platforms,
                structured_versions_json=scope.structured_versions,
                affected_versions=scope.affected_versions,
                fixed_versions=scope.fixed_versions,
                source_url=scope.source_url,
            )
        )
    db.flush()


def _looks_like_kev(external_id: str, source_url: str | None, tags: list[str]) -> bool:
    if external_id.upper().endswith("_KEV"):
        return True
    if source_url and "known-exploited-vulnerabilities" in source_url:
        return True
    return any(tag.lower() in {"kev", "在野利用"} for tag in tags)


def _watchvuln_source_name(content: dict[str, Any]) -> str:
    source = _clean_text(content.get("watchvuln_source"))
    if not source:
        return "watchvuln"
    normalized = source.strip().lower()
    if normalized in {"aliyun-avd", "avd"}:
        normalized = "avd"
    if normalized in {"qianxin-ti", "nox"}:
        normalized = "ti"
    return f"watchvuln:{normalized}"


def _clean_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _compact_list(values: list[str | None]) -> list[str]:
    return [value for value in values if value]


def _dedupe_strings(values: Iterable[str | None]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def _normalize_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item.strip() for item in map(str, value) if item and str(item).strip()]


def _normalize_reference_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list | tuple | set):
        return list(
            dict.fromkeys(
                item
                for raw_item in value
                if (item := _clean_text(raw_item))
            )
        )
    text = _clean_text(value)
    if not text:
        return []
    return list(
        dict.fromkeys(
            part.strip()
            for part in re.split(r"[;,，；\n]\s*", text)
            if part.strip()
        )
    )


def _extract_cve_record_details(cve_record: Any) -> dict[str, Any]:
    """Select machine-usable fields from a CVE JSON 5.x record.

    CISA KEV establishes exploitation priority; the CVE Record supplements it
    with CNA-maintained product/version data. The raw record remains attached
    to the event for later review when it describes multiple products.
    """

    details: dict[str, Any] = {
        "vendor": None,
        "product": None,
        "description": None,
        "affected_versions": None,
        "severity_label": None,
        "severity_cvss": None,
        "published_at": None,
        "references": [],
        "cwes": [],
    }
    if not isinstance(cve_record, dict):
        return details

    containers = cve_record.get("containers")
    if not isinstance(containers, dict):
        return details
    cna = containers.get("cna")
    if not isinstance(cna, dict):
        return details

    details["description"] = _localized_cve_value(cna.get("descriptions"), "value")
    details["references"] = _dedupe_strings(
        _clean_text(reference.get("url"))
        for reference in cna.get("references", [])
        if isinstance(reference, dict)
    )
    details["cwes"] = _dedupe_strings(
        _clean_text(description.get("cweId"))
        for problem_type in cna.get("problemTypes", [])
        if isinstance(problem_type, dict)
        for description in problem_type.get("descriptions", [])
        if isinstance(description, dict)
    )

    affected = _select_cve_affected_product(cna.get("affected"))
    if affected:
        details["vendor"] = _meaningful_cve_value(affected.get("vendor"))
        details["product"] = _meaningful_cve_value(affected.get("product"))
        details["affected_versions"] = _format_cve_affected_versions(
            affected.get("versions")
        )

    severity_cvss, severity_label = _extract_cve_cvss(cna.get("metrics"))
    details["severity_cvss"] = severity_cvss
    details["severity_label"] = severity_label

    metadata = cve_record.get("cveMetadata")
    if isinstance(metadata, dict):
        details["published_at"] = _parse_datetime(metadata.get("datePublished"))
    return details


def _extract_cve_affected_scopes(
    cve_record: Any,
    *,
    source_url: str | None,
) -> list[NormalizedAffectedScope]:
    if not isinstance(cve_record, dict):
        return []
    cna = (cve_record.get("containers") or {}).get("cna")
    if not isinstance(cna, dict) or not isinstance(cna.get("affected"), list):
        return []

    scopes: list[NormalizedAffectedScope] = []
    for affected in cna["affected"]:
        if not isinstance(affected, dict):
            continue
        product = _meaningful_cve_value(affected.get("product"))
        if not product:
            continue
        versions = [
            dict(version)
            for version in affected.get("versions", [])
            if isinstance(version, dict)
        ]
        version_types = {
            value
            for version in versions
            if (value := _clean_text(version.get("versionType")))
        }
        version_type = next(iter(version_types)) if len(version_types) == 1 else None
        default_status = _clean_text(affected.get("defaultStatus"))
        statuses = {
            value.lower()
            for version in versions
            if (value := _clean_text(version.get("status")))
        }
        status = "affected" if "affected" in statuses else default_status or "unknown"
        cpes = _normalize_string_list(affected.get("cpes"))
        scopes.append(
            NormalizedAffectedScope(
                vendor=_meaningful_cve_value(affected.get("vendor")),
                product=product,
                binary_package=_meaningful_cve_value(affected.get("packageName")),
                version_scheme=_cve_version_scheme(version_type),
                version_type=version_type,
                status=status.lower(),
                default_status=default_status.lower() if default_status else None,
                source_authority="cna",
                authority_score=70,
                purl=_meaningful_cve_value(affected.get("packageURL")),
                cpe=cpes[0] if cpes else None,
                platforms=_normalize_string_list(affected.get("platforms")),
                structured_versions=versions,
                affected_versions=_format_cve_affected_versions(versions),
                source_url=source_url,
            )
        )
    return list(
        {
            (
                scope.vendor,
                scope.product,
                scope.binary_package,
                scope.version_type,
                scope.status,
                scope.default_status,
                scope.affected_versions,
                scope.fixed_versions,
                json.dumps(scope.platforms, sort_keys=True),
                json.dumps(scope.structured_versions, sort_keys=True),
            ): scope
            for scope in scopes
        }.values()
    )


def _cve_version_scheme(version_type: str | None) -> str | None:
    normalized = (version_type or "").strip().lower()
    if not normalized:
        return None
    if normalized in {"semver", "semantic", "generic", "custom"}:
        return "generic" if normalized != "custom" else "opaque"
    if normalized in {"git", "git-commit", "commit"}:
        return "git_commit"
    if normalized in {"deb", "debian", "dpkg"}:
        return "debian"
    if normalized in {"rpm", "evr"}:
        return "rpm"
    return "opaque"


def _extract_cve_cvss(metrics: Any) -> tuple[float | None, str | None]:
    """Extract the most current usable CVSS metric from a CVE JSON 5.x CNA."""

    if isinstance(metrics, dict):
        metric_entries = [metrics]
    elif isinstance(metrics, list):
        metric_entries = metrics
    else:
        return None, None

    for metric_key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
        for entry in metric_entries:
            if not isinstance(entry, dict):
                continue
            metric = entry.get(metric_key)
            if not isinstance(metric, dict):
                continue
            score = _parse_float(metric.get("baseScore"))
            if score is None:
                continue
            severity = normalize_severity_label(metric.get("baseSeverity"))
            return score, severity or _severity_label_for_score(score)
    return None, None


def _localized_cve_value(value: Any, field_name: str) -> str | None:
    if not isinstance(value, list):
        return None
    english = next(
        (
            item
            for item in value
            if isinstance(item, dict) and str(item.get("lang", "")).lower() == "en"
        ),
        None,
    )
    if english:
        return _clean_text(english.get(field_name))
    for item in value:
        if isinstance(item, dict) and (text := _clean_text(item.get(field_name))):
            return text
    return None


def _select_cve_affected_product(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, list):
        return None
    for item in value:
        if not isinstance(item, dict):
            continue
        versions = item.get("versions")
        if isinstance(versions, list) and any(
            isinstance(version, dict) and version.get("status") == "affected"
            for version in versions
        ):
            return item
    return next((item for item in value if isinstance(item, dict)), None)


def _format_cve_affected_versions(value: Any) -> str | None:
    if not isinstance(value, list):
        return None
    ranges: list[str | None] = []
    for version in value:
        if not isinstance(version, dict) or version.get("status") != "affected":
            continue
        start = _meaningful_cve_value(version.get("version"))
        end_exclusive = _meaningful_cve_value(version.get("lessThan"))
        end_inclusive = _meaningful_cve_value(version.get("lessThanOrEqual"))
        if start and end_exclusive:
            ranges.append(f">= {start}, < {end_exclusive}")
        elif start and end_inclusive:
            ranges.append(f">= {start}, <= {end_inclusive}")
        elif start:
            ranges.append(start)
    return " | ".join(_dedupe_strings(ranges)) or None


def _meaningful_cve_value(value: Any) -> str | None:
    text = _clean_text(value)
    return None if is_placeholder_value(text) else text


def _split_semicolon_list(value: Any) -> list[str]:
    if value is None:
        return []
    return [part.strip() for part in str(value).split(";") if part.strip()]


def _first_clean_text(payload: dict[str, Any], *field_names: str) -> str | None:
    for field_name in field_names:
        value = _clean_text(payload.get(field_name))
        if value:
            return value
    lowered = {key.lower(): value for key, value in payload.items()}
    for field_name in field_names:
        value = _clean_text(lowered.get(field_name.lower()))
        if value:
            return value
    return None


def _first_cve(value: Any) -> str | None:
    text = _clean_text(value)
    if not text:
        return None
    match = re.search(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE)
    return match.group(0).upper() if match else None


def _parse_float(value: Any) -> float | None:
    text = _clean_text(value)
    if not text:
        return None
    match = re.search(r"(?<!\d)(10(?:\.0)?|[0-9](?:\.[0-9])?)(?!\d)", text)
    if not match:
        return None
    parsed = float(match.group(1))
    if 0 <= parsed <= 10:
        return parsed
    return None


def _severity_label_for_score(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def _contains_any(values: list[str], *needles: str) -> bool:
    normalized_values = [value.lower() for value in values]
    return any(needle.lower() in value for needle in needles for value in normalized_values)


_VERSION_TOKEN = r"([0-9][0-9A-Za-z._+\-]*)"


def _extract_cisa_kev_versions(
    description: str | None,
    required_action: str | None,
) -> tuple[str | None, str | None]:
    """Extract only version constraints explicitly stated in CISA KEV text.

    CISA's catalog does not publish structured affected/fixed version fields.  A
    small number of entries state an unambiguous range in their description or
    action, which we can retain without inferring data from advisory URLs.
    """

    text = "\n".join(value for value in (description, required_action) if value)
    if not text:
        return None, None

    affected_versions: str | None = None
    fixed_versions: str | None = None

    end_of_life_match = re.search(
        rf"versions?\s+{_VERSION_TOKEN}\s+(?:and|or)\s+earlier.*?"
        rf"versions?\s+{_VERSION_TOKEN}\s+(?:and|or)\s+later\s+"
        r"(?:are\s+)?not\s+(?:considered\s+)?vulnerable",
        text,
        re.IGNORECASE | re.DOTALL,
    )
    if end_of_life_match:
        return f"<= {end_of_life_match.group(1)}", end_of_life_match.group(2)

    range_match = re.search(
        rf"versions?\s+{_VERSION_TOKEN}\s+(?:through|to|-)\s+{_VERSION_TOKEN}",
        text,
        re.IGNORECASE,
    )
    if range_match:
        affected_versions = f">= {range_match.group(1)}, <= {range_match.group(2)}"

    before_match = re.search(
        rf"(?:versions?\s+)?(?:before|prior\s+to)\s+(?:version\s+)?{_VERSION_TOKEN}",
        text,
        re.IGNORECASE,
    )
    if before_match:
        affected_versions = f"< {before_match.group(1)}"

    earlier_match = re.search(
        rf"versions?\s+{_VERSION_TOKEN}\s+(?:and|or)\s+earlier",
        text,
        re.IGNORECASE,
    )
    if earlier_match and affected_versions is None:
        affected_versions = f"<= {earlier_match.group(1)}"

    upgrade_match = re.search(
        rf"(?:upgrade|update)\b(?:(?!\bversion\b).){{0,120}}?"
        rf"\b(?:to\s+)?version\s+{_VERSION_TOKEN}"
        r"(?:\s+(?:or|and)\s+later)?",
        text,
        re.IGNORECASE,
    )
    if upgrade_match:
        # `fixed_versions` stores the fixed release, not an affected-version
        # constraint. The matching engine derives the vulnerable-before-fixed
        # range from this field.
        fixed_versions = upgrade_match.group(1)

    return affected_versions, fixed_versions


def _parse_datetime(value: Any) -> datetime | None:
    text = _clean_text(value)
    if text is None:
        return None

    normalized = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed
    except ValueError:
        pass

    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%Y-%m-%d %H:%M:%S"):
        try:
            parsed = datetime.strptime(text, fmt)
            return parsed.replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def _datetime_before(left: datetime, right: datetime) -> bool:
    return _datetime_for_compare(left) < _datetime_for_compare(right)


def _datetime_for_compare(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
