from __future__ import annotations

import json
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Protocol

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.connectors.base import CollectorPage, RawIntelRecord
from app.db.base import utcnow
from app.db.models import (
    IntelCollectionRun,
    IntelRawEvent,
    Vulnerability,
    VulnerabilityAffectedScope,
    VulnerabilitySource,
    VulnerabilitySourceContribution,
)
from app.services.intel_authority import merge_contribution_documents
from app.services.intel_generations import (
    compute_fact_fingerprint,
    upsert_source_contribution,
)
from app.services.intel_ingestion import compute_payload_hash
from app.services.severity import normalize_severity_label


@dataclass(slots=True)
class EnrichmentScope:
    product: str
    vendor: str | None = None
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
    cpe: str | None = None
    purl: str | None = None
    platforms: list[str] = field(default_factory=list)
    structured_versions: list[dict[str, Any]] = field(default_factory=list)
    affected_versions: str | None = None
    fixed_versions: str | None = None
    source_authority: str = "generic"
    authority_score: int = 50
    provenance: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class EnrichmentRecord:
    canonical_id: str
    title: str
    description: str | None
    contribution: dict[str, Any]
    references: list[str] = field(default_factory=list)
    scopes: list[EnrichmentScope] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)


class EnrichmentMapper(Protocol):
    source_name: str

    def map_record(self, record: RawIntelRecord) -> EnrichmentRecord: ...


class EnrichmentMapperRegistry:
    def __init__(self) -> None:
        self._mappers: dict[str, EnrichmentMapper] = {}

    def register(self, mapper: EnrichmentMapper, *, replace: bool = False) -> None:
        if mapper.source_name in self._mappers and not replace:
            raise ValueError(f"enrichment mapper already registered: {mapper.source_name}")
        self._mappers[mapper.source_name] = mapper

    def get(self, source_name: str) -> EnrichmentMapper:
        try:
            return self._mappers[source_name]
        except KeyError as exc:
            raise KeyError(f"unknown enrichment mapper: {source_name}") from exc

    def source_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._mappers))


def normalize_enrichment_page(
    db: Session,
    run: IntelCollectionRun,
    page: CollectorPage,
    *,
    mapper: EnrichmentMapper,
) -> None:
    if mapper.source_name != run.source_name:
        raise ValueError("mapper source does not match collection run")
    if not run.generation_id:
        raise ValueError("collection run has no generation")

    for raw_record in page.records:
        payload_hash = compute_payload_hash(raw_record.payload)
        raw_event = db.scalar(
            select(IntelRawEvent).where(
                IntelRawEvent.provider == run.source_name,
                IntelRawEvent.generation_id == run.generation_id,
                IntelRawEvent.external_key == raw_record.external_id,
                IntelRawEvent.payload_hash == payload_hash,
            )
        )
        if raw_event is None:
            raise ValueError(f"staged raw event not found: {raw_record.external_id}")
        normalized = mapper.map_record(raw_record)
        vulnerability = db.scalar(
            select(Vulnerability).where(
                Vulnerability.canonical_id == normalized.canonical_id
            )
        )
        if vulnerability is None:
            vulnerability = Vulnerability(
                canonical_id=normalized.canonical_id,
                title=normalized.title or normalized.canonical_id,
                description=None,
                staging_generation_id=run.generation_id,
            )
            db.add(vulnerability)
            db.flush()

        upsert_source_contribution(
            db,
            run=run,
            vulnerability_id=vulnerability.id,
            external_key=raw_record.external_id,
            contribution=normalized.contribution,
            provenance={
                **normalized.provenance,
                "raw_event_id": raw_event.id,
                "source_url": raw_record.source_url,
                "parser_version": run.parser_version,
            },
            raw_event_id=raw_event.id,
        )
        _replace_staged_scopes(
            db,
            run=run,
            raw_event=raw_event,
            vulnerability=vulnerability,
            scopes=normalized.scopes,
        )
        raw_event.processing_status = "processed"
        raw_event.processed_at = utcnow()
        raw_event.vulnerability_id = vulnerability.id
        raw_event.last_error = None
        run.processed_count += 1
        db.add_all((raw_event, run))
    db.flush()


def materialize_enrichment_generation(
    db: Session,
    run: IntelCollectionRun,
) -> None:
    if not run.generation_id:
        return
    generation_contributions = db.scalars(
        select(VulnerabilitySourceContribution).where(
            VulnerabilitySourceContribution.source_name == run.source_name,
            VulnerabilitySourceContribution.generation_id == run.generation_id,
            VulnerabilitySourceContribution.is_active.is_(True),
        )
    ).all()
    vulnerability_ids = {row.vulnerability_id for row in generation_contributions}
    for vulnerability_id in vulnerability_ids:
        vulnerability = db.get(Vulnerability, vulnerability_id)
        if vulnerability is None:
            continue
        active_contributions = db.scalars(
            select(VulnerabilitySourceContribution).where(
                VulnerabilitySourceContribution.vulnerability_id == vulnerability_id,
                VulnerabilitySourceContribution.is_active.is_(True),
            )
        ).all()
        merged = merge_contribution_documents(active_contributions)
        _materialize_merged_fields(vulnerability, merged)
        db.add(vulnerability)

    for contribution in generation_contributions:
        raw_event = (
            db.get(IntelRawEvent, contribution.raw_event_id)
            if contribution.raw_event_id
            else None
        )
        if raw_event is None:
            continue
        document = contribution.contribution_json or {}
        source = db.scalar(
            select(VulnerabilitySource).where(
                VulnerabilitySource.source_name == contribution.source_name,
                VulnerabilitySource.external_id == contribution.external_key,
            )
        )
        if source is None:
            source = VulnerabilitySource(
                vulnerability_id=contribution.vulnerability_id,
                source_name=contribution.source_name,
                external_id=contribution.external_key,
                last_payload_hash=raw_event.payload_hash,
            )
        source.vulnerability_id = contribution.vulnerability_id
        source.raw_event_id = raw_event.id
        source.event_type = raw_event.event_type
        source.source_url = raw_event.source_url
        source.title = _text(document.get("title"))
        source.description = _text(document.get("description"))
        source.references_json = _string_list(document.get("references"))
        source.last_payload_hash = raw_event.payload_hash
        source.last_seen_at = utcnow()
        db.add(source)
    db.flush()


def _replace_staged_scopes(
    db: Session,
    *,
    run: IntelCollectionRun,
    raw_event: IntelRawEvent,
    vulnerability: Vulnerability,
    scopes: list[EnrichmentScope],
) -> None:
    db.execute(
        delete(VulnerabilityAffectedScope).where(
            VulnerabilityAffectedScope.vulnerability_id == vulnerability.id,
            VulnerabilityAffectedScope.source_name == run.source_name,
            VulnerabilityAffectedScope.generation_id == run.generation_id,
            VulnerabilityAffectedScope.raw_event_id == raw_event.id,
        )
    )
    seen_scope_keys: set[str] = set()
    for scope in scopes:
        fact = enrichment_scope_fact(scope)
        fingerprint = compute_fact_fingerprint(fact)
        scope_key = sha256(
            f"{raw_event.external_key}\x1f{fingerprint}".encode("utf-8")
        ).hexdigest()
        if scope_key in seen_scope_keys:
            continue
        seen_scope_keys.add(scope_key)
        db.add(
            VulnerabilityAffectedScope(
                vulnerability_id=vulnerability.id,
                raw_event_id=raw_event.id,
                source_name=run.source_name,
                generation_id=run.generation_id,
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
                source_url=raw_event.source_url,
                fact_fingerprint=fingerprint,
                provenance_json=scope.provenance,
                is_active=False,
            )
        )


def enrichment_scope_fact(scope: EnrichmentScope) -> dict[str, Any]:
    return {
        "vendor": scope.vendor,
        "product": scope.product,
        "ecosystem": scope.ecosystem,
        "distro": scope.distro,
        "distro_release": scope.distro_release,
        "source_package": scope.source_package,
        "binary_package": scope.binary_package,
        "architecture": scope.architecture,
        "flavor": scope.flavor,
        "version_scheme": scope.version_scheme,
        "version_type": scope.version_type,
        "status": scope.status,
        "default_status": scope.default_status,
        "cpe": scope.cpe,
        "purl": scope.purl,
        "platforms": scope.platforms,
        "structured_versions": scope.structured_versions,
        "affected_versions": scope.affected_versions,
        "fixed_versions": scope.fixed_versions,
    }


def _materialize_merged_fields(
    vulnerability: Vulnerability,
    merged: dict[str, Any],
) -> None:
    if field := merged.get("title"):
        vulnerability.title = _text(field.value) or vulnerability.title
    if field := merged.get("description"):
        vulnerability.description = _text(field.value)
    if field := merged.get("products"):
        products = field.value if isinstance(field.value, list) else []
        first = next((item for item in products if isinstance(item, dict)), None)
        if first:
            vulnerability.vendor = _text(first.get("vendor"))
            vulnerability.product = _text(first.get("product"))
    metrics = None
    if field := merged.get("nvd_metrics"):
        metrics = field.value
    elif field := merged.get("cna_metrics"):
        metrics = field.value
    score, label = _preferred_cvss(metrics)
    if score is not None:
        vulnerability.severity_cvss = score
    if label:
        vulnerability.severity_label = normalize_severity_label(label)


def _preferred_cvss(metrics: Any) -> tuple[float | None, str | None]:
    candidates: list[tuple[int, float, str | None]] = []
    if isinstance(metrics, dict):
        groups = metrics.items()
    elif isinstance(metrics, list):
        groups = (("cna", metrics),)
    else:
        return None, None
    version_priority = {
        "cvssMetricV40": 40,
        "cvssV4_0": 40,
        "cvssMetricV31": 31,
        "cvssV3_1": 31,
        "cvssMetricV30": 30,
        "cvssV3_0": 30,
        "cvssMetricV2": 20,
        "cvssV2_0": 20,
    }
    for group_name, entries in groups:
        if not isinstance(entries, list):
            entries = [entries]
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            nested_items = entry.items() if group_name == "cna" else ((group_name, entry),)
            for metric_name, metric in nested_items:
                if not isinstance(metric, dict):
                    continue
                data = metric.get("cvssData") if isinstance(metric.get("cvssData"), dict) else metric
                try:
                    score = float(data["baseScore"])
                except (KeyError, TypeError, ValueError):
                    continue
                label = _text(data.get("baseSeverity") or metric.get("baseSeverity"))
                candidates.append((version_priority.get(metric_name, 0), score, label))
    if not candidates:
        return None, None
    _priority, score, label = max(candidates, key=lambda item: item[0])
    return score, label


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return list(dict.fromkeys(text for item in value if (text := _text(item))))
