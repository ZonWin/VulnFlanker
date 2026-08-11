from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select

from app.connectors.cisa_kev import CisaKevConnector
from app.matching.version_rule import (
    evaluate_version_constraint_groups,
    parse_constraint_groups,
    parse_constraints,
    version_satisfies_constraints,
)
from app.core.config import get_settings
from app.db.base import utcnow
from app.db.models import (
    CisaKevMonitorConfig,
    IntelCollectionRun,
    IntelRawEvent,
    Vulnerability,
    VulnerabilityAffectedScope,
    VulnerabilitySource,
)
from app.services.cisa_kev_monitor import (
    get_cisa_kev_monitor_config,
    should_run_cisa_kev_monitor,
)
from app.services.intel_ingestion import collect_cisa_kev
from app.services.intel_normalization import normalize_raw_event
from app.services.intel_tracking import complete_collection_run, create_collection_run
from app.services.platform_settings import get_platform_settings
from app.services.watchvuln_monitor import (
    get_watchvuln_monitor_config,
    should_run_watchvuln_monitor,
)
from app.workers.celery_app import celery_app
from app.workers.tasks import ai_enrich_vulnerability, process_watchvuln_raw_event


def test_affected_version_parser_treats_pipe_as_or_between_exact_versions() -> None:
    groups = parse_constraint_groups("1.161.10 | 1.161.13", None)

    assert len(groups) == 2
    assert [[constraint.operator for constraint in group] for group in groups] == [
        ["=="],
        ["=="],
    ]
    assert evaluate_version_constraint_groups("1.161.10", groups).result is True
    assert evaluate_version_constraint_groups("1.161.13", groups).result is True
    assert evaluate_version_constraint_groups("1.161.11", groups).result is False


def test_affected_version_parser_keeps_pipe_separated_ranges_independent() -> None:
    groups = parse_constraint_groups(
        ">= 1.0, < 1.2 | >= 2.0, <= 2.1",
        None,
    )

    assert len(groups) == 2
    assert evaluate_version_constraint_groups("1.1", groups).result is True
    assert evaluate_version_constraint_groups("2.1", groups).result is True
    assert evaluate_version_constraint_groups("1.5", groups).result is False


SAMPLE_KEV_CATALOG = {
    "catalogVersion": "2026.05.02",
    "dateReleased": "2026-05-02T00:00:00Z",
    "count": 1,
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-0001",
            "vendorProject": "Acme",
            "product": "Edge Gateway",
            "vulnerabilityName": "Acme Edge Gateway Remote Code Execution",
            "dateAdded": "2026-05-01",
            "shortDescription": "Unauthenticated remote code execution in Acme Edge Gateway.",
            "requiredAction": "Upgrade to version 2.4.1 or later.",
            "dueDate": "2026-05-21",
            "knownRansomwareCampaignUse": "Known",
            "notes": "https://example.test/advisory; https://example.test/patch",
            "cwes": ["CWE-78"],
        }
    ],
}

SAMPLE_CVE_RECORD = {
    "dataType": "CVE_RECORD",
    "dataVersion": "5.2",
    "cveMetadata": {
        "cveId": "CVE-2026-48939",
        "state": "PUBLISHED",
        "datePublished": "2026-06-20T11:56:50.752Z",
    },
    "containers": {
        "cna": {
            "affected": [
                {
                    "defaultStatus": "unaffected",
                    "product": "iCagenda extension for Joomla",
                    "vendor": "icagenda.com",
                    "packageName": "com-icagenda",
                    "packageURL": "pkg:generic/com-icagenda",
                    "cpes": ["cpe:2.3:a:icagenda:icagenda:*:*:*:*:*:joomla:*:*"],
                    "platforms": ["Joomla"],
                    "versions": [
                        {
                            "status": "affected",
                            "version": "3.2.1-4.0.7",
                            "versionType": "semver",
                        }
                    ],
                }
            ],
            "descriptions": [
                {
                    "lang": "en",
                    "value": "Structured CVE Record description for iCagenda.",
                }
            ],
            "problemTypes": [
                {
                    "descriptions": [
                        {
                            "lang": "en",
                            "type": "CWE",
                            "cweId": "CWE-434",
                            "description": "Unrestricted upload of file.",
                        }
                    ]
                }
            ],
            "metrics": [
                {
                    "cvssV3_1": {
                        "version": "3.1",
                        "baseScore": 7.5,
                        "baseSeverity": "HIGH",
                    },
                    "cvssV4_0": {
                        "version": "4.0",
                        "baseScore": 9.6,
                        "baseSeverity": "CRITICAL",
                    },
                }
            ],
            "references": [{"url": "https://www.icagenda.com/", "tags": ["product"]}],
        }
    },
}


def test_collect_cisa_kev_ingests_vulnerabilities_and_sources(db_session) -> None:
    connector = CisaKevConnector(
        feed_url="https://example.test/kev.json",
        catalog_url="https://example.test/catalog",
        cve_record_fetch=False,
    )
    connector.fetch_catalog = lambda: SAMPLE_KEV_CATALOG  # type: ignore[method-assign]

    stats = collect_cisa_kev(db_session, connector=connector)

    assert stats.source_name == "cisa-kev"
    assert stats.run_id is not None
    assert stats.fetched_count == 1
    assert stats.stored_count == 1
    assert stats.processed_count == 1

    vulnerability = db_session.scalar(
        select(Vulnerability).where(Vulnerability.canonical_id == "CVE-2026-0001")
    )
    assert vulnerability is not None
    assert vulnerability.kev_status is True
    assert vulnerability.severity_label is None
    assert vulnerability.vendor == "Acme"
    assert vulnerability.product == "Edge Gateway"
    assert vulnerability.remediation == "Upgrade to version 2.4.1 or later."
    assert vulnerability.affected_versions is None
    assert vulnerability.fixed_versions == "2.4.1"

    source = db_session.scalar(
        select(VulnerabilitySource).where(
            VulnerabilitySource.source_name == "cisa-kev",
            VulnerabilitySource.external_id == "CVE-2026-0001",
        )
    )
    assert source is not None
    assert source.references_json == [
        "https://example.test/advisory",
        "https://example.test/patch",
    ]
    assert source.tags_json == ["Acme", "Edge Gateway", "CWE-78", "kev"]

    raw_event = db_session.scalar(
        select(IntelRawEvent).where(IntelRawEvent.provider == "cisa-kev")
    )
    assert raw_event is not None
    assert raw_event.processing_status == "processed"

    run = db_session.get(IntelCollectionRun, stats.run_id)
    assert run is not None
    assert run.status == "completed"
    assert run.fetched_count == 1
    assert run.processed_count == 1


def test_collect_cisa_kev_reuses_raw_event_by_cve_when_catalog_changes(db_session) -> None:
    connector = CisaKevConnector(
        feed_url="https://example.test/kev.json",
        catalog_url="https://example.test/catalog",
        cve_record_fetch=False,
    )
    connector.fetch_catalog = lambda: SAMPLE_KEV_CATALOG  # type: ignore[method-assign]

    first_stats = collect_cisa_kev(db_session, connector=connector)

    raw_event = db_session.scalar(
        select(IntelRawEvent).where(IntelRawEvent.provider == "cisa-kev")
    )
    source = db_session.scalar(
        select(VulnerabilitySource).where(
            VulnerabilitySource.source_name == "cisa-kev",
            VulnerabilitySource.external_id == "CVE-2026-0001",
        )
    )
    assert raw_event is not None
    assert source is not None
    raw_event_id = raw_event.id
    first_payload_hash = raw_event.payload_hash
    first_source_hash = source.last_payload_hash

    updated_catalog = {
        **SAMPLE_KEV_CATALOG,
        "catalogVersion": "2026.05.03",
        "dateReleased": "2026-05-03T00:00:00Z",
        "vulnerabilities": [
            {
                **SAMPLE_KEV_CATALOG["vulnerabilities"][0],
                "product": "Edge Gateway Pro",
                "notes": "https://example.test/advisory; https://example.test/new-patch",
            }
        ],
    }
    connector.fetch_catalog = lambda: updated_catalog  # type: ignore[method-assign]

    second_stats = collect_cisa_kev(db_session, connector=connector)

    raw_events = list(
        db_session.scalars(
            select(IntelRawEvent).where(IntelRawEvent.provider == "cisa-kev")
        )
    )
    assert first_stats.stored_count == 1
    assert second_stats.fetched_count == 1
    assert second_stats.stored_count == 0
    assert second_stats.processed_count == 1
    assert len(raw_events) == 1
    assert raw_events[0].id == raw_event_id
    assert raw_events[0].payload["catalog_version"] == "2026.05.03"
    assert raw_events[0].payload_hash != first_payload_hash
    assert raw_events[0].processing_status == "processed"

    vulnerability = db_session.scalar(
        select(Vulnerability).where(Vulnerability.canonical_id == "CVE-2026-0001")
    )
    source = db_session.scalar(
        select(VulnerabilitySource).where(
            VulnerabilitySource.source_name == "cisa-kev",
            VulnerabilitySource.external_id == "CVE-2026-0001",
        )
    )
    assert vulnerability is not None
    assert source is not None
    assert vulnerability.product == "Edge Gateway Pro"
    assert source.references_json == [
        "https://example.test/advisory",
        "https://example.test/new-patch",
    ]
    assert source.last_payload_hash != first_source_hash


def test_scheduled_cisa_kev_full_collection_backfills_missing_catalog_items(
    db_session,
) -> None:
    connector = CisaKevConnector(
        feed_url="https://example.test/kev.json",
        catalog_url="https://example.test/catalog",
        cve_record_fetch=False,
    )
    connector.fetch_catalog = lambda: SAMPLE_KEV_CATALOG  # type: ignore[method-assign]
    collect_cisa_kev(db_session, connector=connector)

    full_catalog = {
        **SAMPLE_KEV_CATALOG,
        "catalogVersion": "2026.05.03",
        "dateReleased": "2026-05-03T00:00:00Z",
        "count": 2,
        "vulnerabilities": [
            SAMPLE_KEV_CATALOG["vulnerabilities"][0],
            {
                **SAMPLE_KEV_CATALOG["vulnerabilities"][0],
                "cveID": "CVE-2026-0002",
                "product": "Missing Gateway",
                "vulnerabilityName": "Acme Missing Gateway Remote Code Execution",
                "requiredAction": "Upgrade to version 3.1.0 or later.",
            },
        ],
    }
    connector.fetch_catalog = lambda: full_catalog  # type: ignore[method-assign]

    stats = collect_cisa_kev(
        db_session,
        connector=connector,
        trigger_type="scheduled",
    )

    canonical_ids = set(
        db_session.scalars(select(Vulnerability.canonical_id)).all()
    )
    raw_events = list(
        db_session.scalars(
            select(IntelRawEvent).where(IntelRawEvent.provider == "cisa-kev")
        )
    )
    run = db_session.get(IntelCollectionRun, stats.run_id)
    assert stats.fetched_count == 2
    assert stats.stored_count == 1
    assert canonical_ids == {"CVE-2026-0001", "CVE-2026-0002"}
    assert len(raw_events) == 2
    assert run is not None
    assert run.trigger_type == "scheduled"


def test_collect_cisa_kev_latest_only_uses_local_date_watermark(db_session) -> None:
    connector = CisaKevConnector(
        feed_url="https://example.test/kev.json",
        catalog_url="https://example.test/catalog",
        cve_record_fetch=False,
    )
    initial_catalog = {
        **SAMPLE_KEV_CATALOG,
        "vulnerabilities": [
            {
                **SAMPLE_KEV_CATALOG["vulnerabilities"][0],
                "cveID": "CVE-2026-1001",
                "dateAdded": "2026-05-02",
            }
        ],
    }
    connector.fetch_catalog = lambda: initial_catalog  # type: ignore[method-assign]
    collect_cisa_kev(db_session, connector=connector)

    latest_catalog = {
        **SAMPLE_KEV_CATALOG,
        "catalogVersion": "2026.05.03",
        "dateReleased": "2026-05-03T00:00:00Z",
        "count": 4,
        "vulnerabilities": [
            {
                **SAMPLE_KEV_CATALOG["vulnerabilities"][0],
                "cveID": "CVE-2026-1003",
                "product": "Newest Gateway",
                "dateAdded": "2026-05-03",
            },
            {
                **SAMPLE_KEV_CATALOG["vulnerabilities"][0],
                "cveID": "CVE-2026-1002",
                "product": "Same Day Gateway",
                "dateAdded": "2026-05-02",
            },
            {
                **SAMPLE_KEV_CATALOG["vulnerabilities"][0],
                "cveID": "CVE-2026-1001",
                "product": "Existing Gateway",
                "dateAdded": "2026-05-02",
            },
            {
                **SAMPLE_KEV_CATALOG["vulnerabilities"][0],
                "cveID": "CVE-2026-1000",
                "product": "Historical Gateway",
                "dateAdded": "2026-05-01",
            },
        ],
    }
    connector.fetch_catalog = lambda: latest_catalog  # type: ignore[method-assign]

    stats = collect_cisa_kev(
        db_session,
        connector=connector,
        latest_only=True,
        trigger_type="scheduled",
    )

    canonical_ids = set(
        db_session.scalars(select(Vulnerability.canonical_id)).all()
    )
    run = db_session.get(IntelCollectionRun, stats.run_id)
    assert stats.fetched_count == 2
    assert stats.stored_count == 2
    assert canonical_ids == {"CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"}
    assert "CVE-2026-1000" not in canonical_ids
    assert run is not None
    assert run.parameters_json["latest_only"] is True


def test_collect_cisa_kev_limit_zero_disables_latest_watermark(db_session) -> None:
    connector = CisaKevConnector(
        feed_url="https://example.test/kev.json",
        catalog_url="https://example.test/catalog",
        cve_record_fetch=False,
    )
    initial_catalog = {
        **SAMPLE_KEV_CATALOG,
        "vulnerabilities": [
            {
                **SAMPLE_KEV_CATALOG["vulnerabilities"][0],
                "cveID": "CVE-2026-1101",
                "dateAdded": "2026-05-02",
            }
        ],
    }
    connector.fetch_catalog = lambda: initial_catalog  # type: ignore[method-assign]
    collect_cisa_kev(db_session, connector=connector)

    full_catalog = {
        **SAMPLE_KEV_CATALOG,
        "catalogVersion": "2026.05.03",
        "dateReleased": "2026-05-03T00:00:00Z",
        "count": 4,
        "vulnerabilities": [
            {
                **SAMPLE_KEV_CATALOG["vulnerabilities"][0],
                "cveID": "CVE-2026-1103",
                "dateAdded": "2026-05-03",
            },
            {
                **SAMPLE_KEV_CATALOG["vulnerabilities"][0],
                "cveID": "CVE-2026-1102",
                "dateAdded": "2026-05-02",
            },
            {
                **SAMPLE_KEV_CATALOG["vulnerabilities"][0],
                "cveID": "CVE-2026-1101",
                "dateAdded": "2026-05-02",
            },
            {
                **SAMPLE_KEV_CATALOG["vulnerabilities"][0],
                "cveID": "CVE-2026-1100",
                "dateAdded": "2026-05-01",
            },
        ],
    }
    connector.fetch_catalog = lambda: full_catalog  # type: ignore[method-assign]

    stats = collect_cisa_kev(
        db_session,
        connector=connector,
        latest_only=True,
        limit=0,
    )

    canonical_ids = set(
        db_session.scalars(select(Vulnerability.canonical_id)).all()
    )
    run = db_session.get(IntelCollectionRun, stats.run_id)
    assert stats.fetched_count == 4
    assert canonical_ids == {
        "CVE-2026-1100",
        "CVE-2026-1101",
        "CVE-2026-1102",
        "CVE-2026-1103",
    }
    assert run is not None
    assert run.parameters_json["limit"] is None
    assert run.parameters_json["latest_only"] is False


def test_collect_cisa_kev_enriches_from_cve_record_details(db_session) -> None:
    catalog = {
        **SAMPLE_KEV_CATALOG,
        "vulnerabilities": [
            {
                **SAMPLE_KEV_CATALOG["vulnerabilities"][0],
                "cveID": "CVE-2026-48939",
                "vendorProject": "iCagenda",
                "product": "iCagenda",
                "vulnerabilityName": "iCagenda Upload Vulnerability",
                "shortDescription": "Short CISA description.",
            }
        ],
    }
    connector = CisaKevConnector(
        feed_url="https://example.test/kev.json",
        catalog_url="https://example.test/catalog",
        cve_record_fetch=True,
        cve_record_workers=1,
    )
    connector.fetch_catalog = lambda: catalog  # type: ignore[method-assign]
    connector.fetch_cve_record = lambda _: SAMPLE_CVE_RECORD  # type: ignore[method-assign]

    stats = collect_cisa_kev(db_session, connector=connector)

    assert stats.processed_count == 1
    vulnerability = db_session.scalar(
        select(Vulnerability).where(Vulnerability.canonical_id == "CVE-2026-48939")
    )
    assert vulnerability is not None
    assert vulnerability.vendor == "icagenda.com"
    assert vulnerability.product == "iCagenda extension for Joomla"
    assert vulnerability.description == "Structured CVE Record description for iCagenda."
    assert vulnerability.severity_cvss == 9.6
    assert vulnerability.severity_label == "critical"
    assert vulnerability.affected_versions == "3.2.1-4.0.7"
    scopes = list(vulnerability.affected_scopes)
    assert len(scopes) == 1
    assert scopes[0].product == "iCagenda extension for Joomla"
    assert scopes[0].affected_versions == "3.2.1-4.0.7"
    assert scopes[0].binary_package == "com-icagenda"
    assert scopes[0].version_scheme == "generic"
    assert scopes[0].version_type == "semver"
    assert scopes[0].status == "affected"
    assert scopes[0].default_status == "unaffected"
    assert scopes[0].source_authority == "cna"
    assert scopes[0].authority_score == 70
    assert scopes[0].purl == "pkg:generic/com-icagenda"
    assert scopes[0].cpe.startswith("cpe:2.3:a:icagenda")
    assert scopes[0].platforms_json == ["Joomla"]
    assert scopes[0].structured_versions_json[0]["versionType"] == "semver"
    assert vulnerability.published_at is not None
    constraints = parse_constraints(vulnerability.affected_versions, None)
    assert version_satisfies_constraints("3.2.1", constraints) is True
    assert version_satisfies_constraints("4.0.7", constraints) is True
    assert version_satisfies_constraints("4.0.8", constraints) is False

    source = db_session.scalar(
        select(VulnerabilitySource).where(
            VulnerabilitySource.source_name == "cisa-kev",
            VulnerabilitySource.external_id == "CVE-2026-48939",
        )
    )
    assert source is not None
    assert "CWE-434" in source.tags_json
    assert "https://www.icagenda.com/" in source.references_json
    assert "https://www.cve.org/CVERecord?id=CVE-2026-48939" in source.references_json


def test_cisa_kev_keeps_cisa_product_when_cve_record_uses_placeholder(db_session) -> None:
    raw_event = IntelRawEvent(
        provider="cisa-kev",
        event_type="cisa-kev-vulnerability",
        external_key="CVE-2026-0100",
        source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        payload={
            "record": {
                "cveID": "CVE-2026-0100",
                "vendorProject": "Acme",
                "product": "Secure Gateway",
                "vulnerabilityName": "Acme Secure Gateway Vulnerability",
                "dateAdded": "2026-05-01",
                "shortDescription": "CISA product identity remains authoritative.",
                "requiredAction": "Apply the vendor update.",
            },
            "cve_record": {
                "containers": {
                    "cna": {
                        "affected": [{"vendor": "n/a", "product": "N/A"}],
                    }
                }
            },
        },
        payload_hash="cisa-placeholder-product",
        processing_status="pending",
    )
    db_session.add(raw_event)
    db_session.commit()

    normalize_raw_event(db_session, raw_event)

    vulnerability = db_session.scalar(
        select(Vulnerability).where(Vulnerability.canonical_id == "CVE-2026-0100")
    )
    assert vulnerability is not None
    assert vulnerability.vendor == "Acme"
    assert vulnerability.product == "Secure Gateway"
    assert list(vulnerability.affected_scopes) == []


def test_cisa_kev_keeps_all_cve_affected_product_scopes(db_session) -> None:
    raw_event = IntelRawEvent(
        provider="cisa-kev",
        event_type="cisa-kev-vulnerability",
        external_key="CVE-2026-12569",
        source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        payload={
            "record": {
                "cveID": "CVE-2026-12569",
                "vendorProject": "PTC",
                "product": "Windchill and FlexPLM",
                "vulnerabilityName": "PTC Windchill and FlexPLM Vulnerability",
                "dateAdded": "2026-05-01",
                "shortDescription": "Multiple affected PTC products.",
                "requiredAction": "Apply the vendor update.",
            },
            "cve_record": {
                "containers": {
                    "cna": {
                        "affected": [
                            {
                                "vendor": "PTC",
                                "product": "Windchill PDMLink",
                                "versions": [
                                    {"status": "affected", "version": "13.0", "lessThan": "13.1"}
                                ],
                            },
                            {
                                "vendor": "PTC",
                                "product": "FlexPLM",
                                "versions": [
                                    {"status": "affected", "version": "12.0", "lessThanOrEqual": "12.1"}
                                ],
                            },
                        ]
                    }
                }
            },
        },
        payload_hash="cisa-multiple-products",
        processing_status="pending",
    )
    db_session.add(raw_event)
    db_session.commit()

    normalize_raw_event(db_session, raw_event)

    scopes = list(
        db_session.scalars(
            select(VulnerabilityAffectedScope)
            .join(Vulnerability)
            .where(Vulnerability.canonical_id == "CVE-2026-12569")
            .order_by(VulnerabilityAffectedScope.product)
        )
    )
    assert [(scope.product, scope.affected_versions) for scope in scopes] == [
        ("FlexPLM", ">= 12.0, <= 12.1"),
        ("Windchill PDMLink", ">= 13.0, < 13.1"),
    ]


def test_cisa_kev_normalization_extracts_only_explicit_version_ranges(db_session) -> None:
    raw_event = IntelRawEvent(
        provider="cisa-kev",
        event_type="cisa-kev-vulnerability",
        external_key="CVE-2026-0002",
        source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        payload={
            "record": {
                "cveID": "CVE-2026-0002",
                "vendorProject": "Acme",
                "product": "Legacy Gateway",
                "vulnerabilityName": "Acme Legacy Gateway Vulnerability",
                "dateAdded": "2026-05-01",
                "shortDescription": "A vulnerability in the legacy gateway.",
                "requiredAction": (
                    "Versions 6 and earlier for this product are end-of-life and must "
                    "be removed from agency networks. Versions 7 and later are not "
                    "considered vulnerable."
                ),
                "dueDate": "2026-05-21",
                "knownRansomwareCampaignUse": "Unknown",
                "notes": "https://example.test/advisory",
                "cwes": ["CWE-287"],
            }
        },
        payload_hash="cisa-explicit-version-range",
        processing_status="pending",
    )
    db_session.add(raw_event)
    db_session.commit()

    normalize_raw_event(db_session, raw_event)

    vulnerability = db_session.scalar(
        select(Vulnerability).where(Vulnerability.canonical_id == "CVE-2026-0002")
    )
    assert vulnerability is not None
    assert vulnerability.affected_versions == "<= 6"
    assert vulnerability.fixed_versions == "7"


def test_cisa_kev_does_not_replace_richer_cross_source_version_ranges(db_session) -> None:
    watch_raw = IntelRawEvent(
        provider="watchvuln",
        event_type="watchvuln-vulninfo",
        external_key="watch-cisa-version-precedence",
        source_url="https://example.test/watch",
        payload={
            "type": "watchvuln-vulninfo",
            "content": {
                "unique_key": "watch-cisa-version-precedence",
                "cve": "CVE-2026-0003",
                "title": "Acme Gateway Vulnerability",
                "product": "Gateway",
                "affected_versions": ">= 1.0, < 2.4.1",
                "fixed_versions": ">= 2.4.1",
            },
        },
        payload_hash="watch-cisa-version-precedence",
        processing_status="pending",
    )
    cisa_raw = IntelRawEvent(
        provider="cisa-kev",
        event_type="cisa-kev-vulnerability",
        external_key="CVE-2026-0003",
        source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        payload={
            "record": {
                "cveID": "CVE-2026-0003",
                "vendorProject": "Acme",
                "product": "Gateway",
                "vulnerabilityName": "Acme Gateway Vulnerability",
                "dateAdded": "2026-05-01",
                "shortDescription": "Acme Gateway vulnerability.",
                "requiredAction": "Upgrade to version 2.5.0 or later.",
                "dueDate": "2026-05-21",
                "knownRansomwareCampaignUse": "Unknown",
                "notes": "https://example.test/advisory",
            }
        },
        payload_hash="cisa-version-precedence",
        processing_status="pending",
    )
    db_session.add_all([watch_raw, cisa_raw])
    db_session.commit()

    normalize_raw_event(db_session, watch_raw)
    normalize_raw_event(db_session, cisa_raw)

    vulnerability = db_session.scalar(
        select(Vulnerability).where(Vulnerability.canonical_id == "CVE-2026-0003")
    )
    assert vulnerability is not None
    assert vulnerability.affected_versions == ">= 1.0, < 2.4.1"
    assert vulnerability.fixed_versions == ">= 2.4.1"


def test_cisa_kev_collection_endpoint_exposes_ingested_vulnerability(client, monkeypatch) -> None:
    monkeypatch.setattr(CisaKevConnector, "fetch_catalog", lambda self: SAMPLE_KEV_CATALOG)
    monkeypatch.setattr(CisaKevConnector, "fetch_cve_record", lambda self, _: None)

    collect_response = client.post("/api/v1/intel/cisa-kev/collect", json={})
    assert collect_response.status_code == 200
    payload = collect_response.json()
    assert payload["status"] == "completed"
    assert payload["run_id"]
    assert payload["processed_count"] == 1

    list_response = client.get("/api/v1/vulnerabilities")
    assert list_response.status_code == 200
    vulnerabilities = list_response.json()["items"]
    assert len(vulnerabilities) == 1
    assert vulnerabilities[0]["canonical_id"] == "CVE-2026-0001"
    assert vulnerabilities[0]["severity_label"] is None
    assert vulnerabilities[0]["kev_status"] is True

    detail_response = client.get("/api/v1/vulnerabilities/CVE-2026-0001")
    assert detail_response.status_code == 200
    detail_payload = detail_response.json()
    assert detail_payload["sources"][0]["source_name"] == "cisa-kev"

    sources_response = client.get("/api/v1/intel/sources")
    assert sources_response.status_code == 200
    sources_payload = sources_response.json()
    assert [item["source_name"] for item in sources_payload[:3]] == [
        "cisa-kev",
        "watchvuln",
        "aliyun-avd",
    ]
    assert {item["source_name"] for item in sources_payload[3:]} == {
        "cve-list-v5",
        "nvd",
        "canonical-ubuntu",
        "debian-security-tracker",
        "redhat-csaf",
    }
    sources = {item["source_name"]: item for item in sources_payload}
    assert sources["cisa-kev"]["last_status"] == "completed"
    assert sources["cisa-kev"]["raw_event_count"] == 1
    assert sources["cisa-kev"]["processed_event_count"] == 1
    assert sources["cisa-kev"]["vulnerability_count"] == 1

    runs_response = client.get("/api/v1/intel/runs")
    assert runs_response.status_code == 200
    runs = runs_response.json()
    assert len(runs) == 1
    assert runs[0]["source_name"] == "cisa-kev"
    assert runs[0]["processed_count"] == 1
    assert runs[0]["parameters"]["latest_only"] is True

    raw_events_response = client.get("/api/v1/intel/raw-events")
    assert raw_events_response.status_code == 200
    raw_events = raw_events_response.json()
    assert len(raw_events) == 1
    assert raw_events[0]["provider"] == "cisa-kev"
    assert raw_events[0]["vulnerability_canonical_id"] == "CVE-2026-0001"
    assert raw_events[0]["quality"]["has_product"] is True
    assert raw_events[0]["quality"]["has_affected_version"] is False
    assert raw_events[0]["quality"]["has_fixed_version"] is True
    assert raw_events[0]["quality"]["has_severity"] is False
    assert raw_events[0]["quality"]["source_url_count"] == 1
    assert raw_events[0]["quality"]["reference_count"] == 2
    assert "missing_affected_versions" in raw_events[0]["quality"]["issue_codes"]
    assert raw_events[0]["quality"]["needs_ai_enrichment"] is True


def test_cisa_kev_collection_endpoint_treats_limit_zero_as_full(
    client,
    monkeypatch,
) -> None:
    monkeypatch.setattr(CisaKevConnector, "fetch_catalog", lambda self: SAMPLE_KEV_CATALOG)
    monkeypatch.setattr(CisaKevConnector, "fetch_cve_record", lambda self, _: None)

    collect_response = client.post(
        "/api/v1/intel/cisa-kev/collect",
        json={"limit": 0},
    )

    assert collect_response.status_code == 200
    runs_response = client.get("/api/v1/intel/runs")
    assert runs_response.status_code == 200
    runs = runs_response.json()
    assert runs[0]["parameters"]["limit"] is None
    assert runs[0]["parameters"]["latest_only"] is False


def test_watchvuln_webhook_ingests_vulninfo(client, db_session, monkeypatch) -> None:
    settings = get_settings()
    original_token = settings.intel_webhook_token
    settings.intel_webhook_token = "secret-token"

    def fail_queue(_: str):
        raise RuntimeError("broker unavailable")

    monkeypatch.setattr(process_watchvuln_raw_event, "delay", fail_queue)

    try:
        payload = {
            "type": "watchvuln-vulninfo",
            "content": {
                "unique_key": "CVE-2026-1000_KEV",
                "title": "Forwarded KEV vulnerability",
                "description": "WatchVuln forwarded a KEV-style vulnerability.",
                "severity": "critical",
                "cve": "CVE-2026-1000",
                "product": "Forwarded Gateway",
                "affected_versions": "< 2.4.1",
                "fixed_versions": "2.4.1",
                "disclosure": "2026-05-01",
                "solutions": "Apply the vendor patch.",
                "references": ["https://watch.example/vuln"],
                "tags": ["kev", "internet-exposed"],
                "from": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "reason": ["new"],
            },
        }

        response = client.post(
            "/api/v1/intel/watchvuln/webhook",
            json=payload,
            headers={"X-VulnFlanker-Token": "secret-token"},
        )

        assert response.status_code == 202
        response_payload = response.json()
        assert response_payload["provider"] == "watchvuln"
        assert response_payload["processing_status"] == "processed"
        assert response_payload["run_id"]
        assert response_payload["queued"] is False

        vulnerability = db_session.scalar(
            select(Vulnerability).where(Vulnerability.canonical_id == "CVE-2026-1000")
        )
        assert vulnerability is not None
        assert vulnerability.kev_status is True
        assert vulnerability.severity_label == "critical"
        assert vulnerability.product == "Forwarded Gateway"
        assert vulnerability.affected_versions == "< 2.4.1"
        assert vulnerability.fixed_versions == "2.4.1"

        source = db_session.scalar(
            select(VulnerabilitySource).where(
                VulnerabilitySource.source_name == "watchvuln",
                VulnerabilitySource.external_id == "CVE-2026-1000_KEV",
            )
        )
        assert source is not None
        assert source.tags_json == ["kev", "internet-exposed"]

        run = db_session.get(IntelCollectionRun, response_payload["run_id"])
        assert run is not None
        assert run.source_name == "watchvuln"
        assert run.trigger_type == "webhook"
        assert run.processed_count == 1
    finally:
        settings.intel_webhook_token = original_token


def test_aliyun_avd_normalization_stabilizes_canonical_id_and_references(
    client,
    db_session,
) -> None:
    raw_event = IntelRawEvent(
        provider="aliyun-avd",
        event_type="aliyun-avd-high-risk",
        external_key="AVD-2026-QUALITY-0001",
        source_url="https://avd.example/detail?id=AVD-2026-QUALITY-0001",
        payload={
            "source": "high-risk-list",
            "record": {
                "avd_id": "AVD-2026-QUALITY-0001",
                "title": "Messy AVD CVE advisory",
                "cve_id": "related: cve-2026-2000 / CVE-2026-NOT-A-CVE",
                "product": "Quality Gateway",
                "severity": "high",
                "score": "8.8",
                "affected_versions": "< 3.0.0",
                "fixed_versions": "3.0.0",
                "source_url": "https://avd.example/detail?id=AVD-2026-QUALITY-0001",
                "references": (
                    "https://vendor.example/quality-0001; "
                    "https://patch.example/quality-0001"
                ),
            },
        },
        payload_hash="aliyun-quality-hash",
        processing_status="pending",
    )
    db_session.add(raw_event)
    db_session.commit()

    response = client.post(f"/api/v1/intel/raw-events/{raw_event.id}/normalize")

    assert response.status_code == 200
    assert response.json()["canonical_id"] == "CVE-2026-2000"

    source = db_session.scalar(
        select(VulnerabilitySource).where(
            VulnerabilitySource.source_name == "aliyun-avd",
            VulnerabilitySource.external_id == "AVD-2026-QUALITY-0001",
        )
    )
    assert source is not None
    assert source.references_json == [
        "https://vendor.example/quality-0001",
        "https://patch.example/quality-0001",
    ]


def test_raw_event_quality_reports_cross_source_conflicts(
    client,
    db_session,
) -> None:
    cisa_raw = IntelRawEvent(
        provider="cisa-kev",
        event_type="cisa-kev-vulnerability",
        external_key="CVE-2026-2001",
        source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        payload={
            "record": {
                "cveID": "CVE-2026-2001",
                "vendorProject": "Acme",
                "product": "Edge Gateway",
                "vulnerabilityName": "Acme Edge Gateway RCE",
                "dateAdded": "2026-05-01",
                "shortDescription": "Remote code execution.",
                "requiredAction": "Upgrade to version 2.4.1 or later.",
                "dueDate": "2026-05-21",
                "knownRansomwareCampaignUse": "Known",
                "notes": "https://vendor.example/cve-2026-2001",
            },
        },
        payload_hash="cisa-conflict-hash",
        processing_status="pending",
    )
    watch_raw = IntelRawEvent(
        provider="watchvuln",
        event_type="watchvuln-vulninfo",
        external_key="watch-conflict",
        source_url="https://watch.example/conflict",
        payload={
            "type": "watchvuln-vulninfo",
            "content": {
                "unique_key": "watch-conflict",
                "title": "Conflicting product advisory",
                "cve": "CVE-2026-2001",
                "product": "Different Gateway",
                "severity": "critical",
                "references": ["https://watch.example/conflict"],
                "from": "https://watch.example/conflict",
            },
        },
        payload_hash="watch-conflict-hash",
        processing_status="pending",
    )
    db_session.add_all([cisa_raw, watch_raw])
    db_session.commit()

    assert client.post(f"/api/v1/intel/raw-events/{cisa_raw.id}/normalize").status_code == 200
    assert client.post(f"/api/v1/intel/raw-events/{watch_raw.id}/normalize").status_code == 200

    detail_response = client.get(f"/api/v1/intel/raw-events/{watch_raw.id}")

    assert detail_response.status_code == 200
    quality = detail_response.json()["quality"]
    assert quality["source_conflict_count"] >= 1
    assert "product" in quality["conflict_fields"]
    assert "source_conflict_product" in quality["issue_codes"]
    assert quality["needs_human_review"] is True
    vulnerability = db_session.scalar(
        select(Vulnerability).where(Vulnerability.canonical_id == "CVE-2026-2001")
    )
    assert vulnerability is not None
    assert vulnerability.product == "Edge Gateway"


def test_watchvuln_known_exploited_severity_becomes_kev(client, db_session, monkeypatch) -> None:
    settings = get_settings()
    original_token = settings.intel_webhook_token
    settings.intel_webhook_token = "secret-token"

    def fail_queue(_: str):
        raise RuntimeError("broker unavailable")

    monkeypatch.setattr(process_watchvuln_raw_event, "delay", fail_queue)

    try:
        response = client.post(
            "/api/v1/intel/watchvuln/webhook",
            json={
                "type": "watchvuln-vulninfo",
                "content": {
                    "unique_key": "watchvuln-known-exploited",
                    "title": "Known exploited advisory",
                    "cve": "CVE-2026-KEV-SEVERITY",
                    "severity": "known_exploited",
                },
            },
            headers={"X-VulnFlanker-Token": "secret-token"},
        )

        assert response.status_code == 202
        vulnerability = db_session.scalar(
            select(Vulnerability).where(
                Vulnerability.canonical_id == "CVE-2026-KEV-SEVERITY"
            )
        )
        assert vulnerability is not None
        assert vulnerability.severity_label is None
        assert vulnerability.kev_status is True
    finally:
        settings.intel_webhook_token = original_token


def test_watchvuln_webhook_accepts_query_token(client, db_session, monkeypatch) -> None:
    settings = get_settings()
    original_token = settings.intel_webhook_token
    settings.intel_webhook_token = "query-secret"

    def fail_queue(_: str):
        raise RuntimeError("broker unavailable")

    monkeypatch.setattr(process_watchvuln_raw_event, "delay", fail_queue)

    try:
        response = client.post(
            "/api/v1/intel/watchvuln/webhook?token=query-secret",
            json={
                "type": "watchvuln-vulninfo",
                "content": {
                    "unique_key": "watchvuln-demo",
                    "title": "Forwarded advisory",
                },
            },
        )
        assert response.status_code == 202
        vulnerability = db_session.scalar(
            select(Vulnerability).where(
                Vulnerability.canonical_id == "watchvuln-demo"
            )
        )
        assert vulnerability is not None
    finally:
        settings.intel_webhook_token = original_token


def test_watchvuln_monitor_endpoint_updates_runtime_config(client) -> None:
    response = client.get("/api/v1/intel/watchvuln/monitor")
    assert response.status_code == 200
    payload = response.json()
    assert payload["enabled"] is False
    assert payload["interval_seconds"] == 1800
    assert payload["limit"] is None

    update_response = client.patch(
        "/api/v1/intel/watchvuln/monitor",
        json={"enabled": True, "interval_seconds": 900, "limit": 25},
    )
    assert update_response.status_code == 200
    updated = update_response.json()
    assert updated["enabled"] is True
    assert updated["interval_seconds"] == 900
    assert updated["limit"] == 25
    assert updated["next_run_at"] is not None

    clear_limit_response = client.patch(
        "/api/v1/intel/watchvuln/monitor",
        json={"limit": None},
    )
    assert clear_limit_response.status_code == 200
    assert clear_limit_response.json()["limit"] is None


def test_cisa_kev_monitor_endpoint_updates_runtime_config(client) -> None:
    response = client.get("/api/v1/intel/cisa-kev/monitor")
    assert response.status_code == 200
    payload = response.json()
    assert payload["enabled"] is False
    assert payload["interval_seconds"] == 86400
    assert payload["limit"] is None
    assert payload["latest_only"] is False

    update_response = client.patch(
        "/api/v1/intel/cisa-kev/monitor",
        json={
            "enabled": False,
            "interval_seconds": 43200,
            "limit": 250,
            "latest_only": True,
        },
    )
    assert update_response.status_code == 200
    updated = update_response.json()
    assert updated["enabled"] is False
    assert updated["interval_seconds"] == 43200
    assert updated["limit"] == 250
    assert updated["latest_only"] is True
    assert updated["next_run_at"] is None

    enable_response = client.patch(
        "/api/v1/intel/cisa-kev/monitor",
        json={"enabled": True, "limit": None, "latest_only": False},
    )
    assert enable_response.status_code == 200
    enabled = enable_response.json()
    assert enabled["enabled"] is True
    assert enabled["limit"] is None
    assert enabled["latest_only"] is False
    assert enabled["next_run_at"] is not None


def test_watchvuln_monitor_respects_runtime_interval(db_session) -> None:
    config = get_watchvuln_monitor_config(db_session)
    config.enabled = True
    config.interval_seconds = 3600
    db_session.add(config)
    db_session.commit()

    assert should_run_watchvuln_monitor(db_session, config=config) is True

    run = create_collection_run(
        db_session,
        source_name="watchvuln",
        trigger_type="scheduled",
        status="running",
    )
    db_session.commit()
    assert should_run_watchvuln_monitor(db_session, config=config) is False

    complete_collection_run(db_session, run, status="completed")
    run.started_at = utcnow() - timedelta(seconds=1800)
    db_session.add(run)
    db_session.commit()
    assert should_run_watchvuln_monitor(db_session, config=config) is False

    run.started_at = utcnow() - timedelta(seconds=3601)
    db_session.add(run)
    db_session.commit()
    assert should_run_watchvuln_monitor(db_session, config=config) is True


def test_cisa_kev_monitor_respects_scheduled_interval(db_session) -> None:
    config = get_cisa_kev_monitor_config(db_session)
    config.enabled = True
    config.interval_seconds = 86_400
    db_session.add(config)
    db_session.commit()

    assert should_run_cisa_kev_monitor(db_session, config=config) is True

    run = create_collection_run(
        db_session,
        source_name="cisa-kev",
        trigger_type="scheduled",
        status="running",
    )
    db_session.commit()
    assert should_run_cisa_kev_monitor(db_session, config=config) is False

    complete_collection_run(db_session, run, status="completed")
    run.started_at = utcnow() - timedelta(seconds=3600)
    db_session.add(run)
    db_session.commit()
    assert should_run_cisa_kev_monitor(db_session, config=config) is False

    run.started_at = utcnow() - timedelta(seconds=86_401)
    db_session.add(run)
    db_session.commit()
    assert should_run_cisa_kev_monitor(db_session, config=config) is True


def test_celery_beat_schedules_cisa_kev_monitor() -> None:
    schedule = celery_app.conf.beat_schedule

    assert schedule["vulnflanker-cisa-kev-monitor"]["task"] == (
        "vulnflanker.collect_cisa_kev_monitor"
    )
    assert schedule["vulnflanker-enrichment-source-dispatcher"]["task"] == (
        "vulnflanker.dispatch_due_enrichment_sources"
    )
    assert schedule["vulnflanker-enrichment-reevaluation-dispatcher"]["task"] == (
        "vulnflanker.dispatch_pending_enrichment_reevaluations"
    )


def test_raw_event_normalize_endpoint_retries_pending_event(client, db_session) -> None:
    raw_event = IntelRawEvent(
        provider="watchvuln",
        event_type="watchvuln-vulninfo",
        external_key="watchvuln-retry",
        payload={
            "type": "watchvuln-vulninfo",
            "content": {
                "unique_key": "watchvuln-retry",
                "title": "Retryable advisory",
                "cve": "CVE-2026-1999",
                "tags": ["kev"],
            },
        },
        payload_hash="retry-hash",
        processing_status="pending",
    )
    db_session.add(raw_event)
    db_session.commit()

    response = client.post(f"/api/v1/intel/raw-events/{raw_event.id}/normalize")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "processed"
    assert payload["canonical_id"] == "CVE-2026-1999"

    detail_response = client.get(f"/api/v1/intel/raw-events/{raw_event.id}")
    assert detail_response.status_code == 200
    detail_payload = detail_response.json()
    assert detail_payload["processing_status"] == "processed"
    assert detail_payload["quality"]["has_canonical_id"] is True
    assert detail_payload["quality"]["has_exploitation_signal"] is True
    assert detail_payload["quality"]["needs_ai_enrichment"] is True
    assert {
        "missing_product",
        "missing_affected_versions",
        "missing_fixed_versions",
        "missing_references",
    }.issubset(set(detail_payload["quality"]["issue_codes"]))


def test_raw_event_quality_exposes_normalization_failure_reason(
    client,
    db_session,
) -> None:
    raw_event = IntelRawEvent(
        provider="cisa-kev",
        event_type="known-exploited-vulnerability",
        external_key="malformed-kev",
        payload="not-a-dict",
        payload_hash="malformed-kev-hash",
        processing_status="pending",
    )
    db_session.add(raw_event)
    db_session.commit()

    response = client.post(f"/api/v1/intel/raw-events/{raw_event.id}/normalize")

    assert response.status_code == 400
    assert "Normalization failed" in response.json()["detail"]

    db_session.expire_all()
    failed_event = db_session.get(IntelRawEvent, raw_event.id)
    assert failed_event is not None
    assert failed_event.processing_status == "failed"
    assert failed_event.last_error

    detail_response = client.get(f"/api/v1/intel/raw-events/{raw_event.id}")
    assert detail_response.status_code == 200
    detail_payload = detail_response.json()
    assert detail_payload["processing_status"] == "failed"
    assert detail_payload["last_error"] == failed_event.last_error
    assert detail_payload["quality"] is None


def test_normalization_auto_enqueues_ai_enrichment_when_enabled(
    client,
    db_session,
    monkeypatch,
) -> None:
    settings = get_platform_settings(db_session)
    settings.ai_auto_enrich_enabled = True
    settings.ai_allow_web_enrichment_default = True
    db_session.add(settings)
    db_session.commit()
    queued: list[tuple[str, str, str, bool]] = []

    def capture_delay(
        vulnerability_id: str,
        layer: str,
        profile_key: str,
        allow_web_enrichment: bool,
    ):
        queued.append((vulnerability_id, layer, profile_key, allow_web_enrichment))

    monkeypatch.setattr(ai_enrich_vulnerability, "delay", capture_delay)
    raw_event = IntelRawEvent(
        provider="watchvuln",
        event_type="watchvuln-vulninfo",
        external_key="watchvuln-auto-ai",
        payload={
            "type": "watchvuln-vulninfo",
            "content": {
                "unique_key": "watchvuln-auto-ai",
                "title": "Sparse auto AI advisory",
                "cve": "CVE-2026-AUTO-AI",
                "description": "Sparse advisory without product or version ranges.",
            },
        },
        payload_hash="auto-ai-hash",
        processing_status="pending",
    )
    db_session.add(raw_event)
    db_session.commit()

    response = client.post(f"/api/v1/intel/raw-events/{raw_event.id}/normalize")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "processed"
    assert queued == [
        (
            payload["vulnerability_id"],
            "auto",
            "basic_extraction_profile",
            True,
        )
    ]
