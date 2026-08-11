from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.connectors.cve_list_v5 import (
    CveDeltaCursorExpired,
    CveListV5Connector,
    safe_cve_zip_members,
    select_cve_baseline_asset,
    select_cve_delta_changes,
)
from app.connectors.http_client import SourceDownloadError
from app.connectors.nvd import NvdCveConnector, nvd_modified_window, parse_nvd_page
from app.db.base import utcnow
from app.db.models import (
    IntelSourceConfig,
    Vulnerability,
    VulnerabilityAffectedScope,
    VulnerabilitySource,
    VulnerabilitySourceContribution,
)
from app.services.cve_list_normalization import CveListV5Mapper
from app.services.intel_source_collection import collect_enrichment_source
from app.services.nvd_normalization import NvdCveMapper


def _cve_record(cve_id: str = "CVE-2026-9100") -> dict:
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.2",
        "cveMetadata": {
            "cveId": cve_id,
            "state": "PUBLISHED",
            "datePublished": "2026-08-01T00:00:00Z",
            "dateUpdated": "2026-08-02T00:00:00Z",
        },
        "containers": {
            "cna": {
                "providerMetadata": {"shortName": "ACME"},
                "title": "Acme Widget remote code execution",
                "descriptions": [{"lang": "en", "value": "CNA description"}],
                "affected": [
                    {
                        "vendor": "Acme",
                        "product": "Widget",
                        "packageURL": "pkg:pypi/acme-widget",
                        "defaultStatus": "unaffected",
                        "platforms": ["Linux"],
                        "versions": [
                            {
                                "version": "1.0.0",
                                "lessThan": "2.0.0",
                                "status": "affected",
                                "versionType": "semver",
                            }
                        ],
                    }
                ],
                "metrics": [
                    {
                        "cvssV3_1": {
                            "version": "3.1",
                            "baseScore": 7.5,
                            "baseSeverity": "HIGH",
                        }
                    }
                ],
                "references": [
                    {"url": "https://vendor.example/advisory", "tags": ["vendor-advisory"]}
                ],
            },
            "adp": [
                {
                    "providerMetadata": {"shortName": "CVE"},
                    "title": "CVE Program Container",
                    "references": [
                        {"url": "https://vendor.example/advisory", "tags": ["x_transferred"]},
                        {"url": "https://cve.example/program-reference"},
                    ],
                }
            ],
        },
    }


def _nvd_cve(cve_id: str = "CVE-2026-9100") -> dict:
    return {
        "id": cve_id,
        "sourceIdentifier": "nvd@nist.gov",
        "published": "2026-08-01T00:00:00.000",
        "lastModified": "2026-08-03T00:00:00.000",
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": "NVD analysis description"}],
        "metrics": {
            "cvssMetricV31": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                    },
                }
            ]
        },
        "weaknesses": [
            {"description": [{"lang": "en", "value": "CWE-78"}]}
        ],
        "references": [{"url": "https://nvd.example/reference"}],
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "negate": False,
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "1.0.0",
                                "versionEndExcluding": "2.0.0",
                                "matchCriteriaId": "OR-MATCH",
                            }
                        ],
                    },
                    {
                        "operator": "AND",
                        "negate": False,
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:acme:conditional_widget:*:*:*:*:*:*:*:*",
                                "matchCriteriaId": "AND-MATCH",
                            },
                            {
                                "vulnerable": False,
                                "criteria": "cpe:2.3:o:acme:widget_os:*:*:*:*:*:*:*:*",
                            },
                        ],
                    },
                ]
            }
        ],
    }


def _baseline_zip(*records: dict) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for record in records:
            cve_id = record["cveMetadata"]["cveId"]
            archive.writestr(
                f"cvelistV5-main/cves/2026/9xxx/{cve_id}.json",
                json.dumps(record),
            )
        archive.writestr("cvelistV5-main/cves/delta.json", "{}")
    return output.getvalue()


def test_cve_release_selects_daily_baseline() -> None:
    url, name = select_cve_baseline_asset(
        {
            "assets": [
                {
                    "name": "2026-08-11_delta_CVEs_at_0100Z.zip",
                    "browser_download_url": "https://example.invalid/delta.zip",
                },
                {
                    "name": "2026-08-11_all_CVEs_at_midnight.zip",
                    "browser_download_url": "https://github.com/baseline.zip",
                },
            ]
        }
    )

    assert name == "2026-08-11_all_CVEs_at_midnight.zip"
    assert url == "https://github.com/baseline.zip"


def test_cve_delta_deduplicates_latest_change_and_detects_cursor_gap() -> None:
    delta = [
        {
            "fetchTime": "2026-08-10T00:00:00.000Z",
            "new": [
                {
                    "cveId": "CVE-2026-1",
                    "githubLink": "https://raw.githubusercontent.com/old.json",
                    "dateUpdated": "2026-08-10T00:00:00.000Z",
                }
            ],
            "updated": [],
        },
        {
            "fetchTime": "2026-08-11T00:00:00.000Z",
            "new": [],
            "updated": [
                {
                    "cveId": "CVE-2026-1",
                    "githubLink": "https://raw.githubusercontent.com/new.json",
                    "dateUpdated": "2026-08-11T00:00:00.000Z",
                }
            ],
        },
    ]

    changes, latest = select_cve_delta_changes(
        delta,
        since="2026-08-10T00:00:00.000Z",
    )

    assert latest == "2026-08-11T00:00:00.000Z"
    assert changes == [
        {
            "cveId": "CVE-2026-1",
            "githubLink": "https://raw.githubusercontent.com/new.json",
            "dateUpdated": "2026-08-11T00:00:00.000Z",
        }
    ]
    with pytest.raises(CveDeltaCursorExpired):
        select_cve_delta_changes(delta, since="2026-08-09T23:59:59.000Z")


def test_cve_zip_rejects_path_traversal() -> None:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("../CVE-2026-1.json", "{}")
    payload.seek(0)
    with zipfile.ZipFile(payload) as archive:
        with pytest.raises(SourceDownloadError, match="unsafe archive path"):
            safe_cve_zip_members(archive)


def test_cve_mapper_handles_cna_adp_purl_and_reference_provenance() -> None:
    record_payload = _cve_record()
    record = next(
        iter(
            CveListV5Connector(
                get_json=lambda *_args, **_kwargs: {
                    "assets": [
                        {
                            "name": "2026-08-11_all_CVEs_at_midnight.zip",
                            "browser_download_url": "https://github.com/baseline.zip",
                        }
                    ]
                },
                download_artifact=lambda _url: (
                    io.BytesIO(_baseline_zip(record_payload)),
                    "artifact-hash",
                ),
            ).fetch_pages()
        )
    ).records[0]

    normalized = CveListV5Mapper().map_record(record)

    assert normalized.canonical_id == "CVE-2026-9100"
    assert normalized.contribution["cve_state"] == "published"
    assert normalized.contribution["products"][0]["purl"] == "pkg:pypi/acme-widget"
    assert normalized.references == [
        "https://vendor.example/advisory",
        "https://cve.example/program-reference",
    ]
    assert len(normalized.provenance["reference_provenance"]) == 3
    assert normalized.scopes[0].affected_versions == ">= 1.0.0, < 2.0.0"


def test_nvd_window_enforces_official_120_day_limit() -> None:
    end = datetime(2026, 8, 11, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="120 days"):
        nvd_modified_window(
            cursor=None,
            start=end - timedelta(days=121),
            end=end,
            overlap_seconds=300,
        )

    start, cursor_end = nvd_modified_window(
        cursor={"last_modified": "2026-08-10T00:00:00+00:00"},
        start=None,
        end=end,
        overlap_seconds=300,
    )
    assert start == datetime(2026, 8, 9, 23, 55, tzinfo=timezone.utc)
    assert cursor_end == end


def test_nvd_page_parser_rejects_invalid_pagination() -> None:
    with pytest.raises(SourceDownloadError, match="pagination metadata"):
        parse_nvd_page({"vulnerabilities": []}, fetched_at=utcnow())


def test_nvd_mapper_preserves_logic_tree_and_skips_and_scope() -> None:
    payload = _nvd_cve()
    record = parse_nvd_page(
        {
            "resultsPerPage": 2000,
            "startIndex": 0,
            "totalResults": 1,
            "vulnerabilities": [{"cve": payload}],
        },
        fetched_at=utcnow(),
    )[0][0]

    normalized = NvdCveMapper().map_record(record)

    assert normalized.contribution["weaknesses"] == ["CWE-78"]
    assert normalized.contribution["cpe_configurations"] == payload["configurations"]
    assert len(normalized.scopes) == 1
    assert normalized.scopes[0].product == "widget"
    assert normalized.scopes[0].affected_versions == ">= 1.0.0, < 2.0.0"
    assert normalized.scopes[0].provenance["match_criteria_id"] == "OR-MATCH"


def test_cve_and_nvd_collect_independently_of_kev_and_merge_by_field(db_session) -> None:
    cve_payload = _cve_record()
    archive_bytes = _baseline_zip(cve_payload)
    release = {
        "assets": [
            {
                "name": "2026-08-11_all_CVEs_at_midnight.zip",
                "browser_download_url": "https://github.com/baseline.zip",
            }
        ]
    }
    cve_connector = CveListV5Connector(
        page_size=10,
        get_json=lambda *_args, **_kwargs: release,
        download_artifact=lambda _url: (io.BytesIO(archive_bytes), "baseline-hash"),
    )

    cve_run = collect_enrichment_source(
        db_session,
        connector=cve_connector,
        mapper=CveListV5Mapper(),
    )

    vulnerability = db_session.scalar(
        select(Vulnerability).where(Vulnerability.canonical_id == "CVE-2026-9100")
    )
    assert cve_run.status == "activated"
    assert cve_run.update_mode == "snapshot"
    assert vulnerability is not None
    assert vulnerability.title == "Acme Widget remote code execution"
    assert vulnerability.product == "Widget"
    assert vulnerability.kev_status is False
    assert vulnerability.affected_scopes[0].purl == "pkg:pypi/acme-widget"

    nvd_payload = {
        "resultsPerPage": 2000,
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [{"cve": _nvd_cve()}],
    }
    requests: list[dict] = []

    def nvd_get_json(_url, *, params, headers):
        requests.append({"params": params, "headers": headers})
        return nvd_payload

    nvd_connector = NvdCveConnector(get_json=nvd_get_json)
    nvd_run = collect_enrichment_source(
        db_session,
        connector=nvd_connector,
        mapper=NvdCveMapper(),
        start="2026-08-01T00:00:00Z",
        end="2026-08-04T00:00:00Z",
    )
    db_session.expire_all()
    vulnerability = db_session.scalar(
        select(Vulnerability).where(Vulnerability.canonical_id == "CVE-2026-9100")
    )

    assert nvd_run.status == "activated"
    assert nvd_run.update_mode == "modified_window"
    assert requests[0]["params"]["resultsPerPage"] == 2000
    assert vulnerability is not None
    assert vulnerability.description == "CNA description"
    assert vulnerability.severity_cvss == 9.8
    assert vulnerability.severity_label == "critical"
    assert len(vulnerability.affected_scopes) == 2

    contributions = db_session.scalars(
        select(VulnerabilitySourceContribution).where(
            VulnerabilitySourceContribution.vulnerability_id == vulnerability.id,
            VulnerabilitySourceContribution.is_active.is_(True),
        )
    ).all()
    assert {row.source_name for row in contributions} == {"cve-list-v5", "nvd"}
    assert db_session.scalar(
        select(VulnerabilitySource).where(
            VulnerabilitySource.source_name == "cve-list-v5",
            VulnerabilitySource.external_id == "CVE-2026-9100",
        )
    ) is not None
    assert db_session.scalar(
        select(IntelSourceConfig).where(IntelSourceConfig.source_name == "nvd")
    ).cursor_json == {"last_modified": "2026-08-04T00:00:00+00:00"}


def test_nvd_limit_does_not_activate_partial_window(db_session) -> None:
    payload = {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 2,
        "vulnerabilities": [{"cve": _nvd_cve("CVE-2026-9200")}],
    }
    connector = NvdCveConnector(page_size=1, get_json=lambda *_args, **_kwargs: payload)

    with pytest.raises(Exception, match="complete terminal page"):
        collect_enrichment_source(
            db_session,
            connector=connector,
            mapper=NvdCveMapper(),
            start="2026-08-01T00:00:00Z",
            end="2026-08-04T00:00:00Z",
            limit=1,
        )

    config = db_session.scalar(
        select(IntelSourceConfig).where(IntelSourceConfig.source_name == "nvd")
    )
    assert config is not None
    assert config.active_generation_id is None
    assert config.cursor_json == {}
    assert db_session.scalars(
        select(VulnerabilityAffectedScope).where(
            VulnerabilityAffectedScope.source_name == "nvd",
            VulnerabilityAffectedScope.is_active.is_(True),
        )
    ).all() == []
