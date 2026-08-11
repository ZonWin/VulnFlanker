from __future__ import annotations

from dataclasses import dataclass

import pytest
from sqlalchemy import select

from app.connectors.base import (
    CollectorMetadata,
    CollectorPage,
    CollectorUpdateMode,
    RawIntelRecord,
    VulnerabilitySourceConnector,
)
from app.connectors.registry import CollectorRegistry
from app.db.base import utcnow
from app.db.models import (
    IntelCollectionRun,
    IntelRawEvent,
    IntelSourceConfig,
    Vulnerability,
    VulnerabilitySourceContribution,
)
from app.services.intel_authority import merge_contribution_documents
from app.services.intel_generations import (
    IncompleteGenerationError,
    activate_generation,
    begin_generation,
    collect_generation,
    compute_fact_fingerprint,
    mark_generation_ready,
    stage_collector_page,
    upsert_source_contribution,
)


class StaticCollector(VulnerabilitySourceConnector):
    source_name = "test-source"

    def __init__(self, pages: list[CollectorPage] | None = None) -> None:
        self.pages = pages or []

    @property
    def metadata(self) -> CollectorMetadata:
        return CollectorMetadata(
            source_name=self.source_name,
            display_name="Test Source",
            update_mode=CollectorUpdateMode.DELTA,
            parser_version="fixture-1",
            supports_cursor=True,
        )

    def fetch(self, **kwargs) -> list[RawIntelRecord]:
        return [record for page in self.pages for record in page.records]

    def fetch_pages(self, **kwargs):
        yield from self.pages


def _record(external_id: str, value: str = "one") -> RawIntelRecord:
    return RawIntelRecord(
        source_name="test-source",
        external_id=external_id,
        title=external_id,
        payload={"id": external_id, "value": value},
        fetched_at=utcnow(),
    )


def test_legacy_connector_adapter_emits_one_complete_page() -> None:
    collector = StaticCollector()
    collector.fetch_pages = VulnerabilitySourceConnector.fetch_pages.__get__(collector)
    collector.pages = [
        CollectorPage(records=[_record("CVE-2026-1")], page_key="ignored")
    ]

    pages = list(collector.fetch_pages())

    assert len(pages) == 1
    assert pages[0].page_key == "legacy:1"
    assert pages[0].complete is True
    assert pages[0].metadata == {"adapter": "legacy-list"}


def test_collector_registry_rejects_duplicate_source_names() -> None:
    registry = CollectorRegistry()
    registry.register(StaticCollector())

    with pytest.raises(ValueError, match="already registered"):
        registry.register(StaticCollector())

    assert registry.get("test-source").metadata.display_name == "Test Source"
    with pytest.raises(KeyError, match="unknown vulnerability source"):
        registry.get("missing")


def test_generation_activation_is_atomic_and_switches_source_contributions(
    db_session,
) -> None:
    vulnerability = Vulnerability(canonical_id="CVE-2026-9001", title="Generation test")
    db_session.add(vulnerability)
    db_session.flush()
    collector = StaticCollector()

    first_run = begin_generation(db_session, collector)
    stage_collector_page(
        db_session,
        first_run,
        CollectorPage(
            records=[_record("CVE-2026-9001", "old")],
            page_key="1",
            next_cursor={"sequence": 1},
            complete=True,
        ),
    )
    upsert_source_contribution(
        db_session,
        run=first_run,
        vulnerability_id=vulnerability.id,
        external_key="CVE-2026-9001",
        contribution={"description": "old"},
    )
    mark_generation_ready(db_session, first_run)
    activate_generation(db_session, first_run)
    db_session.commit()

    config = db_session.scalar(
        select(IntelSourceConfig).where(IntelSourceConfig.source_name == "test-source")
    )
    first_contribution = db_session.scalar(
        select(VulnerabilitySourceContribution).where(
            VulnerabilitySourceContribution.generation_id == first_run.generation_id
        )
    )
    assert config is not None
    assert config.active_generation_id == first_run.generation_id
    assert config.cursor_json == {"sequence": 1}
    assert first_contribution is not None and first_contribution.is_active is True

    second_run = begin_generation(db_session, collector)
    stage_collector_page(
        db_session,
        second_run,
        CollectorPage(
            records=[_record("CVE-2026-9001", "new")],
            page_key="2",
            next_cursor={"sequence": 2},
            complete=True,
        ),
    )
    upsert_source_contribution(
        db_session,
        run=second_run,
        vulnerability_id=vulnerability.id,
        external_key="CVE-2026-9001",
        contribution={"description": "new"},
    )
    mark_generation_ready(db_session, second_run)
    activate_generation(db_session, second_run)
    db_session.commit()
    db_session.expire_all()

    config = db_session.scalar(
        select(IntelSourceConfig).where(IntelSourceConfig.source_name == "test-source")
    )
    contributions = db_session.scalars(
        select(VulnerabilitySourceContribution).order_by(
            VulnerabilitySourceContribution.created_at
        )
    ).all()
    old_run = db_session.get(IntelCollectionRun, first_run.id)
    new_run = db_session.get(IntelCollectionRun, second_run.id)
    assert config is not None
    assert config.active_generation_id == second_run.generation_id
    assert config.cursor_json == {"sequence": 2}
    assert [row.is_active for row in contributions] == [False, True]
    assert old_run is not None and old_run.status == "superseded"
    assert new_run is not None and new_run.status == "activated"


def test_incomplete_refresh_keeps_last_active_generation(db_session) -> None:
    complete_collector = StaticCollector(
        [
            CollectorPage(
                records=[_record("CVE-2026-9002")],
                page_key="complete",
                next_cursor={"sequence": 1},
                complete=True,
            )
        ]
    )
    active_run = collect_generation(db_session, complete_collector)

    incomplete_collector = StaticCollector(
        [
            CollectorPage(
                records=[_record("CVE-2026-9003")],
                page_key="partial",
                next_cursor={"sequence": 2},
                complete=False,
            )
        ]
    )
    with pytest.raises(IncompleteGenerationError):
        collect_generation(db_session, incomplete_collector)

    db_session.expire_all()
    config = db_session.scalar(
        select(IntelSourceConfig).where(IntelSourceConfig.source_name == "test-source")
    )
    failed_run = db_session.scalar(
        select(IntelCollectionRun)
        .where(IntelCollectionRun.status == "failed")
        .order_by(IntelCollectionRun.started_at.desc())
    )
    assert config is not None
    assert config.active_generation_id == active_run.generation_id
    assert config.cursor_json == {"sequence": 1}
    assert failed_run is not None
    assert failed_run.error_code == "collection_failed"
    assert "complete terminal page" in (failed_run.error_message or "")


def test_delta_activation_only_replaces_changed_vulnerabilities(db_session) -> None:
    first = Vulnerability(canonical_id="CVE-2026-9010", title="First")
    second = Vulnerability(canonical_id="CVE-2026-9011", title="Second")
    db_session.add_all((first, second))
    db_session.flush()
    collector = StaticCollector()

    baseline = begin_generation(db_session, collector)
    for vulnerability in (first, second):
        upsert_source_contribution(
            db_session,
            run=baseline,
            vulnerability_id=vulnerability.id,
            external_key=vulnerability.canonical_id,
            contribution={"description": f"old-{vulnerability.canonical_id}"},
        )
    baseline.completeness_json = {"complete": True, "terminal_page_seen": True}
    mark_generation_ready(db_session, baseline)
    activate_generation(db_session, baseline)
    db_session.commit()

    delta = begin_generation(db_session, collector)
    upsert_source_contribution(
        db_session,
        run=delta,
        vulnerability_id=first.id,
        external_key=first.canonical_id,
        contribution={"description": "new-first"},
    )
    delta.completeness_json = {"complete": True, "terminal_page_seen": True}
    mark_generation_ready(db_session, delta)
    activate_generation(db_session, delta)
    db_session.commit()
    db_session.expire_all()

    active = db_session.scalars(
        select(VulnerabilitySourceContribution)
        .where(VulnerabilitySourceContribution.is_active.is_(True))
        .order_by(VulnerabilitySourceContribution.vulnerability_id)
    ).all()
    assert len(active) == 2
    active_by_vulnerability = {row.vulnerability_id: row for row in active}
    assert active_by_vulnerability[first.id].generation_id == delta.generation_id
    assert active_by_vulnerability[second.id].generation_id == baseline.generation_id


@dataclass
class ContributionFixture:
    source_name: str
    generation_id: str
    external_key: str
    contribution_json: dict
    provenance_json: dict
    is_active: bool = True


def test_field_authority_merge_preserves_conflicts_and_source_boundaries() -> None:
    merged = merge_contribution_documents(
        [
            ContributionFixture(
                source_name="cve-list-v5",
                generation_id="cve-1",
                external_key="CVE-2026-9004",
                contribution_json={
                    "description": "CNA description",
                    "title": "CNA title",
                },
                provenance_json={"container": "cna"},
            ),
            ContributionFixture(
                source_name="nvd",
                generation_id="nvd-1",
                external_key="CVE-2026-9004",
                contribution_json={
                    "description": "NVD description",
                    "nvd_metrics": {"baseScore": 8.8},
                },
                provenance_json={"path": "metrics.cvssMetricV31"},
            ),
            ContributionFixture(
                source_name="cisa-kev",
                generation_id="kev-1",
                external_key="CVE-2026-9004",
                contribution_json={
                    "title": "KEV must not replace title",
                    "known_exploited": True,
                },
                provenance_json={"catalog": "kev"},
            ),
        ]
    )

    assert merged["description"].value == "CNA description"
    assert merged["description"].source_name == "cve-list-v5"
    assert merged["description"].has_conflict is True
    assert merged["title"].value == "CNA title"
    assert len(merged["title"].candidates) == 1
    assert merged["known_exploited"].value is True
    assert merged["nvd_metrics"].value == {"baseScore": 8.8}


def test_fact_fingerprint_ignores_mapping_order() -> None:
    assert compute_fact_fingerprint({"b": 2, "a": [1, 2]}) == compute_fact_fingerprint(
        {"a": [1, 2], "b": 2}
    )


def test_staging_same_record_is_idempotent_within_generation(db_session) -> None:
    collector = StaticCollector()
    run = begin_generation(db_session, collector)
    page = CollectorPage(
        records=[_record("CVE-2026-9005")],
        page_key="same",
        complete=True,
    )

    assert stage_collector_page(db_session, run, page) == (1, 1)
    assert stage_collector_page(db_session, run, page) == (1, 0)
    assert db_session.scalars(
        select(IntelRawEvent).where(IntelRawEvent.generation_id == run.generation_id)
    ).all().__len__() == 1
