from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

from sqlalchemy import select

from app.db.base import utcnow
from app.db.models import (
    IntelCollectionRun,
    IntelSourceConfig,
    Vulnerability,
    VulnerabilitySourceContribution,
)
from app.services.intel_enrichment_orchestration import (
    dispatch_enrichment_reevaluation,
    due_enrichment_source_names,
    pending_enrichment_reevaluation_runs,
    reevaluate_enrichment_run,
    reserve_due_enrichment_sources,
    update_enrichment_source_config,
)
from app.services.intel_tracking import list_source_statuses


def test_generic_enrichment_source_config_api_and_freshness(client, db_session) -> None:
    response = client.patch(
        "/api/v1/intel/sources/nvd",
        json={
            "enabled": True,
            "schedule_seconds": 3600,
            "stale_after_seconds": 7200,
            "expire_after_seconds": 14400,
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["enabled"] is True
    assert payload["update_mode"] == "modified_window"
    assert payload["supports_cursor"] is True
    assert payload["freshness_state"] == "never_collected"
    assert payload["next_run_at"] is not None

    config = db_session.scalar(
        select(IntelSourceConfig).where(IntelSourceConfig.source_name == "nvd")
    )
    assert config is not None
    config.last_success_at = utcnow() - timedelta(seconds=8000)
    db_session.add(config)
    db_session.commit()
    source = next(item for item in list_source_statuses(db_session) if item.source_name == "nvd")
    assert source.freshness_state == "stale"
    assert source.freshness_age_seconds is not None


def test_generic_enrichment_config_rejects_expire_before_stale(client) -> None:
    response = client.patch(
        "/api/v1/intel/sources/nvd",
        json={"stale_after_seconds": 7200, "expire_after_seconds": 3600},
    )
    assert response.status_code == 400
    assert "greater" in response.json()["detail"]


def test_generic_collection_api_queues_registered_source(client, monkeypatch) -> None:
    captured: list[tuple] = []

    def delay(*args):
        captured.append(args)
        return SimpleNamespace(id="enrichment-task-1")

    monkeypatch.setattr(
        "app.api.routes.intel.collect_enrichment_source_task.delay",
        delay,
    )
    response = client.post(
        "/api/v1/intel/sources/redhat-csaf/collect",
        json={"async_mode": True, "force_baseline": True},
    )

    assert response.status_code == 200
    assert response.json()["task_id"] == "enrichment-task-1"
    assert captured == [("redhat-csaf", "manual", None, True)]
    assert client.post(
        "/api/v1/intel/sources/nvd/collect",
        json={"async_mode": True, "force_baseline": True},
    ).status_code == 400
    assert client.post(
        "/api/v1/intel/sources/not-a-source/collect",
        json={},
    ).status_code == 404


def test_due_source_reservation_skips_active_run_and_prevents_repeat(db_session) -> None:
    now = utcnow()
    nvd = update_enrichment_source_config(
        db_session,
        "nvd",
        enabled=True,
        schedule_seconds=3600,
    )
    nvd.last_attempt_at = now - timedelta(seconds=3601)
    canonical = update_enrichment_source_config(
        db_session,
        "canonical-ubuntu",
        enabled=True,
        schedule_seconds=3600,
    )
    canonical.last_attempt_at = now - timedelta(seconds=3601)
    db_session.add_all(
        (
            nvd,
            canonical,
            IntelCollectionRun(
                source_name="canonical-ubuntu",
                trigger_type="scheduled",
                status="staging",
            ),
        )
    )
    db_session.commit()

    assert due_enrichment_source_names(db_session, now=now) == ["nvd"]
    assert reserve_due_enrichment_sources(db_session, now=now) == ["nvd"]
    assert due_enrichment_source_names(db_session, now=now) == []


def test_generation_reevaluation_batches_only_contributed_vulnerabilities(
    db_session,
    monkeypatch,
) -> None:
    run = IntelCollectionRun(
        id="run-enrichment",
        source_name="nvd",
        trigger_type="manual",
        status="activated",
        generation_id="generation-enrichment",
        completeness_json={"complete": True},
    )
    vulnerabilities = [
        Vulnerability(id="vuln-a", canonical_id="CVE-2026-9700", title="A"),
        Vulnerability(id="vuln-b", canonical_id="CVE-2026-9701", title="B"),
        Vulnerability(id="vuln-unrelated", canonical_id="CVE-2026-9702", title="C"),
    ]
    contributions = [
        VulnerabilitySourceContribution(
            vulnerability_id=vulnerability_id,
            source_name="nvd",
            generation_id="generation-enrichment",
            external_key=cve_id,
            contribution_json={},
            provenance_json={},
            fact_fingerprint=f"fingerprint-{vulnerability_id}",
            is_active=True,
        )
        for vulnerability_id, cve_id in (
            ("vuln-a", "CVE-2026-9700"),
            ("vuln-b", "CVE-2026-9701"),
        )
    ]
    db_session.add_all([run, *vulnerabilities, *contributions])
    db_session.commit()
    evaluated: list[str] = []

    def fake_evaluate(_db, *, vulnerability_id, **_kwargs):
        evaluated.append(vulnerability_id)
        return []

    monkeypatch.setattr(
        "app.services.intel_enrichment_orchestration.evaluate_matches",
        fake_evaluate,
    )
    first = reevaluate_enrichment_run(db_session, run.id, batch_size=1)
    second = reevaluate_enrichment_run(
        db_session,
        run.id,
        after_vulnerability_id=first.next_cursor,
        batch_size=1,
    )

    assert first.next_cursor == "vuln-a"
    assert second.next_cursor is None
    assert evaluated == ["vuln-a", "vuln-b"]
    db_session.refresh(run)
    assert run.completeness_json["reevaluation"]["status"] == "completed"
    assert run.completeness_json["reevaluation"]["processed_count"] == 2


def test_reevaluation_dispatch_is_observable_without_changing_run_status(
    db_session,
    monkeypatch,
) -> None:
    run = IntelCollectionRun(
        source_name="nvd",
        trigger_type="manual",
        status="activated",
        generation_id="generation-dispatch",
        completeness_json={"complete": True},
    )
    db_session.add(run)
    db_session.commit()
    monkeypatch.setattr(
        "app.workers.tasks.reevaluate_enrichment_run_task.delay",
        lambda *_args: SimpleNamespace(id="reevaluation-task-1"),
    )

    task_id = dispatch_enrichment_reevaluation(db_session, run)

    assert task_id == "reevaluation-task-1"
    assert run.status == "activated"
    assert run.completeness_json["reevaluation"] == {
        "status": "queued",
        "task_id": "reevaluation-task-1",
        "processed_count": 0,
        "failed_count": 0,
    }


def test_failed_reevaluation_dispatch_is_discovered_for_retry(db_session) -> None:
    run = IntelCollectionRun(
        source_name="nvd",
        trigger_type="manual",
        status="activated",
        generation_id="generation-retry",
        activated_at=utcnow(),
        completeness_json={
            "complete": True,
            "reevaluation": {"status": "dispatch_failed", "error": "broker down"},
        },
    )
    completed = IntelCollectionRun(
        source_name="nvd",
        trigger_type="manual",
        status="activated",
        generation_id="generation-complete",
        activated_at=utcnow() - timedelta(seconds=1),
        completeness_json={
            "complete": True,
            "reevaluation": {"status": "completed"},
        },
    )
    db_session.add_all((run, completed))
    db_session.commit()

    assert [item.id for item in pending_enrichment_reevaluation_runs(db_session)] == [
        run.id
    ]


def test_collection_run_api_exposes_generation_observability(client, db_session) -> None:
    run = IntelCollectionRun(
        source_name="nvd",
        trigger_type="manual",
        status="activated",
        generation_id="generation-visible",
        update_mode="modified_window",
        cursor_before_json={"last_modified": "before"},
        cursor_after_json={"last_modified": "after"},
        completeness_json={"complete": True},
        parser_version="nvd-api-2.0-v1",
        artifacts_count=1,
        activated_at=utcnow(),
    )
    db_session.add(run)
    db_session.commit()

    response = client.get(f"/api/v1/intel/runs/{run.id}")
    assert response.status_code == 200
    payload = response.json()
    assert payload["generation_id"] == "generation-visible"
    assert payload["cursor_after"] == {"last_modified": "after"}
    assert payload["completeness"] == {"complete": True}
    assert payload["parser_version"] == "nvd-api-2.0-v1"
