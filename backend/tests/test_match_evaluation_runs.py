from __future__ import annotations

from sqlalchemy import func, select

from app.api.routes import match_results as match_results_routes
from app.core.config import Settings
from app.core.deployment import deployment_profile
from app.db.models import (
    Asset,
    AssetComponent,
    MatchEvaluationRun,
    MatchEvidence,
    MatchResult,
)
from app.services import matching
from test_matching_engine import create_vulnerability


def _seed_match_pair(db_session):
    asset = Asset(
        agent_id="match-evaluation-agent",
        hostname="match-evaluation-host",
        platform="linux",
        os_family="ubuntu",
        criticality="high",
    )
    db_session.add(asset)
    db_session.flush()
    db_session.add(
        AssetComponent(
            asset_id=asset.id,
            component_name="nginx",
            component_type="package",
            version="1.24.0",
            source_type="dpkg",
        )
    )
    vulnerability = create_vulnerability(
        db_session,
        canonical_id="CVE-2026-MATCH-RUN",
        fixed_versions="1.25.0",
    )
    db_session.commit()
    return asset, vulnerability


def test_match_evaluation_api_persists_progress_and_preserves_evidence(
    client,
    db_session,
) -> None:
    asset, vulnerability = _seed_match_pair(db_session)
    request = {
        "asset_id": asset.id,
        "vulnerability_id": vulnerability.canonical_id,
    }

    first_response = client.post("/api/v1/match-results/evaluate", json=request)

    assert first_response.status_code == 202
    first = first_response.json()
    assert first["status"] == "completed"
    assert first["total_count"] == 1
    assert first["processed_count"] == 1
    assert first["evaluated_count"] == 1
    assert first["skipped_count"] == 0
    assert first["failed_count"] == 0
    assert len(first["sample_result_ids"]) == 1
    assert first["processed_count"] == (
        first["evaluated_count"] + first["skipped_count"] + first["failed_count"]
    )

    run_response = client.get(
        f"/api/v1/match-results/evaluations/{first['run_id']}"
    )
    assert run_response.status_code == 200
    assert run_response.json()["run_id"] == first["run_id"]

    result_id = first["sample_result_ids"][0]
    evidence_ids = set(
        db_session.scalars(
            select(MatchEvidence.id).where(MatchEvidence.match_result_id == result_id)
        ).all()
    )
    assert evidence_ids

    second_response = client.post("/api/v1/match-results/evaluate", json=request)
    assert second_response.status_code == 202
    assert second_response.json()["status"] == "completed"
    assert set(
        db_session.scalars(
            select(MatchEvidence.id).where(MatchEvidence.match_result_id == result_id)
        ).all()
    ) == evidence_ids
    assert db_session.scalar(select(func.count(MatchResult.id))) == 1

    task_items = client.get(
        "/api/v1/task-center/items",
        params={"item_type": "match_evaluation"},
    )
    assert task_items.status_code == 200
    assert len(task_items.json()) == 2
    assert task_items.json()[0]["metrics"]["processed_count"] == 1


def test_duplicate_active_full_evaluation_reuses_one_run(
    client,
    db_session,
    monkeypatch,
) -> None:
    class QueuedTask:
        id = "queued-task"

    monkeypatch.setattr(
        match_results_routes.run_match_evaluation_task,
        "delay",
        lambda _run_id: QueuedTask(),
    )

    first_response = client.post("/api/v1/match-results/evaluate", json={})
    second_response = client.post("/api/v1/match-results/evaluate", json={})

    assert first_response.status_code == 202
    assert second_response.status_code == 202
    assert first_response.json()["run_id"] == second_response.json()["run_id"]
    assert first_response.json()["status"] == "queued"
    assert db_session.scalar(select(func.count(MatchEvaluationRun.id))) == 1


def test_large_scale_switch_only_changes_api_process_counts() -> None:
    standard = deployment_profile(Settings(_env_file=None, large_scale_mode=False))
    large = deployment_profile(Settings(_env_file=None, large_scale_mode=True))

    assert standard.console_api_workers == 1
    assert standard.agent_api_workers == 1
    assert large.console_api_workers > standard.console_api_workers
    assert large.agent_api_workers > standard.agent_api_workers
    assert large.db_pool_size == standard.db_pool_size
    assert large.db_max_overflow == standard.db_max_overflow
    assert large.matching_batch_size == standard.matching_batch_size


def test_standard_mode_caches_settings_and_bulk_loads_existing_results(
    client,
    db_session,
    monkeypatch,
) -> None:
    _, vulnerability = _seed_match_pair(db_session)
    second_asset = Asset(
        agent_id="match-evaluation-agent-2",
        hostname="match-evaluation-host-2",
        platform="linux",
        os_family="ubuntu",
    )
    db_session.add(second_asset)
    db_session.flush()
    db_session.add(
        AssetComponent(
            asset_id=second_asset.id,
            component_name="nginx",
            component_type="package",
            version="1.24.0",
        )
    )
    db_session.commit()

    settings_calls = 0
    bulk_load_calls = 0
    original_get_platform_settings = matching.get_platform_settings
    original_bulk_load = matching._load_existing_match_results

    def counted_get_platform_settings(db):
        nonlocal settings_calls
        settings_calls += 1
        return original_get_platform_settings(db)

    def counted_bulk_load(db, pairs):
        nonlocal bulk_load_calls
        bulk_load_calls += 1
        return original_bulk_load(db, pairs)

    monkeypatch.setattr(matching, "get_platform_settings", counted_get_platform_settings)
    monkeypatch.setattr(matching, "_load_existing_match_results", counted_bulk_load)

    response = client.post(
        "/api/v1/match-results/evaluate",
        json={"vulnerability_id": vulnerability.canonical_id},
    )

    assert response.status_code == 202
    assert response.json()["evaluated_count"] == 2
    assert settings_calls == 1
    assert bulk_load_calls == 1
