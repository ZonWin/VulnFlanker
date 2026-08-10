from __future__ import annotations

from app.db.models import MatchResult, VerificationTask
from app.services.intel_tracking import complete_collection_run, create_collection_run
from test_asset_ingestion import build_linux_snapshot
from test_matching_engine import create_vulnerability


def _create_risk_match_result(client, db_session, *, canonical_id: str) -> str:
    asset_response = client.post(
        "/api/v1/agents/snapshots",
        json=build_linux_snapshot(nginx_version="1.24.0"),
    )
    assert asset_response.status_code == 202
    vulnerability = create_vulnerability(
        db_session,
        canonical_id=canonical_id,
        fixed_versions="1.25.0",
    )
    response = client.post(
        "/api/v1/match-results/evaluate",
        json={"vulnerability_id": vulnerability.canonical_id},
    )
    assert response.status_code == 202
    result_ids = response.json()["sample_result_ids"]
    assert len(result_ids) == 1
    return result_ids[0]


def _create_verification_task(client, match_result_id: str) -> str:
    response = client.post(
        "/api/v1/verification-tasks",
        json={
            "match_result_id": match_result_id,
            "task_type": "package_version_check",
            "requested_by": "operator@example.test",
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


def _create_collection_run(db_session) -> str:
    run = create_collection_run(
        db_session,
        source_name="watchvuln",
        trigger_type="scheduled",
        status="running",
        parameters={"limit": 10},
    )
    db_session.commit()
    return run.id


def test_task_center_lists_verification_intel_and_risk_items(
    client,
    db_session,
) -> None:
    match_result_id = _create_risk_match_result(
        client,
        db_session,
        canonical_id="CVE-2026-TC001",
    )
    task_id = _create_verification_task(client, match_result_id)
    run_id = _create_collection_run(db_session)

    response = client.get("/api/v1/task-center/items")

    assert response.status_code == 200
    payload = response.json()
    item_ids = {item["id"] for item in payload}
    assert f"verification:{task_id}" in item_ids
    assert f"intel_collection:{run_id}" in item_ids
    assert f"risk_queue_item:{match_result_id}" in item_ids

    verification_item = next(item for item in payload if item["raw_id"] == task_id)
    assert verification_item["item_type"] == "verification"
    assert verification_item["status_group"] == "pending"
    assert verification_item["detail_path"] == f"/verification-tasks/{task_id}"
    assert "cancel" in verification_item["available_actions"]

    risk_item = next(item for item in payload if item["raw_id"] == match_result_id)
    assert risk_item["item_type"] == "risk_queue_item"
    assert risk_item["status_group"] == "attention"
    assert risk_item["vulnerability_id"] == "CVE-2026-TC001"
    assert "reevaluate" in risk_item["available_actions"]

    intel_item = next(item for item in payload if item["raw_id"] == run_id)
    assert intel_item["item_type"] == "intel_collection"
    assert intel_item["status_group"] == "running"
    assert intel_item["source"] == "watchvuln"
    assert intel_item["trigger_type"] == "scheduled"


def test_task_center_summary_counts_status_groups(client, db_session) -> None:
    match_result_id = _create_risk_match_result(
        client,
        db_session,
        canonical_id="CVE-2026-TC002",
    )
    task_id = _create_verification_task(client, match_result_id)
    task = db_session.get(VerificationTask, task_id)
    assert task is not None
    task.status = "failed"
    task.error_message = "agent timeout"
    db_session.add(task)

    run = create_collection_run(
        db_session,
        source_name="cisa-kev",
        trigger_type="manual",
        status="running",
    )
    complete_collection_run(
        db_session,
        run,
        fetched_count=1,
        stored_count=1,
        processed_count=1,
        status="completed",
    )
    db_session.commit()

    response = client.get("/api/v1/task-center/summary")

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] >= 3
    assert payload["failed"] >= 1
    assert payload["success"] >= 1
    assert payload["attention"] >= 1
    assert payload["by_type"]["verification"] >= 1
    assert payload["by_type"]["intel_collection"] >= 1
    assert payload["by_type"]["risk_queue_item"] >= 1


def test_task_center_filters_by_type_status_group_and_keyword(
    client,
    db_session,
) -> None:
    match_result_id = _create_risk_match_result(
        client,
        db_session,
        canonical_id="CVE-2026-TC003",
    )
    _create_verification_task(client, match_result_id)
    _create_collection_run(db_session)

    by_type = client.get(
        "/api/v1/task-center/items",
        params={"item_type": "risk_queue_item"},
    )
    assert by_type.status_code == 200
    assert by_type.json()
    assert {item["item_type"] for item in by_type.json()} == {"risk_queue_item"}

    by_group = client.get(
        "/api/v1/task-center/items",
        params={"status_group": "running"},
    )
    assert by_group.status_code == 200
    assert by_group.json()
    assert {item["status_group"] for item in by_group.json()} == {"running"}

    by_keyword = client.get(
        "/api/v1/task-center/items",
        params={"keyword": "TC003"},
    )
    assert by_keyword.status_code == 200
    assert any(item["raw_id"] == match_result_id for item in by_keyword.json())


def test_task_center_risk_item_tracks_status_after_reevaluation(
    client,
    db_session,
) -> None:
    match_result_id = _create_risk_match_result(
        client,
        db_session,
        canonical_id="CVE-2026-TC004",
    )
    match_result = db_session.get(MatchResult, match_result_id)
    assert match_result is not None
    assert match_result.status == "affected"

    response = client.get(
        "/api/v1/task-center/items",
        params={"status": "affected"},
    )

    assert response.status_code == 200
    rows = response.json()
    assert any(item["raw_id"] == match_result_id for item in rows)
