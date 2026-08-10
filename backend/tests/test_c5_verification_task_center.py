from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select

from app.db.base import utcnow
from app.db.models import VerificationTask
from test_asset_ingestion import build_linux_snapshot
from test_matching_engine import create_vulnerability


def _create_match_result(client, db_session, *, canonical_id: str) -> str:
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
    evaluate_response = client.post(
        "/api/v1/match-results/evaluate",
        json={"vulnerability_id": vulnerability.canonical_id},
    )
    assert evaluate_response.status_code == 202
    result_ids = evaluate_response.json()["sample_result_ids"]
    assert len(result_ids) == 1
    return result_ids[0]


def _create_task(client, match_result_id: str) -> dict:
    response = client.post(
        "/api/v1/verification-tasks",
        json={
            "match_result_id": match_result_id,
            "task_type": "package_version_check",
            "requested_by": "operator@example.test",
        },
    )
    assert response.status_code == 201
    return response.json()


def test_c5_lists_details_and_evidence_with_context(client, db_session) -> None:
    match_result_id = _create_match_result(
        client,
        db_session,
        canonical_id="CVE-2026-C5001",
    )
    task = _create_task(client, match_result_id)

    list_response = client.get(
        "/api/v1/verification-tasks",
        params={"status": "queued", "vulnerability_id": "CVE-2026-C5001"},
    )
    assert list_response.status_code == 200
    rows = list_response.json()
    assert len(rows) == 1
    assert rows[0]["id"] == task["id"]
    assert rows[0]["asset_agent_id"] == "agent-linux-001"
    assert rows[0]["vulnerability_canonical_id"] == "CVE-2026-C5001"
    assert rows[0]["evidence_count"] == 0

    detail_response = client.get(f"/api/v1/verification-tasks/{task['id']}")
    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert detail["timeline"][0]["status"] == "queued"
    assert detail["parameters"]["package_name"] == "nginx"

    poll_response = client.get("/api/v1/agents/agent-linux-001/tasks/next")
    assert poll_response.status_code == 200
    assert poll_response.json()["task"]["id"] == task["id"]
    result_response = client.post(
        f"/api/v1/agents/agent-linux-001/tasks/{task['id']}/results",
        json={
            "status": "completed",
            "evidence": [
                {
                    "evidence_type": "package_version",
                    "summary": "Observed nginx 1.24.0 from dpkg.",
                    "confidence": 0.95,
                    "details": {
                        "package_name": "nginx",
                        "observed_version": "1.24.0",
                        "source": "dpkg",
                    },
                }
            ],
        },
    )
    assert result_response.status_code == 202

    evidence_response = client.get(
        "/api/v1/verification-evidence",
        params={"verification_task_id": task["id"]},
    )
    assert evidence_response.status_code == 200
    evidence = evidence_response.json()
    assert len(evidence) == 1
    assert evidence[0]["asset_hostname"] == "web-01.prod.local"
    assert evidence[0]["vulnerability_canonical_id"] == "CVE-2026-C5001"
    assert evidence[0]["details"]["observed_version"] == "1.24.0"


def test_c5_cancels_queued_task_and_retries_with_previous_task_link(
    client,
    db_session,
) -> None:
    match_result_id = _create_match_result(
        client,
        db_session,
        canonical_id="CVE-2026-C5002",
    )
    task = _create_task(client, match_result_id)

    cancel_response = client.post(
        f"/api/v1/verification-tasks/{task['id']}/cancel",
        json={"requested_by": "operator@example.test"},
    )
    assert cancel_response.status_code == 200
    cancelled = cancel_response.json()
    assert cancelled["status"] == "cancelled"
    assert cancelled["cancel_requested_at"] is not None
    assert cancelled["completed_at"] is not None

    retry_response = client.post(
        f"/api/v1/verification-tasks/{task['id']}/retry",
        json={"requested_by": "operator@example.test"},
    )
    assert retry_response.status_code == 201
    retry = retry_response.json()
    assert retry["status"] == "queued"
    assert retry["previous_task_id"] == task["id"]
    assert retry["parameters"]["package_name"] == "nginx"

    detail_response = client.get(f"/api/v1/verification-tasks/{task['id']}")
    assert detail_response.status_code == 200
    assert detail_response.json()["retry_count"] == 1


def test_c5_cancel_in_progress_marks_cancel_requested(client, db_session) -> None:
    match_result_id = _create_match_result(
        client,
        db_session,
        canonical_id="CVE-2026-C5003",
    )
    task = _create_task(client, match_result_id)

    poll_response = client.get("/api/v1/agents/agent-linux-001/tasks/next")
    assert poll_response.status_code == 200
    assert poll_response.json()["task"]["id"] == task["id"]

    cancel_response = client.post(f"/api/v1/verification-tasks/{task['id']}/cancel")
    assert cancel_response.status_code == 200
    cancelled = cancel_response.json()
    assert cancelled["status"] == "cancel_requested"
    assert cancelled["cancel_requested_at"] is not None
    assert cancelled["completed_at"] is None

    retry_response = client.post(f"/api/v1/verification-tasks/{task['id']}/retry")
    assert retry_response.status_code == 400


def test_c5_marks_stale_queued_task_as_failed_on_task_center_query(
    client,
    db_session,
) -> None:
    match_result_id = _create_match_result(
        client,
        db_session,
        canonical_id="CVE-2026-C5004",
    )
    task = _create_task(client, match_result_id)
    db_task = db_session.scalar(select(VerificationTask).where(VerificationTask.id == task["id"]))
    assert db_task is not None
    db_task.created_at = utcnow() - timedelta(days=2)
    db_session.commit()

    list_response = client.get("/api/v1/verification-tasks")
    assert list_response.status_code == 200
    rows = list_response.json()
    assert rows[0]["id"] == task["id"]
    assert rows[0]["status"] == "failed"
    assert rows[0]["error_code"] == "queued_timeout"
