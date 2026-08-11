from __future__ import annotations

from sqlalchemy import select

from app.db.models import MatchResult, VerificationEvidence, VerificationTask
from test_asset_ingestion import build_linux_snapshot
from test_matching_engine import create_vulnerability


def _create_match_result(client, db_session) -> str:
    asset_response = client.post(
        "/api/v1/agents/snapshots",
        json=build_linux_snapshot(nginx_version="1.24.0"),
    )
    assert asset_response.status_code == 202
    vulnerability = create_vulnerability(
        db_session,
        canonical_id="CVE-2026-6601",
        fixed_versions="1.25.0",
    )
    evaluate_response = client.post(
        "/api/v1/match-results/evaluate",
        json={"vulnerability_id": vulnerability.canonical_id},
    )
    assert evaluate_response.status_code == 200
    result_ids = evaluate_response.json()["result_ids"]
    assert len(result_ids) == 1
    return result_ids[0]


def test_agent_polls_and_submits_package_version_verification(
    client,
    db_session,
) -> None:
    match_result_id = _create_match_result(client, db_session)

    create_response = client.post(
        "/api/v1/verification-tasks",
        json={
            "match_result_id": match_result_id,
            "task_type": "package_version_check",
            "requested_by": "operator@example.test",
        },
    )

    assert create_response.status_code == 201
    created_payload = create_response.json()
    assert created_payload["status"] == "queued"
    assert created_payload["parameters"]["package_name"] == "nginx"
    assert created_payload["parameters"]["expected_version"] == "1.25.0"

    poll_response = client.get("/api/v1/agents/agent-linux-001/tasks/next")

    assert poll_response.status_code == 200
    polled_task = poll_response.json()["task"]
    assert polled_task["id"] == created_payload["id"]
    assert polled_task["task_type"] == "package_version_check"

    task = db_session.scalar(select(VerificationTask))
    assert task is not None
    assert task.status == "in_progress"
    assert task.assigned_at is not None

    result_response = client.post(
        f"/api/v1/agents/agent-linux-001/tasks/{task.id}/results",
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
    assert result_response.json()["evidence_count"] == 1
    db_session.refresh(task)
    assert task.status == "completed"
    assert task.completed_at is not None

    evidence = db_session.scalar(select(VerificationEvidence))
    assert evidence is not None
    assert evidence.verification_task_id == task.id
    assert evidence.match_result_id == match_result_id
    assert evidence.evidence_type == "package_version"
    assert evidence.details_json["observed_version"] == "1.24.0"

    agents_response = client.get("/api/v1/agents")
    assert agents_response.status_code == 200
    agent_payload = agents_response.json()[0]
    assert agent_payload["agent_id"] == "agent-linux-001"
    assert agent_payload["asset_primary_ip"] == "10.10.20.15"
    assert agent_payload["last_task_poll_at"] is not None
    assert agent_payload["task_stats"]["total"] == 1
    assert agent_payload["task_stats"]["completed"] == 1


def test_legacy_agent_package_not_found_result_is_completed_absence(
    client,
    db_session,
) -> None:
    match_result_id = _create_match_result(client, db_session)
    create_response = client.post(
        "/api/v1/verification-tasks",
        json={
            "match_result_id": match_result_id,
            "parameters": {"package_name": "missing-package"},
        },
    )
    assert create_response.status_code == 201
    task_id = create_response.json()["id"]

    poll_response = client.get("/api/v1/agents/agent-linux-001/tasks/next")
    assert poll_response.status_code == 200
    assert poll_response.json()["task"]["id"] == task_id

    result_response = client.post(
        f"/api/v1/agents/agent-linux-001/tasks/{task_id}/results",
        json={
            "status": "failed",
            "error_code": "package_not_found",
            "error_message": "package missing-package was not found",
        },
    )

    assert result_response.status_code == 202
    assert result_response.json() == {
        "status": "completed",
        "task_id": task_id,
        "evidence_count": 1,
    }
    task = db_session.get(VerificationTask, task_id)
    assert task is not None
    assert task.status == "completed"
    assert task.error_code is None
    assert task.error_message is None

    evidence = db_session.scalar(
        select(VerificationEvidence).where(
            VerificationEvidence.verification_task_id == task_id
        )
    )
    assert evidence is not None
    assert evidence.evidence_type == "package_absence"
    assert evidence.details_json["observed"] is False

    match_result = db_session.get(MatchResult, match_result_id)
    assert match_result is not None
    assert match_result.status == "needs_review"
    assert evidence.details_json["evidence_origin"] == "agent"
    assert evidence.details_json["decision_reason_code"] == (
        "verification.package_absence_inconclusive"
    )


def test_unknown_agent_task_type_is_rejected(client, db_session) -> None:
    match_result_id = _create_match_result(client, db_session)

    response = client.post(
        "/api/v1/verification-tasks",
        json={
            "match_result_id": match_result_id,
            "task_type": "shell_command",
        },
    )

    assert response.status_code == 400
    assert "Unsupported verification task type" in response.json()["detail"]


def test_paged_verification_task_summary_counts_full_filtered_result_set(
    client,
    db_session,
) -> None:
    match_result_id = _create_match_result(client, db_session)
    match_result = db_session.get(MatchResult, match_result_id)
    assert match_result is not None
    statuses = (
        ["queued"] * 10
        + ["in_progress"] * 5
        + ["failed"] * 5
        + ["rejected"] * 5
        + ["completed"] * 10
    )
    for index, status in enumerate(statuses):
        task = VerificationTask(
            asset_id=match_result.asset_id,
            match_result_id=match_result_id,
            task_type="package_version_check",
            status=status,
        )
        db_session.add(task)
        db_session.flush()
        if index < 7:
            db_session.add(
                VerificationEvidence(
                    verification_task_id=task.id,
                    match_result_id=match_result_id,
                    evidence_type="package_version",
                    summary=f"Evidence {index}",
                    confidence=0.9,
                )
            )
    db_session.commit()

    response = client.get("/api/v1/verification-tasks?paged=true&offset=0&limit=30")

    assert response.status_code == 200
    payload = response.json()
    assert len(payload["items"]) == 30
    assert payload["has_more"] is True
    assert payload["total"] == 35
    assert payload["active_count"] == 15
    assert payload["failed_count"] == 10
    assert payload["evidence_count"] == 7
