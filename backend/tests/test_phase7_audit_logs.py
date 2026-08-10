from __future__ import annotations

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


def test_phase7_audit_logs_track_verification_lifecycle(
    client,
    db_session,
) -> None:
    match_result_id = _create_match_result(
        client,
        db_session,
        canonical_id="CVE-2026-9701",
    )

    create_response = client.post(
        f"/api/v1/match-results/{match_result_id}/verification-tasks",
        json={
            "requested_by": "operator@example.test",
            "parameters": {
                "api_token": "super-secret-token",
            },
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

    audit_response = client.get("/api/v1/audit/logs?limit=20")
    assert audit_response.status_code == 200
    audit_logs = audit_response.json()
    actions = {log["action"] for log in audit_logs}
    assert {
        "verification_task.created",
        "verification_task.assigned",
        "verification_task.result_received",
        "match_result.verification_updated",
    }.issubset(actions)

    created_log = next(
        log
        for log in audit_logs
        if log["action"] == "verification_task.created"
    )
    assert created_log["actor_id"] == "test-admin-user"
    assert created_log["details"]["actor_username"] == "test-admin"
    assert created_log["details"]["parameters"]["api_token"] == "[redacted]"

    assigned_log = next(
        log
        for log in audit_logs
        if log["action"] == "verification_task.assigned"
    )
    assert assigned_log["actor_type"] == "agent"
    assert assigned_log["actor_id"] == "agent-linux-001"

    update_response = client.get(
        "/api/v1/audit/logs",
        params={
            "action": "match_result.verification_updated",
            "resource_id": match_result_id,
        },
    )
    assert update_response.status_code == 200
    update_logs = update_response.json()
    assert len(update_logs) == 1
    assert update_logs[0]["details"]["new_status"] == "verified"
    assert update_logs[0]["details"]["verification_task_id"] == task_id


def test_phase7_audit_logs_rejected_verification_task_type(
    client,
    db_session,
) -> None:
    match_result_id = _create_match_result(
        client,
        db_session,
        canonical_id="CVE-2026-9702",
    )

    response = client.post(
        "/api/v1/verification-tasks",
        json={
            "match_result_id": match_result_id,
            "task_type": "shell_command",
            "requested_by": "operator@example.test",
        },
    )
    assert response.status_code == 400

    audit_response = client.get(
        "/api/v1/audit/logs",
        params={
            "action": "verification_task.rejected",
            "outcome": "rejected",
        },
    )
    assert audit_response.status_code == 200
    audit_logs = audit_response.json()
    assert len(audit_logs) == 1
    assert audit_logs[0]["actor_id"] == "test-admin-user"
    assert audit_logs[0]["details"]["actor_username"] == "test-admin"
    assert audit_logs[0]["details"]["task_type"] == "shell_command"
