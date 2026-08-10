from __future__ import annotations

from sqlalchemy import func, select

from app.db.models import (
    AgentStatus,
    Asset,
    MatchEvidence,
    MatchResult,
    VerificationEvidence,
    VerificationTask,
)
from test_asset_ingestion import build_linux_snapshot
from test_matching_engine import create_vulnerability


def test_delete_asset_removes_risks_and_can_keep_agent_for_reingestion(
    client,
    db_session,
) -> None:
    asset_response = client.post(
        "/api/v1/agents/snapshots",
        json=build_linux_snapshot(nginx_version="1.24.0"),
    )
    asset_id = asset_response.json()["asset_id"]
    vulnerability = create_vulnerability(
        db_session,
        canonical_id="CVE-2026-ASSET-LIFECYCLE",
        fixed_versions="1.25.0",
    )

    evaluate_response = client.post(
        "/api/v1/match-results/evaluate",
        json={"asset_id": asset_id, "vulnerability_id": vulnerability.canonical_id},
    )
    assert evaluate_response.status_code == 202
    match_result = db_session.scalar(select(MatchResult))
    assert match_result is not None
    task = VerificationTask(
        asset_id=asset_id,
        match_result_id=match_result.id,
        task_type="package_version_check",
        status="completed",
    )
    db_session.add(task)
    db_session.flush()
    db_session.add(
        VerificationEvidence(
            verification_task_id=task.id,
            match_result_id=match_result.id,
            evidence_type="agent_result",
            summary="verified",
            confidence=0.95,
        )
    )
    db_session.commit()

    delete_response = client.request(
        "DELETE",
        f"/api/v1/assets/{asset_id}",
        json={"delete_agent": False},
    )

    assert delete_response.status_code == 200
    payload = delete_response.json()
    assert payload["asset_deleted"] is True
    assert payload["agent_deleted"] is False
    assert payload["match_results_deleted"] == 1
    assert payload["verification_tasks_deleted"] == 1
    assert db_session.scalar(select(func.count(Asset.id))) == 0
    assert db_session.scalar(select(func.count(MatchResult.id))) == 0
    assert db_session.scalar(select(func.count(MatchEvidence.id))) == 0
    assert db_session.scalar(select(func.count(VerificationTask.id))) == 0
    assert db_session.scalar(select(func.count(VerificationEvidence.id))) == 0
    assert (
        db_session.scalar(
            select(AgentStatus).where(AgentStatus.agent_id == "agent-linux-001")
        )
        is not None
    )

    reingest_response = client.post(
        "/api/v1/agents/snapshots",
        json=build_linux_snapshot(
            nginx_version="1.26.1",
            collected_at="2026-05-05T13:00:00Z",
        ),
    )

    assert reingest_response.status_code == 202
    assert reingest_response.json()["asset_action"] == "created"
    assert db_session.scalar(select(func.count(Asset.id))) == 1
