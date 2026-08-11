from __future__ import annotations

from sqlalchemy import select

from app.db.models import (
    Asset,
    AssetComponent,
    MatchResult,
    VerificationEvidence,
    VerificationTask,
)
from app.services.matching import evaluate_matches
from app.services.verification_orchestrator import run_local_verification_task
from test_asset_ingestion import build_linux_snapshot
from test_matching_engine import create_vulnerability


def _create_affected_match_result(client, db_session, *, canonical_id: str) -> str:
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
    assert evaluate_response.status_code == 200
    result_ids = evaluate_response.json()["result_ids"]
    assert len(result_ids) == 1
    return result_ids[0]


def test_phase6_agent_result_updates_match_status_confidence_and_detail(
    client,
    db_session,
) -> None:
    match_result_id = _create_affected_match_result(
        client,
        db_session,
        canonical_id="CVE-2026-8601",
    )
    match_result = db_session.get(MatchResult, match_result_id)
    assert match_result is not None
    original_risk_score = match_result.risk_score

    create_response = client.post(
        f"/api/v1/match-results/{match_result_id}/verification-tasks",
        json={"requested_by": "operator@example.test"},
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

    db_session.refresh(match_result)
    assert match_result.status == "verified"
    assert match_result.confidence == 0.95
    assert match_result.risk_score >= original_risk_score
    assert "Verification confirmed nginx 1.24.0 is inside the affected range" in (
        match_result.match_reason or ""
    )

    detail_response = client.get(f"/api/v1/match-results/{match_result_id}")
    assert detail_response.status_code == 200
    detail_payload = detail_response.json()
    assert detail_payload["status"] == "verified"
    assert detail_payload["verification_evidence"][0]["details"]["observed_version"] == "1.24.0"

    risk_queue_response = client.get("/api/v1/match-results/risk-queue")
    assert risk_queue_response.status_code == 200
    assert risk_queue_response.json()[0]["status"] == "verified"


def test_phase6_package_verification_can_mark_match_not_affected(
    client,
    db_session,
) -> None:
    match_result_id = _create_affected_match_result(
        client,
        db_session,
        canonical_id="CVE-2026-8602",
    )

    create_response = client.post(
        "/api/v1/verification-tasks",
        json={"match_result_id": match_result_id},
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
                    "summary": "Observed nginx 1.26.0 from dpkg.",
                    "confidence": 0.95,
                    "details": {
                        "package_name": "nginx",
                        "observed_version": "1.26.0",
                        "source": "dpkg",
                    },
                }
            ],
        },
    )
    assert result_response.status_code == 202

    match_result = db_session.get(MatchResult, match_result_id)
    assert match_result is not None
    db_session.refresh(match_result)
    assert match_result.status == "not_affected"
    assert match_result.confidence == 0.95
    assert match_result.risk_score == 0.0


def test_phase6_worker_executes_local_package_version_check(
    client,
    db_session,
) -> None:
    match_result_id = _create_affected_match_result(
        client,
        db_session,
        canonical_id="CVE-2026-8603",
    )
    create_response = client.post(
        "/api/v1/verification-tasks",
        json={"match_result_id": match_result_id, "requested_by": "worker-test"},
    )
    assert create_response.status_code == 201
    task_id = create_response.json()["id"]

    result = run_local_verification_task(db_session, task_id)

    assert result == {
        "status": "completed",
        "task_id": task_id,
        "evidence_count": 1,
    }
    task = db_session.get(VerificationTask, task_id)
    assert task is not None
    assert task.status == "completed"

    evidence = db_session.scalar(select(VerificationEvidence))
    assert evidence is not None
    assert evidence.details_json["observed_version"] == "1.24.0"

    match_result = db_session.get(MatchResult, match_result_id)
    assert match_result is not None
    assert match_result.status == "verified"


def test_phase6_verification_defaults_to_matched_component_name(
    client,
    db_session,
) -> None:
    asset = Asset(
        agent_id="agent-linux-alias-001",
        hostname="inetutils-host",
        platform="linux",
        os_family="ubuntu",
        os_version="24.04",
    )
    db_session.add(asset)
    db_session.flush()
    db_session.add(
        AssetComponent(
            asset_id=asset.id,
            component_name="inetutils-telnet",
            component_type="package",
            version="2:2.5-3ubuntu4.2",
            source_type="dpkg",
        )
    )
    vulnerability = create_vulnerability(
        db_session,
        canonical_id="CVE-2026-8607",
        vendor="GNU",
        product="Inetutils",
        fixed_versions=None,
        affected_versions=">= 1.9.3, <= 2.7",
    )
    results = evaluate_matches(db_session, vulnerability_id=vulnerability.canonical_id)
    assert len(results) == 1
    match_result_id = results[0].id

    create_response = client.post(
        "/api/v1/verification-tasks",
        json={"match_result_id": match_result_id, "requested_by": "package-alias-test"},
    )

    assert create_response.status_code == 201
    assert create_response.json()["parameters"]["package_name"] == "inetutils-telnet"


def test_phase6_worker_marks_absent_package_not_affected(
    client,
    db_session,
) -> None:
    match_result_id = _create_affected_match_result(
        client,
        db_session,
        canonical_id="CVE-2026-8606",
    )
    create_response = client.post(
        "/api/v1/verification-tasks",
        json={
            "match_result_id": match_result_id,
            "parameters": {"package_name": "missing-package"},
            "requested_by": "worker-test",
        },
    )
    assert create_response.status_code == 201
    task_id = create_response.json()["id"]

    result = run_local_verification_task(db_session, task_id)

    assert result == {
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
            VerificationEvidence.evidence_type == "package_absence"
        )
    )
    assert evidence is not None
    assert evidence.details_json["package_name"] == "missing-package"
    assert evidence.details_json["observed"] is False

    match_result = db_session.get(MatchResult, match_result_id)
    assert match_result is not None
    assert match_result.status == "not_affected"
    assert match_result.risk_score == 0.0


def test_phase6_worker_executes_local_kernel_version_check(
    client,
    db_session,
) -> None:
    snapshot = build_linux_snapshot()
    snapshot["kernel_version"] = "5.15.0-119-generic"
    asset_response = client.post("/api/v1/agents/snapshots", json=snapshot)
    assert asset_response.status_code == 202
    vulnerability = create_vulnerability(
        db_session,
        canonical_id="CVE-2026-8604",
        product="Linux Kernel",
        fixed_versions=None,
        affected_versions=(
            "4.11 <= Linux Kernel < 5.10.255 "
            "5.12 <= Linux Kernel < 5.15.205 "
            "5.16 <= Linux Kernel < 6.1.171"
        ),
    )
    evaluate_response = client.post(
        "/api/v1/match-results/evaluate",
        json={"vulnerability_id": vulnerability.canonical_id},
    )
    assert evaluate_response.status_code == 200
    match_result_id = evaluate_response.json()["result_ids"][0]

    create_response = client.post(
        "/api/v1/verification-tasks",
        json={"match_result_id": match_result_id, "requested_by": "kernel-test"},
    )
    assert create_response.status_code == 201
    task_payload = create_response.json()
    assert task_payload["parameters"]["package_name"] == "Linux Kernel"
    assert task_payload["parameters"]["component_type"] == "kernel"

    result = run_local_verification_task(db_session, task_payload["id"])

    assert result == {
        "status": "completed",
        "task_id": task_payload["id"],
        "evidence_count": 1,
    }
    task = db_session.get(VerificationTask, task_payload["id"])
    assert task is not None
    assert task.status == "completed"

    evidence = db_session.scalar(
        select(VerificationEvidence).where(
            VerificationEvidence.evidence_type == "kernel_version"
        )
    )
    assert evidence is not None
    assert evidence.details_json["observed_version"] == "5.15.0-119-generic"

    match_result = db_session.get(MatchResult, match_result_id)
    assert match_result is not None
    assert match_result.status == "needs_review"
    assert "comparison was inconclusive" in (match_result.match_reason or "")


def test_phase6_worker_executes_local_os_version_text_check(
    client,
    db_session,
) -> None:
    asset_response = client.post("/api/v1/agents/snapshots", json=build_linux_snapshot())
    assert asset_response.status_code == 202
    vulnerability = create_vulnerability(
        db_session,
        canonical_id="CVE-2026-8605",
        product="Ubuntu",
        fixed_versions=None,
        affected_versions="Ubuntu 20.04 LTS, Ubuntu 22.04 LTS",
    )
    evaluate_response = client.post(
        "/api/v1/match-results/evaluate",
        json={"vulnerability_id": vulnerability.canonical_id},
    )
    assert evaluate_response.status_code == 200
    match_result_id = evaluate_response.json()["result_ids"][0]

    create_response = client.post(
        "/api/v1/verification-tasks",
        json={"match_result_id": match_result_id, "requested_by": "os-test"},
    )
    assert create_response.status_code == 201
    task_payload = create_response.json()
    assert task_payload["parameters"]["package_name"] == "Ubuntu"
    assert task_payload["parameters"]["component_type"] == "operating_system"

    result = run_local_verification_task(db_session, task_payload["id"])

    assert result == {
        "status": "completed",
        "task_id": task_payload["id"],
        "evidence_count": 1,
    }
    evidence = db_session.scalar(
        select(VerificationEvidence).where(
            VerificationEvidence.evidence_type == "os_version"
        )
    )
    assert evidence is not None
    assert evidence.details_json["observed_version"] == "22.04"

    match_result = db_session.get(MatchResult, match_result_id)
    assert match_result is not None
    assert match_result.status == "verified"
