from __future__ import annotations

import json

from sqlalchemy import select

from app.connectors.cisa_kev import CisaKevConnector
from app.db.models import (
    MatchEvidence,
    MatchResult,
    VerificationEvidence,
    VerificationTask,
    Vulnerability,
)
from test_asset_ingestion import build_linux_snapshot


PHASE2_TO_6A_CISA_KEV_CATALOG = {
    "catalogVersion": "2026.05.06",
    "dateReleased": "2026-05-06T00:00:00Z",
    "count": 1,
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-7601",
            "vendorProject": "Nginx",
            "product": "nginx",
            "vulnerabilityName": "Nginx HTTP Gateway Remote Code Execution",
            "dateAdded": "2026-05-06",
            "shortDescription": "Remote code execution in affected nginx deployments.",
            "requiredAction": "Upgrade nginx to version 1.25.0 or later.",
            "dueDate": "2026-05-27",
            "knownRansomwareCampaignUse": "Known",
            "notes": json.dumps(
                {
                    "requires_public_access": True,
                    "affected_os": ["linux", "ubuntu"],
                }
            ),
        }
    ],
}


def test_phase2_to_6a_joint_flow_reaches_agent_verification_evidence(
    client,
    db_session,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        CisaKevConnector,
        "fetch_catalog",
        lambda self: PHASE2_TO_6A_CISA_KEV_CATALOG,
    )
    monkeypatch.setattr(CisaKevConnector, "fetch_cve_record", lambda self, _: None)

    intel_response = client.post("/api/v1/intel/cisa-kev/collect", json={})
    assert intel_response.status_code == 200
    assert intel_response.json()["processed_count"] == 1

    vulnerability = db_session.scalar(
        select(Vulnerability).where(Vulnerability.canonical_id == "CVE-2026-7601")
    )
    assert vulnerability is not None
    assert vulnerability.kev_status is True
    assert vulnerability.product == "nginx"
    assert vulnerability.fixed_versions == "1.25.0"

    asset_response = client.post(
        "/api/v1/agents/snapshots",
        json=build_linux_snapshot(nginx_version="1.24.0"),
    )
    assert asset_response.status_code == 202
    asset_id = asset_response.json()["asset_id"]

    asset_detail_response = client.get(f"/api/v1/assets/{asset_id}")
    assert asset_detail_response.status_code == 200
    assert asset_detail_response.json()["components"][0]["component_name"] == "nginx"

    evaluate_response = client.post(
        "/api/v1/match-results/evaluate",
        json={"asset_id": asset_id, "vulnerability_id": vulnerability.canonical_id},
    )
    assert evaluate_response.status_code == 202
    evaluate_payload = evaluate_response.json()
    assert evaluate_payload["evaluated_count"] == 1
    match_result_id = evaluate_payload["sample_result_ids"][0]

    match_result = db_session.get(MatchResult, match_result_id)
    assert match_result is not None
    assert match_result.status == "affected"
    assert match_result.risk_score > 0

    match_evidence_types = {
        evidence.evidence_type
        for evidence in db_session.scalars(select(MatchEvidence)).all()
    }
    assert {"product_match", "package_version", "os_condition", "public_exposure"}.issubset(
        match_evidence_types
    )

    risk_queue_response = client.get("/api/v1/match-results/risk-queue")
    assert risk_queue_response.status_code == 200
    risk_queue = risk_queue_response.json()
    assert len(risk_queue) == 1
    assert risk_queue[0]["vulnerability_canonical_id"] == "CVE-2026-7601"
    assert risk_queue[0]["risk_priority"] in {"low", "medium", "high", "critical"}
    assert risk_queue[0]["risk_factors"]
    assert risk_queue[0]["risk_explanation"]

    verification_create_response = client.post(
        "/api/v1/verification-tasks",
        json={
            "match_result_id": match_result_id,
            "task_type": "package_version_check",
            "requested_by": "phase2-to-6a-joint-test",
        },
    )
    assert verification_create_response.status_code == 201
    verification_payload = verification_create_response.json()
    assert verification_payload["status"] == "queued"
    assert verification_payload["parameters"]["package_name"] == "nginx"
    assert verification_payload["parameters"]["expected_version"] == "1.25.0"

    poll_response = client.get("/api/v1/agents/agent-linux-001/tasks/next")
    assert poll_response.status_code == 200
    polled_task = poll_response.json()["task"]
    assert polled_task["id"] == verification_payload["id"]
    assert polled_task["task_type"] == "package_version_check"
    assert polled_task["match_result_id"] == match_result_id

    task = db_session.get(VerificationTask, verification_payload["id"])
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

    verification_evidence = db_session.scalar(select(VerificationEvidence))
    assert verification_evidence is not None
    assert verification_evidence.verification_task_id == task.id
    assert verification_evidence.match_result_id == match_result_id
    assert verification_evidence.evidence_type == "package_version"
    assert verification_evidence.details_json["observed_version"] == "1.24.0"
