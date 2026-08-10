from __future__ import annotations

from sqlalchemy import select

from app.db.models import (
    AuditLog,
    MatchResult,
    MatchResultHandlingRecord,
    Vulnerability,
    VulnerabilitySource,
)
from test_asset_ingestion import build_linux_snapshot


def create_vulnerability(
    db_session,
    *,
    canonical_id: str,
    fixed_versions: str,
    affected_versions: str = "< 1.25.0",
) -> Vulnerability:
    vulnerability = Vulnerability(
        canonical_id=canonical_id,
        title=f"{canonical_id} nginx vulnerability",
        vendor="nginx",
        product="nginx",
        severity_label="high",
        severity_cvss=9.8,
        poc_status=True,
        affected_versions=affected_versions,
        fixed_versions=fixed_versions,
    )
    db_session.add(vulnerability)
    db_session.flush()
    db_session.add(
        VulnerabilitySource(
            vulnerability_id=vulnerability.id,
            source_name="test-source",
            external_id=canonical_id,
            source_url=f"https://example.test/vulns/{canonical_id}",
            title=vulnerability.title,
            description="Test source record for a match-ready nginx vulnerability.",
            severity_raw="high",
            references_json=[f"https://example.test/references/{canonical_id}"],
            last_payload_hash=f"hash-{canonical_id}",
        )
    )
    db_session.commit()
    return vulnerability


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
        json={
            "asset_id": asset_response.json()["asset_id"],
            "vulnerability_id": vulnerability.canonical_id,
        },
    )
    assert evaluate_response.status_code == 202, evaluate_response.text
    result_ids = evaluate_response.json()["sample_result_ids"]
    assert len(result_ids) == 1
    return result_ids[0]


def test_manual_handling_closes_filters_and_reopens_risk_queue_item(
    client,
    db_session,
) -> None:
    match_result_id = _create_affected_match_result(
        client,
        db_session,
        canonical_id="CVE-2026-9901",
    )

    update_response = client.patch(
        f"/api/v1/match-results/{match_result_id}/handling",
        json={
            "handling_status": "resolved",
            "note": "Patched during the maintenance window.",
        },
    )

    assert update_response.status_code == 200
    detail = update_response.json()
    assert detail["handling_status"] == "resolved"
    assert detail["handling_note"] == "Patched during the maintenance window."
    assert detail["handling_closed_at"] is not None
    assert detail["handling_records"][0]["from_status"] == "unprocessed"
    assert detail["handling_records"][0]["to_status"] == "resolved"
    assert detail["handling_records"][0]["actor_username"] == "test-admin"

    match_result = db_session.get(MatchResult, match_result_id)
    assert match_result is not None
    assert match_result.handling_status == "resolved"
    assert match_result.handling_closed_at is not None

    record = db_session.scalar(
        select(MatchResultHandlingRecord).where(
            MatchResultHandlingRecord.match_result_id == match_result_id
        )
    )
    assert record is not None
    assert record.action == "status_changed"
    assert record.note == "Patched during the maintenance window."

    handling_records_response = client.get("/api/v1/audit/handling-records")
    assert handling_records_response.status_code == 200
    handling_records = handling_records_response.json()
    assert len(handling_records) == 1
    handling_record = handling_records[0]
    assert handling_record["match_result_id"] == match_result_id
    assert handling_record["risk_code"] is not None
    assert handling_record["vulnerability_canonical_id"] == "CVE-2026-9901"
    assert handling_record["asset_hostname"] == "web-01.prod.local"
    assert handling_record["action"] == "status_changed"
    assert handling_record["to_status"] == "resolved"
    assert handling_record["actor_username"] == "test-admin"

    audit_log = db_session.scalar(
        select(AuditLog).where(AuditLog.action == "match_result.handling_updated")
    )
    assert audit_log is not None
    assert audit_log.actor_id == "test-admin-user"
    assert audit_log.details_json["new_handling_status"] == "resolved"

    open_queue_response = client.get("/api/v1/match-results/risk-queue")
    assert open_queue_response.status_code == 200
    assert open_queue_response.json() == []

    closed_queue_response = client.get(
        "/api/v1/match-results/risk-queue?handling_scope=closed"
    )
    assert closed_queue_response.status_code == 200
    assert [item["id"] for item in closed_queue_response.json()] == [match_result_id]

    status_queue_response = client.get(
        "/api/v1/match-results/risk-queue?handling_status=resolved"
    )
    assert status_queue_response.status_code == 200
    assert [item["id"] for item in status_queue_response.json()] == [match_result_id]

    reopen_response = client.post(
        f"/api/v1/match-results/{match_result_id}/handling/reopen",
        json={"note": "Reopened for another manual review."},
    )

    assert reopen_response.status_code == 200
    reopened_detail = reopen_response.json()
    assert reopened_detail["handling_status"] == "unprocessed"
    assert reopened_detail["handling_closed_at"] is None
    assert [item["action"] for item in reopened_detail["handling_records"]] == [
        "reopened",
        "status_changed",
    ]
    assert reopened_detail["handling_records"][0]["note"] == (
        "Reopened for another manual review."
    )

    reopened_queue_response = client.get("/api/v1/match-results/risk-queue")
    assert reopened_queue_response.status_code == 200
    assert [item["id"] for item in reopened_queue_response.json()] == [match_result_id]


def test_reevaluation_keeps_manual_handling_status_and_history(
    client,
    db_session,
) -> None:
    match_result_id = _create_affected_match_result(
        client,
        db_session,
        canonical_id="CVE-2026-9902",
    )
    update_response = client.patch(
        f"/api/v1/match-results/{match_result_id}/handling",
        json={
            "handling_status": "risk_accepted",
            "note": "Accepted after business review.",
        },
    )
    assert update_response.status_code == 200

    reevaluate_response = client.post(
        f"/api/v1/match-results/{match_result_id}/reevaluate"
    )

    assert reevaluate_response.status_code == 200
    detail = reevaluate_response.json()
    assert detail["handling_status"] == "risk_accepted"
    assert detail["handling_closed_at"] is not None
    assert detail["handling_records"][0]["note"] == "Accepted after business review."
    assert len(detail["handling_records"]) == 1


def test_verification_result_keeps_manual_handling_status_and_history(
    client,
    db_session,
) -> None:
    match_result_id = _create_affected_match_result(
        client,
        db_session,
        canonical_id="CVE-2026-9903",
    )
    update_response = client.patch(
        f"/api/v1/match-results/{match_result_id}/handling",
        json={
            "handling_status": "remediating",
            "note": "Patch rollout is in progress.",
        },
    )
    assert update_response.status_code == 200

    create_response = client.post(
        f"/api/v1/match-results/{match_result_id}/verification-tasks",
        json={},
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

    detail_response = client.get(f"/api/v1/match-results/{match_result_id}")
    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert detail["status"] == "verified"
    assert detail["handling_status"] == "remediating"
    assert detail["handling_records"][0]["note"] == "Patch rollout is in progress."
    assert len(detail["handling_records"]) == 1
