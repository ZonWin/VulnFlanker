from __future__ import annotations

import copy
import json

from sqlalchemy import select

from app.connectors.cisa_kev import CisaKevConnector
from app.db.models import Asset, AuditLog, MatchResult, VerificationEvidence, Vulnerability
from test_asset_ingestion import build_linux_snapshot


C0_CISA_KEV_CATALOG = {
    "catalogVersion": "2026.05.10-c0",
    "dateReleased": "2026-05-10T00:00:00Z",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-C0-0001",
            "vendorProject": "Nginx",
            "product": "nginx",
            "vulnerabilityName": "C0 Nginx Fixed Version Demo Vulnerability",
            "dateAdded": "2026-05-10",
            "shortDescription": "C0 demo vulnerability with a known fixed version.",
            "requiredAction": "Upgrade nginx to version 1.25.0 or later.",
            "dueDate": "2026-05-31",
            "knownRansomwareCampaignUse": "Known",
            "notes": json.dumps(
                {
                    "requires_public_access": True,
                    "affected_os": ["linux", "ubuntu"],
                }
            ),
        },
        {
            "cveID": "CVE-2026-C0-0002",
            "vendorProject": "Nginx",
            "product": "nginx",
            "vulnerabilityName": "C0 Nginx Review Required Demo Vulnerability",
            "dateAdded": "2026-05-10",
            "shortDescription": "C0 demo vulnerability without structured version data.",
            "requiredAction": "Review the vendor advisory and apply the recommended update.",
            "dueDate": "2026-05-31",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": json.dumps(
                {
                    "requires_public_access": True,
                    "affected_os": ["linux", "ubuntu"],
                }
            ),
        },
    ],
}


def _c0_cve_record(cve_id: str) -> dict[str, object] | None:
    if cve_id != "CVE-2026-C0-0002":
        return None
    return {
        "cveMetadata": {"datePublished": "2026-05-10T00:00:00Z"},
        "containers": {
            "cna": {
                "affected": [
                    {
                        "vendor": "Nginx",
                        "product": "nginx",
                        "versions": [
                            {
                                "version": "vendor-advisory",
                                "status": "affected",
                            }
                        ],
                    }
                ],
                "descriptions": [
                    {
                        "lang": "en",
                        "value": (
                            "C0 demo vulnerability with affected versions described "
                            "only in the vendor advisory."
                        ),
                    }
                ],
                "references": [
                    {"url": "https://example.test/c0/nginx-review-required"}
                ],
            }
        },
    }


def _snapshot(
    *,
    agent_id: str,
    hostname: str,
    nginx_version: str,
) -> dict[str, object]:
    payload = copy.deepcopy(build_linux_snapshot(nginx_version=nginx_version))
    payload["agent_id"] = agent_id
    payload["hostname"] = hostname
    payload["collected_at"] = "2026-05-10T00:00:00Z"
    return payload


def _match_result_for(
    db_session,
    *,
    canonical_id: str,
    agent_id: str,
) -> MatchResult:
    result = db_session.scalar(
        select(MatchResult)
        .join(MatchResult.vulnerability)
        .join(MatchResult.asset)
        .where(
            Vulnerability.canonical_id == canonical_id,
            Asset.agent_id == agent_id,
        )
    )
    assert result is not None
    return result


def test_c0_core_chain_demo_baseline_covers_collection_matching_risk_and_verification(
    client,
    db_session,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        CisaKevConnector,
        "fetch_catalog",
        lambda self: C0_CISA_KEV_CATALOG,
    )
    monkeypatch.setattr(
        CisaKevConnector,
        "fetch_cve_record",
        lambda self, cve_id: _c0_cve_record(cve_id),
    )

    intel_response = client.post("/api/v1/intel/cisa-kev/collect", json={})
    assert intel_response.status_code == 200
    intel_payload = intel_response.json()
    assert intel_payload["processed_count"] == 2

    affected_asset_response = client.post(
        "/api/v1/agents/snapshots",
        json=_snapshot(
            agent_id="c0-agent-affected",
            hostname="c0-web-affected.local",
            nginx_version="1.24.0",
        ),
    )
    assert affected_asset_response.status_code == 202

    safe_asset_response = client.post(
        "/api/v1/agents/snapshots",
        json=_snapshot(
            agent_id="c0-agent-safe",
            hostname="c0-web-safe.local",
            nginx_version="1.26.0",
        ),
    )
    assert safe_asset_response.status_code == 202

    evaluate_response = client.post("/api/v1/match-results/evaluate", json={})
    assert evaluate_response.status_code == 202
    assert evaluate_response.json()["evaluated_count"] == 4

    affected_result = _match_result_for(
        db_session,
        canonical_id="CVE-2026-C0-0001",
        agent_id="c0-agent-affected",
    )
    safe_result = _match_result_for(
        db_session,
        canonical_id="CVE-2026-C0-0001",
        agent_id="c0-agent-safe",
    )
    review_result = _match_result_for(
        db_session,
        canonical_id="CVE-2026-C0-0002",
        agent_id="c0-agent-affected",
    )
    assert affected_result.status == "affected"
    assert affected_result.risk_score > 0
    assert safe_result.status == "not_affected"
    assert safe_result.risk_score == 0
    assert review_result.status == "needs_review"
    assert review_result.risk_score > 0

    risk_queue_response = client.get("/api/v1/match-results/risk-queue")
    assert risk_queue_response.status_code == 200
    risk_queue = risk_queue_response.json()
    risk_queue_ids = {item["id"] for item in risk_queue}
    assert affected_result.id in risk_queue_ids
    assert review_result.id in risk_queue_ids
    assert safe_result.id not in risk_queue_ids
    assert all(item["risk_factors"] for item in risk_queue)
    assert all(item["risk_explanation"] for item in risk_queue)

    verification_create_response = client.post(
        "/api/v1/verification-tasks",
        json={
            "match_result_id": affected_result.id,
            "task_type": "package_version_check",
            "requested_by": "c0-baseline",
        },
    )
    assert verification_create_response.status_code == 201
    task_id = verification_create_response.json()["id"]

    poll_response = client.get("/api/v1/agents/c0-agent-affected/tasks/next")
    assert poll_response.status_code == 200
    assert poll_response.json()["task"]["id"] == task_id

    result_response = client.post(
        f"/api/v1/agents/c0-agent-affected/tasks/{task_id}/results",
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

    db_session.refresh(affected_result)
    assert affected_result.status == "verified"
    assert affected_result.confidence == 0.95

    detail_response = client.get(f"/api/v1/match-results/{affected_result.id}")
    assert detail_response.status_code == 200
    detail_payload = detail_response.json()
    assert detail_payload["status"] == "verified"
    assert detail_payload["evidence"]
    assert detail_payload["verification_evidence"]

    verification_evidence = db_session.scalar(select(VerificationEvidence))
    assert verification_evidence is not None
    assert verification_evidence.match_result_id == affected_result.id

    audit_actions = {
        log.action
        for log in db_session.scalars(select(AuditLog)).all()
    }
    assert {
        "verification_task.created",
        "verification_task.assigned",
        "verification_task.result_received",
        "match_result.verification_updated",
    }.issubset(audit_actions)


def test_c0_openapi_schema_keeps_core_chain_paths(client) -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200
    paths = set(response.json()["paths"])
    assert {
        "/api/v1/intel/cisa-kev/collect",
        "/api/v1/agents/snapshots",
        "/api/v1/match-results/evaluate",
        "/api/v1/match-results/risk-queue",
        "/api/v1/verification-tasks",
        "/api/v1/agents/{agent_id}/tasks/next",
        "/api/v1/agents/{agent_id}/tasks/{task_id}/results",
        "/api/v1/audit/logs",
    }.issubset(paths)
