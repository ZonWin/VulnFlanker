from __future__ import annotations

import json

from sqlalchemy import select

from app.connectors.cisa_kev import CisaKevConnector
from app.db.models import MatchEvidence, MatchResult, Vulnerability
from test_asset_ingestion import build_linux_snapshot


JOINT_CISA_KEV_CATALOG = {
    "catalogVersion": "2026.05.06",
    "dateReleased": "2026-05-06T00:00:00Z",
    "count": 1,
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-4404",
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


def test_phase2_to_phase4_joint_flow_matches_ingested_intel_to_asset(
    client,
    db_session,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        CisaKevConnector,
        "fetch_catalog",
        lambda self: JOINT_CISA_KEV_CATALOG,
    )
    monkeypatch.setattr(CisaKevConnector, "fetch_cve_record", lambda self, _: None)

    intel_response = client.post("/api/v1/intel/cisa-kev/collect", json={})
    assert intel_response.status_code == 200
    assert intel_response.json()["processed_count"] == 1

    vulnerability = db_session.scalar(
        select(Vulnerability).where(Vulnerability.canonical_id == "CVE-2026-4404")
    )
    assert vulnerability is not None
    assert vulnerability.product == "nginx"
    assert vulnerability.fixed_versions == "1.25.0"
    assert vulnerability.kev_status is True

    asset_response = client.post(
        "/api/v1/agents/snapshots",
        json=build_linux_snapshot(nginx_version="1.24.0"),
    )
    assert asset_response.status_code == 202
    asset_id = asset_response.json()["asset_id"]

    evaluate_response = client.post(
        "/api/v1/match-results/evaluate",
        json={"asset_id": asset_id, "vulnerability_id": vulnerability.canonical_id},
    )
    assert evaluate_response.status_code == 202
    evaluate_payload = evaluate_response.json()
    assert evaluate_payload["evaluated_count"] == 1

    match_result = db_session.scalar(select(MatchResult))
    assert match_result is not None
    assert match_result.status == "affected"
    assert match_result.vulnerability_id == vulnerability.id
    assert match_result.asset_id == asset_id
    assert match_result.confidence > 0.7
    assert match_result.risk_score > 0

    evidence_types = {
        evidence.evidence_type
        for evidence in db_session.scalars(select(MatchEvidence)).all()
    }
    assert {"product_match", "package_version", "os_condition", "public_exposure"}.issubset(
        evidence_types
    )

    list_response = client.get("/api/v1/match-results")
    assert list_response.status_code == 200
    list_payload = list_response.json()
    assert len(list_payload) == 1
    assert list_payload[0]["status"] == "affected"
    assert list_payload[0]["vulnerability_canonical_id"] == "CVE-2026-4404"
    assert list_payload[0]["asset_hostname"] == "web-01.prod.local"
