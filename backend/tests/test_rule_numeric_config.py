from __future__ import annotations

from sqlalchemy import select

from app.db.models import MatchResult
from test_asset_ingestion import build_linux_snapshot
from test_matching_engine import create_vulnerability


def test_rule_numeric_config_endpoint_exposes_defaults(client) -> None:
    response = client.get("/api/v1/rule-config")

    assert response.status_code == 200
    payload = response.json()
    assert payload["model_version"] == "risk-v2.0"
    assert payload["matching_confidences"]["product_rule"]["matched"] == 0.78
    assert payload["risk_factor_values"]["exploitability"]["kev"] == 8.0
    assert payload["risk_weights"]["severity"] == 0.3
    assert payload["risk_priority_thresholds"]["high"] == 7.0
    assert payload["weight_total"] == 1.0


def test_matching_confidence_can_be_configured(client, db_session) -> None:
    update_response = client.patch(
        "/api/v1/rule-config",
        json={"matching_confidences": {"version_rule": {"safe_range": 0.91}}},
    )
    assert update_response.status_code == 200

    client.post(
        "/api/v1/agents/snapshots",
        json=build_linux_snapshot(nginx_version="1.26.0"),
    )
    vulnerability = create_vulnerability(
        db_session,
        canonical_id="CVE-2026-7101",
        fixed_versions="1.25.0",
    )

    response = client.post(
        "/api/v1/match-results/evaluate",
        json={"vulnerability_id": vulnerability.canonical_id},
    )

    assert response.status_code == 202
    match_result = db_session.scalar(select(MatchResult))
    assert match_result is not None
    assert match_result.status == "not_affected"
    assert match_result.confidence == 0.91


def test_risk_weights_can_be_configured(client, db_session) -> None:
    update_response = client.patch(
        "/api/v1/rule-config",
        json={
            "risk_weights": {
                "severity": 0.0,
                "exploitability": 0.0,
                "exposure": 0.0,
                "business_criticality": 0.0,
                "confidence": 1.0,
                "verification": 0.0,
                "asset_freshness": 0.0,
            }
        },
    )
    assert update_response.status_code == 200

    client.post(
        "/api/v1/agents/snapshots",
        json=build_linux_snapshot(nginx_version="1.24.0"),
    )
    vulnerability = create_vulnerability(
        db_session,
        canonical_id="CVE-2026-7102",
        fixed_versions="1.25.0",
    )

    response = client.post(
        "/api/v1/match-results/evaluate",
        json={"vulnerability_id": vulnerability.canonical_id},
    )

    assert response.status_code == 202
    match_result = db_session.scalar(select(MatchResult))
    assert match_result is not None
    assert match_result.status == "affected"
    assert match_result.risk_score == 7.8
    assert match_result.risk_factors_json
    assert {
        factor["name"]: factor["weight"]
        for factor in match_result.risk_factors_json
    }["confidence"] == 1.0


def test_rule_numeric_config_rejects_invalid_threshold_order(client) -> None:
    response = client.patch(
        "/api/v1/rule-config",
        json={"risk_priority_thresholds": {"medium": 9.0}},
    )

    assert response.status_code == 400
    assert "low < medium < high < critical" in response.json()["detail"]
