from __future__ import annotations

from app.db.models import VulnerabilityAffectedScope
from app.matching.pipeline import PipelineResult
from app.matching.scope_resolver import ScopeResolution
from app.services.matching import _aggregate_scope_pipeline_results
from app.verification.package_version_check import decide_package_version_match_update


def _version_evidence(
    version: str,
    *,
    package_name: str = "nginx",
    source: str = "dpkg",
    version_scheme: str | None = None,
) -> list[dict]:
    return [
        {
            "evidence_type": "package_version",
            "confidence": 0.95,
            "details": {
                "package_name": package_name,
                "observed_version": version,
                "source": source,
                "version_scheme": version_scheme,
                "evidence_origin": "agent",
            },
        }
    ]


def test_verification_rejects_reported_product_identity_mismatch() -> None:
    decision = decide_package_version_match_update(
        task_status="completed",
        error_code=None,
        evidence_items=_version_evidence("1.0", package_name="openssl"),
        affected_versions="< 2.0",
        fixed_versions=None,
        expected_package_name="nginx",
    )

    assert decision.match_status == "needs_review"
    assert decision.reason_code == "verification.product_identity_mismatch"
    assert decision.details["identity_matches"] is False


def test_verification_cannot_lexically_order_rpm_evr() -> None:
    decision = decide_package_version_match_update(
        task_status="completed",
        error_code=None,
        evidence_items=_version_evidence("1.0-1.el9", source="rpm"),
        affected_versions="< 2.0-1.el9",
        fixed_versions=None,
        expected_package_name="nginx",
        constraint_version_scheme="rpm",
        source_authority="distribution",
        authority_score=100,
    )

    assert decision.match_status == "needs_review"
    assert decision.reason_code == "verification.version_inconclusive"
    assert decision.details["comparisons"][0]["reason_code"] == (
        "version.rpm.comparator_unavailable"
    )


def test_verification_records_debian_comparator_and_authority() -> None:
    decision = decide_package_version_match_update(
        task_status="completed",
        error_code=None,
        evidence_items=_version_evidence(
            "1:1.24.0-1ubuntu1",
            version_scheme="debian",
        ),
        affected_versions=None,
        fixed_versions="1:1.25.0-1ubuntu1",
        expected_package_name="nginx",
        constraint_version_scheme="debian",
        source_authority="distribution",
        authority_score=100,
    )

    assert decision.match_status == "verified"
    assert decision.reason_code == "verification.version_affected"
    assert decision.details["source_authority"] == "distribution"
    assert decision.details["comparisons"][0]["comparator"] == "debian_policy"


def test_scope_rule_trace_is_consolidated_without_losing_scope_ids() -> None:
    first_scope = VulnerabilityAffectedScope(
        id="scope-1",
        vulnerability_id="vuln-1",
        source_name="source-a",
        scope_key="one",
        product="nginx",
    )
    second_scope = VulnerabilityAffectedScope(
        id="scope-2",
        vulnerability_id="vuln-1",
        source_name="source-b",
        scope_key="two",
        product="nginx",
    )
    pipeline = PipelineResult(
        status="affected",
        confidence=0.8,
        reason="matched",
        rule_version="test",
        rule_trace=[
            {
                "rule_name": "product_rule",
                "status": "affected",
                "reason_code": "product.matched",
                "reason": "matched",
                "confidence": 0.8,
            }
        ],
    )
    resolution = ScopeResolution(
        applicable=[first_scope, second_scope],
        selected=[first_scope, second_scope],
    )

    result = _aggregate_scope_pipeline_results(
        [(first_scope, pipeline), (second_scope, pipeline)],
        resolution=resolution,
    )

    assert len(result.rule_trace) == 1
    assert result.rule_trace[0]["affected_scope_ids"] == ["scope-1", "scope-2"]
