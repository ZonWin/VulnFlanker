from __future__ import annotations

from dataclasses import dataclass, field
import re

from app.matching.base import MatchContext, MatchRule, RuleResult, rule_confidence
from app.matching.exposure_rule import ExposureRule
from app.matching.feature_rule import FeatureRule
from app.matching.os_rule import OperatingSystemRule
from app.matching.product_aliases import product_aliases
from app.matching.product_rule import ProductRule
from app.matching.utils import product_candidates, public_exposures_for_product
from app.matching.version_rule import VersionRule


@dataclass(slots=True)
class PipelineResult:
    status: str
    confidence: float
    reason: str
    rule_version: str
    evidence: list[dict] = field(default_factory=list)
    rule_results: list[RuleResult] = field(default_factory=list)
    rule_trace: list[dict] = field(default_factory=list)


DEFAULT_RULES: tuple[MatchRule, ...] = (
    ProductRule(),
    VersionRule(),
    OperatingSystemRule(),
    FeatureRule(),
    ExposureRule(),
)


def evaluate_pipeline(
    context: MatchContext,
    rules: tuple[MatchRule, ...] = DEFAULT_RULES,
) -> PipelineResult:
    evaluated_rules: list[tuple[MatchRule, RuleResult]] = []
    for rule in rules:
        result = rule.evaluate(context)
        if result.rule_name is None:
            result.rule_name = rule.rule_name
        evaluated_rules.append((rule, result))

    rule_results = [result for _, result in evaluated_rules]
    active_results = [
        result for result in rule_results if result.status != "not_applicable"
    ]
    evidence = []
    for result in active_results:
        for item in result.evidence:
            evidence.append({"rule_name": result.rule_name, **item})

    blocking_results = [
        result
        for result in active_results
        if result.status == "not_affected"
        and result.rule_name in {"product_rule", "version_rule", "os_rule", "exposure_rule"}
    ]
    review_results = [
        result for result in active_results if result.status == "needs_review"
    ]
    affected_results = [
        result for result in active_results if result.status == "affected"
    ]

    if blocking_results:
        status = "not_affected"
        confidence = max(result.confidence for result in blocking_results)
        reason = "; ".join(result.reason for result in blocking_results)
    elif review_results:
        status = "needs_review"
        confidence = min(result.confidence for result in review_results)
        reason = "; ".join(result.reason for result in review_results)
    elif affected_results:
        status = "affected"
        confidence = min(result.confidence for result in affected_results)
        reason = "; ".join(result.reason for result in affected_results)
    else:
        status = "needs_review"
        confidence = rule_confidence(context, "pipeline", "no_conclusive_result", 0.3)
        reason = "No matching rule produced a conclusive result."

    rule_version = "match-pipeline-v1"
    return PipelineResult(
        status=status,
        confidence=round(confidence, 2),
        reason=reason,
        rule_version=rule_version,
        evidence=evidence,
        rule_results=rule_results,
        rule_trace=[
            _rule_trace(context, rule, result)
            for rule, result in evaluated_rules
        ],
    )


def _rule_trace(
    context: MatchContext,
    rule: MatchRule,
    result: RuleResult,
) -> dict:
    return {
        "rule_name": result.rule_name or rule.rule_name,
        "rule_version": rule.rule_version,
        "executed": result.status != "not_applicable",
        "status": result.status,
        "confidence": round(result.confidence, 2),
        "reason": result.reason,
        "reason_code": result.reason_code or _reason_code(result),
        "uncertain_reason": result.reason if result.status == "needs_review" else None,
        "input_summary": _input_summary(context, rule.rule_name),
        "evidence_count": len(result.evidence),
    }


def _reason_code(result: RuleResult) -> str:
    rule_name = result.rule_name or "unknown_rule"
    reason_key = re.sub(r"[^a-z0-9]+", "_", result.reason.lower()).strip("_")
    if not reason_key:
        reason_key = "no_reason"
    return f"{rule_name}.{result.status}.{reason_key[:80]}"


def _input_summary(context: MatchContext, rule_name: str) -> dict[str, object]:
    product = context.vulnerability.get("product")
    if rule_name == "product_rule":
        matched_components = [
            _candidate_summary(candidate)
            for candidate in product_candidates(context)
        ][:8]
        return {
            "expected_product": product,
            "aliases": product_aliases(str(product)) if product else [],
            "matched_components": matched_components,
        }
    if rule_name == "version_rule":
        matched_versions = [
            _candidate_summary(candidate)
            for candidate in product_candidates(context)
            if candidate.get("version")
        ][:8]
        return {
            "expected_product": product,
            "affected_versions": context.vulnerability.get("affected_versions"),
            "fixed_versions": context.vulnerability.get("fixed_versions"),
            "matched_versions": matched_versions,
        }
    if rule_name == "os_rule":
        return {
            "asset_os": [
                context.asset.get("platform"),
                context.asset.get("os_family"),
                context.asset.get("os_version"),
                context.asset.get("kernel_version"),
            ],
            "affected_os": context.vulnerability_conditions.get("affected_os"),
        }
    if rule_name == "feature_rule":
        return {
            "requires_module": context.vulnerability_conditions.get("requires_module"),
            "requires_feature_flag": context.vulnerability_conditions.get(
                "requires_feature_flag"
            ),
        }
    if rule_name == "exposure_rule":
        public_exposure_count = sum(
            1 for exposure in context.asset_exposures if exposure.get("is_public")
        )
        return {
            "requires_public_access": context.vulnerability_conditions.get(
                "requires_public_access"
            ),
            "public_exposure_count": public_exposure_count,
            "matching_public_exposure_count": len(public_exposures_for_product(context)),
        }
    return {}


def _candidate_summary(candidate: dict) -> dict[str, object]:
    return {
        "name": candidate.get("component_name") or candidate.get("product"),
        "kind": candidate.get("kind"),
        "version": candidate.get("version"),
        "source": candidate.get("source_type") or candidate.get("service_name"),
    }
