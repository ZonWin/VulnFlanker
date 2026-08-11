from __future__ import annotations

from app.matching.base import MatchContext, MatchRule, RuleResult, rule_confidence
from app.matching.utils import values_match


class FeatureRule(MatchRule):
    rule_name = "feature_rule"

    def evaluate(self, context: MatchContext) -> RuleResult:
        required_values = _required_values(context)
        if not required_values:
            confidence = rule_confidence(context, self.rule_name, "not_applicable", 0.0)
            return RuleResult(
                status="not_applicable",
                confidence=confidence,
                reason="No module or feature condition is defined for this vulnerability.",
                reason_code="feature.not_required",
                evidence=[],
                rule_name=self.rule_name,
            )

        observed_values = []
        for component in context.asset_components:
            observed_values.extend(
                [
                    component.get("component_name"),
                    component.get("component_type"),
                    component.get("install_path"),
                ]
            )
        for exposure in context.asset_exposures:
            observed_values.extend(
                [
                    exposure.get("service_name"),
                    exposure.get("product"),
                    exposure.get("banner"),
                ]
            )

        matched = [
            value for value in required_values if values_match(str(value), observed_values)
        ]
        if matched:
            confidence = rule_confidence(context, self.rule_name, "matched", 0.62)
            return RuleResult(
                status="affected",
                confidence=confidence,
                reason="Required module or feature was observed in asset evidence.",
                reason_code="feature.observed",
                evidence=[
                    {
                        "type": "feature_condition",
                        "summary": f"Observed required module or feature: {value}.",
                        "confidence": confidence,
                        "details": {"required": value},
                    }
                    for value in matched
                ],
                rule_name=self.rule_name,
            )

        confidence = rule_confidence(context, self.rule_name, "missing_observed", 0.42)
        return RuleResult(
            status="needs_review",
            confidence=confidence,
            reason="Vulnerability requires a module or feature that asset evidence cannot confirm.",
            reason_code="feature.unconfirmed",
            evidence=[
                {
                    "type": "feature_condition",
                    "summary": "Required module or feature was not observed in the current asset profile.",
                    "confidence": confidence,
                    "details": {"required": required_values},
                }
            ],
            rule_name=self.rule_name,
        )


def _required_values(context: MatchContext) -> list[str]:
    values = []
    for key in ("requires_module", "requires_feature_flag"):
        value = context.vulnerability_conditions.get(key)
        if not value:
            continue
        if isinstance(value, str):
            values.append(value)
        else:
            values.extend(str(item) for item in value)
    return values
