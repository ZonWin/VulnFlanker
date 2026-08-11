from __future__ import annotations

from app.matching.base import MatchContext, MatchRule, RuleResult, rule_confidence
from app.matching.utils import normalize_name


class OperatingSystemRule(MatchRule):
    rule_name = "os_rule"

    def evaluate(self, context: MatchContext) -> RuleResult:
        affected_os = context.vulnerability_conditions.get("affected_os")
        if not affected_os:
            confidence = rule_confidence(context, self.rule_name, "not_applicable", 0.0)
            return RuleResult(
                status="not_applicable",
                confidence=confidence,
                reason="No operating system restriction is defined for this vulnerability.",
                reason_code="os.not_restricted",
                evidence=[],
                rule_name=self.rule_name,
            )

        if isinstance(affected_os, str):
            affected_os_values = [affected_os]
        else:
            affected_os_values = list(affected_os)

        asset_values = [
            context.asset.get("platform"),
            context.asset.get("os_family"),
            context.asset.get("os_version"),
        ]
        asset_keys = [normalize_name(value) for value in asset_values if value]
        expected_keys = [normalize_name(str(value)) for value in affected_os_values]
        matched = any(
            expected and any(expected in asset_key or asset_key in expected for asset_key in asset_keys)
            for expected in expected_keys
        )

        if matched:
            confidence = rule_confidence(context, self.rule_name, "matched", 0.72)
            return RuleResult(
                status="affected",
                confidence=confidence,
                reason="Asset operating system matches the vulnerability restriction.",
                reason_code="os.matched",
                evidence=[
                    {
                        "type": "os_condition",
                        "summary": "Asset OS is inside the vulnerability affected OS set.",
                        "confidence": confidence,
                        "details": {
                            "asset_os": asset_values,
                            "affected_os": affected_os_values,
                        },
                    }
                ],
                rule_name=self.rule_name,
            )

        confidence = rule_confidence(context, self.rule_name, "not_matched", 0.84)
        return RuleResult(
            status="not_affected",
            confidence=confidence,
            reason="Asset operating system does not match the vulnerability restriction.",
            reason_code="os.not_matched",
            evidence=[
                {
                    "type": "os_condition",
                    "summary": "Asset OS is outside the vulnerability affected OS set.",
                    "confidence": confidence,
                    "details": {
                        "asset_os": asset_values,
                        "affected_os": affected_os_values,
                    },
                }
            ],
            rule_name=self.rule_name,
        )
