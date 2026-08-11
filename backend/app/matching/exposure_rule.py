from __future__ import annotations

from app.matching.base import MatchContext, MatchRule, RuleResult, rule_confidence
from app.matching.utils import listening_exposures_for_product, public_exposures_for_product


class ExposureRule(MatchRule):
    rule_name = "exposure_rule"

    def evaluate(self, context: MatchContext) -> RuleResult:
        requires_public_access = context.vulnerability_conditions.get("requires_public_access")
        if requires_public_access is not True:
            confidence = rule_confidence(context, self.rule_name, "not_applicable", 0.0)
            return RuleResult(
                status="not_applicable",
                confidence=confidence,
                reason="No public exposure requirement is defined for this vulnerability.",
                reason_code="exposure.not_required",
                evidence=[],
                rule_name=self.rule_name,
            )

        exposures = public_exposures_for_product(context)
        if not exposures:
            listening_exposures = listening_exposures_for_product(context)
            if listening_exposures:
                confidence = rule_confidence(
                    context,
                    self.rule_name,
                    "local_listening",
                    0.55,
                )
                return RuleResult(
                    status="needs_review",
                    confidence=confidence,
                    reason=(
                        "Vulnerability requires public access; matching local listening "
                        "service exists but public reachability was not observed."
                    ),
                    reason_code="exposure.local_only",
                    evidence=[
                        {
                            "type": "listening_exposure",
                            "summary": (
                                "Matching service is listening locally, but it is not marked "
                                "as public exposure."
                            ),
                            "raw_ref": exposure.get("id"),
                            "confidence": confidence,
                            "details": {
                                "address": exposure.get("address"),
                                "port": exposure.get("port"),
                                "protocol": exposure.get("protocol"),
                                "service_name": exposure.get("service_name"),
                                "product": exposure.get("product"),
                                "is_public": exposure.get("is_public"),
                            },
                        }
                        for exposure in listening_exposures
                    ],
                    rule_name=self.rule_name,
                )

            confidence = rule_confidence(
                context,
                self.rule_name,
                "no_public_exposure",
                0.8,
            )
            return RuleResult(
                status="not_affected",
                confidence=confidence,
                reason="Vulnerability requires public access, but no matching public exposure was observed.",
                reason_code="exposure.not_public",
                evidence=[
                    {
                        "type": "public_exposure",
                        "summary": "No matching public exposure was observed.",
                        "confidence": confidence,
                        "details": {
                            "public_exposure_count": sum(
                                1
                                for exposure in context.asset_exposures
                                if exposure.get("is_public")
                            ),
                            "listening_exposure_count": len(context.asset_exposures),
                        },
                    }
                ],
                rule_name=self.rule_name,
            )

        confidence = rule_confidence(context, self.rule_name, "public_exposure", 0.76)
        return RuleResult(
            status="affected",
            confidence=confidence,
            reason="Vulnerability requires public access and the asset has matching public exposure.",
            reason_code="exposure.public",
            evidence=[
                {
                    "type": "public_exposure",
                    "summary": (
                        "Matching public exposure observed on "
                        f"{exposure.get('protocol')}/{exposure.get('port')}."
                    ),
                    "raw_ref": exposure.get("id"),
                    "confidence": confidence,
                    "details": {
                        "address": exposure.get("address"),
                        "port": exposure.get("port"),
                        "protocol": exposure.get("protocol"),
                        "service_name": exposure.get("service_name"),
                        "product": exposure.get("product"),
                        "is_public": exposure.get("is_public"),
                        "exposure_kind": exposure.get("exposure_kind"),
                    },
                }
                for exposure in exposures
            ],
            rule_name=self.rule_name,
        )
