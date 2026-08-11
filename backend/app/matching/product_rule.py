from __future__ import annotations

from app.matching.base import MatchContext, MatchRule, RuleResult, rule_confidence
from app.matching.product_aliases import product_aliases
from app.matching.product_identity import MIN_CONCLUSIVE_PRODUCT_SCORE
from app.matching.utils import product_candidates


class ProductRule(MatchRule):
    rule_name = "product_rule"

    def evaluate(self, context: MatchContext) -> RuleResult:
        product = context.vulnerability.get("product")
        if not product:
            confidence = rule_confidence(context, self.rule_name, "missing_product", 0.2)
            return RuleResult(
                status="needs_review",
                confidence=confidence,
                reason="Vulnerability has no normalized product field.",
                reason_code="product.missing",
                evidence=[
                    {
                        "type": "product_unavailable",
                        "summary": "No vulnerability product is available for candidate selection.",
                    }
                ],
                rule_name=self.rule_name,
            )

        aliases = product_aliases(product)
        candidates = product_candidates(context)
        if not candidates:
            confidence = rule_confidence(context, self.rule_name, "no_candidate", 0.82)
            return RuleResult(
                status="not_affected",
                confidence=confidence,
                reason=f"No asset component or exposure matched product {product}.",
                reason_code="product.no_match",
                evidence=[
                    {
                        "type": "product_no_match",
                        "summary": f"No observed asset component or exposure matched {product}.",
                        "details": {"expected_product": product, "aliases": aliases},
                    }
                ],
                rule_name=self.rule_name,
            )

        conclusive_candidates = [
            candidate
            for candidate in candidates
            if int(candidate.get("match_score") or 0) >= MIN_CONCLUSIVE_PRODUCT_SCORE
        ]
        if not conclusive_candidates:
            confidence = rule_confidence(context, self.rule_name, "weak_candidate", 0.45)
            return RuleResult(
                status="needs_review",
                confidence=confidence,
                reason=(
                    f"Only weak contextual evidence matched product {product}; "
                    "a product identity match is still required."
                ),
                reason_code="product.weak_candidate",
                evidence=[
                    _candidate_evidence(
                        candidate,
                        product=product,
                        aliases=aliases,
                        confidence=confidence,
                        evidence_type="product_candidate",
                    )
                    for candidate in candidates
                ],
                rule_name=self.rule_name,
            )

        confidence = rule_confidence(context, self.rule_name, "matched", 0.78)
        evidence = [
            _candidate_evidence(
                candidate,
                product=product,
                aliases=aliases,
                confidence=confidence,
                evidence_type="product_match",
            )
            for candidate in conclusive_candidates
        ]
        return RuleResult(
            status="affected",
            confidence=confidence,
            reason=f"Asset has observed evidence for product {product}.",
            reason_code="product.matched",
            evidence=evidence,
            rule_name=self.rule_name,
        )


def _candidate_evidence(
    candidate: dict,
    *,
    product: str,
    aliases: list[str],
    confidence: float,
    evidence_type: str,
) -> dict:
    label = candidate.get("component_name") or candidate.get("product")
    product_matches = candidate.get("product_matches") or []
    return {
        "type": evidence_type,
        "summary": (
            f"Observed {candidate['kind']} matched product {product} "
            f"with {candidate.get('match_strength', 'unknown')} strength: {label}."
        ),
        "raw_ref": candidate.get("id"),
        "confidence": confidence,
        "details": {
            "kind": candidate["kind"],
            "name": label,
            "version": candidate.get("version"),
            "expected_product": product,
            "aliases": aliases,
            "match_score": candidate.get("match_score"),
            "match_strength": candidate.get("match_strength"),
            "matched_aliases": sorted(
                {
                    str(match.get("expected"))
                    for match in product_matches
                    if match.get("expected")
                }
            ),
            "matched_fields": product_matches,
            "related_observations": candidate.get("related_observations") or [],
        },
    }
