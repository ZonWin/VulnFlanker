from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass(slots=True)
class MatchContext:
    asset_id: str
    vulnerability_id: str
    asset: dict = field(default_factory=dict)
    vulnerability: dict = field(default_factory=dict)
    asset_components: list[dict] = field(default_factory=list)
    asset_exposures: list[dict] = field(default_factory=list)
    vulnerability_conditions: dict = field(default_factory=dict)
    rule_confidences: dict[str, dict[str, float]] = field(default_factory=dict)
    product_candidate_cache: list[dict] | None = None


def rule_confidence(
    context: MatchContext,
    rule_name: str,
    key: str,
    default: float,
) -> float:
    try:
        return float(context.rule_confidences.get(rule_name, {}).get(key, default))
    except (TypeError, ValueError):
        return default


@dataclass(slots=True)
class RuleResult:
    status: str
    confidence: float
    reason: str
    evidence: list[dict] = field(default_factory=list)
    rule_name: str | None = None
    reason_code: str | None = None


class MatchRule(ABC):
    rule_name: str
    rule_version: str = "v1"

    @abstractmethod
    def evaluate(self, context: MatchContext) -> RuleResult:
        """Evaluate whether an asset is affected by a vulnerability."""
