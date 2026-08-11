from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from app.matching.base import MatchContext, MatchRule, RuleResult, rule_confidence
from app.matching.product_identity import MIN_CONCLUSIVE_PRODUCT_SCORE
from app.matching.utils import normalize_name, product_candidates
from app.matching.versioning import (
    VersionComparison,
    VersionScheme,
    classify_version,
    compare_version_identities,
    infer_observed_version_scheme,
    is_atomic_distro_or_commit_version,
)


VERSION_LITERAL_PATTERN = (
    r"(?:[0-9][0-9a-zA-Z.\-_+:~]*|[a-fA-F][0-9a-fA-F]{6,63})"
)


@dataclass(slots=True)
class VersionConstraint:
    operator: str
    version: str
    source: str = "affected_versions"
    derived_from: str | None = None
    version_scheme: str | None = None


@dataclass(slots=True)
class VersionEvaluation:
    result: bool | None
    reason: str | None = None
    comparisons: list[dict[str, Any]] | None = None


class VersionRule(MatchRule):
    rule_name = "version_rule"

    def evaluate(self, context: MatchContext) -> RuleResult:
        product_matches = [
            candidate
            for candidate in product_candidates(context)
            if int(candidate.get("match_score") or 0) >= MIN_CONCLUSIVE_PRODUCT_SCORE
        ]
        if not product_matches:
            confidence = rule_confidence(
                context,
                self.rule_name,
                "not_applicable",
                0.0,
            )
            return RuleResult(
                status="not_applicable",
                confidence=confidence,
                reason="Version rule was skipped because the product did not match the asset.",
                reason_code="version.product_not_matched",
                evidence=[],
                rule_name=self.rule_name,
            )

        candidates = [
            candidate
            for candidate in product_matches
            if candidate.get("version")
        ]
        if not candidates:
            confidence = rule_confidence(
                context,
                self.rule_name,
                "no_observed_version",
                0.35,
            )
            return RuleResult(
                status="needs_review",
                confidence=confidence,
                reason="No product-matched component has an observed version.",
                reason_code="version.observed_version_missing",
                evidence=[
                    {
                        "type": "package_version",
                        "summary": "Version comparison could not run without an observed version.",
                    }
                ],
                rule_name=self.rule_name,
            )

        constraint_groups = parse_constraint_groups(
            context.vulnerability.get("affected_versions"),
            context.vulnerability.get("fixed_versions"),
        )
        if not constraint_groups:
            exact_matches = [
                candidate
                for candidate in candidates
                if _affected_text_mentions_candidate_version(
                    candidate,
                    context.vulnerability.get("affected_versions"),
                )
            ]
            if exact_matches:
                confidence = rule_confidence(
                    context,
                    self.rule_name,
                    "exact_affected",
                    0.78,
                )
                return RuleResult(
                    status="affected",
                    confidence=confidence,
                    reason=(
                        "Asset OS or kernel version is explicitly listed in the "
                        "affected version text."
                    ),
                    reason_code="version.explicitly_listed",
                    evidence=[
                        _version_evidence(
                            {
                                "candidate": candidate,
                                "version": str(candidate["version"]),
                                "constraint_groups": [],
                                "comparison_reason": (
                                    "Affected text explicitly mentions this asset "
                                    "OS/kernel version."
                                ),
                                "comparisons": [],
                            },
                            "Observed asset platform version is listed as affected.",
                            confidence,
                        )
                        for candidate in exact_matches
                    ],
                    rule_name=self.rule_name,
                )

            confidence = rule_confidence(
                context,
                self.rule_name,
                "no_machine_readable_range",
                0.45,
            )
            return RuleResult(
                status="needs_review",
                confidence=confidence,
                reason="Vulnerability has no machine-readable affected or fixed version range.",
                reason_code="version.constraint_missing",
                evidence=[
                    {
                        "type": "package_version",
                        "summary": "No affected_versions or fixed_versions constraint was available.",
                    }
                ],
                rule_name=self.rule_name,
            )

        affected: list[dict[str, Any]] = []
        safe: list[dict[str, Any]] = []
        uncertain: list[dict[str, Any]] = []
        for candidate in candidates:
            version = str(candidate["version"])
            evaluation = evaluate_version_constraint_groups(
                version,
                constraint_groups,
                observed_scheme=_candidate_version_scheme(candidate),
            )
            record = {
                "candidate": candidate,
                "version": version,
                "constraint_groups": [
                    [
                        _constraint_details(constraint)
                        for constraint in group
                    ]
                    for group in constraint_groups
                ],
                "constraint_summary": _constraint_summary(constraint_groups),
                "comparison_reason": evaluation.reason,
                "comparisons": evaluation.comparisons or [],
            }
            if evaluation.result is True:
                affected.append(record)
            elif evaluation.result is False:
                safe.append(record)
            else:
                uncertain.append(record)

        if affected:
            confidence = rule_confidence(
                context,
                self.rule_name,
                "affected_range",
                0.82,
            )
            evidence = [
                _version_evidence(
                    item,
                    "Observed version is inside the affected range.",
                    confidence,
                )
                for item in affected
            ]
            return RuleResult(
                status="affected",
                confidence=confidence,
                reason="At least one matched component version is inside the affected range.",
                reason_code="version.affected_range",
                evidence=evidence,
                rule_name=self.rule_name,
            )

        if uncertain:
            confidence = rule_confidence(
                context,
                self.rule_name,
                "uncertain_comparison",
                0.5,
            )
            evidence = [
                _version_evidence(
                    item,
                    "Observed version could not be compared reliably.",
                    confidence,
                )
                for item in uncertain
            ]
            return RuleResult(
                status="needs_review",
                confidence=confidence,
                reason="Version data exists, but at least one comparison was not reliable.",
                reason_code="version.comparison_inconclusive",
                evidence=evidence,
                rule_name=self.rule_name,
            )

        confidence = rule_confidence(context, self.rule_name, "safe_range", 0.86)
        evidence = [
            _version_evidence(
                item,
                "Observed version is outside the affected range.",
                confidence,
            )
            for item in safe
        ]
        return RuleResult(
            status="not_affected",
            confidence=confidence,
            reason="All matched component versions are outside the affected range.",
            reason_code="version.safe_range",
            evidence=evidence,
            rule_name=self.rule_name,
        )


def _version_evidence(item: dict[str, Any], summary: str, confidence: float) -> dict:
    candidate = item["candidate"]
    label = candidate.get("component_name") or candidate.get("product")
    comparison_reason = item.get("comparison_reason")
    constraint_summary = item.get("constraint_summary")
    if comparison_reason:
        summary = f"{summary} Reason: {comparison_reason}"
    if constraint_summary:
        summary = f"{summary} Constraint source: {constraint_summary}"
    comparisons = item.get("comparisons", [])
    first_comparison = comparisons[0] if comparisons else {}
    return {
        "type": _version_evidence_type(candidate),
        "summary": f"{summary} {label}={item['version']}.",
        "raw_ref": candidate.get("id"),
        "confidence": confidence,
        "details": {
            "name": label,
            "version": item["version"],
            "constraints": [
                constraint
                for group in item.get("constraint_groups", [])
                for constraint in group
            ],
            "constraint_groups": item.get("constraint_groups", []),
            "constraint_summary": constraint_summary,
            "comparison_reason": comparison_reason,
            "comparisons": comparisons,
            "observed_scheme": first_comparison.get("observed_scheme"),
            "constraint_scheme": first_comparison.get("constraint_scheme"),
            "comparator": first_comparison.get("comparator"),
            "comparison_reason_code": first_comparison.get("reason_code"),
        },
    }


def parse_constraints(
    affected_versions: str | None,
    fixed_versions: str | None,
) -> list[VersionConstraint]:
    return [
        constraint
        for group in parse_constraint_groups(affected_versions, fixed_versions)
        for constraint in group
    ]


def parse_constraint_groups(
    affected_versions: str | None,
    fixed_versions: str | None,
) -> list[list[VersionConstraint]]:
    groups: list[list[VersionConstraint]] = []
    if affected_versions:
        groups.extend(_constraint_groups_from_affected_text(affected_versions))

    if fixed_versions:
        fixed = first_version(fixed_versions)
        if fixed:
            fixed_constraint = VersionConstraint(
                "<",
                fixed,
                source="fixed_versions",
                derived_from="fixed_version_implies_affected_before_fixed",
            )
            if groups:
                groups = [group + [fixed_constraint] for group in groups]
            else:
                groups.append([fixed_constraint])

    return groups


def _constraints_from_affected_text(text: str) -> list[VersionConstraint]:
    return [
        constraint
        for group in _constraint_groups_from_affected_text(text)
        for constraint in group
    ]


def _constraint_groups_from_affected_text(text: str) -> list[list[VersionConstraint]]:
    lowered = text.lower().strip()
    branches = [branch.strip() for branch in lowered.split("|") if branch.strip()]
    if len(branches) > 1:
        return [
            group
            for branch in branches
            for group in _constraint_groups_from_affected_branch(branch)
        ]
    return _constraint_groups_from_affected_branch(lowered)


def _constraint_groups_from_affected_branch(
    lowered: str,
) -> list[list[VersionConstraint]]:
    if lowered in {"all", "all versions", "*"}:
        return [[VersionConstraint(">=", "0", source="affected_versions")]]
    if is_atomic_distro_or_commit_version(lowered):
        return [[VersionConstraint("==", lowered)]]

    groups: list[list[VersionConstraint]] = []
    used_spans: list[tuple[int, int]] = []

    product_range_pattern = re.compile(
        r"(?P<lower>\d[0-9a-zA-Z.\-_+]*)\s*"
        r"(?P<lower_op><=|<)\s*[^<>=]{0,120}?\s*"
        r"(?P<upper_op><=|<)\s*v?(?P<upper>\d[0-9a-zA-Z.\-_+]*)"
    )
    for match in product_range_pattern.finditer(lowered):
        lower_operator = ">=" if match.group("lower_op") == "<=" else ">"
        groups.append(
            [
                VersionConstraint(lower_operator, match.group("lower")),
                VersionConstraint(match.group("upper_op"), match.group("upper")),
            ]
        )
        used_spans.append(match.span())

    range_pattern = re.compile(
        r"(?P<lower>\d+(?:[.\-_][0-9a-zA-Z]+)+)\s*(?:-|to|through)\s*"
        r"(?P<upper>\d+(?:[.\-_][0-9a-zA-Z]+)+)"
    )
    for match in range_pattern.finditer(lowered):
        if _span_is_used(match.span(), used_spans):
            continue
        groups.append(
            [
                VersionConstraint(">=", match.group("lower")),
                VersionConstraint("<=", match.group("upper")),
            ]
        )
        used_spans.append(match.span())

    operator_constraints: list[VersionConstraint] = []
    operator_pattern = re.compile(
        rf"(<=|>=|<|>|==|=)\s*v?({VERSION_LITERAL_PATTERN})"
    )
    for match in operator_pattern.finditer(lowered):
        if _span_is_used(match.span(), used_spans):
            continue
        operator = match.group(1)
        operator_constraints.append(
            VersionConstraint("==" if operator == "=" else operator, match.group(2))
        )
    if operator_constraints:
        groups.append(operator_constraints)

    before_match = re.search(
        rf"(?:before|prior to|earlier than|below)\s+v?({VERSION_LITERAL_PATTERN})",
        lowered,
    )
    if before_match and not _span_is_used(before_match.span(), used_spans):
        groups.append([VersionConstraint("<", before_match.group(1))])

    earlier_match = re.search(rf"v?({VERSION_LITERAL_PATTERN})\s+and earlier", lowered)
    if earlier_match and not _span_is_used(earlier_match.span(), used_spans):
        groups.append([VersionConstraint("<=", earlier_match.group(1))])

    if not groups:
        exact_match = re.fullmatch(rf"v?({VERSION_LITERAL_PATTERN})", lowered)
        if exact_match:
            groups.append([VersionConstraint("==", exact_match.group(1))])

    return groups


def first_version(text: str) -> str | None:
    match = re.search(rf"v?({VERSION_LITERAL_PATTERN})", text)
    if not match:
        return None
    return match.group(1)


def version_satisfies_constraints(
    version: str,
    constraints: list[VersionConstraint],
) -> bool | None:
    return evaluate_version_constraints(version, constraints).result


def evaluate_version_constraints(
    version: str,
    constraints: list[VersionConstraint],
    *,
    allow_metadata_mismatch: bool = False,
    observed_scheme: VersionScheme | str | None = None,
) -> VersionEvaluation:
    evaluations: list[bool] = []
    comparisons: list[dict[str, Any]] = []
    for constraint in constraints:
        comparison_result = compare_version_identities(
            version,
            constraint.version,
            left_scheme=observed_scheme,
            right_scheme=constraint.version_scheme,
        )
        compared = comparison_result.result
        reason = comparison_result.reason
        matched = (
            _apply_operator(compared, constraint.operator)
            if compared is not None
            else None
        )
        comparison = _comparison_details(
            observed_version=version,
            constraint=constraint,
            compare_result=compared,
            matched=matched,
            comparison=comparison_result,
        )
        comparisons.append(comparison)
        if compared is None:
            return VersionEvaluation(
                result=None,
                reason=reason or "Version comparison was not reliable.",
                comparisons=comparisons,
            )
        evaluations.append(matched)
    return VersionEvaluation(result=all(evaluations), comparisons=comparisons)


def evaluate_version_constraint_groups(
    version: str,
    constraint_groups: list[list[VersionConstraint]],
    *,
    allow_metadata_mismatch: bool = False,
    observed_scheme: VersionScheme | str | None = None,
) -> VersionEvaluation:
    comparisons: list[dict[str, str | int | bool | None]] = []
    uncertain_reason: str | None = None
    for group_index, constraints in enumerate(constraint_groups):
        evaluation = evaluate_version_constraints(
            version,
            constraints,
            allow_metadata_mismatch=allow_metadata_mismatch,
            observed_scheme=observed_scheme,
        )
        comparisons.extend(
            {**comparison, "group_index": group_index}
            for comparison in (evaluation.comparisons or [])
        )
        if evaluation.result is True:
            return VersionEvaluation(result=True, comparisons=comparisons)
        if evaluation.result is None:
            uncertain_reason = evaluation.reason

    if uncertain_reason:
        return VersionEvaluation(
            result=None,
            reason=uncertain_reason,
            comparisons=comparisons,
        )
    return VersionEvaluation(result=False, comparisons=comparisons)


def compare_versions(left: str, right: str) -> int | None:
    compared, _ = compare_versions_with_reason(left, right)
    return compared


def compare_versions_with_reason(
    left: str,
    right: str,
    *,
    allow_metadata_mismatch: bool = False,
) -> tuple[int | None, str | None]:
    comparison = compare_version_identities(left, right)
    return comparison.result, comparison.reason


def _has_distro_release_metadata(version: str) -> bool:
    if re.search(r"(ubuntu|debian|deb|el\d+|rhel|fc\d+|amzn)", version):
        return True
    return bool(re.search(r"-\d", version))


def _constraint_details(constraint: VersionConstraint) -> dict[str, str | None]:
    return {
        "operator": constraint.operator,
        "version": constraint.version,
        "source": constraint.source,
        "derived_from": constraint.derived_from,
        "version_scheme": constraint.version_scheme,
    }


def _constraint_summary(
    constraint_groups: list[list[VersionConstraint]],
) -> str | None:
    fixed_versions = [
        constraint.version
        for group in constraint_groups
        for constraint in group
        if constraint.derived_from == "fixed_version_implies_affected_before_fixed"
    ]
    if not fixed_versions:
        return None
    fixed_list = ", ".join(sorted(set(fixed_versions)))
    return (
        "fixed_versions is interpreted as affected versions before "
        f"{fixed_list}."
    )


def _comparison_details(
    *,
    observed_version: str,
    constraint: VersionConstraint,
    compare_result: int | None,
    matched: bool | None,
    comparison: VersionComparison,
) -> dict[str, Any]:
    return {
        "observed_version": observed_version,
        "operator": constraint.operator,
        "constraint_version": constraint.version,
        "constraint_source": constraint.source,
        "derived_from": constraint.derived_from,
        "compare_result": compare_result,
        "matched": matched,
        "reason": comparison.reason,
        "reason_code": comparison.reason_code,
        "comparator": comparison.comparator,
        "observed_scheme": comparison.left_scheme.value,
        "constraint_scheme": comparison.right_scheme.value,
        "observed_normalized": comparison.left_normalized,
        "constraint_normalized": comparison.right_normalized,
        "observed_metadata": _version_metadata_profile(observed_version),
        "constraint_metadata": _version_metadata_profile(constraint.version),
    }


def _version_metadata_profile(version: str) -> dict[str, bool | str]:
    cleaned = version.strip().lower()
    return {
        "scheme": classify_version(cleaned).value,
        "has_epoch": ":" in cleaned,
        "has_distro_release_metadata": _has_distro_release_metadata(cleaned),
        "has_tilde": "~" in cleaned,
    }


def _span_is_used(span: tuple[int, int], used_spans: list[tuple[int, int]]) -> bool:
    start, end = span
    return any(
        start >= used_start and end <= used_end
        for used_start, used_end in used_spans
    )


def _version_evidence_type(candidate: dict[str, Any]) -> str:
    component_type = candidate.get("component_type")
    if component_type == "operating_system":
        return "os_version"
    if component_type == "kernel":
        return "kernel_version"
    return "package_version"


def _candidate_version_scheme(candidate: dict[str, Any]) -> VersionScheme:
    return infer_observed_version_scheme(
        str(candidate.get("version") or ""),
        explicit=candidate.get("version_scheme"),
        ecosystem=candidate.get("ecosystem"),
        source_type=candidate.get("source_type"),
        component_type=candidate.get("component_type"),
        distro=candidate.get("distro"),
    )


def _affected_text_mentions_candidate_version(
    candidate: dict[str, Any],
    affected_versions: str | None,
) -> bool:
    if candidate.get("component_type") not in {"operating_system", "kernel"}:
        return False
    version = candidate.get("version")
    if not affected_versions or not version:
        return False

    text_key = normalize_name(affected_versions)
    version_key = normalize_name(str(version))
    if not version_key or version_key not in text_key:
        return False

    name_keys = [
        normalize_name(str(value))
        for value in (
            candidate.get("component_name"),
            candidate.get("source_type"),
            candidate.get("install_path"),
        )
        if value
    ]
    return any(name_key and name_key in text_key for name_key in name_keys)


def _apply_operator(compared: int, operator: str) -> bool:
    if operator == "<":
        return compared < 0
    if operator == "<=":
        return compared <= 0
    if operator == ">":
        return compared > 0
    if operator == ">=":
        return compared >= 0
    if operator == "==":
        return compared == 0
    return False
