from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.matching.product_aliases import product_aliases
from app.matching.utils import name_tokens, normalize_name
from app.matching.version_rule import evaluate_version_constraint_groups, parse_constraint_groups
from app.matching.versioning import infer_observed_version_scheme


TASK_TYPE = "package_version_check"
EVIDENCE_TYPE = "package_version"
ABSENCE_EVIDENCE_TYPE = "package_absence"
VERSION_EVIDENCE_TYPES = {EVIDENCE_TYPE, "kernel_version", "os_version"}
PLATFORM_COMPONENT_TYPES = {"kernel", "operating_system"}


@dataclass(slots=True)
class PackageVersionExecution:
    status: str
    evidence: list[dict[str, object]]
    error_code: str | None = None
    error_message: str | None = None


@dataclass(slots=True)
class PackageVersionDecision:
    match_status: str | None
    confidence: float | None
    reason: str | None
    reason_code: str
    details: dict[str, object] = field(default_factory=dict)


def execute_package_version_check(
    parameters: dict[str, object],
    asset_components: list[Any],
) -> PackageVersionExecution:
    package_name = _string_value(parameters.get("package_name"))
    if not package_name:
        return PackageVersionExecution(
            status="failed",
            evidence=[],
            error_code="missing_package_name",
            error_message="package_version_check requires package_name",
        )

    component_type = _requested_component_type(parameters, package_name)
    component = _find_component(
        asset_components,
        package_name,
        component_type=component_type,
    )
    if component is None:
        if component_type in PLATFORM_COMPONENT_TYPES:
            return PackageVersionExecution(
                status="failed",
                evidence=[],
                error_code=f"missing_{'kernel' if component_type == 'kernel' else 'os'}_version",
                error_message=f"No {component_type} facts were available for {package_name}",
            )
        return PackageVersionExecution(
            status="completed",
            evidence=[
                build_package_absence_evidence(
                    package_name,
                    evidence_origin="local_worker",
                    inventory_complete=True,
                )
            ],
        )

    component_name = _string_value(_component_value(component, "component_name")) or package_name
    observed_version = _string_value(_component_value(component, "version"))
    source = _string_value(_component_value(component, "source_type")) or "asset_snapshot"
    observed_component_type = (
        _string_value(_component_value(component, "component_type")) or "package"
    )
    evidence_type = _evidence_type_for_component(observed_component_type)

    return PackageVersionExecution(
        status="completed",
        evidence=[
            {
                "evidence_type": evidence_type,
                "summary": f"Observed {component_name} {observed_version} from {source}.",
                "raw_ref": _component_value(component, "id"),
                "confidence": 0.94 if evidence_type != EVIDENCE_TYPE else 0.92,
                "details": {
                    "package_name": component_name,
                    "component_type": observed_component_type,
                    "observed_version": observed_version,
                    "source": source,
                    "ecosystem": _component_value(component, "ecosystem"),
                    "distro": _component_value(component, "distro"),
                    "distro_release": _component_value(component, "distro_release"),
                    "source_package": _component_value(component, "source_package"),
                    "binary_package": _component_value(component, "binary_package"),
                    "architecture": _component_value(component, "architecture"),
                    "flavor": _component_value(component, "flavor"),
                    "version_scheme": _component_value(component, "version_scheme"),
                },
            }
        ],
    )


def decide_package_version_match_update(
    *,
    task_status: str,
    error_code: str | None,
    evidence_items: list[Any],
    affected_versions: str | None,
    fixed_versions: str | None,
    expected_package_name: str | None = None,
    constraint_version_scheme: str | None = None,
    source_authority: str | None = None,
    authority_score: int | None = None,
) -> PackageVersionDecision:
    if task_status != "completed":
        if error_code:
            return PackageVersionDecision(
                match_status=None,
                confidence=None,
                reason=f"Verification did not complete: {error_code}.",
                reason_code="verification.task_incomplete",
                details={"error_code": error_code},
            )
        return PackageVersionDecision(
            match_status=None,
            confidence=None,
            reason=f"Verification ended with status {task_status}.",
            reason_code="verification.task_not_completed",
            details={"task_status": task_status},
        )

    absence_evidence = _first_absence_evidence(evidence_items)
    if absence_evidence is not None:
        details = _evidence_value(absence_evidence, "details_json") or {}
        package_name = (
            _string_value(details.get("package_name"))
            or _string_value(details.get("name"))
            or "component"
        )
        confidence = _confidence_value(_evidence_value(absence_evidence, "confidence"))
        evidence_origin = _string_value(details.get("evidence_origin"))
        inventory_complete = details.get("inventory_complete") is True
        identity_matches = _package_identity_matches(
            expected_package_name,
            package_name,
        )
        decision_details = {
            "expected_package_name": expected_package_name,
            "observed_package_name": package_name,
            "evidence_origin": evidence_origin,
            "inventory_complete": inventory_complete,
            "identity_matches": identity_matches,
            "source_authority": source_authority,
            "authority_score": authority_score,
        }
        if not (
            evidence_origin == "local_worker"
            and inventory_complete
            and identity_matches
        ):
            return PackageVersionDecision(
                match_status="needs_review",
                confidence=min(confidence, 0.6),
                reason=(
                    f"Verification did not find {package_name}, but the absence "
                    "evidence cannot prove the expected product is absent."
                ),
                reason_code="verification.package_absence_inconclusive",
                details=decision_details,
            )
        return PackageVersionDecision(
            match_status="not_affected",
            confidence=confidence,
            reason=f"Verification confirmed {package_name} is not installed on the asset.",
            reason_code="verification.package_absent",
            details=decision_details,
        )

    evidence = _first_version_evidence(evidence_items)
    if evidence is None:
        return PackageVersionDecision(
            match_status=None,
            confidence=None,
            reason="Verification completed without version evidence.",
            reason_code="verification.version_evidence_missing",
        )

    details = _evidence_value(evidence, "details_json") or {}
    evidence_type = _string_value(_evidence_value(evidence, "evidence_type"))
    package_name = (
        _string_value(details.get("package_name"))
        or _string_value(details.get("name"))
        or "component"
    )
    component_type = _string_value(details.get("component_type")) or _component_type_for_evidence(
        evidence_type
    )
    observed_version = _string_value(details.get("observed_version"))
    confidence = _confidence_value(_evidence_value(evidence, "confidence"))
    identity_matches = _package_identity_matches(expected_package_name, package_name)
    base_details: dict[str, object] = {
        "expected_package_name": expected_package_name,
        "observed_package_name": package_name,
        "identity_matches": identity_matches,
        "observed_version": observed_version,
        "constraint_version_scheme": constraint_version_scheme,
        "source_authority": source_authority,
        "authority_score": authority_score,
    }

    if not identity_matches:
        return PackageVersionDecision(
            match_status="needs_review",
            confidence=min(confidence, 0.6),
            reason=(
                f"Verification reported {package_name}, which does not match "
                f"the expected product identity {expected_package_name}."
            ),
            reason_code="verification.product_identity_mismatch",
            details=base_details,
        )

    if not observed_version:
        return PackageVersionDecision(
            match_status="needs_review",
            confidence=confidence,
            reason=f"Verification observed {package_name}, but no version was returned.",
            reason_code="verification.version_missing",
            details=base_details,
        )

    constraint_groups = parse_constraint_groups(affected_versions, fixed_versions)
    if not constraint_groups:
        if _affected_text_mentions_observed_version(
            package_name,
            observed_version,
            affected_versions,
        ):
            return PackageVersionDecision(
                match_status="verified",
                confidence=confidence,
                reason=(
                    f"Verification confirmed {package_name} {observed_version} "
                    "is listed in the affected version text."
                ),
                reason_code="verification.affected_version_listed",
                details=base_details,
            )
        return PackageVersionDecision(
            match_status="needs_review",
            confidence=confidence,
            reason=(
                f"Verification observed {package_name} {observed_version}, "
                "but no version constraint was available."
            ),
            reason_code="verification.constraint_missing",
            details=base_details,
        )

    for group in constraint_groups:
        for constraint in group:
            if constraint_version_scheme:
                constraint.version_scheme = constraint_version_scheme

    observed_scheme = infer_observed_version_scheme(
        observed_version,
        explicit=_string_value(details.get("version_scheme")) or None,
        ecosystem=_string_value(details.get("ecosystem")) or None,
        source_type=_string_value(details.get("source")) or None,
        component_type=component_type,
        distro=_string_value(details.get("distro")) or None,
    )

    evaluation = evaluate_version_constraint_groups(
        observed_version,
        constraint_groups,
        observed_scheme=observed_scheme,
    )
    evaluation_details = {
        **base_details,
        "observed_scheme": observed_scheme.value,
        "comparison_reason": evaluation.reason,
        "comparisons": evaluation.comparisons or [],
    }
    if evaluation.result is True:
        return PackageVersionDecision(
            match_status="verified",
            confidence=confidence,
            reason=(
                f"Verification confirmed {package_name} {observed_version} "
                "is inside the affected range."
            ),
            reason_code="verification.version_affected",
            details=evaluation_details,
        )
    if evaluation.result is False:
        return PackageVersionDecision(
            match_status="not_affected",
            confidence=confidence,
            reason=(
                f"Verification confirmed {package_name} {observed_version} "
                "is outside the affected range."
            ),
            reason_code="verification.version_not_affected",
            details=evaluation_details,
        )
    return PackageVersionDecision(
        match_status="needs_review",
        confidence=confidence,
        reason=(
            f"Verification observed {package_name} {observed_version}, "
            f"but version comparison was inconclusive: {evaluation.reason}."
        ),
        reason_code="verification.version_inconclusive",
        details=evaluation_details,
    )


def _find_component(
    asset_components: list[Any],
    package_name: str,
    *,
    component_type: str | None = None,
) -> Any | None:
    for component in asset_components:
        if component_type and _component_type(component) != component_type:
            continue
        if any(
            _package_identity_matches(package_name, observed_name)
            for observed_name in (
                _component_value(component, "component_name"),
                _component_value(component, "source_package"),
                _component_value(component, "binary_package"),
            )
        ):
            return component
    return None


def _first_version_evidence(evidence_items: list[Any]) -> Any | None:
    for evidence in evidence_items:
        if _evidence_value(evidence, "evidence_type") in VERSION_EVIDENCE_TYPES:
            return evidence
    return None


def _first_absence_evidence(evidence_items: list[Any]) -> Any | None:
    for evidence in evidence_items:
        if _evidence_value(evidence, "evidence_type") == ABSENCE_EVIDENCE_TYPE:
            return evidence
    return None


def build_package_absence_evidence(
    package_name: str,
    *,
    source: str = "asset_component_inventory",
    confidence: float = 0.95,
    evidence_origin: str = "unknown",
    inventory_complete: bool = False,
) -> dict[str, object]:
    return {
        "evidence_type": ABSENCE_EVIDENCE_TYPE,
        "summary": f"Package {package_name} was not observed in the asset package inventory.",
        "raw_ref": None,
        "confidence": confidence,
        "details": {
            "package_name": package_name,
            "component_type": "package",
            "observed": False,
            "source": source,
            "evidence_origin": evidence_origin,
            "inventory_complete": inventory_complete,
        },
    }


def _package_identity_matches(expected: str | None, observed: object) -> bool:
    expected_key = normalize_name(expected)
    observed_text = _string_value(observed)
    observed_key = normalize_name(observed_text)
    if not expected_key or not observed_key:
        return False
    if expected_key == observed_key:
        return True
    alias_keys = {normalize_name(alias) for alias in product_aliases(expected)}
    if observed_key in alias_keys:
        return True
    observed_tokens = name_tokens(observed_text)
    return bool(observed_tokens and normalize_name(observed_tokens[0]) in alias_keys)


def _evidence_value(evidence: Any, field_name: str) -> Any:
    if isinstance(evidence, dict):
        if field_name == "details_json":
            return evidence.get("details_json") or evidence.get("details")
        return evidence.get(field_name)
    return getattr(evidence, field_name, None)


def _component_value(component: Any, field_name: str) -> Any:
    if isinstance(component, dict):
        return component.get(field_name)
    return getattr(component, field_name, None)


def _component_type(component: Any) -> str:
    return _normalize_component_type(_component_value(component, "component_type"))


def _requested_component_type(
    parameters: dict[str, object],
    package_name: str,
) -> str | None:
    explicit = _normalize_component_type(parameters.get("component_type"))
    if explicit:
        return explicit

    package_key = normalize_name(package_name)
    if package_key in {
        "linuxkernel",
        "kernel",
        "linuximage",
        "linuximagegeneric",
        "linuxheaders",
    }:
        return "kernel"
    if package_key in {
        "ubuntu",
        "ubuntulinux",
        "debian",
        "debianlinux",
        "redhatenterpriselinux",
        "rhel",
        "redhat",
        "redhatlinux",
        "centos",
        "centoslinux",
        "rockylinux",
        "rocky",
        "almalinux",
        "amazonlinux",
        "amzn",
        "amzn2",
    }:
        return "operating_system"
    return None


def _normalize_component_type(value: object) -> str:
    key = normalize_name(_string_value(value))
    if key == "kernel":
        return "kernel"
    if key in {"operatingsystem", "os"}:
        return "operating_system"
    if key == "package":
        return "package"
    return ""


def _evidence_type_for_component(component_type: str) -> str:
    normalized = _normalize_component_type(component_type)
    if normalized == "kernel":
        return "kernel_version"
    if normalized == "operating_system":
        return "os_version"
    return EVIDENCE_TYPE


def _component_type_for_evidence(evidence_type: str) -> str:
    if evidence_type == "kernel_version":
        return "kernel"
    if evidence_type == "os_version":
        return "operating_system"
    return "package"


def _affected_text_mentions_observed_version(
    package_name: str,
    observed_version: str,
    affected_versions: str | None,
) -> bool:
    if not affected_versions:
        return False
    text_key = normalize_name(affected_versions)
    version_key = normalize_name(observed_version)
    name_keys = {normalize_name(package_name)}
    name_keys.update(normalize_name(alias) for alias in product_aliases(package_name))
    return bool(
        version_key
        and version_key in text_key
        and any(name_key and name_key in text_key for name_key in name_keys)
    )


def _string_value(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _confidence_value(value: object) -> float:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(confidence, 1.0))
