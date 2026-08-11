from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any

from app.matching.product_identity import (
    MIN_PRODUCT_CANDIDATE_SCORE,
    PRODUCT_MATCH_SCORES,
    product_match_strength,
)


LOOSE_TOKEN_BLOCKLIST = {
    "apache",
    "core",
    "http",
    "kernel",
    "linux",
    "server",
    "service",
    "ssh",
}


def normalize_name(value: str | None) -> str:
    if not value:
        return ""
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def name_tokens(value: str | None) -> list[str]:
    if not value:
        return []
    return re.findall(r"[a-z0-9]+", value.lower())


def values_match(expected: str | None, candidates: Iterable[str | None]) -> bool:
    return bool(matching_value_pairs([expected], candidates))


def matching_value_pairs(
    expected_values: Iterable[str | None],
    candidates: Iterable[str | None],
) -> list[dict[str, str]]:
    matches: list[dict[str, str]] = []
    for expected in expected_values:
        for candidate in candidates:
            basis = value_match_basis(expected, candidate)
            if basis:
                matches.append(
                    {
                        "expected": str(expected),
                        "candidate": str(candidate),
                        "basis": basis,
                    }
                )
    return matches


def value_match_basis(expected: str | None, candidate: str | None) -> str | None:
    expected_key = normalize_name(expected)
    if not expected_key:
        return None
    candidate_key = normalize_name(candidate)
    if not candidate_key:
        return None
    if candidate_key == expected_key:
        return "exact"

    candidate_tokens = set(name_tokens(candidate))
    if (
        expected_key not in LOOSE_TOKEN_BLOCKLIST
        and len(expected_key) >= 4
        and expected_key in candidate_tokens
    ):
        return "token"
    return None


def values_match_any(expected_values: Iterable[str | None], candidates: Iterable[str | None]) -> bool:
    return bool(matching_value_pairs(expected_values, candidates))


def extract_conditions(notes: str | None) -> dict[str, Any]:
    if not notes:
        return {}
    try:
        parsed = json.loads(notes)
    except json.JSONDecodeError:
        return {}
    if isinstance(parsed, dict):
        return parsed
    return {}


def product_candidates(context: Any) -> list[dict]:
    if context.product_candidate_cache is not None:
        return context.product_candidate_cache

    product = context.vulnerability.get("product")
    from app.matching.product_aliases import product_aliases

    product_names = product_aliases(product)
    candidates: list[dict] = []

    for component in [*context.asset_components, *asset_platform_components(context)]:
        matches = _component_product_matches(
            context.vulnerability,
            component,
            product_names,
        )
        if matches:
            candidates.append(_scored_candidate("component", component, matches))

    for exposure in context.asset_exposures:
        matches = _exposure_product_matches(
            product,
            exposure,
            product_names,
        )
        if matches:
            candidates.append(_scored_candidate("exposure", exposure, matches))

    context.product_candidate_cache = _deduplicate_product_candidates(
        context.vulnerability,
        candidates,
    )
    return context.product_candidate_cache


def _component_product_matches(
    vulnerability: dict[str, Any],
    component: dict[str, Any],
    product_names: list[str],
) -> list[dict[str, Any]]:
    product = vulnerability.get("product")
    scope = vulnerability.get("affected_scope") or {}
    matches: list[dict[str, Any]] = []

    for field_name in ("purl", "cpe"):
        expected = scope.get(field_name) or vulnerability.get(field_name)
        candidate = component.get(field_name)
        if _identifiers_equal(expected, candidate):
            matches.append(
                _scored_match(field_name, expected, candidate, "identifier")
            )

    expected_packages = _unique_values(
        scope.get("source_package"),
        scope.get("binary_package"),
        vulnerability.get("source_package"),
        vulnerability.get("binary_package"),
    )
    for expected in expected_packages:
        for field_name in ("source_package", "binary_package", "component_name"):
            candidate = component.get(field_name)
            if _names_equal(expected, candidate):
                matches.append(_scored_match(field_name, expected, candidate, "package"))

    component_name = component.get("component_name")
    if str(component.get("component_type") or "").lower() == "package":
        component_tokens = name_tokens(component_name)
        for expected in product_names:
            if component_tokens and normalize_name(expected) == component_tokens[0]:
                matches.append(
                    _scored_match("component_name", expected, component_name, "package")
                )
    if _names_equal(product, component_name):
        matches.append(_scored_match("component_name", product, component_name, "exact"))
    else:
        matches.extend(
            _alias_or_token_matches(
                product_names,
                "component_name",
                component_name,
            )
        )

    matches.extend(
        _context_matches(product_names, "install_path", component.get("install_path"))
    )
    return _unique_matches(matches)


def _exposure_product_matches(
    product: str | None,
    exposure: dict[str, Any],
    product_names: list[str],
) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    observed_product = exposure.get("product")
    if _names_equal(product, observed_product):
        matches.append(_scored_match("product", product, observed_product, "exact"))
    else:
        matches.extend(
            _alias_or_token_matches(product_names, "product", observed_product)
        )
    matches.extend(
        _alias_or_token_matches(
            product_names,
            "service_name",
            exposure.get("service_name"),
        )
    )
    matches.extend(_context_matches(product_names, "banner", exposure.get("banner")))
    return _unique_matches(matches)


def _alias_or_token_matches(
    expected_values: Iterable[str | None],
    field_name: str,
    candidate: str | None,
) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for expected in expected_values:
        basis = value_match_basis(expected, candidate)
        if basis == "exact":
            matches.append(_scored_match(field_name, expected, candidate, "alias"))
        elif basis == "token":
            matches.append(_scored_match(field_name, expected, candidate, "token"))
    return matches


def _context_matches(
    expected_values: Iterable[str | None],
    field_name: str,
    candidate: str | None,
) -> list[dict[str, Any]]:
    if not candidate:
        return []
    candidate_key = normalize_name(candidate)
    candidate_tokens = set(name_tokens(candidate))
    for expected in expected_values:
        expected_key = normalize_name(expected)
        if expected_key and (
            expected_key in candidate_key or expected_key in candidate_tokens
        ):
            return [_scored_match(field_name, expected, candidate, "context")]
    return []


def _scored_match(
    field_name: str,
    expected: object,
    candidate: object,
    strength: str,
) -> dict[str, Any]:
    return {
        "field": field_name,
        "expected": str(expected),
        "candidate": str(candidate),
        "basis": strength,
        "strength": strength,
        "score": PRODUCT_MATCH_SCORES[strength],
    }


def _scored_candidate(
    kind: str,
    observed: dict[str, Any],
    matches: list[dict[str, Any]],
) -> dict[str, Any]:
    score = max(int(match["score"]) for match in matches)
    return {
        **observed,
        "kind": kind,
        "product_matches": matches,
        "match_score": score,
        "match_strength": product_match_strength(score),
    }


def _deduplicate_product_candidates(
    vulnerability: dict[str, Any],
    candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    candidates = [
        candidate
        for candidate in candidates
        if int(candidate.get("match_score") or 0) >= MIN_PRODUCT_CANDIDATE_SCORE
    ]
    if _is_generic_kernel_scope(vulnerability):
        kernel_candidates = [
            candidate for candidate in candidates if _is_kernel_candidate(candidate)
        ]
        if len(kernel_candidates) > 1:
            preferred = max(
                kernel_candidates,
                key=lambda candidate: (
                    str(candidate.get("source_type") or "").lower() == "uname",
                    int(candidate.get("match_score") or 0),
                ),
            )
            related = [
                _observation_summary(candidate)
                for candidate in kernel_candidates
                if candidate is not preferred
            ]
            preferred = {**preferred, "related_observations": related}
            candidates = [
                candidate
                for candidate in candidates
                if candidate not in kernel_candidates
            ]
            candidates.append(preferred)

    deduplicated: dict[tuple[object, ...], dict[str, Any]] = {}
    for candidate in candidates:
        key = _candidate_identity_key(candidate)
        existing = deduplicated.get(key)
        if existing is None:
            deduplicated[key] = candidate
            continue
        if int(candidate.get("match_score") or 0) > int(
            existing.get("match_score") or 0
        ):
            existing, candidate = candidate, existing
            deduplicated[key] = existing
        existing.setdefault("related_observations", []).append(
            _observation_summary(candidate)
        )
    return sorted(
        deduplicated.values(),
        key=lambda candidate: (
            -int(candidate.get("match_score") or 0),
            str(candidate.get("id") or ""),
        ),
    )


def _is_generic_kernel_scope(vulnerability: dict[str, Any]) -> bool:
    from app.matching.product_aliases import product_aliases

    scope = vulnerability.get("affected_scope") or {}
    if any(
        scope.get(field)
        for field in ("source_package", "binary_package", "purl", "cpe")
    ):
        return False
    aliases = {
        normalize_name(value)
        for value in product_aliases(vulnerability.get("product"))
    }
    return normalize_name("linux kernel") in aliases


def _is_kernel_candidate(candidate: dict[str, Any]) -> bool:
    if str(candidate.get("component_type") or "").lower() == "kernel":
        return True
    names = _unique_values(
        candidate.get("component_name"),
        candidate.get("source_package"),
        candidate.get("binary_package"),
    )
    return any(
        normalize_name(name).startswith(("linuximage", "linuxheaders"))
        or normalize_name(name) in {"linux", "linuxkernel", "kernel"}
        for name in names
    )


def _candidate_identity_key(candidate: dict[str, Any]) -> tuple[object, ...]:
    for field_name in ("purl", "cpe"):
        value = candidate.get(field_name)
        if value:
            return (candidate.get("kind"), field_name, str(value).strip().lower())
    return (
        candidate.get("kind"),
        normalize_name(candidate.get("ecosystem")),
        normalize_name(candidate.get("distro")),
        normalize_name(candidate.get("distro_release")),
        normalize_name(candidate.get("source_package")),
        normalize_name(candidate.get("binary_package")),
        normalize_name(candidate.get("component_name") or candidate.get("product")),
        str(candidate.get("version") or ""),
    )


def _observation_summary(candidate: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": candidate.get("id"),
        "kind": candidate.get("kind"),
        "name": candidate.get("component_name") or candidate.get("product"),
        "version": candidate.get("version"),
        "source_type": candidate.get("source_type"),
        "match_score": candidate.get("match_score"),
    }


def _names_equal(left: object, right: object) -> bool:
    left_name = normalize_name(str(left or ""))
    return bool(left_name) and left_name == normalize_name(str(right or ""))


def _identifiers_equal(left: object, right: object) -> bool:
    left_identifier = str(left or "").strip().lower()
    return bool(left_identifier) and left_identifier == str(right or "").strip().lower()


def _unique_values(*values: object) -> list[str]:
    return list(dict.fromkeys(str(value) for value in values if value))


def _unique_matches(matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[tuple[object, ...], dict[str, Any]] = {}
    for match in matches:
        key = (
            match.get("field"),
            match.get("expected"),
            match.get("candidate"),
            match.get("strength"),
        )
        unique[key] = match
    return sorted(
        unique.values(),
        key=lambda match: (
            -int(match.get("score") or 0),
            str(match.get("field") or ""),
        ),
    )


def asset_platform_components(context: Any) -> list[dict]:
    asset = context.asset or {}
    candidates: list[dict] = []
    os_family = asset.get("os_family")
    platform = asset.get("platform")
    os_version = asset.get("os_version")
    kernel_version = asset.get("kernel_version")
    architecture = asset.get("architecture")
    distro = str(os_family).lower() if os_family else None
    distro_release = str(os_version) if os_version else None
    package_ecosystem = (
        "deb"
        if distro in {"ubuntu", "debian"}
        else "rpm"
        if distro in {"rhel", "redhat", "centos", "rocky", "almalinux", "amzn"}
        else None
    )

    if os_family or platform or os_version:
        os_name = str(os_family or platform or "operating system")
        candidates.append(
            {
                "id": f"{asset.get('id') or context.asset_id}:os",
                "component_name": os_name,
                "component_type": "operating_system",
                "version": os_version,
                "source_type": "os-release",
                "install_path": " ".join(
                    str(value)
                    for value in (os_family, os_version)
                    if value
                )
                or None,
                "platform": platform,
                "ecosystem": package_ecosystem,
                "distro": distro,
                "distro_release": distro_release,
                "architecture": architecture,
                "version_scheme": "generic",
                "evidence_ref": "asset.os_version",
            }
        )

    if kernel_version:
        candidates.append(
            {
                "id": f"{asset.get('id') or context.asset_id}:kernel",
                "component_name": "Linux Kernel",
                "component_type": "kernel",
                "version": kernel_version,
                "source_type": "uname",
                "ecosystem": package_ecosystem,
                "distro": distro,
                "distro_release": distro_release,
                "source_package": "linux" if package_ecosystem == "deb" else "kernel",
                "architecture": architecture,
                "flavor": _kernel_flavor(str(kernel_version)),
                "version_scheme": (
                    "ubuntu_kernel" if distro == "ubuntu" else "generic"
                ),
                "install_path": " ".join(
                    str(value) for value in (platform, kernel_version) if value
                )
                or None,
                "evidence_ref": "asset.kernel_version",
            }
        )

    return candidates


def _kernel_flavor(version: str) -> str | None:
    match = re.search(r"-\d+(?:\.\d+)?-([a-z][a-z0-9-]*)$", version.lower())
    return match.group(1) if match else None


def public_exposures_for_product(context: Any) -> list[dict]:
    product = context.vulnerability.get("product")
    from app.matching.product_aliases import product_aliases

    product_names = product_aliases(product)
    matches: list[dict] = []
    for exposure in context.asset_exposures:
        if not exposure.get("is_public"):
            continue
        if not product_names or values_match_any(
            product_names,
            (
                exposure.get("product"),
                exposure.get("service_name"),
                exposure.get("banner"),
            ),
        ):
            matches.append(exposure)
    return matches


def listening_exposures_for_product(context: Any) -> list[dict]:
    product = context.vulnerability.get("product")
    from app.matching.product_aliases import product_aliases

    product_names = product_aliases(product)
    matches: list[dict] = []
    for exposure in context.asset_exposures:
        if exposure.get("state") and str(exposure.get("state")).lower() != "open":
            continue
        if not product_names or values_match_any(
            product_names,
            (
                exposure.get("product"),
                exposure.get("service_name"),
                exposure.get("banner"),
            ),
        ):
            matches.append(exposure)
    return matches
