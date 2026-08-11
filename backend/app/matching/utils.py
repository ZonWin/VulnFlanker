from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any


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
    product = context.vulnerability.get("product")
    from app.matching.product_aliases import product_aliases

    product_names = product_aliases(product)
    candidates: list[dict] = []

    for component in [*context.asset_components, *asset_platform_components(context)]:
        matches = _product_field_matches(
            product_names,
            {
                "component_name": component.get("component_name"),
                "component_type": component.get("component_type"),
                "source_type": component.get("source_type"),
                "install_path": component.get("install_path"),
            },
        )
        if matches:
            candidates.append(
                {
                    "kind": "component",
                    "product_matches": matches,
                    **component,
                }
            )

    for exposure in context.asset_exposures:
        matches = _product_field_matches(
            product_names,
            {
                "product": exposure.get("product"),
                "service_name": exposure.get("service_name"),
                "banner": exposure.get("banner"),
            },
        )
        if matches:
            candidates.append(
                {
                    "kind": "exposure",
                    "product_matches": matches,
                    **exposure,
                }
            )

    return candidates


def _product_field_matches(
    product_names: Iterable[str | None],
    field_values: dict[str, str | None],
) -> list[dict[str, str]]:
    matches: list[dict[str, str]] = []
    for field_name, field_value in field_values.items():
        for match in matching_value_pairs(product_names, [field_value]):
            matches.append({"field": field_name, **match})
    return matches


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
