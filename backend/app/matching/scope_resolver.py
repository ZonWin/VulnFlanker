from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.matching.utils import normalize_name


UBUNTU_RELEASES = {
    "trusty": "14.04",
    "xenial": "16.04",
    "bionic": "18.04",
    "focal": "20.04",
    "jammy": "22.04",
    "noble": "24.04",
    "oracular": "24.10",
    "plucky": "25.04",
    "questing": "25.10",
    "resolute": "26.04",
}

DISTRO_ALIASES = {
    "ubuntu": {"ubuntu", "ubuntulinux"},
    "debian": {"debian", "debianlinux"},
    "rhel": {"rhel", "redhat", "redhatenterpriselinux"},
    "centos": {"centos", "centoslinux"},
    "rocky": {"rocky", "rockylinux"},
    "almalinux": {"alma", "almalinux"},
    "amzn": {"amzn", "amazonlinux"},
    "windows": {"windows", "microsoftwindows"},
    "macos": {"macos", "osx", "macosx"},
}

ARCHITECTURE_ALIASES = {
    "x8664": {"x8664", "amd64"},
    "aarch64": {"aarch64", "arm64"},
    "i386": {"i386", "i486", "i586", "i686", "x86"},
}


@dataclass(slots=True)
class ScopeResolution:
    applicable: list[Any] = field(default_factory=list)
    selected: list[Any] = field(default_factory=list)
    excluded: list[dict[str, str | None]] = field(default_factory=list)


def resolve_affected_scopes(asset: Any, scopes: list[Any]) -> ScopeResolution:
    applicable: list[Any] = []
    excluded: list[dict[str, str | None]] = []
    for scope in scopes:
        applies, reason = scope_applies_to_asset(asset, scope)
        if applies:
            applicable.append(scope)
        else:
            excluded.append(
                {
                    "scope_id": _text(_value(scope, "id")),
                    "reason": reason,
                }
            )

    if not applicable:
        return ScopeResolution(excluded=excluded)

    highest_rank = max(_scope_rank(scope) for scope in applicable)
    selected = [scope for scope in applicable if _scope_rank(scope) == highest_rank]
    for scope in applicable:
        if scope not in selected:
            excluded.append(
                {
                    "scope_id": _text(_value(scope, "id")),
                    "reason": "superseded_by_more_authoritative_specific_scope",
                }
            )
    return ScopeResolution(
        applicable=applicable,
        selected=selected,
        excluded=excluded,
    )


def scope_applies_to_asset(asset: Any, scope: Any) -> tuple[bool, str | None]:
    asset_distro = _canonical_distro(
        _value(asset, "os_family") or _value(asset, "platform")
    )
    scope_distro = _canonical_distro(_value(scope, "distro"))
    if scope_distro and scope_distro != asset_distro:
        return False, "distro_mismatch"

    scope_release = _value(scope, "distro_release")
    if scope_release and not _releases_match(
        scope_release,
        _value(asset, "os_version"),
    ):
        return False, "distro_release_mismatch"

    scope_ecosystem = normalize_name(_value(scope, "ecosystem"))
    if scope_ecosystem and scope_ecosystem not in _asset_ecosystems(asset):
        return False, "ecosystem_mismatch"

    scope_architecture = _canonical_architecture(_value(scope, "architecture"))
    asset_architecture = _canonical_architecture(_value(asset, "architecture"))
    if scope_architecture and (
        not asset_architecture or scope_architecture != asset_architecture
    ):
        return False, "architecture_mismatch"

    package_names = _asset_package_names(asset)
    source_package = normalize_name(_value(scope, "source_package"))
    if source_package and source_package not in package_names:
        return False, "source_package_mismatch"
    binary_package = normalize_name(_value(scope, "binary_package"))
    if binary_package and binary_package not in package_names:
        return False, "binary_package_mismatch"

    scope_flavor = normalize_name(_value(scope, "flavor"))
    if scope_flavor and scope_flavor not in _asset_flavors(asset):
        return False, "flavor_mismatch"

    if not _platforms_apply(asset, _value(scope, "platforms_json") or []):
        return False, "platform_mismatch"
    return True, None


def scope_specificity(scope: Any) -> int:
    weighted_fields = {
        "distro": 2,
        "distro_release": 3,
        "source_package": 4,
        "binary_package": 4,
        "architecture": 2,
        "flavor": 3,
        "purl": 5,
        "cpe": 5,
    }
    score = sum(
        weight
        for field_name, weight in weighted_fields.items()
        if _value(scope, field_name)
    )
    if _value(scope, "platforms_json"):
        score += 1
    return score


def _scope_rank(scope: Any) -> tuple[int, int, int]:
    authority = normalize_name(_value(scope, "source_authority"))
    is_distribution_scope = int(
        authority in {"distribution", "distributionvendor"}
        and bool(_value(scope, "distro"))
    )
    try:
        authority_score = int(_value(scope, "authority_score") or 0)
    except (TypeError, ValueError):
        authority_score = 0
    return is_distribution_scope, authority_score, scope_specificity(scope)


def _asset_package_names(asset: Any) -> set[str]:
    names: set[str] = set()
    for component in _value(asset, "components") or []:
        for field_name in ("component_name", "source_package", "binary_package"):
            name = normalize_name(_value(component, field_name))
            if name:
                names.add(name)
    distro = _canonical_distro(_value(asset, "os_family") or _value(asset, "platform"))
    if _value(asset, "kernel_version"):
        names.add("linux" if distro in {"ubuntu", "debian"} else "kernel")
    return names


def _asset_ecosystems(asset: Any) -> set[str]:
    ecosystems = {
        normalize_name(_value(component, "ecosystem"))
        for component in (_value(asset, "components") or [])
        if _value(component, "ecosystem")
    }
    distro = _canonical_distro(_value(asset, "os_family") or _value(asset, "platform"))
    if distro in {"ubuntu", "debian"}:
        ecosystems.add("deb")
    elif distro in {"rhel", "centos", "rocky", "almalinux", "amzn"}:
        ecosystems.add("rpm")
    return ecosystems


def _asset_flavors(asset: Any) -> set[str]:
    flavors = {
        normalize_name(_value(component, "flavor"))
        for component in (_value(asset, "components") or [])
        if _value(component, "flavor")
    }
    kernel_version = str(_value(asset, "kernel_version") or "").lower()
    match = re.search(r"-\d+(?:\.\d+)?-([a-z][a-z0-9-]*)$", kernel_version)
    if match:
        flavors.add(normalize_name(match.group(1)))
    known_flavors = (
        "aws",
        "azure",
        "gcp",
        "gke",
        "ibm",
        "lowlatency",
        "nvidia",
        "oem",
        "oracle",
        "raspi",
        "realtime",
    )
    for package_name in _asset_package_names(asset):
        for flavor in known_flavors:
            if flavor in package_name:
                flavors.add(normalize_name(flavor))
    return flavors


def _platforms_apply(asset: Any, platforms: list[object]) -> bool:
    if not platforms:
        return True
    asset_distro = _canonical_distro(
        _value(asset, "os_family") or _value(asset, "platform")
    )
    asset_arch = _canonical_architecture(_value(asset, "architecture"))
    known_constraints: list[bool] = []
    for platform in platforms:
        text = str(platform)
        platform_distro = _known_distro(text)
        if platform_distro:
            release_match = re.search(r"\d{2}\.\d{2}", text)
            known_constraints.append(
                platform_distro == asset_distro
                and (
                    release_match is None
                    or _releases_match(release_match.group(0), _value(asset, "os_version"))
                )
            )
            continue
        platform_arch = _known_architecture(text)
        if platform_arch:
            known_constraints.append(platform_arch == asset_arch)
    return not known_constraints or any(known_constraints)


def _canonical_distro(value: object) -> str | None:
    normalized = normalize_name(str(value or ""))
    if not normalized or normalized == "upstream":
        return None if not normalized else "upstream"
    for canonical, aliases in DISTRO_ALIASES.items():
        if normalized in aliases or any(alias in normalized for alias in aliases):
            return canonical
    return normalized


def _known_distro(value: object) -> str | None:
    normalized = normalize_name(str(value or ""))
    for canonical, aliases in DISTRO_ALIASES.items():
        if normalized in aliases or any(alias in normalized for alias in aliases):
            return canonical
    return None


def _canonical_architecture(value: object) -> str | None:
    normalized = normalize_name(str(value or ""))
    if not normalized:
        return None
    for canonical, aliases in ARCHITECTURE_ALIASES.items():
        if normalized in aliases:
            return canonical
    return normalized


def _known_architecture(value: object) -> str | None:
    normalized = normalize_name(str(value or ""))
    for canonical, aliases in ARCHITECTURE_ALIASES.items():
        if normalized in aliases:
            return canonical
    return None


def _releases_match(left: object, right: object) -> bool:
    left_aliases = _release_aliases(left)
    right_aliases = _release_aliases(right)
    return bool(left_aliases and right_aliases and left_aliases & right_aliases)


def _release_aliases(value: object) -> set[str]:
    normalized = str(value or "").strip().lower().replace("lts", "").strip()
    if not normalized:
        return set()
    aliases = {normalize_name(normalized)}
    for codename, version in UBUNTU_RELEASES.items():
        if normalized in {codename, version}:
            aliases.update({normalize_name(codename), normalize_name(version)})
    return aliases


def _value(item: Any, field_name: str) -> Any:
    if isinstance(item, dict):
        return item.get(field_name)
    return getattr(item, field_name, None)


def _text(value: object) -> str | None:
    if value is None:
        return None
    return str(value)
