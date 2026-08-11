from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from itertools import zip_longest


class VersionScheme(StrEnum):
    GENERIC = "generic"
    DEBIAN = "debian"
    RPM = "rpm"
    UBUNTU_KERNEL = "ubuntu_kernel"
    GIT_COMMIT = "git_commit"
    OPAQUE = "opaque"


@dataclass(frozen=True, slots=True)
class VersionComparison:
    result: int | None
    left_scheme: VersionScheme
    right_scheme: VersionScheme
    comparator: str | None
    reason: str | None = None
    reason_code: str | None = None
    left_normalized: str | None = None
    right_normalized: str | None = None


_GIT_COMMIT_RE = re.compile(r"[0-9a-f]{7,64}", re.IGNORECASE)
_UBUNTU_KERNEL_UNAME_RE = re.compile(
    r"(?P<base>\d+\.\d+\.\d+)-(?P<abi>\d+)"
    r"(?:\.(?P<upload>\d+))?(?:-(?P<flavor>[a-z][a-z0-9-]*))?",
    re.IGNORECASE,
)
_UBUNTU_KERNEL_PACKAGE_RE = re.compile(
    r"(?P<base>\d+\.\d+\.\d+)\.(?P<abi>\d+)\.(?P<upload>\d+)",
    re.IGNORECASE,
)
_RPM_RELEASE_RE = re.compile(r"(?:^|[.+-])(?:el\d+|fc\d+|amzn\d*)", re.IGNORECASE)
_DEBIAN_RELEASE_RE = re.compile(
    r"(?:ubuntu|debian|deb\d|bpo\d|\+deb|~deb)",
    re.IGNORECASE,
)
_GENERIC_VERSION_RE = re.compile(r"[0-9][0-9a-z.+_~:\-]*", re.IGNORECASE)


def coerce_version_scheme(value: VersionScheme | str | None) -> VersionScheme | None:
    if value is None or value == "":
        return None
    if isinstance(value, VersionScheme):
        return value
    try:
        return VersionScheme(str(value).strip().lower())
    except ValueError:
        return VersionScheme.OPAQUE


def classify_version(
    value: str,
    *,
    hint: VersionScheme | str | None = None,
) -> VersionScheme:
    hinted = coerce_version_scheme(hint)
    if hinted is not None:
        return hinted

    cleaned = _clean_version(value)
    if not cleaned or re.search(r"\s", cleaned):
        return VersionScheme.OPAQUE
    if _looks_like_git_commit(cleaned):
        return VersionScheme.GIT_COMMIT
    if _parse_ubuntu_kernel(cleaned) is not None:
        return VersionScheme.UBUNTU_KERNEL
    if _RPM_RELEASE_RE.search(cleaned):
        return VersionScheme.RPM
    if ":" in cleaned or _DEBIAN_RELEASE_RE.search(cleaned):
        return VersionScheme.DEBIAN
    if _GENERIC_VERSION_RE.fullmatch(cleaned):
        return VersionScheme.GENERIC
    return VersionScheme.OPAQUE


def is_atomic_distro_or_commit_version(value: str) -> bool:
    scheme = classify_version(value)
    return scheme in {
        VersionScheme.DEBIAN,
        VersionScheme.RPM,
        VersionScheme.UBUNTU_KERNEL,
        VersionScheme.GIT_COMMIT,
    }


def compare_version_identities(
    left: str,
    right: str,
    *,
    left_scheme: VersionScheme | str | None = None,
    right_scheme: VersionScheme | str | None = None,
) -> VersionComparison:
    left_clean = _clean_version(left)
    right_clean = _clean_version(right)
    resolved_left = classify_version(left_clean, hint=left_scheme)
    resolved_right = classify_version(right_clean, hint=right_scheme)

    if not left_clean or not right_clean:
        return _uncomparable(
            resolved_left,
            resolved_right,
            "One side of the version comparison is empty.",
            "version.empty",
            left_clean,
            right_clean,
        )
    if VersionScheme.OPAQUE in {resolved_left, resolved_right}:
        return _uncomparable(
            resolved_left,
            resolved_right,
            "One side does not use a recognized version scheme.",
            "version.scheme.opaque",
            left_clean,
            right_clean,
        )
    if resolved_left != resolved_right and _plain_debian_generic_pair(
        left_clean,
        right_clean,
        resolved_left,
        resolved_right,
    ):
        result = _compare_generic_versions(left_clean, right_clean)
        return VersionComparison(
            result=result,
            left_scheme=resolved_left,
            right_scheme=resolved_right,
            comparator="plain_upstream_bridge",
            left_normalized=left_clean,
            right_normalized=right_clean,
        )
    if resolved_left != resolved_right:
        return _uncomparable(
            resolved_left,
            resolved_right,
            (
                "Version schemes differ: "
                f"{resolved_left.value} vs {resolved_right.value}."
            ),
            "version.scheme.mismatch",
            left_clean,
            right_clean,
        )

    if resolved_left == VersionScheme.GIT_COMMIT:
        if left_clean.lower() == right_clean.lower():
            return VersionComparison(
                result=0,
                left_scheme=resolved_left,
                right_scheme=resolved_right,
                comparator="git_identity",
                left_normalized=left_clean.lower(),
                right_normalized=right_clean.lower(),
            )
        return _uncomparable(
            resolved_left,
            resolved_right,
            "Git commits require repository ancestry; lexical ordering is invalid.",
            "version.git.ancestry_required",
            left_clean.lower(),
            right_clean.lower(),
            comparator="git_identity",
        )

    if resolved_left == VersionScheme.DEBIAN:
        result = compare_debian_versions(left_clean, right_clean)
        return VersionComparison(
            result=result,
            left_scheme=resolved_left,
            right_scheme=resolved_right,
            comparator="debian_policy",
            left_normalized=left_clean,
            right_normalized=right_clean,
        )

    if resolved_left == VersionScheme.UBUNTU_KERNEL:
        return _compare_ubuntu_kernel_versions(left_clean, right_clean)

    if resolved_left == VersionScheme.RPM:
        return _uncomparable(
            resolved_left,
            resolved_right,
            "RPM EVR comparison requires an RPM-compatible comparator.",
            "version.rpm.comparator_unavailable",
            left_clean,
            right_clean,
        )

    result = _compare_generic_versions(left_clean, right_clean)
    if result is None:
        return _uncomparable(
            resolved_left,
            resolved_right,
            "One side did not contain comparable version tokens.",
            "version.generic.no_tokens",
            left_clean,
            right_clean,
            comparator="generic_segments",
        )
    return VersionComparison(
        result=result,
        left_scheme=resolved_left,
        right_scheme=resolved_right,
        comparator="generic_segments",
        left_normalized=left_clean,
        right_normalized=right_clean,
    )


def compare_debian_versions(left: str, right: str) -> int:
    left_epoch, left_upstream, left_revision = _split_debian_version(left)
    right_epoch, right_upstream, right_revision = _split_debian_version(right)
    if left_epoch != right_epoch:
        return 1 if left_epoch > right_epoch else -1
    upstream_result = _compare_debian_part(left_upstream, right_upstream)
    if upstream_result:
        return upstream_result
    return _compare_debian_part(left_revision, right_revision)


def _split_debian_version(value: str) -> tuple[int, str, str]:
    epoch = 0
    remainder = value
    if ":" in remainder:
        possible_epoch, possible_remainder = remainder.split(":", 1)
        if possible_epoch.isdigit():
            epoch = int(possible_epoch)
            remainder = possible_remainder
    if "-" in remainder:
        upstream, revision = remainder.rsplit("-", 1)
    else:
        upstream, revision = remainder, "0"
    return epoch, upstream, revision


def _compare_debian_part(left: str, right: str) -> int:
    left_index = 0
    right_index = 0
    while left_index < len(left) or right_index < len(right):
        while (
            (left_index < len(left) and not left[left_index].isdigit())
            or (right_index < len(right) and not right[right_index].isdigit())
        ):
            left_char = (
                left[left_index]
                if left_index < len(left) and not left[left_index].isdigit()
                else ""
            )
            right_char = (
                right[right_index]
                if right_index < len(right) and not right[right_index].isdigit()
                else ""
            )
            left_order = _debian_char_order(left_char)
            right_order = _debian_char_order(right_char)
            if left_order != right_order:
                return 1 if left_order > right_order else -1
            if left_char:
                left_index += 1
            if right_char:
                right_index += 1

        left_start = left_index
        right_start = right_index
        while left_index < len(left) and left[left_index].isdigit():
            left_index += 1
        while right_index < len(right) and right[right_index].isdigit():
            right_index += 1
        left_digits = left[left_start:left_index].lstrip("0") or "0"
        right_digits = right[right_start:right_index].lstrip("0") or "0"
        if len(left_digits) != len(right_digits):
            return 1 if len(left_digits) > len(right_digits) else -1
        if left_digits != right_digits:
            return 1 if left_digits > right_digits else -1
    return 0


def _debian_char_order(value: str) -> int:
    if value == "~":
        return -1
    if value == "":
        return 0
    if value.isalpha():
        return ord(value)
    return ord(value) + 256


def _compare_ubuntu_kernel_versions(left: str, right: str) -> VersionComparison:
    left_parts = _parse_ubuntu_kernel(left)
    right_parts = _parse_ubuntu_kernel(right)
    assert left_parts is not None and right_parts is not None
    left_base, left_abi, left_upload, _left_flavor = left_parts
    right_base, right_abi, right_upload, _right_flavor = right_parts

    base_result = _compare_generic_versions(left_base, right_base)
    if base_result:
        result = base_result
    elif left_abi != right_abi:
        result = 1 if left_abi > right_abi else -1
    elif left_upload is None or right_upload is None:
        if left_upload is right_upload:
            result = 0
        else:
            return _uncomparable(
                VersionScheme.UBUNTU_KERNEL,
                VersionScheme.UBUNTU_KERNEL,
                (
                    "Kernel ABI is equal, but only one side includes the upload "
                    "revision needed to prove the fix boundary."
                ),
                "version.ubuntu_kernel.upload_missing",
                _normalize_ubuntu_kernel(left_parts),
                _normalize_ubuntu_kernel(right_parts),
                comparator="ubuntu_kernel_abi",
            )
    elif left_upload != right_upload:
        result = 1 if left_upload > right_upload else -1
    else:
        result = 0
    return VersionComparison(
        result=result,
        left_scheme=VersionScheme.UBUNTU_KERNEL,
        right_scheme=VersionScheme.UBUNTU_KERNEL,
        comparator="ubuntu_kernel_abi",
        left_normalized=_normalize_ubuntu_kernel(left_parts),
        right_normalized=_normalize_ubuntu_kernel(right_parts),
    )


def _parse_ubuntu_kernel(value: str) -> tuple[str, int, int | None, str | None] | None:
    match = _UBUNTU_KERNEL_UNAME_RE.fullmatch(value)
    if match:
        return (
            match.group("base"),
            int(match.group("abi")),
            int(match.group("upload")) if match.group("upload") else None,
            match.group("flavor"),
        )
    match = _UBUNTU_KERNEL_PACKAGE_RE.fullmatch(value)
    if match:
        return (
            match.group("base"),
            int(match.group("abi")),
            int(match.group("upload")),
            None,
        )
    return None


def _normalize_ubuntu_kernel(parts: tuple[str, int, int | None, str | None]) -> str:
    base, abi, upload, flavor = parts
    normalized = f"{base}-{abi}"
    if upload is not None:
        normalized += f".{upload}"
    if flavor:
        normalized += f"-{flavor.lower()}"
    return normalized


def _compare_generic_versions(left: str, right: str) -> int | None:
    left_parts = _generic_version_parts(left)
    right_parts = _generic_version_parts(right)
    if not left_parts or not right_parts:
        return None
    for left_part, right_part in zip_longest(left_parts, right_parts, fillvalue=0):
        if left_part == right_part:
            continue
        if isinstance(left_part, int) and isinstance(right_part, int):
            return 1 if left_part > right_part else -1
        left_text = str(left_part)
        right_text = str(right_part)
        if left_text != right_text:
            return 1 if left_text > right_text else -1
    return 0


def _generic_version_parts(version: str) -> list[int | str]:
    parts: list[int | str] = []
    for part in re.findall(r"\d+|[a-z]+", version.lower()):
        parts.append(int(part) if part.isdigit() else part)
    return parts


def _looks_like_git_commit(value: str) -> bool:
    if not _GIT_COMMIT_RE.fullmatch(value):
        return False
    return len(value) >= 12 or bool(re.search(r"[a-f]", value, re.IGNORECASE))


def _plain_debian_generic_pair(
    left: str,
    right: str,
    left_scheme: VersionScheme,
    right_scheme: VersionScheme,
) -> bool:
    if {left_scheme, right_scheme} != {VersionScheme.DEBIAN, VersionScheme.GENERIC}:
        return False
    debian_value = left if left_scheme == VersionScheme.DEBIAN else right
    return not any(marker in debian_value for marker in (":", "-", "~"))


def _clean_version(value: str) -> str:
    cleaned = str(value or "").strip()
    if cleaned[:1].lower() == "v" and len(cleaned) > 1 and cleaned[1].isdigit():
        return cleaned[1:]
    return cleaned


def _uncomparable(
    left_scheme: VersionScheme,
    right_scheme: VersionScheme,
    reason: str,
    reason_code: str,
    left_normalized: str,
    right_normalized: str,
    *,
    comparator: str | None = None,
) -> VersionComparison:
    return VersionComparison(
        result=None,
        left_scheme=left_scheme,
        right_scheme=right_scheme,
        comparator=comparator,
        reason=reason,
        reason_code=reason_code,
        left_normalized=left_normalized,
        right_normalized=right_normalized,
    )
