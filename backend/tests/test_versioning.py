from __future__ import annotations

import pytest

from app.matching.version_rule import (
    evaluate_version_constraint_groups,
    parse_constraint_groups,
)
from app.matching.versioning import (
    VersionScheme,
    classify_version,
    compare_debian_versions,
    compare_version_identities,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("0bdddc5f4b29535b9a209da60a33f4f3f9c8b3d2", VersionScheme.GIT_COMMIT),
        ("5.15.0-119-generic", VersionScheme.UBUNTU_KERNEL),
        ("5.15.0-179.189", VersionScheme.UBUNTU_KERNEL),
        ("5.15.0.119.119", VersionScheme.UBUNTU_KERNEL),
        ("1:2.34.1-1ubuntu1.11", VersionScheme.DEBIAN),
        ("2.4.58", VersionScheme.GENERIC),
    ],
)
def test_classify_version_schemes(value: str, expected: VersionScheme) -> None:
    assert classify_version(value) == expected


def test_git_commit_and_kernel_version_are_not_comparable() -> None:
    comparison = compare_version_identities(
        "5.15.0-119-generic",
        "0bdddc5f4b29535b9a209da60a33f4f3f9c8b3d2",
    )

    assert comparison.result is None
    assert comparison.reason_code == "version.scheme.mismatch"


def test_distinct_git_commits_require_ancestry_instead_of_lexical_order() -> None:
    comparison = compare_version_identities(
        "0bdddc5f4b29535b9a209da60a33f4f3f9c8b3d2",
        "78a4c4e0c78cb321f65b3c9ead6c69c8d2b6d456",
    )

    assert comparison.result is None
    assert comparison.reason_code == "version.git.ancestry_required"


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("1:2.34.1-1ubuntu1.11", "1:2.34.1-1ubuntu1.13", -1),
        ("2:1.0-1", "1:99.0-9", 1),
        ("1.0~beta1", "1.0", -1),
        ("1.0-1ubuntu2", "1.0-1ubuntu10", -1),
        ("1.0", "1.0-0", 0),
    ],
)
def test_debian_policy_version_order(left: str, right: str, expected: int) -> None:
    assert compare_debian_versions(left, right) == expected


def test_ubuntu_kernel_abi_compares_before_upload_revision() -> None:
    affected = compare_version_identities("5.15.0-119-generic", "5.15.0-179.189")
    fixed = compare_version_identities("5.15.0-119-generic", "5.15.0-70.77")

    assert affected.result == -1
    assert fixed.result == 1
    assert affected.comparator == "ubuntu_kernel_abi"


def test_equal_kernel_abi_without_upload_revision_is_inconclusive() -> None:
    comparison = compare_version_identities("5.15.0-119-generic", "5.15.0-119.129")

    assert comparison.result is None
    assert comparison.reason_code == "version.ubuntu_kernel.upload_missing"


def test_ubuntu_hyphen_version_is_an_exact_version_not_a_range() -> None:
    groups = parse_constraint_groups("5.8.0-50.56", None)

    assert [[(item.operator, item.version) for item in group] for group in groups] == [
        [("==", "5.8.0-50.56")]
    ]


def test_legacy_compact_range_remains_supported() -> None:
    groups = parse_constraint_groups("3.2.1-4.0.7", None)

    assert evaluate_version_constraint_groups("3.2.1", groups).result is True
    assert evaluate_version_constraint_groups("4.0.8", groups).result is False


def test_plain_dpkg_version_can_bridge_to_plain_upstream_constraint() -> None:
    groups = parse_constraint_groups("< 1.25.0", "1.25.0")
    evaluation = evaluate_version_constraint_groups(
        "1.26.0",
        groups,
        observed_scheme=VersionScheme.DEBIAN,
    )

    assert evaluation.result is False
    assert evaluation.comparisons
    assert evaluation.comparisons[0]["comparator"] == "plain_upstream_bridge"


def test_hash_range_cannot_mark_kernel_affected() -> None:
    groups = parse_constraint_groups(
        ">= 0bdddc5f4b29535b9a209da60a33f4f3f9c8b3d2, "
        "< 78a4c4e0c78cb321f65b3c9ead6c69c8d2b6d456",
        None,
    )
    evaluation = evaluate_version_constraint_groups(
        "5.15.0-119-generic",
        groups,
        observed_scheme=VersionScheme.UBUNTU_KERNEL,
    )

    assert evaluation.result is None
    assert evaluation.comparisons
    assert evaluation.comparisons[0]["reason_code"] == "version.scheme.mismatch"
