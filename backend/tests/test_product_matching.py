from __future__ import annotations

import pytest

from app.matching.base import MatchContext
from app.matching.product_rule import ProductRule
from app.matching.utils import product_candidates
from app.matching.version_rule import VersionRule


def _context(
    *,
    product: str = "nginx",
    affected_scope: dict | None = None,
    components: list[dict] | None = None,
    exposures: list[dict] | None = None,
    asset: dict | None = None,
) -> MatchContext:
    return MatchContext(
        asset_id="asset-1",
        vulnerability_id="vuln-1",
        asset=asset or {},
        vulnerability={
            "product": product,
            "affected_versions": "< 2.0",
            "affected_scope": affected_scope,
        },
        asset_components=components or [],
        asset_exposures=exposures or [],
    )


@pytest.mark.parametrize(
    ("product", "component", "expected_score", "expected_strength"),
    [
        ("nginx", {"component_name": "nginx"}, 90, "exact"),
        ("Apache HTTP Server", {"component_name": "apache2"}, 80, "alias"),
        ("postgresql", {"component_name": "custom postgresql service"}, 60, "token"),
    ],
)
def test_product_match_strengths_are_ranked(
    product: str,
    component: dict,
    expected_score: int,
    expected_strength: str,
) -> None:
    candidate = product_candidates(
        _context(product=product, components=[{"id": "component-1", **component}])
    )[0]

    assert candidate["match_score"] == expected_score
    assert candidate["match_strength"] == expected_strength


def test_structured_identifiers_and_packages_outrank_names() -> None:
    identifier = product_candidates(
        _context(
            product="different display name",
            affected_scope={"purl": "pkg:deb/ubuntu/nginx@1.24"},
            components=[
                {
                    "id": "component-1",
                    "component_name": "nginx-core",
                    "purl": "pkg:deb/ubuntu/nginx@1.24",
                }
            ],
        )
    )[0]
    package = product_candidates(
        _context(
            product="Linux Kernel",
            affected_scope={"source_package": "linux"},
            components=[
                {
                    "id": "component-2",
                    "component_name": "linux-image-5.15.0-100-generic",
                    "source_package": "linux",
                }
            ],
        )
    )[0]

    assert (identifier["match_score"], identifier["match_strength"]) == (100, "identifier")
    assert (package["match_score"], package["match_strength"]) == (95, "package")


def test_package_family_prefix_is_a_conclusive_package_identity() -> None:
    candidate = product_candidates(
        _context(
            product="Inetutils",
            components=[
                {
                    "id": "component-1",
                    "component_name": "inetutils-telnet",
                    "component_type": "package",
                }
            ],
        )
    )[0]

    assert (candidate["match_score"], candidate["match_strength"]) == (95, "package")


def test_banner_only_match_requires_review_and_cannot_run_version_rule() -> None:
    context = _context(
        exposures=[
            {
                "id": "exposure-1",
                "service_name": "http",
                "banner": "reverse proxy via nginx/1.24.0",
                "version": "1.24.0",
            }
        ]
    )

    candidate = product_candidates(context)[0]
    product_result = ProductRule().evaluate(context)
    version_result = VersionRule().evaluate(context)

    assert (candidate["match_score"], candidate["match_strength"]) == (45, "context")
    assert product_result.status == "needs_review"
    assert product_result.evidence[0]["type"] == "product_candidate"
    assert version_result.status == "not_applicable"


def test_no_match_uses_negative_evidence_type() -> None:
    result = ProductRule().evaluate(
        _context(components=[{"id": "component-1", "component_name": "openssl"}])
    )

    assert result.status == "not_affected"
    assert result.evidence[0]["type"] == "product_no_match"


def test_generic_kernel_candidates_are_cached_and_consolidated() -> None:
    components = [
        {
            "id": "package-kernel",
            "component_name": "linux-image-generic",
            "component_type": "package",
            "version": "5.15.0.100.96",
            "source_type": "dpkg-query",
        }
    ]
    context = _context(
        product="Linux",
        components=components,
        asset={
            "id": "asset-1",
            "os_family": "Ubuntu",
            "os_version": "22.04",
            "kernel_version": "5.15.0-100-generic",
            "architecture": "x86_64",
        },
    )

    first = product_candidates(context)
    components.append({"id": "late", "component_name": "Linux Kernel"})
    second = product_candidates(context)

    assert first is second
    assert len(first) == 1
    assert first[0]["source_type"] == "uname"
    assert first[0]["related_observations"][0]["id"] == "package-kernel"


def test_explicit_kernel_package_scope_keeps_distinct_observations() -> None:
    context = _context(
        product="Linux",
        affected_scope={"source_package": "linux"},
        components=[
            {
                "id": "package-kernel",
                "component_name": "linux-image-generic",
                "source_package": "linux",
                "version": "5.15.0.100.96",
            }
        ],
        asset={
            "id": "asset-1",
            "os_family": "Ubuntu",
            "os_version": "22.04",
            "kernel_version": "5.15.0-100-generic",
        },
    )

    assert len(product_candidates(context)) == 2
