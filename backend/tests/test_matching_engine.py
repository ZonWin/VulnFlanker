from __future__ import annotations

from sqlalchemy.orm import Session

from app.db.models import Vulnerability, VulnerabilitySource
from app.matching.product_aliases import product_aliases
from app.matching.utils import values_match_any


def create_vulnerability(
    db_session: Session,
    *,
    canonical_id: str,
    fixed_versions: str,
    affected_versions: str = "< 1.25.0",
    vendor: str = "nginx",
    product: str = "nginx",
    severity_label: str = "high",
    severity_cvss: float = 9.8,
    kev_status: bool = False,
    poc_status: bool = True,
) -> Vulnerability:
    vulnerability = Vulnerability(
        canonical_id=canonical_id,
        title=f"{canonical_id} {product} vulnerability",
        vendor=vendor,
        product=product,
        severity_label=severity_label,
        severity_cvss=severity_cvss,
        kev_status=kev_status,
        poc_status=poc_status,
        affected_versions=affected_versions,
        fixed_versions=fixed_versions,
    )
    db_session.add(vulnerability)
    db_session.flush()
    db_session.add(
        VulnerabilitySource(
            vulnerability_id=vulnerability.id,
            source_name="test-source",
            external_id=canonical_id,
            source_url=f"https://example.test/vulns/{canonical_id}",
            title=vulnerability.title,
            description="Test source record for a match-ready vulnerability.",
            severity_raw=severity_label,
            references_json=[f"https://example.test/references/{canonical_id}"],
            last_payload_hash=f"hash-{canonical_id}",
        )
    )
    db_session.commit()
    return vulnerability


def test_linux_product_uses_explicit_kernel_aliases_without_loose_linux_token() -> None:
    linux_aliases = product_aliases("Linux")

    assert values_match_any(linux_aliases, ["Linux Kernel"])
    assert values_match_any(linux_aliases, ["linux-image-generic"])
    assert not values_match_any(linux_aliases, ["binutils-x86-64-linux-gnu"])


def test_generic_product_tokens_do_not_match_unrelated_package_names() -> None:
    assert not values_match_any(["service"], ["python3-service-identity"])
    assert not values_match_any(["core"], ["apport-core-dump-handler"])
