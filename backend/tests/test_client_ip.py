from __future__ import annotations

from app.core.client_ip import resolve_client_address


def _resolve(
    peer: str,
    forwarded: str | None = None,
    *,
    trusted: str = "10.0.0.0/8,127.0.0.1/32",
    exempt: str = "",
):
    return resolve_client_address(
        peer_host=peer,
        forwarded_for=forwarded,
        trusted_proxy_cidrs=trusted,
        ban_exempt_cidrs=exempt,
        ipv6_prefix_length=64,
    )


def test_untrusted_peer_cannot_spoof_forwarded_for() -> None:
    result = _resolve("203.0.113.8", "198.51.100.4")

    assert result.address == "203.0.113.8"
    assert result.ip_key == "203.0.113.8/32"


def test_trusted_proxy_chain_uses_first_untrusted_address_from_right() -> None:
    result = _resolve(
        "10.0.0.5",
        "192.0.2.99, 198.51.100.7, 10.0.0.9",
    )

    assert result.address == "198.51.100.7"


def test_ipv6_addresses_are_grouped_by_configured_prefix() -> None:
    result = _resolve("2001:db8:1:2::99", trusted="")

    assert result.address == "2001:db8:1:2::99"
    assert result.ip_key == "2001:db8:1:2::/64"


def test_ban_exemption_uses_resolved_client_address() -> None:
    result = _resolve(
        "10.0.0.5",
        "198.51.100.7",
        exempt="198.51.100.0/24",
    )

    assert result.is_ban_exempt is True

