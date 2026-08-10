from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from typing import TypeAlias

from fastapi import Request

from app.core.config import Settings


IpAddress: TypeAlias = IPv4Address | IPv6Address


@dataclass(frozen=True)
class ClientAddress:
    address: str
    ip_key: str
    peer_address: str
    is_ban_exempt: bool


def resolve_request_client(request: Request, settings: Settings) -> ClientAddress:
    if request.client is None:
        raise ValueError("Request has no client address")
    return resolve_client_address(
        peer_host=request.client.host,
        forwarded_for=request.headers.get("x-forwarded-for"),
        trusted_proxy_cidrs=settings.login_trusted_proxy_cidrs,
        ban_exempt_cidrs=settings.login_ban_exempt_cidrs,
        ipv6_prefix_length=settings.login_ipv6_prefix_length,
    )


def resolve_client_address(
    *,
    peer_host: str,
    forwarded_for: str | None,
    trusted_proxy_cidrs: str,
    ban_exempt_cidrs: str,
    ipv6_prefix_length: int,
) -> ClientAddress:
    peer = _parse_address(peer_host)
    trusted_networks = _parse_networks(trusted_proxy_cidrs)
    client = peer

    if _address_in_networks(peer, trusted_networks) and forwarded_for:
        forwarded = [
            parsed
            for item in forwarded_for.split(",")
            if (parsed := _try_parse_address(item.strip())) is not None
        ]
        if forwarded:
            client = forwarded[0]
            for candidate in reversed([*forwarded, peer]):
                if not _address_in_networks(candidate, trusted_networks):
                    client = candidate
                    break

    prefix_length = 32 if isinstance(client, IPv4Address) else ipv6_prefix_length
    client_network = ip_network(f"{client}/{prefix_length}", strict=False)
    exempt_networks = _parse_networks(ban_exempt_cidrs)
    return ClientAddress(
        address=client.compressed,
        ip_key=client_network.with_prefixlen,
        peer_address=peer.compressed,
        is_ban_exempt=_address_in_networks(client, exempt_networks),
    )


def normalize_ip_key(value: str, *, ipv6_prefix_length: int = 64) -> str:
    address = _parse_address(value)
    prefix_length = 32 if isinstance(address, IPv4Address) else ipv6_prefix_length
    return ip_network(f"{address}/{prefix_length}", strict=False).with_prefixlen


def validate_cidr_list(value: str) -> str:
    _parse_networks(value)
    return value


def _parse_networks(value: str) -> tuple[object, ...]:
    networks = []
    for raw in value.split(","):
        normalized = raw.strip()
        if normalized:
            networks.append(ip_network(normalized, strict=False))
    return tuple(networks)


def _address_in_networks(address: IpAddress, networks: tuple[object, ...]) -> bool:
    return any(address.version == network.version and address in network for network in networks)


def _try_parse_address(value: str) -> IpAddress | None:
    try:
        return _parse_address(value)
    except ValueError:
        return None


def _parse_address(value: str) -> IpAddress:
    normalized = value.strip().strip("[]").split("%", 1)[0]
    return ip_address(normalized)

