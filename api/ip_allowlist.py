"""
Optional IP allowlist middleware helper.

ALLOWED_IPS=10.0.0.5,192.168.1.0/24,2001:db8::/32
Empty / unset = allow all (rely on network edge).
"""
from __future__ import annotations

import ipaddress
import os
from typing import Iterable, List, Optional, Union

Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def allowlist_enabled() -> bool:
    return bool(os.getenv("ALLOWED_IPS", "").strip())


def _networks() -> List[Network]:
    nets: List[Network] = []
    for part in os.getenv("ALLOWED_IPS", "").split(","):
        raw = part.strip()
        if not raw:
            continue
        if "/" not in raw:
            raw = f"{raw}/32" if ":" not in raw else f"{raw}/128"
        nets.append(ipaddress.ip_network(raw, strict=False))
    return nets


def client_ip_from_headers(
    forwarded_for: Optional[str],
    real_ip: Optional[str],
    peer: Optional[str],
) -> Optional[str]:
    """Prefer X-Forwarded-For (first hop) when behind a trusted proxy."""
    if forwarded_for:
        first = forwarded_for.split(",")[0].strip()
        if first:
            return first
    if real_ip and real_ip.strip():
        return real_ip.strip()
    return peer


def ip_allowed(ip_str: Optional[str], networks: Optional[Iterable[Network]] = None) -> bool:
    if not allowlist_enabled():
        return True
    if not ip_str:
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    nets = list(networks) if networks is not None else _networks()
    if not nets:
        return True
    return any(addr in net for net in nets)
