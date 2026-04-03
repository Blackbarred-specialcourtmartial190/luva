"""IPv4 classification helpers for passive traffic analysis."""

from __future__ import annotations

import ipaddress


def is_private_ipv4(ip: str) -> bool:
    """True if address is RFC 1918, loopback, link-local, or CGNAT."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.version != 4:
        return False
    return a.is_private or a.is_loopback or a.is_link_local


def is_public_ipv4(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.version == 4 and a.is_global
