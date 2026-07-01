"""Resolução de dst_prefix a partir de um IP, usando protected_prefixes como referência."""

from __future__ import annotations

import ipaddress


def resolve_dst_prefix(ip: str, protected_prefixes: list[dict]) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip

    best: ipaddress._BaseNetwork | None = None
    for entry in protected_prefixes:
        try:
            net = ipaddress.ip_network(entry["prefix"], strict=False)
        except (ValueError, KeyError):
            continue
        if addr in net and (best is None or net.prefixlen > best.prefixlen):
            best = net
    if best is not None:
        return str(best)

    fallback_len = 24 if addr.version == 4 else 64
    return str(ipaddress.ip_network(f"{addr}/{fallback_len}", strict=False))
