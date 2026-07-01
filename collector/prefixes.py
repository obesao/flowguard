"""Resolução de dst_prefix a partir de um IP, usando protected_prefixes como referência."""

from __future__ import annotations

import ipaddress


def match_protected_prefix(ip: str, protected_prefixes: list[dict]) -> str | None:
    """Retorna o prefixo protegido (mais específico) que contém o IP, ou None se
    o IP não pertencer a nenhum — sem fallback, ao contrário de resolve_dst_prefix."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None

    best: ipaddress._BaseNetwork | None = None
    for entry in protected_prefixes:
        try:
            net = ipaddress.ip_network(entry["prefix"], strict=False)
        except (ValueError, KeyError):
            continue
        if addr in net and (best is None or net.prefixlen > best.prefixlen):
            best = net
    return str(best) if best is not None else None


def resolve_dst_prefix(ip: str, protected_prefixes: list[dict]) -> str:
    matched = match_protected_prefix(ip, protected_prefixes)
    if matched is not None:
        return matched

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip

    fallback_len = 24 if addr.version == 4 else 64
    return str(ipaddress.ip_network(f"{addr}/{fallback_len}", strict=False))
