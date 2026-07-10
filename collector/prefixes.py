"""Resolução de dst_prefix a partir de um IP, usando protected_prefixes como referência."""

from __future__ import annotations

import ipaddress

# Cache de 1 slot dos objetos ipaddress.ip_network() já parseados de
# protected_prefixes — achado real de profiling de CPU (2026-07-10):
# match_protected_prefix é chamado 2x por registro NetFlow (dst_ip e src_ip) em
# flowguard.py::_aggregate_once, e sem isso reparseava TODAS as CIDRs de
# protected_prefixes (ipaddress.ip_network(), parsing de string) a CADA chamada —
# ~46% da CPU do daemon inteiro. protected_prefixes só muda de fato num
# reload_config() (novo objeto de lista); chave por id() + guarda de identidade
# evita servir cache velho se o id for reciclado pelo GC.
_cache_key: int | None = None
_cache_list_ref: list | None = None
_cache_networks: list[ipaddress._BaseNetwork] = []


def _parsed_networks(protected_prefixes: list[dict]) -> list[ipaddress._BaseNetwork]:
    global _cache_key, _cache_list_ref, _cache_networks
    if _cache_key == id(protected_prefixes) and _cache_list_ref is protected_prefixes:
        return _cache_networks
    parsed = []
    for entry in protected_prefixes:
        try:
            parsed.append(ipaddress.ip_network(entry["prefix"], strict=False))
        except (ValueError, KeyError):
            continue
    _cache_key = id(protected_prefixes)
    _cache_list_ref = protected_prefixes
    _cache_networks = parsed
    return parsed


def match_protected_prefix(ip: str, protected_prefixes: list[dict]) -> str | None:
    """Retorna o prefixo protegido (mais específico) que contém o IP, ou None se
    o IP não pertencer a nenhum — sem fallback, ao contrário de resolve_dst_prefix."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None

    best: ipaddress._BaseNetwork | None = None
    for net in _parsed_networks(protected_prefixes):
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
