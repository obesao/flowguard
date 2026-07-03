"""Leitura da configuração BGP real do roteador de borda, pra alimentar os
templates de sessão/anúncio (ver router_templates.yaml: bgp_peer_toggle,
bgp_prefix_advertise) com peers e prefixos de verdade em vez do operador
digitar IP na mão — reduz erro de digitação e evita listar/tocar em algo que
não existe na config real.

Só leitura (`display current-configuration ...`) — nunca aplica nada aqui.
Reaproveita a mesma conexão/credenciais de routercfg/apply.py.
"""

from __future__ import annotations

import re

from routercfg.apply import _connect, _device_for

_BGP_AS_RE = re.compile(r"^\s*bgp (\d+)\s*$", re.M)
_PEER_AS_RE = re.compile(r"^\s*peer (\d+\.\d+\.\d+\.\d+) as-number (\d+)\s*$", re.M)
_PEER_GROUP_RE = re.compile(r"^\s*peer (\d+\.\d+\.\d+\.\d+) group (\S+)\s*$", re.M)
_PEER_DESC_RE = re.compile(r"^\s*peer (\d+\.\d+\.\d+\.\d+) description (.+?)\s*$", re.M)
_PEER_IGNORE_RE = re.compile(r"^\s*peer (\d+\.\d+\.\d+\.\d+) ignore\s*$", re.M)
_NETWORK_RE = re.compile(r"^\s*network (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)", re.M)

DISCOVER_COMMAND = "display current-configuration configuration bgp"


def _mask_to_prefixlen(mask: str) -> int:
    return sum(bin(int(octet)).count("1") for octet in mask.split("."))


def parse_bgp_config(raw: str) -> dict:
    as_match = _BGP_AS_RE.search(raw)
    local_as = as_match.group(1) if as_match else None

    descriptions = dict(_PEER_DESC_RE.findall(raw))
    ignored = set(_PEER_IGNORE_RE.findall(raw))
    groups = dict(_PEER_GROUP_RE.findall(raw))

    remote_as_by_ip = dict(_PEER_AS_RE.findall(raw))
    all_ips = set(remote_as_by_ip) | set(groups) | set(descriptions) | ignored

    peers = []
    for ip in sorted(all_ips):
        peers.append({
            "peer_ip": ip,
            "remote_as": remote_as_by_ip.get(ip),
            "group": groups.get(ip),
            "description": descriptions.get(ip, ""),
            "state": "down" if ip in ignored else "up",
        })

    networks = []
    for ip, mask in _NETWORK_RE.findall(raw):
        networks.append({"network": ip, "mask": mask, "cidr": f"{ip}/{_mask_to_prefixlen(mask)}"})

    return {"local_as": local_as, "peers": peers, "networks": networks}


def discover_bgp(device_name: str | None = None) -> dict:
    device = _device_for(device_name)
    conn = _connect(device)
    try:
        raw = conn.send_command(DISCOVER_COMMAND, read_timeout=30)
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass
    return parse_bgp_config(raw)
