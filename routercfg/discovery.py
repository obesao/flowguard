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
from routercfg.templates import ValidationError

_BGP_AS_RE = re.compile(r"^\s*bgp (\d+)\s*$", re.M)
_PEER_AS_RE = re.compile(r"^\s*peer (\d+\.\d+\.\d+\.\d+) as-number (\d+)\s*$", re.M)
_PEER_GROUP_RE = re.compile(r"^\s*peer (\d+\.\d+\.\d+\.\d+) group (\S+)\s*$", re.M)
_PEER_DESC_RE = re.compile(r"^\s*peer (\d+\.\d+\.\d+\.\d+) description (.+?)\s*$", re.M)
_PEER_IGNORE_RE = re.compile(r"^\s*peer (\d+\.\d+\.\d+\.\d+) ignore\s*$", re.M)
_NETWORK_RE = re.compile(r"^\s*network (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)", re.M)

# Nota importante: os separadores abaixo usam [ \t] (não \s) de propósito.
# Achado real testando contra o roteador de verdade: \s inclui \n — um `\s*`
# posicionado ANTES de um grupo de captura (ports) "vazava" pra próxima linha
# inteira (já que "." não casa \n, mas nada impedia o \s* de atravessar a
# quebra de linha e o grupo seguinte recomeçar a casar já na linha de baixo),
# misturando o VID/status de uma VLAN com o conteúdo da próxima. `^`/`$` com
# re.M sozinhos não protegem contra isso — só ancoram o INÍCIO/FIM da linha,
# não impedem separadores gulosos no meio do padrão de cruzar pra outra linha.
_IF_LINE_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][\w/.\-()]*)[ \t]+(?P<ip>\S+)[ \t]+(?P<phy>\*down|!down|\^down|up|down)[ \t]+(?P<proto>up|down)(?:[ \t]+\S+)*[ \t]*$",
    re.M,
)
_VLAN_LINE_RE = re.compile(
    r"^(?P<vid>\d{1,4})[ \t]+(?:(?P<name>\S+)[ \t]+)?(?P<status>enable|disable)[ \t]*(?P<ports>\S.*\S|\S)?[ \t]*$",
    re.M,
)
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_ROUTE_PREFIX_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b")
_TOTAL_ROUTES_RE = re.compile(r"Total Number of Routes:\s*(\d+)")

DISCOVER_COMMAND = "display current-configuration configuration bgp"
DISCOVER_INTERFACES_COMMAND = "display ip interface brief"
DISCOVER_VLANS_COMMAND = "display vlan brief"


def _mask_to_prefixlen(mask: str) -> int:
    return sum(bin(int(octet)).count("1") for octet in mask.split("."))


def _normalize_lines(raw: str) -> str:
    """Normaliza CRLF/CR pra LF antes de parsear — defensivo contra
    equipamentos/versões de VRP que devolvem saída com "\\r\\n" via SSH (não
    foi a causa do bug real de linhas se misturando descrito em _IF_LINE_RE/
    _VLAN_LINE_RE, mas evita reintroduzir o mesmo tipo de problema se algum
    regex futuro usar "$" sem cuidado)."""
    return raw.replace("\r\n", "\n").replace("\r", "\n")


def parse_bgp_config(raw: str) -> dict:
    raw = _normalize_lines(raw)
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


def parse_interfaces(raw: str) -> list[dict]:
    raw = _normalize_lines(raw)
    out = []
    for m in _IF_LINE_RE.finditer(raw):
        phy = m.group("phy")
        out.append({
            "name": m.group("name"),
            "ip": None if m.group("ip").lower() == "unassigned" else m.group("ip"),
            "physical": phy.lstrip("*!^"),
            "protocol": m.group("proto"),
            "admin_down": phy.startswith("*"),
        })
    return out


def parse_vlans(raw: str) -> list[dict]:
    raw = _normalize_lines(raw)
    out = []
    for m in _VLAN_LINE_RE.finditer(raw):
        out.append({
            "vlan_id": m.group("vid"),
            "name": m.group("name"),
            "status": m.group("status"),
            "ports": (m.group("ports") or "").strip(),
        })
    return out


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


def discover_all(device_name: str | None = None) -> dict:
    """Igual a discover_bgp(), mas numa única conexão SSH também lê interfaces
    e VLANs — evita 3 conexões separadas pra montar a tela de descoberta."""
    device = _device_for(device_name)
    conn = _connect(device)
    try:
        bgp_raw = conn.send_command(DISCOVER_COMMAND, read_timeout=30)
        if_raw = conn.send_command(DISCOVER_INTERFACES_COMMAND, read_timeout=30)
        vlan_raw = conn.send_command(DISCOVER_VLANS_COMMAND, read_timeout=30)
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass
    result = parse_bgp_config(bgp_raw)
    result["interfaces"] = parse_interfaces(if_raw)
    result["vlans"] = parse_vlans(vlan_raw)
    return result


def parse_peer_routes(raw: str, peer_ip: str, direction: str) -> dict:
    raw = _normalize_lines(raw)
    prefixes = sorted(set(_ROUTE_PREFIX_RE.findall(raw)))
    total_match = _TOTAL_ROUTES_RE.search(raw)
    return {
        "peer_ip": peer_ip,
        "direction": direction,
        "prefixes": prefixes,
        "total_reported": int(total_match.group(1)) if total_match else None,
    }


def discover_peer_routes(peer_ip: str, direction: str = "advertised", device_name: str | None = None) -> dict:
    """Lê os prefixos que o roteador está anunciando pra (advertised) ou
    recebendo de (received) um peer BGP específico — resolve "quero ver
    redes/hosts advertidos pra cada operadora" sem precisar abrir um
    terminal. Só leitura.

    peer_ip vira parte literal do comando VRP enviado via SSH — validado
    contra um regex de IPv4 estrito ANTES de montar a string do comando,
    mesma preocupação de injeção que os campos de template (ver
    routercfg/templates.py), mesmo esta função não passando pelo mecanismo
    de templates."""
    if direction not in ("advertised", "received"):
        raise ValidationError("direction deve ser 'advertised' ou 'received'")
    if not _IPV4_RE.match(peer_ip or ""):
        raise ValidationError("peer_ip inválido")

    device = _device_for(device_name)
    conn = _connect(device)
    try:
        raw = conn.send_command(f"display bgp routing-table peer {peer_ip} {direction}-routes", read_timeout=30)
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass
    return parse_peer_routes(raw, peer_ip, direction)
