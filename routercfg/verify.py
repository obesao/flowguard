"""Confere se uma regra FlowSpec/RTBH do FlowGuard está DE FATO no roteador,
consultando via SSH um comando `display` (só leitura) — nunca confia
cegamente no que o ExaBGP disse ter aceitado nem no que está gravado local em
flowspec_rules. Motivação: bugs reais encontrados nesta base onde o estado
local dizia uma coisa (ex: "revertida") e a regra de verdade na borda dizia
outra (continuava anunciada, cliente continuava bloqueado).

Reaproveita _connect/_device_for de routercfg/apply.py — mesma fonte de
credenciais (warmode.yaml), mesmo padrão try/finally de desconexão de
routercfg/discovery.py. Só leitura, nunca aplica nada.

Sintaxe VRP validada ao vivo contra os dois equipamentos reais
(NE8000BGP e HUAWEI-PPPOE-222) antes de escrever os parsers abaixo:
- RTBH: `display bgp routing-table {ip} {masklen}` — ip e máscara SEPARADOS
  por espaço, NUNCA notação CIDR (achado real: com CIDR o VRP faz
  longest-prefix-match e devolve silenciosamente uma rota completamente
  diferente quando o /32 específico não existe, em vez de avisar). Ausência
  do prefixo exato: "Info: The network does not exist."
- FlowSpec: `display bgp flow routing-table` — a CLI só filtra por
  ReIndex/peer (nenhum dos dois disponível aqui), então a checagem é por
  substring nos campos "Source IP"/"Destination IP" de cada bloco da saída
  completa. A ação (discard/rate-limit) não aparece nessa tela — confirmar
  isso fica fora do escopo por ora (arriscado inventar parser pro extended
  community sem mais amostras reais)."""

from __future__ import annotations

import re

from routercfg.apply import _connect, _device_for
from routercfg.templates import ValidationError

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_ENTRY_HEADER_RE = re.compile(r"^\s*BGP routing table entry information of (\S+):", re.M)
_COMMUNITY_LINE_RE = re.compile(r"^\s*Community:\s*(.+)$", re.M)
_COMMUNITY_VALUE_RE = re.compile(r"<([^>]+)>")
_NEXTHOP_RE = re.compile(r"^\s*Original nexthop:\s*(\S+)", re.M)
_NOT_FOUND_MARKERS = ("does not exist", "no matching")
_UNRECOGNIZED_MARKERS = ("unrecognized command", "incomplete command")

_FLOW_ENTRY_RE = re.compile(r"ReIndex\s*:\s*\d+.*?(?=ReIndex\s*:\s*\d+|\Z)", re.S)
_FLOW_SRC_RE = re.compile(r"Source IP\s*:\s*(\S+)")
_FLOW_DST_RE = re.compile(r"Destination IP\s*:\s*(\S+)")

RTBH_COMMAND = "display bgp routing-table {ip} {masklen}"
FLOWSPEC_COMMAND = "display bgp flow routing-table"

MATCH_FOUND = "found"
MATCH_FOUND_MISMATCH = "found_mismatch"
MATCH_NOT_FOUND = "not_found"
MATCH_INCONCLUSIVE = "inconclusive"  # saída do equipamento não reconhecida pelo parser
MATCH_ERROR = "error"  # não deu nem pra perguntar ao equipamento (SSH/config) — ver bgp/manager.py.verify_rule


def _split_prefix(prefix: str) -> tuple[str, str]:
    ip, _, masklen = (prefix or "").partition("/")
    if not _IPV4_RE.match(ip) or not masklen.isdigit():
        raise ValidationError(f"prefixo inválido pra verificação: {prefix!r}")
    return ip, masklen


def parse_rtbh_route(raw: str, prefix: str, expected_community: str | None,
                      expected_nexthop: str | None) -> dict:
    lowered = raw.lower()
    if any(marker in lowered for marker in _NOT_FOUND_MARKERS):
        return {"match_status": MATCH_NOT_FOUND,
                "detail": "rota não encontrada no roteador (equipamento respondeu que o prefixo não existe)."}

    header = _ENTRY_HEADER_RE.search(raw)
    if not header:
        return {"match_status": MATCH_INCONCLUSIVE,
                "detail": "formato de saída não reconhecido pelo parser — confira a saída bruta abaixo."}
    if header.group(1) != prefix:
        # não deveria acontecer com busca exata (ip+masklen separados), mas
        # não custa nada não confiar cegamente numa resposta pro prefixo errado
        return {"match_status": MATCH_INCONCLUSIVE,
                "detail": f"roteador respondeu sobre {header.group(1)}, não {prefix} — confira a saída bruta."}

    community_line = _COMMUNITY_LINE_RE.search(raw)
    communities = _COMMUNITY_VALUE_RE.findall(community_line.group(1)) if community_line else []
    nexthop_match = _NEXTHOP_RE.search(raw)
    nexthop = nexthop_match.group(1) if nexthop_match else None

    mismatches = []
    if expected_community and expected_community not in communities:
        mismatches.append(f"community esperada {expected_community}, encontrada {communities or 'nenhuma'}")
    if expected_nexthop and nexthop != expected_nexthop:
        mismatches.append(f"nexthop esperado {expected_nexthop}, encontrado {nexthop or 'nenhum'}")

    matched = {"community": communities, "nexthop": nexthop}
    if mismatches:
        return {"match_status": MATCH_FOUND_MISMATCH, "detail": "; ".join(mismatches), "matched": matched}
    return {"match_status": MATCH_FOUND, "detail": "rota confirmada no roteador com community/nexthop esperados.",
            "matched": matched}


def parse_flowspec_routes(raw: str) -> list[dict]:
    entries = []
    for block in _FLOW_ENTRY_RE.findall(raw):
        src = _FLOW_SRC_RE.search(block)
        dst = _FLOW_DST_RE.search(block)
        entries.append({"src_prefix": src.group(1) if src else None,
                         "dst_prefix": dst.group(1) if dst else None})
    return entries


def parse_flowspec_match(raw: str, rule: dict) -> dict:
    if any(marker in raw.lower() for marker in _UNRECOGNIZED_MARKERS):
        return {"match_status": MATCH_INCONCLUSIVE,
                "detail": "comando não reconhecido pelo equipamento — sintaxe VRP pode ter mudado."}
    src_prefix, dst_prefix = rule.get("src_prefix"), rule.get("dst_prefix")
    for entry in parse_flowspec_routes(raw):
        if (not src_prefix or entry["src_prefix"] == src_prefix) and \
           (not dst_prefix or entry["dst_prefix"] == dst_prefix):
            return {"match_status": MATCH_FOUND,
                    "detail": "regra encontrada na tabela FlowSpec do roteador "
                              "(compara origem/destino; ação discard/rate-limit não é conferida nesta versão).",
                    "matched": entry}
    return {"match_status": MATCH_NOT_FOUND,
            "detail": "nenhuma entrada da tabela FlowSpec do roteador bate com a origem/destino desta regra."}


def verify_rtbh(prefix: str, expected_community: str | None, expected_nexthop: str | None,
                 device_name: str | None = None) -> dict:
    ip, masklen = _split_prefix(prefix)
    device = _device_for(device_name)
    conn = _connect(device)
    command = RTBH_COMMAND.format(ip=ip, masklen=masklen)
    try:
        raw = conn.send_command(command, read_timeout=20)
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass
    result = parse_rtbh_route(raw, prefix, expected_community, expected_nexthop)
    result["command"] = command
    result["raw_output"] = raw
    result["expected"] = {"community": expected_community, "nexthop": expected_nexthop}
    return result


def verify_flowspec(rule: dict, device_name: str | None = None) -> dict:
    device = _device_for(device_name)
    conn = _connect(device)
    command = FLOWSPEC_COMMAND
    try:
        raw = conn.send_command(command, read_timeout=20)
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass
    result = parse_flowspec_match(raw, rule)
    result["command"] = command
    result["raw_output"] = raw
    result["expected"] = {"src_prefix": rule.get("src_prefix"), "dst_prefix": rule.get("dst_prefix")}
    return result


def verify_rule(rule: dict, device_name: str | None, bgp_cfg: dict) -> dict:
    """Ponto de entrada único — despacha por rule['action']. bgp_cfg só é usado
    pra RTBH (precisa de rtbh_community/nexthop_blackhole configurados)."""
    if rule.get("action") == "rtbh":
        return verify_rtbh(rule.get("dst_prefix"), bgp_cfg.get("rtbh_community"),
                            bgp_cfg.get("nexthop_blackhole"), device_name)
    return verify_flowspec(rule, device_name)
