"""Tradução de regras FlowGuard para a sintaxe de comando (texto) da API do ExaBGP.

A sintaxe é a documentada em exabgp.conf(5) e replicada nos exemplos do próprio
pacote (/usr/share/doc/exabgp/examples/api-flow.conf, conf-flow.conf): comandos
enviados ao ExaBGP pelo `process` são sempre texto, mesmo com `encoder json`
configurado — esse encoder afeta só as mensagens que o ExaBGP manda PARA o
processo, não o sentido inverso.
"""

from __future__ import annotations

_SIZE_SUFFIXES = {"k": 1_000, "m": 1_000_000, "g": 1_000_000_000}

_MATCH_FIELDS = {
    "dst_prefix": "destination",
    "src_prefix": "source",
    "protocol": "protocol",
    "dst_port": "destination-port",
    "src_port": "source-port",
    "tcp_flags": "tcp-flags",
    "pkt_len": "packet-length",
}

_RULE_STRING_KEYS = {
    "dst": "dst_prefix",
    "src": "src_prefix",
    "protocol": "protocol",
    "dst-port": "dst_port",
    "src-port": "src_port",
    "tcp-flags": "tcp_flags",
    "pkt-len": "pkt_len",
}
_RULE_STRING_ACTIONS = {"discard", "rate-limit", "rtbh", "redirect"}


def parse_size(value: str) -> int:
    """Converte '1M', '500K', '2G' (ou um número puro) em bps inteiro."""
    value = value.strip()
    suffix = value[-1:].lower()
    if suffix in _SIZE_SUFFIXES:
        return int(float(value[:-1]) * _SIZE_SUFFIXES[suffix])
    return int(value)


def parse_rule_string(rule_str: str) -> dict:
    """Faz parse do formato usado por `flowguard-cli flowspec add "dst=X protocol=udp src-port=53 rate-limit=1M"`."""
    rule: dict = {}
    action = None
    for token in rule_str.split():
        if "=" not in token:
            raise ValueError(f"token inválido (esperado key=value): {token}")
        key, value = token.split("=", 1)
        if key in _RULE_STRING_ACTIONS:
            if key == "discard":
                action = "discard"
            elif key == "rtbh":
                action = "rtbh"
            elif key == "rate-limit":
                action = f"rate-limit:{parse_size(value)}"
            elif key == "redirect":
                action = f"redirect:{value}"
        elif key in _RULE_STRING_KEYS:
            rule[_RULE_STRING_KEYS[key]] = value
        else:
            raise ValueError(f"campo desconhecido na regra: {key}")
    if action is None:
        raise ValueError("regra precisa de uma ação: discard, rate-limit=N, rtbh ou redirect=N")
    rule["action"] = action
    return rule


def _match_clause(rule: dict) -> str:
    parts = []
    for field, keyword in _MATCH_FIELDS.items():
        value = rule.get(field)
        if not value:
            continue
        if field in ("dst_port", "src_port", "pkt_len") and value[0] not in "=><!":
            value = f"={value}"
        parts.append(f"{keyword} {value};")
    if not parts:
        raise ValueError("regra FlowSpec sem nenhum campo de match")
    return " ".join(parts)


def _then_clause(action: str) -> str:
    if action == "discard":
        return "discard;"
    if action.startswith("rate-limit:"):
        return f"rate-limit {action.split(':', 1)[1]};"
    if action.startswith("redirect:"):
        return f"redirect {action.split(':', 1)[1]};"
    raise ValueError(f"ação FlowSpec desconhecida: {action}")


def flowspec_announce(rule: dict) -> str:
    return f"announce flow route {{ match {{ {_match_clause(rule)} }} then {{ {_then_clause(rule['action'])} }} }}"


def flowspec_withdraw(rule: dict) -> str:
    return f"withdraw flow route {{ match {{ {_match_clause(rule)} }} }}"


def rtbh_announce(prefix: str, community: str, nexthop: str) -> str:
    # community é AS:NN em 16+16 bits (RFC 1997) — não pode ser o nosso AS real
    # (262620, ASN de 4 bytes, estoura os 16 bits: exabgp quebra com "'L' format
    # requires 0 <= number <= 4294967295" ao empacotar). O NE8000 casa a aceitação
    # da rota pelo community-filter basic COMM_FASTNETMON_BLACKHOLE, que permite
    # especificamente 2626:669 — um valor convencional (não o AS real), configurado
    # assim do lado do Huawei. bgp.rtbh_community em config.yaml precisa bater com
    # exatamente esse valor.
    return f"announce route {prefix} next-hop {nexthop} community [{community}]"


def rtbh_withdraw(prefix: str) -> str:
    return f"withdraw route {prefix}"


def build_command(action: str, kind: str, rule: dict, neighbor: str | None = None) -> str:
    """neighbor (opcional): IP do peer BGP alvo — sem isso, o ExaBGP propaga o
    comando pra TODOS os peers configurados que casem a address-family (comportamento
    de antes de existir mais de um neighbor no exabgp.conf). Com múltiplos peers
    (ex.: NE8000BGP + NE8000-PPPOE), regras destinadas a só um deles devem
    especificar o neighbor pra não anunciar onde não faz sentido (nunca vai casar
    tráfego lá, mas polui o estado BGP anunciado e a auditoria)."""
    if kind == "flowspec":
        command = flowspec_announce(rule) if action == "announce" else flowspec_withdraw(rule)
    elif kind == "rtbh":
        if action == "announce":
            command = rtbh_announce(rule["dst_prefix"], rule["community"], rule["nexthop"])
        else:
            command = rtbh_withdraw(rule["dst_prefix"])
    else:
        raise ValueError(f"kind desconhecido: {kind}")
    return f"neighbor {neighbor} {command}" if neighbor else command


# Campos de match FIXOS por attack_type (o que define a assinatura do ataque —
# protocolo/porta de origem — não é um parâmetro de intensidade ajustável). Tipos
# ausentes daqui (ddos_volumetrico, anomalia_baseline) não têm porta/protocolo fixo
# pra casar em FlowSpec — o match cai só no dst_prefix inteiro.
_MATCH_TEMPLATES = {
    "dns_amp": {"protocol": "udp", "src_port": "53"},
    "ntp_amp": {"protocol": "udp", "src_port": "123"},
    "ssdp_amp": {"protocol": "udp", "src_port": "1900"},
    "memcached_amp": {"protocol": "udp", "src_port": "11211"},
    "cldap_amp": {"protocol": "udp", "src_port": "389"},
}

_ATTACK_LABELS = {
    "ddos_volumetrico": "DDoS volumétrico",
    "dns_amp": "amplificação DNS",
    "ntp_amp": "amplificação NTP",
    "ssdp_amp": "amplificação SSDP",
    "memcached_amp": "amplificação Memcached",
    "cldap_amp": "amplificação CLDAP",
    "anomalia_baseline": "anomalia de baseline",
}


def _describe_match(match: dict) -> str:
    if not match:
        return "todo o tráfego pro prefixo"
    parts = [f"{match['protocol']} origem {match['src_port']}"]
    if match.get("pkt_len"):
        parts.append(f"pacote {match['pkt_len']}b")
    return ", ".join(parts)


def suggest_mitigation(attack_type: str, dst_prefix: str, mitigation_profiles: dict = None) -> dict:
    """Mitigação recomendada para um ataque já confirmado pela engine de detecção —
    kind/pkt_len_min/rate_limit_mbps vêm de mitigation_profiles (ver
    configio.DEFAULT_MITIGATION_PROFILES; None ou tipo ausente usa esses defaults, o
    mesmo comportamento de antes dessa configuração existir).

    kind == "rtbh": blackhole total do prefixo via BGP (independe de match).
    kind == "rate_limit": FlowSpec, não descarta — só limita a banda do tráfego que
    casa o match (ou do prefixo inteiro, pros tipos sem porta/protocolo fixo).
    kind == "discard" (default): FlowSpec, descarta só o tráfego que casa o match.
    """
    profile = (mitigation_profiles or {}).get(attack_type) or {}
    match = dict(_MATCH_TEMPLATES.get(attack_type, {}))
    default_kind = "discard" if match else "rtbh"
    kind = profile.get("kind", default_kind)
    label_suffix = f" ({_ATTACK_LABELS.get(attack_type, attack_type)})"

    if attack_type in ("dns_amp", "ntp_amp"):
        default_pkt_len = 512 if attack_type == "dns_amp" else 400
        pkt_len_min = profile.get("pkt_len_min", default_pkt_len)
        match["pkt_len"] = f">{int(pkt_len_min)}"

    if kind == "rtbh":
        return {
            "kind": "rtbh", "rule": {"dst_prefix": dst_prefix},
            "label": f"RTBH: bloqueio total do prefixo{label_suffix}",
        }

    if kind == "rate_limit":
        rate_mbps = profile.get("rate_limit_mbps", 50)
        rule = {**match, "dst_prefix": dst_prefix, "action": f"rate-limit:{int(rate_mbps * 1_000_000)}"}
        return {
            "kind": "flowspec", "rule": rule,
            "label": f"FlowSpec: limita a {rate_mbps} Mbps — {_describe_match(match)}{label_suffix}",
        }

    # discard
    rule = {**match, "dst_prefix": dst_prefix, "action": "discard"}
    return {
        "kind": "flowspec", "rule": rule,
        "label": f"FlowSpec: descarta {_describe_match(match)}{label_suffix}",
    }
