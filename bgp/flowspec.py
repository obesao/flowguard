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


def build_command(action: str, kind: str, rule: dict) -> str:
    if kind == "flowspec":
        return flowspec_announce(rule) if action == "announce" else flowspec_withdraw(rule)
    if kind == "rtbh":
        if action == "announce":
            return rtbh_announce(rule["dst_prefix"], rule["community"], rule["nexthop"])
        return rtbh_withdraw(rule["dst_prefix"])
    raise ValueError(f"kind desconhecido: {kind}")


# Mitigação padrão por attack_type, conforme a coluna "Ação Padrão" da tabela
# "Ataques Detectados" do spec (flowguard.md) — só cobre os tipos que
# analyzer/engine.py realmente levanta hoje (ddos_volumetrico + AMP_PORTS).
_SUGGESTED_FLOWSPEC = {
    "dns_amp": ({"protocol": "udp", "src_port": "53", "pkt_len": ">512", "action": "discard"},
                "FlowSpec: discard UDP origem 53, pacote >512b (amplificação DNS)"),
    "ntp_amp": ({"protocol": "udp", "src_port": "123", "pkt_len": ">400", "action": "discard"},
                "FlowSpec: discard UDP origem 123, pacote >400b (amplificação NTP)"),
    "ssdp_amp": ({"protocol": "udp", "src_port": "1900", "action": "discard"},
                 "FlowSpec: discard UDP origem 1900 (amplificação SSDP)"),
    "memcached_amp": ({"protocol": "udp", "src_port": "11211", "action": "discard"},
                       "FlowSpec: discard UDP origem 11211 (amplificação Memcached)"),
    "cldap_amp": ({"protocol": "udp", "src_port": "389", "action": "discard"},
                  "FlowSpec: discard UDP origem 389 (amplificação CLDAP)"),
}


def suggest_mitigation(attack_type: str, dst_prefix: str) -> dict:
    """Mitigação recomendada para um ataque já confirmado pela engine de detecção.

    ddos_volumetrico não tem protocolo/porta fixos para casar em FlowSpec — a
    recomendação cai para RTBH (bloqueia o prefixo inteiro), igual à tabela do spec.
    """
    entry = _SUGGESTED_FLOWSPEC.get(attack_type)
    if entry is None:
        return {"kind": "rtbh", "rule": {"dst_prefix": dst_prefix}, "label": "RTBH: bloqueio total do prefixo (ataque volumétrico, sem padrão de porta/protocolo)"}
    template, label = entry
    return {"kind": "flowspec", "rule": {**template, "dst_prefix": dst_prefix}, "label": label}
