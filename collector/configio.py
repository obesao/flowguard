"""Leitura/gravação do config.yaml e dos arquivos auxiliares (prefixos monitorados, whitelist).

Mantidos em arquivos separados para que edições via CLI/CGI (whitelist add/del,
monitor add/del) não precisem reescrever o config.yaml inteiro — o que perderia
os comentários do operador e arriscaria tocar em chaves não relacionadas.
"""

from __future__ import annotations

from pathlib import Path

import yaml

DEFAULT_PROTECTED_PREFIXES_FILE = "/root/flowguard/protected_prefixes.yaml"
DEFAULT_WHITELIST_FILE = "/root/flowguard/whitelist.yaml"
DEFAULT_DETECTION_TOGGLES_FILE = "/root/flowguard/detection_toggles.yaml"
DEFAULT_MITIGATION_PROFILES_FILE = "/root/flowguard/mitigation_profiles.yaml"


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}

    pp_path = cfg.get("protected_prefixes_file", DEFAULT_PROTECTED_PREFIXES_FILE)
    wl_path = cfg.get("whitelist_file", DEFAULT_WHITELIST_FILE)
    dt_path = cfg.get("detection_toggles_file", DEFAULT_DETECTION_TOGGLES_FILE)
    mp_path = cfg.get("mitigation_profiles_file", DEFAULT_MITIGATION_PROFILES_FILE)

    cfg["protected_prefixes"] = load_yaml_list(pp_path)
    cfg["whitelist"] = load_yaml_list(wl_path)
    cfg["detection_toggles"] = load_feature_toggles(dt_path)
    cfg["mitigation_profiles"] = load_mitigation_profiles(mp_path)
    # caminhos resolvidos, para quem precisar editar os arquivos (ex: whitelist add/del)
    cfg["_protected_prefixes_file"] = pp_path
    cfg["_whitelist_file"] = wl_path
    cfg["_detection_toggles_file"] = dt_path
    cfg["_mitigation_profiles_file"] = mp_path
    return cfg


def load_yaml_list(path: str) -> list:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except FileNotFoundError:
        return []
    return data or []


def save_yaml_list(path: str, items: list, header_comment: str = "") -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        if header_comment:
            fh.write(header_comment.rstrip() + "\n")
        yaml.safe_dump(items, fh, sort_keys=False, allow_unicode=True)


# --- detection_toggles.yaml: liga/desliga por checkbox (portal) cada tipo de ataque ---
# Arquivo separado do config.yaml pelo mesmo motivo de protected_prefixes/whitelist:
# editar via portal não pode reescrever (nem perder os comentários de) o config.yaml
# principal. Chave ausente/arquivo inexistente = habilitado — nenhum tipo de ataque
# fica silenciosamente inativo por causa dessa feature em quem nunca configurou isso.
DEFAULT_FEATURE_TOGGLES = {
    "ddos_volumetrico": True,
    "dns_amp": True,
    "ntp_amp": True,
    "ssdp_amp": True,
    "memcached_amp": True,
    "cldap_amp": True,
    "anomalia_baseline": True,
}

TOGGLES_HEADER = (
    "# detection_toggles.yaml — liga/desliga cada tipo de ataque detectado, editável via\n"
    "# portal (aba Configuração > Funções) ou flowguard-cli toggles set.\n"
    "# Chave ausente = habilitado (mesmo padrão de antes desta feature existir)."
)


def load_feature_toggles(path: str) -> dict:
    """Retorna os toggles mesclados com os defaults — nunca falta uma chave, mesmo se
    o arquivo não existir ainda ou tiver sido criado com só algumas chaves."""
    merged = dict(DEFAULT_FEATURE_TOGGLES)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except FileNotFoundError:
        data = None
    if data:
        merged.update({k: bool(v) for k, v in data.items() if k in DEFAULT_FEATURE_TOGGLES})
    return merged


def save_feature_toggle(path: str, key: str, value: bool) -> dict:
    """Atalho de 1 chave só — ver save_feature_toggles (usada pelo botão "Aplicar
    novas configurações" do portal, que manda todas as mudanças pendentes de uma vez)."""
    return save_feature_toggles(path, {key: value})


def save_feature_toggles(path: str, changes: dict) -> dict:
    """Lê o estado atual (mesclado com defaults), aplica TODAS as mudanças de uma vez
    numa única leitura+escrita, e persiste só chaves conhecidas — evita que um
    detection_toggles.yaml corrompido/editado à mão propague lixo. Retorna o dict
    completo já atualizado. 1 read+write só (em vez de 1 por chave) é o que permite o
    chamador (socket_server) tratar isso como atômico sob concorrência."""
    unknown = sorted(k for k in changes if k not in DEFAULT_FEATURE_TOGGLES)
    if unknown:
        raise ValueError(f"toggle(s) desconhecido(s): {', '.join(unknown)}")
    current = load_feature_toggles(path)
    for key, value in changes.items():
        current[key] = bool(value)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(TOGGLES_HEADER.rstrip() + "\n")
        yaml.safe_dump(current, fh, sort_keys=False, allow_unicode=True)
    return current


# --- mitigation_profiles.yaml: estratégia de mitigação sugerida, por tipo de ataque ---
# Antes, bgp/flowspec.suggest_mitigation() tinha essas escolhas fixas no código: RTBH
# (blackhole total do prefixo) pra ddos_volumetrico/anomalia_baseline — que não têm
# porta/protocolo fixos pra casar em FlowSpec — e "discard" (derruba só o tráfego que
# casa o padrão) pros 5 tipos de amplificação, com limiar de tamanho de pacote também
# fixo. Isso vira config editável por tipo de ataque: RTBH continua sendo uma opção,
# mas "discard" (mais cirúrgico) e "rate_limit" (não derruba nada, só limita banda —
# a opção menos agressiva) passam a valer pra qualquer tipo, e o limiar de pacote/banda
# fica ajustável em vez de fixo.
MITIGATION_KINDS = ("rtbh", "discard", "rate_limit")

# pkt_len_min só existe (e só faz sentido) pra dns_amp/ntp_amp — nos outros tipos de
# amplificação o tamanho do pacote nunca fez parte do match original.
DEFAULT_MITIGATION_PROFILES = {
    "ddos_volumetrico": {"kind": "rtbh", "rate_limit_mbps": 100},
    "dns_amp": {"kind": "discard", "pkt_len_min": 512, "rate_limit_mbps": 50},
    "ntp_amp": {"kind": "discard", "pkt_len_min": 400, "rate_limit_mbps": 50},
    "ssdp_amp": {"kind": "discard", "rate_limit_mbps": 50},
    "memcached_amp": {"kind": "discard", "rate_limit_mbps": 50},
    "cldap_amp": {"kind": "discard", "rate_limit_mbps": 50},
    "anomalia_baseline": {"kind": "rtbh", "rate_limit_mbps": 50},
}

MITIGATION_PROFILES_HEADER = (
    "# mitigation_profiles.yaml — estratégia de mitigação sugerida (aba Ataques >\n"
    "# Aplicar Sugestão) por tipo de ataque:\n"
    "#   rtbh        - blackhole total do prefixo via BGP (mais agressivo)\n"
    "#   discard     - FlowSpec: descarta só o tráfego que casa o padrão do ataque\n"
    "#   rate_limit  - FlowSpec: não descarta, só limita a banda do tráfego que casa\n"
    "# pkt_len_min (bytes) e rate_limit_mbps são os parâmetros de intensidade do filtro.\n"
    "# Editável via portal (aba Configuração > Mitigação) ou flowguard-cli mitigation set.\n"
    "# Chave/campo ausente ou arquivo inexistente = comportamento original."
)


def load_mitigation_profiles(path: str) -> dict:
    """Retorna os perfis mesclados com os defaults — nunca falta um tipo de ataque nem
    um campo dele, mesmo se o arquivo não existir ainda ou tiver só algumas chaves."""
    merged = {attack_type: dict(fields) for attack_type, fields in DEFAULT_MITIGATION_PROFILES.items()}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except FileNotFoundError:
        data = None
    if data:
        for attack_type, fields in data.items():
            if attack_type not in merged or not isinstance(fields, dict):
                continue
            for key, value in fields.items():
                if key in merged[attack_type]:
                    merged[attack_type][key] = value
    return merged


def _validate_mitigation_changes(changes: dict) -> None:
    unknown_types = sorted(t for t in changes if t not in DEFAULT_MITIGATION_PROFILES)
    if unknown_types:
        raise ValueError(f"tipo(s) de ataque desconhecido(s): {', '.join(unknown_types)}")
    for attack_type, fields in changes.items():
        if not isinstance(fields, dict):
            raise ValueError(f"{attack_type}: valor precisa ser um objeto {{campo: valor}}")
        allowed = DEFAULT_MITIGATION_PROFILES[attack_type]
        unknown_fields = sorted(f for f in fields if f not in allowed)
        if unknown_fields:
            raise ValueError(f"{attack_type}: campo(s) desconhecido(s): {', '.join(unknown_fields)}")
        if "kind" in fields and fields["kind"] not in MITIGATION_KINDS:
            raise ValueError(f"{attack_type}.kind inválido ({fields['kind']!r}) — use um de {MITIGATION_KINDS}")
        for numeric_field in ("pkt_len_min", "rate_limit_mbps"):
            if numeric_field in fields:
                try:
                    value = float(fields[numeric_field])
                except (TypeError, ValueError):
                    raise ValueError(f"{attack_type}.{numeric_field} precisa ser numérico")
                if value <= 0:
                    raise ValueError(f"{attack_type}.{numeric_field} precisa ser positivo")


def save_mitigation_profiles(path: str, changes: dict) -> dict:
    """Lê o estado atual (mesclado com defaults), aplica TODAS as mudanças de uma vez
    numa única leitura+escrita (mesmo motivo de save_feature_toggles: atômico sob
    concorrência), validando tipo de ataque/campo/kind conhecidos ANTES de escrever
    qualquer coisa. Retorna o dict completo já atualizado."""
    _validate_mitigation_changes(changes)
    current = load_mitigation_profiles(path)
    for attack_type, fields in changes.items():
        current[attack_type].update(fields)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(MITIGATION_PROFILES_HEADER.rstrip() + "\n")
        yaml.safe_dump(current, fh, sort_keys=False, allow_unicode=True)
    return current
