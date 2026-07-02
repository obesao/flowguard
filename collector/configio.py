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


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}

    pp_path = cfg.get("protected_prefixes_file", DEFAULT_PROTECTED_PREFIXES_FILE)
    wl_path = cfg.get("whitelist_file", DEFAULT_WHITELIST_FILE)
    dt_path = cfg.get("detection_toggles_file", DEFAULT_DETECTION_TOGGLES_FILE)

    cfg["protected_prefixes"] = load_yaml_list(pp_path)
    cfg["whitelist"] = load_yaml_list(wl_path)
    cfg["detection_toggles"] = load_feature_toggles(dt_path)
    # caminhos resolvidos, para quem precisar editar os arquivos (ex: whitelist add/del)
    cfg["_protected_prefixes_file"] = pp_path
    cfg["_whitelist_file"] = wl_path
    cfg["_detection_toggles_file"] = dt_path
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
