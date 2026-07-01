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


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}

    pp_path = cfg.get("protected_prefixes_file", DEFAULT_PROTECTED_PREFIXES_FILE)
    wl_path = cfg.get("whitelist_file", DEFAULT_WHITELIST_FILE)

    cfg["protected_prefixes"] = load_yaml_list(pp_path)
    cfg["whitelist"] = load_yaml_list(wl_path)
    # caminhos resolvidos, para quem precisar editar os arquivos (ex: whitelist add/del)
    cfg["_protected_prefixes_file"] = pp_path
    cfg["_whitelist_file"] = wl_path
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
