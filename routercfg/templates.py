"""Registro de templates de configuração do roteador de borda (VRP) e validação
dos campos preenchidos pelo operador no portal.

Design deliberado: edição só via templates pré-definidos em router_templates.yaml
(versionado, sem segredos) — nunca CLI livre vinda do formulário. Cada campo tem
um tipo com validação estrita; um valor que não bate com o tipo é rejeitado, não
sanitizado. Em especial, quebra de linha/`;`/`|` são sempre proibidos em qualquer
campo — mesmo em modo "template", se um valor fosse concatenado sem essa checagem
um operador (ou erro de digitação) poderia injetar comandos VRP extras não
previstos pelo template.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

DEFAULT_TEMPLATES_PATH = "/root/flowguard/router_templates.yaml"

_FORBIDDEN_CHARS = re.compile(r"[\r\n\x00-\x1f;|`]")

_PATTERNS = {
    "ipv4": re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$"),
    "ipv4_cidr": re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)/(?:[0-9]|[12]\d|3[0-2])$"),
    "interface_name": re.compile(r"^[A-Za-z][A-Za-z0-9-]*\d+(?:/\d+){1,2}(?:\.\d+)?$"),
    "text_safe": re.compile(r"^[A-Za-z0-9 ._-]{1,80}$"),
}


class ValidationError(ValueError):
    pass


class TemplateError(ValueError):
    pass


def _cidr_to_mask(prefix_len: int) -> str:
    bits = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF if prefix_len else 0
    return ".".join(str((bits >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def _cidr_to_wildcard(prefix_len: int) -> str:
    mask = _cidr_to_mask(prefix_len)
    return ".".join(str(255 - int(o)) for o in mask.split("."))


def load_templates(path: str = DEFAULT_TEMPLATES_PATH) -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    templates = data.get("templates") or []
    for t in templates:
        if not t.get("commands"):
            raise TemplateError(f"template '{t.get('id')}' sem 'commands'")
        if not t.get("undo_commands"):
            raise TemplateError(f"template '{t.get('id')}' sem 'undo_commands' (toda mudança precisa de reversão definida)")
    return templates


def list_templates_public(path: str = DEFAULT_TEMPLATES_PATH) -> list[dict]:
    """Metadados de templates pra exibir no portal — sem os comandos VRP crus
    (o preview de comandos só é revelado depois que os campos são validados,
    via preview())."""
    out = []
    for t in load_templates(path):
        out.append({
            "id": t["id"],
            "label": t.get("label", t["id"]),
            "category": t.get("category", ""),
            "description": t.get("description", ""),
            "device_name": t.get("device_name"),
            "fields": [
                {
                    "name": f["name"],
                    "label": f.get("label", f["name"]),
                    "type": f["type"],
                    "required": f.get("required", True),
                    "options": f.get("options"),
                    "default": f.get("default"),
                    "min": f.get("min"),
                    "max": f.get("max"),
                    "help": f.get("help", ""),
                }
                for f in t.get("fields", [])
            ],
        })
    return out


def get_template(template_id: str, path: str = DEFAULT_TEMPLATES_PATH) -> dict:
    for t in load_templates(path):
        if t["id"] == template_id:
            return t
    raise ValidationError(f"template desconhecido: {template_id}")


def validate_field(field: dict, raw_value) -> str:
    name = field["name"]
    value = "" if raw_value is None else str(raw_value).strip()
    if _FORBIDDEN_CHARS.search(value):
        raise ValidationError(f"{name}: caractere não permitido (quebra de linha ou separador de comando)")
    if not value:
        if field.get("required", True):
            raise ValidationError(f"{name}: obrigatório")
        return str(field.get("default", ""))

    ftype = field["type"]
    if ftype == "enum":
        options = field.get("options") or []
        if value not in options:
            raise ValidationError(f"{name}: valor deve ser um de {options}")
        return value
    if ftype == "int_range":
        try:
            n = int(value)
        except ValueError:
            raise ValidationError(f"{name}: precisa ser um número inteiro")
        lo, hi = field.get("min", 0), field.get("max", 2**31 - 1)
        if not (lo <= n <= hi):
            raise ValidationError(f"{name}: precisa estar entre {lo} e {hi}")
        return str(n)

    pattern = _PATTERNS.get(ftype)
    if pattern is None:
        raise ValidationError(f"{name}: tipo de campo desconhecido ({ftype})")
    if not pattern.match(value):
        raise ValidationError(f"{name}: formato inválido para o tipo {ftype}")
    return value


def _resolve_fields(template: dict, values: dict) -> dict:
    resolved = {}
    for field in template.get("fields", []):
        name = field["name"]
        val = validate_field(field, (values or {}).get(name))
        resolved[name] = val
        if field["type"] == "ipv4_cidr" and val:
            network, _, prefix_len_s = val.partition("/")
            prefix_len = int(prefix_len_s)
            resolved[f"{name}_network"] = network
            resolved[f"{name}_mask"] = _cidr_to_mask(prefix_len)
            resolved[f"{name}_wildcard"] = _cidr_to_wildcard(prefix_len)

    # segunda passada: command_map/undo_command_map podem referenciar campos
    # de OUTROS fields (ex: "peer {peer_ip} ignore" dentro do map do campo
    # "action") — precisa do dict `resolved` já completo, não dá pra formatar
    # na mesma passada em que ele ainda está sendo construído.
    for field in template.get("fields", []):
        name = field["name"]
        val = resolved.get(name)
        if field["type"] != "enum":
            continue
        if field.get("command_map") and val in field["command_map"]:
            resolved[f"{name}_cmd"] = field["command_map"][val].format(**resolved)
        if field.get("undo_command_map") and val in field["undo_command_map"]:
            resolved[f"{name}_undo_cmd"] = field["undo_command_map"][val].format(**resolved)
    return resolved


def _render(command_lines: list[str], resolved: dict) -> list[str]:
    rendered = []
    for line in command_lines:
        try:
            rendered.append(line.format(**resolved))
        except KeyError as exc:
            raise TemplateError(f"placeholder não resolvido no template: {exc}")
    return rendered


def build_commands(template_id: str, values: dict, path: str = DEFAULT_TEMPLATES_PATH) -> dict:
    """Valida os campos de `template_id` contra `values` e devolve os comandos
    finais (de aplicação e de reversão) com os placeholders já substituídos.
    Levanta ValidationError se algum campo for inválido — nunca aplica parcial."""
    template = get_template(template_id, path)
    resolved = _resolve_fields(template, values)
    return {
        "template_id": template_id,
        "label": template.get("label", template_id),
        "device_name": template.get("device_name"),
        "values": {k: v for k, v in resolved.items()},
        "commands": _render(template["commands"], resolved),
        "undo_commands": _render(template["undo_commands"], resolved),
    }
