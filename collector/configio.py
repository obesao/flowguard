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
DEFAULT_DETECTION_TEMPLATES_FILE = "/root/flowguard/detection_templates.yaml"
DEFAULT_DETECTION_OVERRIDES_FILE = "/root/flowguard/detection_overrides.yaml"


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}

    pp_path = cfg.get("protected_prefixes_file", DEFAULT_PROTECTED_PREFIXES_FILE)
    wl_path = cfg.get("whitelist_file", DEFAULT_WHITELIST_FILE)
    dt_path = cfg.get("detection_toggles_file", DEFAULT_DETECTION_TOGGLES_FILE)
    mp_path = cfg.get("mitigation_profiles_file", DEFAULT_MITIGATION_PROFILES_FILE)
    dtpl_path = cfg.get("detection_templates_file", DEFAULT_DETECTION_TEMPLATES_FILE)
    dov_path = cfg.get("detection_overrides_file", DEFAULT_DETECTION_OVERRIDES_FILE)

    cfg["protected_prefixes"] = load_yaml_list(pp_path)
    cfg["whitelist"] = load_yaml_list(wl_path)
    cfg["detection_toggles"] = load_feature_toggles(dt_path)
    cfg["mitigation_profiles"] = load_mitigation_profiles(mp_path)
    cfg["detection_templates"] = load_detection_templates(dtpl_path)
    # ajuste fino via portal/CLI, aplicado por cima do detection.* já presente no
    # config.yaml — reload_config() do daemon recarrega load_config() inteiro do
    # zero, então isso aplica automaticamente sem precisar de nenhum estado extra
    # (diferente do ClientGuard, cujo reload não relê o config.yaml principal).
    cfg["detection"] = {**(cfg.get("detection") or {}), **load_detection_overrides(dov_path)}
    # caminhos resolvidos, para quem precisar editar os arquivos (ex: whitelist add/del)
    cfg["_protected_prefixes_file"] = pp_path
    cfg["_whitelist_file"] = wl_path
    cfg["_detection_toggles_file"] = dt_path
    cfg["_mitigation_profiles_file"] = mp_path
    cfg["_detection_templates_file"] = dtpl_path
    cfg["_detection_overrides_file"] = dov_path
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
    "syn_flood": True,
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

# auto_mode controla se a mitigação sai sozinha na abertura do ataque (sem esperar
# clique manual): "off" (padrão — nada muda pra quem nunca configurou isso),
# "suggestion" (espelha o botão "Aplicar Sugestão", usa kind/pkt_len_min/
# rate_limit_mbps abaixo), "rtbh" (espelha o botão "Mitigar", bloqueio total
# direto, ignorando o kind configurado). Ver bgp/manager.BgpManager.auto_mitigate.
# Além do tipo de ataque estar com auto_mode != "off", o PREFIXO em si precisa ter
# auto_mitigate: true em protected_prefixes.yaml (aba Monitor) — as duas travas
# precisam estar ligadas, nenhuma sozinha basta.
MITIGATION_AUTO_MODES = ("off", "suggestion", "rtbh")

# rtbh_default_ttl_s: duração padrão (segundos) do bloqueio RTBH — depois desse
# tempo a regra expira sozinha e é retirada (ver BgpManager.expire_cycle). É uma
# chave GLOBAL, reservada dentro do mesmo mitigation_profiles.yaml (não um campo
# por tipo de ataque como os de cima) — só vale pro botão "Mitigar"/auto_mode
# "rtbh"; FlowSpec (discard/rate_limit) continua usando mitigation.default_ttl_s
# do config.yaml, sem mudança. Pode ser sobrescrita pontualmente por quem chama
# ban() (ex: o operador escolhe outra duração na hora de clicar "Mitigar").
RTBH_TTL_KEY = "rtbh_default_ttl_s"
DEFAULT_RTBH_TTL_S = 3600

# pkt_len_min só existe (e só faz sentido) pra dns_amp/ntp_amp — nos outros tipos de
# amplificação o tamanho do pacote nunca fez parte do match original.
DEFAULT_MITIGATION_PROFILES = {
    "ddos_volumetrico": {"kind": "rtbh", "rate_limit_mbps": 100, "auto_mode": "off"},
    "dns_amp": {"kind": "discard", "pkt_len_min": 512, "rate_limit_mbps": 50, "auto_mode": "off"},
    "ntp_amp": {"kind": "discard", "pkt_len_min": 400, "rate_limit_mbps": 50, "auto_mode": "off"},
    "ssdp_amp": {"kind": "discard", "rate_limit_mbps": 50, "auto_mode": "off"},
    "memcached_amp": {"kind": "discard", "rate_limit_mbps": 50, "auto_mode": "off"},
    "cldap_amp": {"kind": "discard", "rate_limit_mbps": 50, "auto_mode": "off"},
    "syn_flood": {"kind": "discard", "rate_limit_mbps": 50, "auto_mode": "off"},
    "anomalia_baseline": {"kind": "rtbh", "rate_limit_mbps": 50, "auto_mode": "off"},
}

MITIGATION_PROFILES_HEADER = (
    "# mitigation_profiles.yaml — estratégia de mitigação sugerida (aba Ataques >\n"
    "# Aplicar Sugestão) por tipo de ataque:\n"
    "#   rtbh        - blackhole total do prefixo via BGP (mais agressivo)\n"
    "#   discard     - FlowSpec: descarta só o tráfego que casa o padrão do ataque\n"
    "#   rate_limit  - FlowSpec: não descarta, só limita a banda do tráfego que casa\n"
    "# pkt_len_min (bytes) e rate_limit_mbps são os parâmetros de intensidade do filtro.\n"
    "# auto_mode - dispara a mitigação sozinha na abertura do ataque, sem clique manual:\n"
    "#   off        - nunca dispara sozinho (padrão)\n"
    "#   suggestion - aplica o kind acima automaticamente (Aplicar Sugestão automático)\n"
    "#   rtbh       - bloqueia o prefixo inteiro automaticamente (Mitigar automático)\n"
    "# Só tem efeito nos prefixos com auto_mitigate: true em protected_prefixes.yaml.\n"
    "# rtbh_default_ttl_s - duração padrão (segundos) do bloqueio RTBH (botão \"Mitigar\"\n"
    "#   e auto_mode=rtbh) antes de expirar e ser retirado sozinho. Chave global, não é\n"
    "#   por tipo de ataque. FlowSpec continua usando mitigation.default_ttl_s (config.yaml).\n"
    "# Editável via portal (aba Configuração > Mitigação) ou flowguard-cli mitigation set.\n"
    "# Chave/campo ausente ou arquivo inexistente = comportamento original."
)


def load_mitigation_profiles(path: str) -> dict:
    """Retorna os perfis mesclados com os defaults — nunca falta um tipo de ataque nem
    um campo dele, mesmo se o arquivo não existir ainda ou tiver só algumas chaves.
    O dict retornado também carrega a chave global RTBH_TTL_KEY (não é um tipo de
    ataque, ver definição acima) — suggest_mitigation()/auto_mitigate() só fazem
    .get(attack_type), então essa chave extra nunca colide com um tipo real."""
    merged = {attack_type: dict(fields) for attack_type, fields in DEFAULT_MITIGATION_PROFILES.items()}
    merged[RTBH_TTL_KEY] = DEFAULT_RTBH_TTL_S
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except FileNotFoundError:
        data = None
    if data:
        if RTBH_TTL_KEY in data:
            try:
                merged[RTBH_TTL_KEY] = int(data[RTBH_TTL_KEY])
            except (TypeError, ValueError):
                pass
        for attack_type, fields in data.items():
            if attack_type not in DEFAULT_MITIGATION_PROFILES or not isinstance(fields, dict):
                continue
            for key, value in fields.items():
                if key in merged[attack_type]:
                    merged[attack_type][key] = value
    return merged


def _validate_mitigation_changes(changes: dict) -> None:
    unknown_types = sorted(t for t in changes if t not in DEFAULT_MITIGATION_PROFILES and t != RTBH_TTL_KEY)
    if unknown_types:
        raise ValueError(f"tipo(s) de ataque desconhecido(s): {', '.join(unknown_types)}")
    if RTBH_TTL_KEY in changes:
        try:
            value = int(changes[RTBH_TTL_KEY])
        except (TypeError, ValueError):
            raise ValueError(f"{RTBH_TTL_KEY} precisa ser um número inteiro de segundos")
        if value <= 0:
            raise ValueError(f"{RTBH_TTL_KEY} precisa ser positivo")
    for attack_type, fields in changes.items():
        if attack_type == RTBH_TTL_KEY:
            continue
        if not isinstance(fields, dict):
            raise ValueError(f"{attack_type}: valor precisa ser um objeto {{campo: valor}}")
        allowed = DEFAULT_MITIGATION_PROFILES[attack_type]
        unknown_fields = sorted(f for f in fields if f not in allowed)
        if unknown_fields:
            raise ValueError(f"{attack_type}: campo(s) desconhecido(s): {', '.join(unknown_fields)}")
        if "kind" in fields and fields["kind"] not in MITIGATION_KINDS:
            raise ValueError(f"{attack_type}.kind inválido ({fields['kind']!r}) — use um de {MITIGATION_KINDS}")
        if "auto_mode" in fields and fields["auto_mode"] not in MITIGATION_AUTO_MODES:
            raise ValueError(f"{attack_type}.auto_mode inválido ({fields['auto_mode']!r}) — "
                              f"use um de {MITIGATION_AUTO_MODES}")
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
        if attack_type == RTBH_TTL_KEY:
            current[RTBH_TTL_KEY] = int(fields)
        else:
            current[attack_type].update(fields)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(MITIGATION_PROFILES_HEADER.rstrip() + "\n")
        yaml.safe_dump(current, fh, sort_keys=False, allow_unicode=True)
    return current


# --- detection_templates.yaml: perfis de limiar reutilizáveis por tipo de rede -----
# Associado a um prefixo via `template:` em protected_prefixes.yaml — mesma ideia do
# ClientGuard (ver customers.yaml/detection_templates.yaml de lá), aplicada aqui aos
# limiares de DDoS volumétrico/amplificação (analyzer/engine.py resolve: thresholds
# explícito do prefixo > template > detection.* global de config.yaml).
DETECTION_TEMPLATES_HEADER = (
    "# detection_templates.yaml — perfis de limiar de detecção reutilizáveis por tipo de\n"
    "# rede/prefixo, associados via `template:` em protected_prefixes.yaml. Evita\n"
    "# recalibrar os mesmos números pra cada prefixo novo do mesmo perfil (ex.: pool CGNAT,\n"
    "# onde o tráfego agregado de muitos clientes combinados exige limiar bem mais alto que\n"
    "# um cliente único). Editável via portal (aba Configuração > FlowGuard) ou\n"
    "# flowguard-cli detection templates set|del.\n"
    "#\n"
    "# Ordem de precedência (do mais específico pro mais genérico): thresholds explícito\n"
    "# em protected_prefixes.yaml > template > detection.* em config.yaml (usado por\n"
    "# qualquer prefixo sem thresholds/template)."
)
# mesmas chaves que protected_prefixes.yaml::thresholds já suporta (ver
# analyzer/engine.py) — um template é só uma forma reutilizável de definir as duas.
DETECTION_TEMPLATE_KEYS = {"ddos_bps_threshold", "ddos_pps_threshold", "amp_bps_threshold"}


def load_detection_templates(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except FileNotFoundError:
        return {}
    return data or {}


def save_detection_template(path: str, name: str, values: dict, description: str = "") -> dict:
    """Cria ou substitui (nome já existente = sobrescreve) um template inteiro — não é
    merge parcial de campos, pra não deixar uma chave antiga órfã se o operador trocar
    de ideia sobre o que o template define."""
    if not name or not name.replace("_", "").replace("-", "").isalnum() or name != name.lower():
        raise ValueError("nome do template deve ser minúsculo, só letras/números/_/-")
    unknown = sorted(k for k in values if k not in DETECTION_TEMPLATE_KEYS)
    if unknown:
        raise ValueError(f"campo(s) desconhecido(s) no template: {', '.join(unknown)}")
    for key, val in values.items():
        if not isinstance(val, int) or isinstance(val, bool) or val <= 0:
            raise ValueError(f"{key} deve ser um inteiro positivo")
    current = load_detection_templates(path)
    entry = dict(values)
    if description:
        entry["description"] = description
    elif name in current and current[name].get("description"):
        entry["description"] = current[name]["description"]  # preserva descrição existente
    current[name] = entry
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(DETECTION_TEMPLATES_HEADER.rstrip() + "\n")
        yaml.safe_dump(current, fh, sort_keys=False, allow_unicode=True)
    return current


def delete_detection_template(path: str, name: str) -> dict:
    current = load_detection_templates(path)
    if name not in current:
        raise ValueError(f"template '{name}' não existe")
    del current[name]
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(DETECTION_TEMPLATES_HEADER.rstrip() + "\n")
        yaml.safe_dump(current, fh, sort_keys=False, allow_unicode=True)
    return current


# --- detection_overrides.yaml: ajuste fino dos limiares de config.yaml::detection ---
# via portal/CLI, sem tocar no config.yaml principal (mesmo motivo de
# protected_prefixes/whitelist/toggles: editar via portal não pode reescrever, e
# perder os comentários de, o config.yaml). reload_config() do daemon já relê
# config.yaml inteiro a cada chamada, então isso aplica sem reiniciar o daemon.
DETECTION_OVERRIDES_HEADER = (
    "# detection_overrides.yaml — ajuste fino dos limiares de detection.* em\n"
    "# config.yaml, aplicado por cima a cada carga/reload (sem reiniciar o daemon).\n"
    "# Editável via portal (aba Configuração > FlowGuard) ou\n"
    "# flowguard-cli detection set. Vazio = usa os valores de config.yaml sem ajuste."
)
DETECTION_TUNABLE_KEYS = {
    "ddos_bps_threshold", "ddos_pps_threshold", "amp_bps_threshold",
    "syn_ratio_threshold", "syn_min_pps_floor", "min_attack_duration_s",
    "attack_stale_close_s", "baseline_min_duration_s",
    "baseline_enabled", "baseline_window_minutes", "baseline_min_samples", "baseline_sigma",
    "baseline_min_bps",
}


def load_detection_overrides(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except FileNotFoundError:
        return {}
    data = data or {}
    return {k: v for k, v in data.items() if k in DETECTION_TUNABLE_KEYS}


def save_detection_overrides(path: str, changes: dict) -> dict:
    """Read-modify-write atômico (mesmo padrão de save_feature_toggles) — aplica todas
    as mudanças pendentes numa leitura+escrita só. Passar valor None pra uma chave
    REMOVE o override (volta a usar o valor de config.yaml), não grava null."""
    unknown = sorted(k for k in changes if k not in DETECTION_TUNABLE_KEYS)
    if unknown:
        raise ValueError(f"limiar(es) desconhecido(s): {', '.join(unknown)}")
    current = load_detection_overrides(path)
    for key, value in changes.items():
        if value is None:
            current.pop(key, None)
        else:
            current[key] = value
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(DETECTION_OVERRIDES_HEADER.rstrip() + "\n")
        yaml.safe_dump(current, fh, sort_keys=False, allow_unicode=True)
    return current
