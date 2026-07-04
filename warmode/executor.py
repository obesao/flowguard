"""war_mode — "botão de emergência": executa, em paralelo, os comandos configurados
via SSH em vários equipamentos de rede (NE8000, A10, etc.) de uma vez só. Pensado pra
um cenário de DDoS massivo onde o operador precisa aplicar mitigação de borda rápido,
em mais de um equipamento, sem digitar comando por comando em cada um.

Deliberadamente standalone (não depende do flowguard.service estar de pé, nem fala com
o socket do daemon) — é chamado direto pelo CGI do portal e pelo flowguard-cli. Config
(hosts, credenciais, comandos) fica em warmode.yaml, fora do git (contém senha em texto
puro — mesma lógica de proteção que /root/ai/.env: só permissão de arquivo, root-only,
list de sensitive/gitignored, não é multiusuário)."""

from __future__ import annotations

import concurrent.futures
import json
import logging
import os
import sys
import time
from pathlib import Path

import yaml
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import notifier

LOG = logging.getLogger("flowguard.warmode")

DEFAULT_CONFIG_PATH = "/root/flowguard/warmode.yaml"
FLOWGUARD_CONFIG_PATH = "/root/flowguard/config.yaml"
AUDIT_LOG_PATH = "/var/log/flowguard-warmode-audit.jsonl"
STATE_PATH = "/root/flowguard/warmode/state.json"


def load_config(path: str = DEFAULT_CONFIG_PATH) -> dict:
    p = Path(path)
    if not p.exists():
        return {"devices": []}
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {"devices": []}


def get_state(path: str = STATE_PATH) -> dict:
    """Estado atual do Modo Guerra (ligado/desligado + desde quando) — lido pelo
    portal (botão único/timer) e pelo report.py (aviso periódico no WhatsApp).
    Puramente declarativo: reflete a intenção do operador (clicou pra ligar/
    desligar), não se os comandos SSH tiveram sucesso em todos os equipamentos —
    isso já é reportado separadamente (audit log / resultado no modal)."""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"active": False, "started_at": None}


def _write_state(active: bool, path: str = STATE_PATH) -> None:
    if active:
        current = get_state(path)
        started_at = current.get("started_at") if current.get("active") else int(time.time())
        state = {"active": True, "started_at": started_at}
    else:
        state = {"active": False, "started_at": None}
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(state), encoding="utf-8")


def load_devices_masked(config_path: str = DEFAULT_CONFIG_PATH) -> list[dict]:
    """Pra tela de configuração no portal — nunca devolve a senha salva, só se
    ela existe (has_password), pra não reexibir segredo já gravado. Inclui
    enabled (participa ou não do próximo lote) e last_run (audit log) pra
    dar visibilidade na própria lista, sem precisar abrir log/rodar de fato."""
    cfg = load_config(config_path)
    last_runs = last_runs_by_device()
    out = []
    for d in cfg.get("devices") or []:
        name = d.get("name") or d.get("host", "")
        out.append({
            "name": d.get("name", ""),
            "host": d.get("host", ""),
            "port": d.get("port", 22),
            "device_type": d.get("device_type", ""),
            "username": d.get("username", ""),
            "has_password": bool(d.get("password")),
            "enable_mode": bool(d.get("enable_mode", False)),
            "enabled": bool(d.get("enabled", True)),
            "commands": d.get("commands") or [],
            "revert_commands": d.get("revert_commands") or [],
            "last_run": last_runs.get(name),
        })
    return out


def save_devices(devices: list[dict], config_path: str = DEFAULT_CONFIG_PATH) -> None:
    """Grava a lista de equipamentos vinda do formulário do portal. Cada item sem
    "password" (ausente/vazia) mantém a senha já salva daquele host — o frontend
    nunca recebe a senha de volta, só edita se quiser trocá-la."""
    existing_by_host = {d.get("host"): d for d in (load_config(config_path).get("devices") or [])}
    out = []
    for d in devices:
        host = d["host"]
        row = {
            "name": d.get("name") or host,
            "host": host,
            "port": int(d.get("port") or 22),
            "device_type": d["device_type"],
            "username": d.get("username", ""),
            "enable_mode": bool(d.get("enable_mode", False)),
            "enabled": bool(d.get("enabled", True)),
            "commands": [c for c in (d.get("commands") or []) if c.strip()],
            "revert_commands": [c for c in (d.get("revert_commands") or []) if c.strip()],
        }
        new_password = d.get("password") or ""
        if new_password:
            row["password"] = new_password
        else:
            row["password"] = existing_by_host.get(host, {}).get("password", "")
        out.append(row)
    Path(config_path).parent.mkdir(parents=True, exist_ok=True)
    with open(config_path, "w", encoding="utf-8") as fh:
        fh.write("# warmode.yaml — editado via portal (Configuração do Modo Guerra > trocar senha pra acessar).\n")
        yaml.safe_dump({"devices": out}, fh, sort_keys=False, allow_unicode=True)
    # contém senhas SSH dos equipamentos em texto puro — root-only, sempre; sem isso
    # o arquivo nasce 644 (umask padrão) e qualquer usuário local lê as credenciais
    os.chmod(config_path, 0o600)


def _send_commands(conn, commands: list[str], timeout: float) -> str:
    outputs = []
    if commands and commands[0].strip().lower() == "system-view":
        # entra em system-view: o prompt muda de "<host>" (modo usuário) pra
        # "[host]" (config) — send_command() por linha espera sempre o prompt
        # original e trava até o timeout. send_config_set() entra/sai do modo
        # de config sozinho e reconhece os dois formatos de prompt.
        cfg_commands = [c for c in commands[1:] if c.strip() and c.strip() != "#"]
        out = conn.send_config_set(cfg_commands, read_timeout=timeout)
        outputs.append(f"$ system-view\n{out}")
    else:
        for cmd in commands:
            out = conn.send_command(cmd, read_timeout=timeout, strip_prompt=False, strip_command=False)
            outputs.append(f"$ {cmd}\n{out}")
    return "\n\n".join(outputs)


def _connect_device(device: dict, timeout: float):
    """Abre a sessão SSH/Netmiko — compartilhado entre _run_device (roda
    comandos de verdade) e test_device (só valida credencial/alcance)."""
    conn = ConnectHandler(
        device_type=device["device_type"],
        host=device["host"],
        port=int(device.get("port") or 22),
        username=device.get("username", ""),
        password=device.get("password", ""),
        secret=device.get("enable_secret", device.get("password", "")),
        timeout=timeout,
        conn_timeout=timeout,
        fast_cli=False,
    )
    if device.get("enable_mode"):
        conn.enable()
    return conn


def _run_device(device: dict, timeout: float, mode: str = "apply") -> dict:
    name = device.get("name") or device.get("host", "?")
    commands = device.get("commands" if mode == "apply" else "revert_commands") or []
    t0 = time.monotonic()
    if not commands:
        error = ("nenhum comando configurado pra este equipamento" if mode == "apply"
                  else "nenhum comando de reversão configurado pra este equipamento")
        return {"device": name, "ok": False, "error": error, "output": "", "elapsed_s": 0.0}

    conn = None
    try:
        conn = _connect_device(device, timeout)
        output = _send_commands(conn, commands, timeout)
        return {
            "device": name, "ok": True, "output": output,
            "elapsed_s": round(time.monotonic() - t0, 1),
        }
    except NetmikoAuthenticationException:
        return {"device": name, "ok": False, "error": "autenticação falhou (usuário/senha)", "output": "", "elapsed_s": round(time.monotonic() - t0, 1)}
    except NetmikoTimeoutException:
        return {"device": name, "ok": False, "error": "timeout de conexão SSH", "output": "", "elapsed_s": round(time.monotonic() - t0, 1)}
    except Exception as exc:
        return {"device": name, "ok": False, "error": str(exc), "output": "", "elapsed_s": round(time.monotonic() - t0, 1)}
    finally:
        if conn is not None:
            try:
                conn.disconnect()
            except Exception:
                pass


def test_device(device: dict, config_path: str = DEFAULT_CONFIG_PATH, timeout: float = 12.0) -> dict:
    """Só abre/fecha a sessão SSH (nenhum comando de produção é enviado) — pra
    validar credencial/alcance de um equipamento antes de precisar dele de
    verdade num incidente. Se password vier em branco (equipamento já salvo,
    operador não redigitou), usa a senha já gravada pra aquele host — mesma
    regra de "campo em branco = mantém o que já tem" de save_devices."""
    device = dict(device)
    if not device.get("password") and device.get("host"):
        existing = {d.get("host"): d for d in (load_config(config_path).get("devices") or [])}
        device["password"] = existing.get(device["host"], {}).get("password", "")

    t0 = time.monotonic()
    conn = None
    try:
        conn = _connect_device(device, timeout)
        return {"ok": True, "elapsed_s": round(time.monotonic() - t0, 1)}
    except NetmikoAuthenticationException:
        return {"ok": False, "error": "autenticação falhou (usuário/senha)", "elapsed_s": round(time.monotonic() - t0, 1)}
    except NetmikoTimeoutException:
        return {"ok": False, "error": "timeout de conexão SSH", "elapsed_s": round(time.monotonic() - t0, 1)}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "elapsed_s": round(time.monotonic() - t0, 1)}
    finally:
        if conn is not None:
            try:
                conn.disconnect()
            except Exception:
                pass


def last_runs_by_device(audit_log_path: str = AUDIT_LOG_PATH, max_lines: int = 1000) -> dict[str, dict]:
    """Última execução de cada equipamento (por nome), lida do audit log —
    pra mostrar na tela de configuração sem precisar abrir log/rodar de novo.
    Entradas são append-only em ordem cronológica, então sobrescrever ao
    iterar deixa o valor mais recente por equipamento. Só olha as últimas
    max_lines linhas (Modo Guerra roda raramente — não é por ciclo de
    agregação — mas evita crescer sem limite se isso mudar)."""
    p = Path(audit_log_path)
    if not p.exists():
        return {}
    try:
        lines = p.read_text(encoding="utf-8").splitlines()[-max_lines:]
    except OSError:
        return {}
    latest: dict[str, dict] = {}
    for line in lines:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        for r in record.get("results") or []:
            device_name = r.get("device")
            if not device_name:
                continue
            latest[device_name] = {
                "ts": record.get("ts"), "mode": record.get("mode"),
                "ok": r.get("ok"), "error": r.get("error"),
            }
    return latest


def _audit(trigger: str, mode: str, results: list[dict]) -> None:
    record = {
        "ts": int(time.time()), "trigger": trigger, "mode": mode,
        "results": [{"device": r["device"], "ok": r["ok"], "elapsed_s": r.get("elapsed_s"),
                     "error": r.get("error")} for r in results],
    }
    try:
        Path(AUDIT_LOG_PATH).parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError:
        LOG.exception("falha ao gravar audit log do modo guerra")


def _notify_whatsapp(trigger: str, mode: str, results: list[dict]) -> None:
    """Lê alerts.whatsapp direto do config.yaml do FlowGuard (só leitura de arquivo,
    não depende do daemon/socket estar de pé — mantém o executor standalone)."""
    try:
        alerts_cfg = (yaml.safe_load(Path(FLOWGUARD_CONFIG_PATH).read_text(encoding="utf-8")) or {}).get("alerts", {})
    except OSError:
        return
    if not alerts_cfg.get("whatsapp"):
        return
    ok_devices = [r["device"] for r in results if r["ok"]]
    fail_devices = [r["device"] for r in results if not r["ok"]]
    action_label = "acionado" if mode == "apply" else "revertido (saída)"
    icon = "🚨" if mode == "apply" else "🔙"
    message = f"{icon} MODO GUERRA {action_label} (gatilho: {trigger})"
    if ok_devices:
        message += f"\nOK: {', '.join(ok_devices)}"
    if fail_devices:
        message += f"\nFALHA: {', '.join(fail_devices)}"
    notifier.send_whatsapp(message)


def list_devices(config_path: str = DEFAULT_CONFIG_PATH) -> list[dict]:
    """Metadados dos equipamentos configurados, sem senha — pra exibir na UI antes
    de disparar de fato. Inclui enabled=false pros desativados aparecerem
    esmaecidos no modal ("não vai rodar") em vez de simplesmente sumirem —
    evita o operador se perguntar "cadê meu equipamento" no meio de um incidente."""
    cfg = load_config(config_path)
    return [
        {
            "name": d.get("name") or d.get("host", "?"),
            "host": d.get("host"),
            "device_type": d.get("device_type"),
            "enabled": bool(d.get("enabled", True)),
            "n_commands": len(d.get("commands") or []),
            "n_revert_commands": len(d.get("revert_commands") or []),
        }
        for d in (cfg.get("devices") or [])
    ]


def _run_war_mode(mode: str, config_path: str, timeout: float, trigger: str) -> list[dict]:
    cfg = load_config(config_path)
    # equipamento com enabled=false fica de fora do lote de propósito (ex:
    # manutenção, credencial vencida) sem precisar apagar comandos/credenciais
    # salvos — não aparece nem em "results", então nem no audit log/WhatsApp
    devices = [d for d in (cfg.get("devices") or []) if d.get("enabled", True)]
    if not devices:
        return []
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(devices)) as pool:
        futures = {pool.submit(_run_device, d, timeout, mode): d for d in devices}
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())
    LOG.warning("MODO GUERRA %s (%s): %s", mode, trigger,
                [{"device": r["device"], "ok": r["ok"]} for r in results])
    _write_state(mode == "apply")
    _audit(trigger, mode, results)
    _notify_whatsapp(trigger, mode, results)
    return results


def run_war_mode(config_path: str = DEFAULT_CONFIG_PATH, timeout: float = 25.0, trigger: str = "manual") -> list[dict]:
    return _run_war_mode("apply", config_path, timeout, trigger)


def run_war_mode_revert(config_path: str = DEFAULT_CONFIG_PATH, timeout: float = 25.0, trigger: str = "manual") -> list[dict]:
    """Sai do Modo Guerra: roda os comandos de reversão de cada equipamento (o
    inverso dos comandos aplicados), pra voltar o estado de antes do incidente."""
    return _run_war_mode("revert", config_path, timeout, trigger)


if __name__ == "__main__":
    import sys
    print(json.dumps(run_war_mode(trigger="cli-direct"), indent=2, ensure_ascii=False), file=sys.stdout)
    sys.exit(0)
