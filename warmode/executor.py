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
import time
from pathlib import Path

import yaml
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

LOG = logging.getLogger("flowguard.warmode")

DEFAULT_CONFIG_PATH = "/root/flowguard/warmode.yaml"
AUDIT_LOG_PATH = "/var/log/flowguard-warmode-audit.jsonl"


def load_config(path: str = DEFAULT_CONFIG_PATH) -> dict:
    p = Path(path)
    if not p.exists():
        return {"devices": []}
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {"devices": []}


def _run_device(device: dict, timeout: float) -> dict:
    name = device.get("name") or device.get("host", "?")
    commands = device.get("commands") or []
    t0 = time.monotonic()
    if not commands:
        return {"device": name, "ok": False, "error": "nenhum comando configurado pra este equipamento", "output": "", "elapsed_s": 0.0}

    conn = None
    try:
        conn = ConnectHandler(
            device_type=device["device_type"],
            host=device["host"],
            port=device.get("port", 22),
            username=device["username"],
            password=device["password"],
            secret=device.get("enable_secret", device.get("password", "")),
            timeout=timeout,
            conn_timeout=timeout,
            fast_cli=False,
        )
        if device.get("enable_mode"):
            conn.enable()
        outputs = []
        for cmd in commands:
            out = conn.send_command(cmd, read_timeout=timeout, strip_prompt=False, strip_command=False)
            outputs.append(f"$ {cmd}\n{out}")
        return {
            "device": name, "ok": True, "output": "\n\n".join(outputs),
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


def _audit(trigger: str, results: list[dict]) -> None:
    record = {
        "ts": int(time.time()), "trigger": trigger,
        "results": [{"device": r["device"], "ok": r["ok"], "elapsed_s": r.get("elapsed_s"),
                     "error": r.get("error")} for r in results],
    }
    try:
        Path(AUDIT_LOG_PATH).parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError:
        LOG.exception("falha ao gravar audit log do modo guerra")


def list_devices(config_path: str = DEFAULT_CONFIG_PATH) -> list[dict]:
    """Metadados dos equipamentos configurados, sem senha — pra exibir na UI antes
    de disparar de fato."""
    cfg = load_config(config_path)
    return [
        {
            "name": d.get("name") or d.get("host", "?"),
            "host": d.get("host"),
            "device_type": d.get("device_type"),
            "n_commands": len(d.get("commands") or []),
        }
        for d in (cfg.get("devices") or [])
    ]


def run_war_mode(config_path: str = DEFAULT_CONFIG_PATH, timeout: float = 25.0, trigger: str = "manual") -> list[dict]:
    cfg = load_config(config_path)
    devices = cfg.get("devices") or []
    if not devices:
        return []
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(devices)) as pool:
        futures = {pool.submit(_run_device, d, timeout): d for d in devices}
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())
    LOG.warning("MODO GUERRA acionado (%s): %s", trigger,
                [{"device": r["device"], "ok": r["ok"]} for r in results])
    _audit(trigger, results)
    return results


if __name__ == "__main__":
    import sys
    print(json.dumps(run_war_mode(trigger="cli-direct"), indent=2, ensure_ascii=False), file=sys.stdout)
    sys.exit(0)
