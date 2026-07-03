"""Aplica templates de configuração no roteador de borda via SSH (Netmiko).

Fonte das credenciais de conexão: warmode.yaml (mesmo arquivo do "Modo Guerra",
ver flowguard/warmode/executor.py) — reaproveita a MESMA fonte de verdade em vez
de duplicar credenciais SSH num segundo arquivo fora do git. O equipamento é
escolhido por nome (`device_name` do template, ou "NE8000BGP" por padrão —
mesmo equipamento usado pela mitigação de borda do ClientGuard, ver
clientguard/edge_mitigation.py).

Segurança de aplicação (ver prompt original / README):
  1. Cria um ponto de rollback nativo do VRP antes de aplicar (best-effort —
     se o equipamento/versão não suportar, só loga um aviso e segue).
  2. Aplica os comandos do template.
  3. Grava um job pendente de confirmação e dispara um processo detached que,
     se o operador não confirmar dentro da janela (padrão 5min), reverte
     sozinho — preferindo o rollback point nativo (reversão completa e
     fidedigna) e caindo pros `undo_commands` do próprio template se o
     rollback point não existir/falhar (ver routercfg/templates.py: todo
     template é obrigado a definir undo_commands).
Isso existe pra nunca deixar um erro de configuração remoto (ex: mudança que
derruba o link de gerência) sem uma saída automática — não há console serial
disponível aqui.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path

import yaml
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import notifier  # noqa: E402
from warmode.executor import load_config as _load_warmode_config  # noqa: E402
from routercfg.templates import build_commands, ValidationError  # noqa: E402

LOG = logging.getLogger("flowguard.routercfg")

JOBS_DIR = Path("/root/flowguard/routercfg_jobs")
AUDIT_LOG_PATH = "/var/log/flowguard-routercfg-audit.jsonl"
DEFAULT_DEVICE_NAME = "NE8000BGP"
DEFAULT_CONFIRM_WINDOW_S = 300
_ROLLBACK_POINT_RE = re.compile(r"ID is (\d+)")


def _device_for(device_name: str | None) -> dict:
    name = device_name or DEFAULT_DEVICE_NAME
    cfg = _load_warmode_config()
    for d in cfg.get("devices") or []:
        if d.get("name") == name:
            if not d.get("host") or not d.get("password"):
                raise ValidationError(
                    f"equipamento '{name}' está em warmode.yaml mas sem host/senha preenchidos"
                )
            return d
    raise ValidationError(
        f"equipamento '{name}' não encontrado em warmode.yaml — configure-o na tela "
        "'⚙️ Modo Guerra' (mesmo arquivo de credenciais) antes de usar esta função"
    )


def _connect(device: dict):
    return ConnectHandler(
        device_type=device["device_type"],
        host=device["host"],
        port=device.get("port", 22),
        username=device["username"],
        password=device["password"],
        secret=device.get("enable_secret", device.get("password", "")),
        timeout=20,
        conn_timeout=20,
        fast_cli=False,
    )


def _create_rollback_point(conn, job_id: str) -> str | None:
    try:
        out = conn.send_config_set([f"configuration rollback point create description routercfg-{job_id[:8]}"])
        m = _ROLLBACK_POINT_RE.search(out)
        return m.group(1) if m else None
    except Exception:
        LOG.warning("não foi possível criar ponto de rollback nativo (equipamento/versão pode não suportar)", exc_info=True)
        return None


def _audit(event: str, job: dict, extra: dict | None = None) -> None:
    record = {
        "ts": int(time.time()), "event": event, "job_id": job.get("id"),
        "template_id": job.get("template_id"), "device_name": job.get("device_name"),
        "trigger": job.get("trigger"),
    }
    if extra:
        record.update(extra)
    try:
        Path(AUDIT_LOG_PATH).parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        LOG.exception("falha ao gravar audit log de routercfg")


def _notify(message: str) -> None:
    try:
        notifier.send_whatsapp(message)
    except Exception:
        LOG.exception("falha ao notificar WhatsApp (routercfg)")


def _job_path(job_id: str) -> Path:
    return JOBS_DIR / f"{job_id}.json"


def _save_job(job: dict) -> None:
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    p = _job_path(job["id"])
    p.write_text(json.dumps(job, ensure_ascii=False, indent=2), encoding="utf-8")
    p.chmod(0o600)


def _load_job(job_id: str) -> dict | None:
    p = _job_path(job_id)
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def list_history(limit: int = 50) -> list[dict]:
    if not JOBS_DIR.exists():
        return []
    jobs = []
    for p in JOBS_DIR.glob("*.json"):
        try:
            jobs.append(json.loads(p.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            continue
    jobs.sort(key=lambda j: j.get("created_at", 0), reverse=True)
    return jobs[:limit]


def preview(template_id: str, values: dict) -> dict:
    built = build_commands(template_id, values)
    return {
        "template_id": built["template_id"], "label": built["label"],
        "commands": built["commands"], "undo_commands": built["undo_commands"],
    }


def apply_template(template_id: str, values: dict, trigger: str = "portal",
                    confirm_window_s: int = DEFAULT_CONFIRM_WINDOW_S) -> dict:
    built = build_commands(template_id, values)
    device = _device_for(built["device_name"])
    job_id = uuid.uuid4().hex
    now = time.time()

    conn = _connect(device)
    try:
        rollback_point = _create_rollback_point(conn, job_id)
        output = conn.send_config_set(built["commands"])
    except NetmikoAuthenticationException:
        raise ValidationError("autenticação SSH falhou (usuário/senha em warmode.yaml)")
    except NetmikoTimeoutException:
        raise ValidationError("timeout de conexão SSH com o equipamento")
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass

    job = {
        "id": job_id,
        "template_id": template_id,
        "label": built["label"],
        "device_name": device.get("name"),
        "values": built["values"],
        "commands": built["commands"],
        "undo_commands": built["undo_commands"],
        "rollback_point": rollback_point,
        "created_at": now,
        "expires_at": now + confirm_window_s,
        "confirm_window_s": confirm_window_s,
        "status": "pending_confirm",
        "trigger": trigger,
        "apply_output": output,
    }
    _save_job(job)
    _audit("applied", job, {"rollback_point": rollback_point})
    _notify(
        f"🔧 Config aplicada no roteador de borda: {built['label']}\n"
        f"Job {job_id[:8]} — confirme em até {confirm_window_s // 60}min ou será revertida automaticamente."
    )
    _spawn_auto_revert_worker(job_id)
    return job


def _spawn_auto_revert_worker(job_id: str) -> None:
    python_bin = sys.executable
    module_dir = str(Path(__file__).resolve().parent.parent)
    subprocess.Popen(
        [python_bin, "-c",
         f"import sys; sys.path.insert(0, {module_dir!r}); "
         f"from routercfg.apply import _auto_revert_worker; _auto_revert_worker({job_id!r})"],
        start_new_session=True, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True,
    )


def _revert(job: dict) -> dict:
    device = _device_for(job.get("device_name"))
    conn = _connect(device)
    try:
        if job.get("rollback_point"):
            try:
                out = conn.send_command(
                    f"rollback configuration to point {job['rollback_point']}", read_timeout=60
                )
                return {"method": "rollback_point", "output": out}
            except Exception:
                LOG.warning("rollback point falhou, tentando undo_commands do template", exc_info=True)
        out = conn.send_config_set(job["undo_commands"])
        return {"method": "undo_commands", "output": out}
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass


def confirm_job(job_id: str) -> dict:
    job = _load_job(job_id)
    if not job:
        raise ValidationError("job não encontrado")
    if job["status"] != "pending_confirm":
        raise ValidationError(f"job já está '{job['status']}', não é possível confirmar")
    job["status"] = "confirmed"
    job["confirmed_at"] = time.time()
    _save_job(job)
    _audit("confirmed", job)
    _notify(f"✅ Config do roteador confirmada: {job['label']} (job {job_id[:8]})")
    return job


def revert_job(job_id: str, trigger: str = "manual") -> dict:
    job = _load_job(job_id)
    if not job:
        raise ValidationError("job não encontrado")
    if job["status"] in ("reverted", "auto_reverted"):
        raise ValidationError(f"job já está '{job['status']}'")
    result = _revert(job)
    job["status"] = "reverted" if trigger == "manual" else "auto_reverted"
    job["reverted_at"] = time.time()
    job["revert_result"] = result
    _save_job(job)
    _audit("reverted", job, {"method": result["method"], "trigger": trigger})
    _notify(f"↩️ Config do roteador revertida ({trigger}): {job['label']} (job {job_id[:8]})")
    return job


def _auto_revert_worker(job_id: str) -> None:
    """Roda detached (start_new_session) — sobrevive ao fim do processo CGI que
    disparou apply_template(). Dorme até a janela de confirmação expirar e só
    reverte se ninguém confirmou nem reverteu manualmente nesse meio tempo."""
    job = _load_job(job_id)
    if not job:
        return
    delay = max(0.0, job["expires_at"] - time.time())
    time.sleep(delay)
    job = _load_job(job_id)
    if not job or job["status"] != "pending_confirm":
        return
    try:
        revert_job(job_id, trigger="auto")
    except Exception:
        LOG.exception("falha na reversão automática do job %s", job_id)
        _audit("auto_revert_failed", job)
        _notify(f"⚠️ FALHA ao reverter automaticamente a config do roteador (job {job_id[:8]}) — verifique manualmente!")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "_worker":
        _auto_revert_worker(sys.argv[2])
