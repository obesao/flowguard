"""warmode/report.py — enquanto o Modo Guerra estiver ativo, envia periodicamente
(via systemd timer, ver init/flowguard-warmode-report.{service,timer}) um aviso
no WhatsApp com o tempo decorrido e um resumo panorâmico gerado por IA (fase do
incidente, tipos de ataque, prefixos/links afetados, tráfego). No-op se o Modo
Guerra estiver desligado — o timer roda sempre, este script decide se há algo
a fazer.

Deliberadamente um processo próprio, fora do flowguard.service — mesma
filosofia do resto do warmode (ver executor.py): continua funcionando mesmo se
o daemon estiver sob estresse, justo quando um DDoS real está em andamento.
Lê o SQLite diretamente (mesmo padrão já usado por cgi-bin/flowguard-ai.sh),
não fala com o socket do daemon.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import time
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import notifier
from ai.client import AIClient
from collector import storage
from warmode.executor import FLOWGUARD_CONFIG_PATH, get_state

LOG = logging.getLogger("flowguard.warmode.report")


def _fmt_duration(seconds: int) -> str:
    hours, rem = divmod(max(seconds, 0), 3600)
    minutes = rem // 60
    return f"{hours}h{minutes:02d}min"


async def _build_message(cfg: dict, elapsed_s: int) -> str:
    conn = storage.connect(cfg["database"]["path"])
    stats = storage.daemon_stats(conn)
    attacks = storage.list_attacks(conn, active_only=True)

    summary = await AIClient(cfg.get("ai", {})).war_mode_summary(elapsed_s, stats, attacks)

    header = f"🚨 MODO GUERRA — ativo há {_fmt_duration(elapsed_s)}"
    if summary:
        return f"{header}\n\n{summary}"
    # IA indisponível/desabilitada/rate-limited — nunca deixa o operador sem
    # nenhuma atualização só por causa disso, manda o factual puro
    fallback = (
        f"Tráfego: {stats['bps'] / 1e6:.1f} Mbps, {stats['pps']:,} pps. "
        f"Ataques ativos: {stats['active_attacks']}. Regras ativas: {stats['active_rules']}."
    )
    return f"{header}\n\n{fallback}"


def run_report() -> bool:
    state = get_state()
    if not state.get("active"):
        return False

    cfg = yaml.safe_load(Path(FLOWGUARD_CONFIG_PATH).read_text(encoding="utf-8")) or {}
    if not (cfg.get("alerts") or {}).get("whatsapp"):
        return False

    elapsed_s = int(time.time()) - int(state.get("started_at") or time.time())
    message = asyncio.run(_build_message(cfg, elapsed_s))
    return notifier.send_whatsapp(message)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sent = run_report()
    print("enviado" if sent else "nada a fazer (Modo Guerra inativo ou alerts.whatsapp desligado)")
