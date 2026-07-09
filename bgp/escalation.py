"""Bloqueio progressivo por reincidência (estilo fail2ban) — só pro detector de port
scan (analyzer/engine.py::evaluate_scan_cycle). Não se aplica a ddos_volumetrico/
amplificação/syn_flood/anomalia_baseline: esses mitigam a VÍTIMA (RTBH/discard no
prefixo inteiro), não têm um único src_ip de atacante pra escalar contra — um DDoS
real tem milhares de origens diferentes.

Config em escalation.yaml (collector/configio.py::load_escalation/save_escalation).
Reincidência é contada via o histórico de flowspec_rules (nunca deleta linha, só
active=0) — nenhuma tabela nova precisa existir só pra isso.
"""

from __future__ import annotations

import time

from collector import storage


def next_ttl_s(conn, src_ip: str, cfg: dict, base_ttl_s: int | None = None) -> int:
    """TTL (segundos) do próximo bloqueio de src_ip, crescendo com o número de vezes
    que ele já foi bloqueado dentro de cfg['tracking_window_s']. offense_no=0 na
    primeira ofensa (usa base_ttl_s puro), cresce por cfg['factor'] a cada
    reincidência, até travar em cfg['max_ttl_s'] depois de cfg['max_steps']."""
    base = base_ttl_s if base_ttl_s is not None else cfg["base_ttl_s"]
    if not cfg.get("enabled", True):
        return base
    since = int(time.time()) - cfg["tracking_window_s"]
    offense_no = storage.count_recent_flowspec_blocks(conn, f"{src_ip}/32", since)
    step = min(offense_no, cfg["max_steps"])
    return min(int(base * (cfg["factor"] ** step)), cfg["max_ttl_s"])
