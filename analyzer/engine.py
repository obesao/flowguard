"""Motor de detecção: DDoS volumétrico + amplificação (DNS/NTP/SSDP/Memcached/CLDAP)
+ anomalia de baseline (EWMA por prefixo).

Roda ao final de cada ciclo de agregação do daemon, recebendo os totais já
calculados em memória (sem round-trip ao SQLite para os dados do ciclo atual).
Escopado apenas aos prefixos em protected_prefixes — os demais dst_prefix
vistos no tráfego (destinos de saída dos clientes, ex: Facebook/Apple) não são
algo que se possa ou deva mitigar via FlowSpec/RTBH.

Todas as leituras/escritas em `attacks` de um ciclo são feitas em 1 SELECT +
1 transação de escrita (não 1 round-trip por prefixo x tipo de ataque) — com
8 prefixos x 6 tipos isso evitava ~96 commits individuais por ciclo, tempo
suficiente para estourar o timeout de clientes do socket de controle.
"""

from __future__ import annotations

import ipaddress
import logging
import math

from collector import storage

LOG = logging.getLogger("flowguard.detect")

# porta de origem (UDP) -> (tipo de ataque, severidade) — ver "Ataques Detectados" no spec
AMP_PORTS = {
    53: ("dns_amp", "critical"),
    123: ("ntp_amp", "critical"),
    1900: ("ssdp_amp", "critical"),
    11211: ("memcached_amp", "critical"),
    389: ("cldap_amp", "high"),
}


def _is_whitelisted(prefix: str, whitelist: list[str]) -> bool:
    try:
        net = ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return False
    for entry in whitelist:
        try:
            wl_net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if net == wl_net or net.subnet_of(wl_net):
            return True
    return False


class DetectionEngine:
    def __init__(self, daemon):
        self.daemon = daemon
        # (dst_prefix, attack_type) -> timestamp em que a condição começou a ser observada
        self._pending: dict[tuple, float] = {}

    async def evaluate_cycle(self, now: int, proto_totals: dict, amp_totals: dict) -> None:
        cfg = self.daemon.config
        detection_cfg = cfg.get("detection", {})
        protected = cfg.get("protected_prefixes", [])
        whitelist = cfg.get("whitelist", [])
        min_duration = detection_cfg.get("min_attack_duration_s", 10)
        default_bps_threshold = detection_cfg.get("ddos_bps_threshold", 500_000_000)
        default_pps_threshold = detection_cfg.get("ddos_pps_threshold", 100_000)

        baseline_enabled = detection_cfg.get("baseline_enabled", True)
        baseline_min_samples = detection_cfg.get("baseline_min_samples", 120)
        baseline_sigma = detection_cfg.get("baseline_sigma", 4)
        baseline_min_bps = detection_cfg.get("baseline_min_bps", 5_000_000)
        baseline_window_min = detection_cfg.get("baseline_window_minutes", 180)
        interval_s = cfg["database"]["aggregate_interval_s"]
        baseline_alpha = 2 / (max(1, (baseline_window_min * 60) / interval_s) + 1)

        open_attacks = await self.daemon.run_read_db(storage.list_open_attacks_by_key)
        baselines = await self.daemon.run_read_db(storage.list_baselines) if baseline_enabled else {}

        to_insert: list[dict] = []
        to_update: list[tuple] = []
        to_close: list[tuple] = []
        to_notify: list[tuple] = []
        baseline_updates: list[tuple] = []

        for entry in protected:
            prefix = entry.get("prefix")
            if not prefix or _is_whitelisted(prefix, whitelist):
                continue

            overrides = entry.get("thresholds") or {}
            bps_threshold = overrides.get("ddos_bps_threshold", default_bps_threshold)
            pps_threshold = overrides.get("ddos_pps_threshold", default_pps_threshold)

            by_proto = proto_totals.get(prefix, {})
            total_bps = sum(v["bps"] for v in by_proto.values())
            total_pps = sum(v["pps"] for v in by_proto.values())
            volumetric_hit = total_bps > bps_threshold or total_pps > pps_threshold

            # attack_type tem que ser ESTÁVEL entre ciclos — usar o protocolo dominante
            # no nome (ddos_tcp/ddos_udp) faz a chave trocar sempre que dois protocolos
            # de volume parecido alternam de líder, abandonando o registro anterior, que
            # nunca mais seria reavaliado para fechar (ficaria "preso" aberto para sempre).
            self._evaluate(now, prefix, "ddos_volumetrico", "critical", volumetric_hit, total_bps, total_pps,
                            min_duration, entry, open_attacks, to_insert, to_update, to_close, to_notify)

            any_amp_hit = False
            for src_port, (amp_type, severity) in AMP_PORTS.items():
                amp = amp_totals.get((prefix, src_port))
                amp_bps = amp["bps"] if amp else 0
                amp_pps = amp["pps"] if amp else 0
                amp_hit = amp_bps > bps_threshold
                any_amp_hit = any_amp_hit or amp_hit
                self._evaluate(now, prefix, amp_type, severity, amp_hit, amp_bps, amp_pps,
                                min_duration, entry, open_attacks, to_insert, to_update, to_close, to_notify)

            # Anomalia de baseline: só entra em jogo quando o limiar estático (acima) NÃO
            # disparou — ela existe pra pegar ataques relevantes pra um cliente PEQUENO
            # (que nunca chegaria perto do limiar fixo global), não pra duplicar alerta
            # de um pico que o limiar estático já capturou.
            anomaly_hit = False
            if baseline_enabled and not volumetric_hit and not any_amp_hit:
                baseline = baselines.get(prefix)
                if baseline and baseline["samples"] >= baseline_min_samples:
                    bps_std = math.sqrt(max(baseline["bps_var"], 0))
                    anomaly_threshold = baseline["bps_mean"] + baseline_sigma * bps_std
                    anomaly_hit = (
                        total_bps > anomaly_threshold
                        and total_bps > baseline_min_bps
                        and total_bps > baseline["bps_mean"] * 1.5
                    )
                    self._evaluate(now, prefix, "anomalia_baseline", "high", anomaly_hit, total_bps, total_pps,
                                    min_duration, entry, open_attacks, to_insert, to_update, to_close, to_notify)

            if baseline_enabled and not (volumetric_hit or any_amp_hit or anomaly_hit):
                baseline_updates.append((prefix, total_bps, total_pps, baseline_alpha, now))

        if to_insert or to_update or to_close:
            await self.daemon.run_db(storage.apply_attack_changes, self.daemon.conn, to_insert, to_update, to_close)

        if baseline_updates:
            await self.daemon.run_db(storage.update_baselines, self.daemon.conn, baseline_updates)

        for prefix, attack_type, severity, bps, pps, entry in to_notify:
            LOG.warning(
                "ATAQUE DETECTADO: %s em %s (%s) — %.1f Mbps, %s pps",
                attack_type, prefix, entry.get("customer") or "?", bps / 1e6, f"{pps:,}".replace(",", "."),
            )
            await self.daemon.notify_attack(prefix, attack_type, severity, bps, pps, entry)

        for prefix, attack_type, bps_peak in to_close_log(to_close, open_attacks):
            LOG.info("ataque encerrado: %s em %s (pico %.1f Mbps)", attack_type, prefix, bps_peak / 1e6)

    def _evaluate(self, now, prefix, attack_type, severity, triggered, bps, pps, min_duration, entry,
                  open_attacks, to_insert, to_update, to_close, to_notify) -> None:
        key = (prefix, attack_type)
        existing = open_attacks.get(key)

        if triggered:
            first_seen = self._pending.setdefault(key, now)
            if (now - first_seen) >= min_duration:
                if existing:
                    to_update.append((existing["id"], bps, pps))
                else:
                    to_insert.append({
                        "ts_start": now, "dst_prefix": prefix, "customer": entry.get("customer", ""),
                        "attack_type": attack_type, "severity": severity, "bps_peak": bps, "pps_peak": pps,
                    })
                    to_notify.append((prefix, attack_type, severity, bps, pps, entry))
        else:
            self._pending.pop(key, None)
            if existing:
                to_close.append((existing["id"], now))


def to_close_log(to_close: list[tuple], open_attacks: dict[tuple, dict]):
    by_id = {row["id"]: key for key, row in open_attacks.items()}
    for attack_id, _ts_end in to_close:
        key = by_id.get(attack_id)
        if key is None:
            continue
        prefix, attack_type = key
        yield prefix, attack_type, open_attacks[key]["bps_peak"]
