#!/usr/bin/env python3
"""FlowGuard — daemon principal: recebe NetFlow v9, agrega por janela e grava em SQLite."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import aiohttp

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ai.client import AIClient
from analyzer.engine import AMP_PORTS, DetectionEngine
from api.socket_server import SocketServer
from bgp.manager import BgpManager
from collector import configio, storage
from collector.netflow import TemplateStore, parse_packet
from collector.prefixes import match_protected_prefix, resolve_dst_prefix

LOG = logging.getLogger("flowguard")

DEFAULT_CONFIG_PATH = str(Path(__file__).resolve().parent / "config.yaml")


def load_config(path: str) -> dict:
    return configio.load_config(path)


def setup_logging(cfg: dict, foreground: bool) -> None:
    level = getattr(logging, cfg["daemon"]["log_level"].upper(), logging.INFO)
    log_file = cfg["daemon"]["log_file"]
    handlers: list[logging.Handler] = []
    try:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file))
    except OSError:
        pass
    if foreground:
        handlers.append(logging.StreamHandler(sys.stdout))
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        handlers=handlers,
        force=True,
    )


class FlowGuardDaemon:
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.config = load_config(config_path)
        self.template_store = TemplateStore()
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=100_000)
        # check_same_thread=False: a conexão de escrita só roda no único worker do
        # db_executor, nunca concorrentemente — isso só relaxa a checagem do sqlite3
        # para permitir o acesso vindo de uma thread diferente da principal.
        #
        # Pool de LEITURA separado da escrita de propósito: em WAL, leitores não ficam
        # bloqueados por um escritor em andamento — mas se compartilhassem a mesma
        # thread/executor, consultas do CLI ficariam enfileiradas atrás da escrita
        # pesada do flow_aggs (1-1.6s a cada ciclo com o volume real de tráfego).
        # Cada worker do pool de leitura usa SUA PRÓPRIA conexão (thread-local) — o
        # sqlite3 do Python não garante acesso concorrente seguro a uma única conexão
        # compartilhada entre threads, mesmo com a biblioteca em modo "serialized".
        self.db_path = self.config["database"]["path"]
        self.conn = storage.connect(self.db_path, check_same_thread=False)
        self.db_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="flowguard-db-write")
        self.read_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="flowguard-db-read")
        self._read_local = threading.local()
        self._stop_event = asyncio.Event()
        self._cycle_count = 0
        self.started_at = time.time()
        self.socket_server = SocketServer(self)
        self.detector = DetectionEngine(self)
        self.bgp_manager = BgpManager(self)
        self.ai = AIClient(self.config.get("ai", {}))
        self._shutdown_task: asyncio.Task | None = None

    async def run_db(self, func, *args, **kwargs):
        """Executa uma chamada bloqueante de escrita fora do event loop principal."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self.db_executor, lambda: func(*args, **kwargs))

    def _get_read_conn(self):
        conn = getattr(self._read_local, "conn", None)
        if conn is None:
            conn = storage.connect(self.db_path, check_same_thread=False)
            self._read_local.conn = conn
        return conn

    async def run_read_db(self, func, *args, **kwargs):
        """Executa uma consulta de leitura num executor separado da escrita, com uma
        conexão própria por thread — em WAL isso não fica bloqueado por uma gravação
        em andamento nem corre risco de corromper estado de cursor entre threads."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self.read_executor, lambda: func(self._get_read_conn(), *args, **kwargs))

    def reload_config(self) -> None:
        try:
            self.config = load_config(self.config_path)
            self.ai = AIClient(self.config.get("ai", {}))
            LOG.info("config recarregado de %s", self.config_path)
        except Exception:
            LOG.exception("falha ao recarregar config")

    def dump_stats(self) -> None:
        asyncio.ensure_future(self._dump_stats_async())

    async def notify_attack(self, attack_id: int, prefix: str, attack_type: str, severity: str,
                             bps: int, pps: int, entry: dict) -> None:
        alerts_cfg = self.config.get("alerts", {})
        severity_rank = {"info": 0, "medium": 1, "high": 2, "critical": 3}
        min_sev_wa = alerts_cfg.get("min_severity_wa", "high")

        ai_analysis = await self._maybe_analyze_attack(attack_id, prefix, attack_type, severity, bps, pps, entry)

        if alerts_cfg.get("whatsapp") and severity_rank.get(severity, 0) >= severity_rank.get(min_sev_wa, 2):
            # TODO: integrar com um provedor real de WhatsApp (Evolution API/Z-API/Twilio/etc).
            # Por enquanto só loga — ver wa_dest em config.yaml para o destino pretendido.
            LOG.info(
                "[WhatsApp pendente] destino=%s: ataque %s em %s (%s) — %.1f Mbps%s",
                alerts_cfg.get("wa_dest"), attack_type, prefix, entry.get("customer") or "?", bps / 1e6,
                f"\nAnálise IA: {ai_analysis}" if ai_analysis else "",
            )

        webhook_url = alerts_cfg.get("webhook_url")
        if webhook_url:
            payload = {
                "attack_id": attack_id, "dst_prefix": prefix, "attack_type": attack_type, "severity": severity,
                "bps": bps, "pps": pps, "customer": entry.get("customer", ""), "ai_analysis": ai_analysis,
            }
            try:
                async with aiohttp.ClientSession() as session:
                    await session.post(webhook_url, json=payload, timeout=aiohttp.ClientTimeout(total=5))
            except Exception:
                LOG.exception("falha ao enviar webhook de alerta para %s", webhook_url)

    async def _maybe_analyze_attack(self, attack_id: int, prefix: str, attack_type: str, severity: str,
                                     bps: int, pps: int, entry: dict) -> str | None:
        """Gera (se ai.enabled e a severidade qualificar) a análise factual do ataque via
        IA e já grava em attacks.ai_analysis — assim o CLI só lê o que já foi calculado
        aqui, em vez de chamar a IA de novo a cada consulta."""
        if not self.ai.enabled or not self.ai.severity_qualifies(severity):
            return None

        try:
            min_duration = self.config.get("detection", {}).get("min_attack_duration_s", 10)
            ts_start = int(time.time()) - min_duration - self.config["database"]["aggregate_interval_s"]
            detail = await self.run_read_db(storage.attack_detail, prefix, ts_start, None)
            analysis = await self.ai.analyze_attack(
                attack_type, severity, prefix, entry.get("customer") or "", bps, pps, detail,
            )
            if analysis:
                await self.run_db(storage.save_ai_analysis, self.conn, attack_id, analysis)
                LOG.info("[Análise IA] ataque #%s (%s em %s): %s", attack_id, attack_type, prefix, analysis)
            return analysis
        except Exception:
            LOG.exception("falha ao gerar análise de IA para o ataque #%s — seguindo sem ela", attack_id)
            return None

    async def _dump_stats_async(self) -> None:
        interval = self.config["database"]["aggregate_interval_s"]
        stats = await self.run_db(storage.daemon_stats, self.conn, window_s=interval)
        LOG.info(
            "STATS bps=%s pps=%s flows=%s ataques_ativos=%s regras_ativas=%s",
            stats["bps"], stats["pps"], stats["flows"],
            stats["active_attacks"], stats["active_rules"],
        )

    async def udp_listener(self) -> None:
        loop = asyncio.get_running_loop()
        bind_ip = self.config["collector"]["bind_ip"]
        port = self.config["collector"]["netflow_port"]
        sampling_rate = self.config["collector"]["sampling_rate"]
        daemon = self

        class Protocol(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr) -> None:
                peer = addr[0]
                try:
                    records = parse_packet(data, peer, daemon.template_store, sampling_rate)
                except Exception:
                    LOG.exception("erro ao parsear pacote NetFlow de %s", peer)
                    return
                for rec in records:
                    try:
                        daemon.queue.put_nowait(rec)
                    except asyncio.QueueFull:
                        LOG.warning("queue interna cheia, descartando flow")

        transport, _ = await loop.create_datagram_endpoint(Protocol, local_addr=(bind_ip, port))
        LOG.info("UDP listener ativo em %s:%s (NetFlow v9)", bind_ip, port)
        try:
            await self._stop_event.wait()
        finally:
            transport.close()

    async def aggregator_loop(self) -> None:
        interval = self.config["database"]["aggregate_interval_s"]
        retention_days = self.config["database"]["retention_days"]
        while not self._stop_event.is_set():
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=interval)
                break
            except asyncio.TimeoutError:
                pass
            try:
                await self._aggregate_once()
                self._cycle_count += 1
                cycles_per_hour = max(1, int(3600 / interval))
                if self._cycle_count % cycles_per_hour == 0:
                    pruned = await self.run_db(storage.prune_old_aggs, self.conn, retention_days)
                    if pruned:
                        LOG.info("retenção: %d agregados antigos removidos", pruned)
            except Exception:
                LOG.exception("falha no ciclo de agregação/detecção — pulando este ciclo, coleta continua")

    async def _aggregate_once(self) -> None:
        records = []
        while not self.queue.empty():
            try:
                records.append(self.queue.get_nowait())
            except asyncio.QueueEmpty:
                break

        protected = self.config.get("protected_prefixes", [])
        interval = self.config["database"]["aggregate_interval_s"]
        groups: dict[tuple, dict] = defaultdict(
            lambda: {"bytes": 0, "packets": 0, "flow_count": 0, "src_ips": defaultdict(int), "dst_ips": defaultdict(int)}
        )
        # totais por (prefixo, protocolo) — usados pela detecção de DDoS volumétrico
        proto_totals: dict[tuple, dict] = defaultdict(lambda: {"bytes": 0, "packets": 0})
        # totais por (prefixo, src_port) só para portas de amplificação conhecidas — baixa
        # cardinalidade de propósito, não vale a pena rastrear src_port para todo o tráfego
        amp_totals: dict[tuple, dict] = defaultdict(lambda: {"bytes": 0, "packets": 0})

        for rec in records:
            matched_dst_prefix = match_protected_prefix(rec.dst_ip, protected)
            prefix = matched_dst_prefix if matched_dst_prefix is not None else resolve_dst_prefix(rec.dst_ip, protected)
            g = groups[(prefix, rec.protocol, rec.dst_port, "in")]
            g["bytes"] += rec.real_bytes
            g["packets"] += rec.real_packets
            g["flow_count"] += 1
            g["src_ips"][rec.src_ip] += rec.real_bytes
            # host /32 de destino só é rastreado dentro de prefixos de fato protegidos
            # (não no /24 de fallback) — é o que permite mostrar qual host exato foi
            # atacado/está consumindo, em vez de só o bloco inteiro
            if matched_dst_prefix is not None:
                g["dst_ips"][rec.dst_ip] += rec.real_bytes

            pt = proto_totals[(prefix, rec.protocol)]
            pt["bytes"] += rec.real_bytes
            pt["packets"] += rec.real_packets

            if rec.protocol == 17 and rec.src_port in AMP_PORTS:
                at = amp_totals[(prefix, rec.src_port)]
                at["bytes"] += rec.real_bytes
                at["packets"] += rec.real_packets

            # tráfego de saída (cliente protegido como origem) — só quando o src
            # cai num prefixo protegido; sem fallback pra não explodir cardinalidade
            # com todo IP externo, e sem granularidade de porta (não usado pela
            # detecção, só pelo gráfico de tráfego por prefixo)
            src_prefix = match_protected_prefix(rec.src_ip, protected)
            if src_prefix is not None:
                go = groups[(src_prefix, rec.protocol, 0, "out")]
                go["bytes"] += rec.real_bytes
                go["packets"] += rec.real_packets
                go["flow_count"] += 1

        now = int(time.time())
        rows = []
        for (prefix, protocol, dst_port, direction), g in groups.items():
            bps = int(g["bytes"] * 8 / interval)
            pps = int(g["packets"] / interval)
            avg_pkt_size = int(g["bytes"] / g["packets"]) if g["packets"] else 0
            top_src = sorted(g["src_ips"].items(), key=lambda kv: kv[1], reverse=True)[:10]
            top_dst = sorted(g["dst_ips"].items(), key=lambda kv: kv[1], reverse=True)[:10]
            rows.append({
                "ts": now, "dst_prefix": prefix, "protocol": protocol, "dst_port": dst_port,
                "bps": bps, "pps": pps, "flow_count": g["flow_count"], "avg_pkt_size": avg_pkt_size,
                "top_src_ips": [ip for ip, _ in top_src], "src_countries": {}, "direction": direction,
                "top_dst_ips": [ip for ip, _ in top_dst],
            })

        if rows:
            t0 = time.monotonic()
            await self.run_db(storage.insert_flow_aggs_batch, self.conn, rows)
            write_ms = (time.monotonic() - t0) * 1000
            LOG.debug("agregação: %d flows -> %d grupos (gravação: %.1fms)", len(records), len(groups), write_ms)
            if write_ms > 1000:
                LOG.warning("gravação de agregados demorou %.0fms (%d grupos) — pode atrasar o próximo ciclo",
                            write_ms, len(groups))

        proto_totals_bps: dict[str, dict] = defaultdict(dict)
        for (prefix, protocol), v in proto_totals.items():
            proto_totals_bps[prefix][protocol] = {
                "bps": int(v["bytes"] * 8 / interval), "pps": int(v["packets"] / interval),
            }
        amp_totals_bps = {
            key: {"bps": int(v["bytes"] * 8 / interval), "pps": int(v["packets"] / interval)}
            for key, v in amp_totals.items()
        }
        # roda mesmo sem tráfego no ciclo, para fechar ataques que já não estão mais ativos
        await self.detector.evaluate_cycle(now, proto_totals_bps, amp_totals_bps)
        await self.bgp_manager.expire_cycle()

    async def ai_report_loop(self) -> None:
        """Resumo executivo horário via IA dos ataques da última hora — só roda se
        ai.enabled e ai.hourly_report estiverem ligados (ver run())."""
        while not self._stop_event.is_set():
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=3600)
                break
            except asyncio.TimeoutError:
                pass
            attacks = await self.run_read_db(storage.list_attacks, False, 3600)
            summary = await self.ai.hourly_summary(attacks)
            if summary:
                LOG.info("[Relatório horário IA] %s", summary)

    async def run(self) -> None:
        tasks = [self.udp_listener(), self.aggregator_loop(), self.socket_server.start()]
        if self.ai.enabled and self.ai.hourly_report:
            tasks.append(self.ai_report_loop())
        await asyncio.gather(*tasks)
        if self._shutdown_task:
            await self._shutdown_task

    def stop(self) -> None:
        self._stop_event.set()
        self.socket_server.close()
        # retira regras FlowSpec/RTBH ativas antes de sair (ver Observações Importantes #4
        # no spec) — agendado aqui e aguardado em run(), já que stop() é chamado
        # sincronamente pelo signal handler e não pode dar await direto.
        self._shutdown_task = asyncio.ensure_future(self.bgp_manager.withdraw_all())


def daemonize() -> None:
    """Double-fork clássico (compatível com Type=forking do systemd unit)."""
    if os.fork() > 0:
        sys.exit(0)
    os.setsid()
    if os.fork() > 0:
        sys.exit(0)
    sys.stdout.flush()
    sys.stderr.flush()
    devnull_fd = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull_fd, sys.stdin.fileno())
    os.dup2(devnull_fd, sys.stdout.fileno())
    os.dup2(devnull_fd, sys.stderr.fileno())


def write_pid_file(path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(str(os.getpid()))


def remove_pid_file(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description="FlowGuard daemon")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--daemon", action="store_true", help="roda em background (double-fork)")
    args = parser.parse_args()

    if args.daemon:
        daemonize()

    daemon = FlowGuardDaemon(args.config)
    setup_logging(daemon.config, foreground=not args.daemon)
    write_pid_file(daemon.config["daemon"]["pid_file"])

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.add_signal_handler(signal.SIGHUP, daemon.reload_config)
    loop.add_signal_handler(signal.SIGUSR1, daemon.dump_stats)
    loop.add_signal_handler(signal.SIGTERM, daemon.stop)
    loop.add_signal_handler(signal.SIGINT, daemon.stop)

    LOG.info("FlowGuard daemon iniciado (pid=%d)", os.getpid())
    try:
        loop.run_until_complete(daemon.run())
    finally:
        daemon.db_executor.shutdown(wait=True)
        daemon.read_executor.shutdown(wait=True)
        remove_pid_file(daemon.config["daemon"]["pid_file"])
        LOG.info("FlowGuard daemon encerrado")


if __name__ == "__main__":
    main()
