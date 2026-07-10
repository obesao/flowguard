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
from analyzer.engine import AMP_PORTS, DetectionEngine, PROTO_TCP, TCP_FLAG_ACK, TCP_FLAG_SYN
from api.socket_server import SocketServer
from bgp.manager import BgpManager
from collector import configio, storage
from collector.netflow import TemplateStore, parse_packet
from collector.prefixes import match_protected_prefix, resolve_dst_prefix
import notifier

LOG = logging.getLogger("flowguard")

DEFAULT_CONFIG_PATH = str(Path(__file__).resolve().parent / "config.yaml")

# rótulo amigável da ação de mitigação pros alertas de WhatsApp — chaves espelham
# flowspec_rules.action (ver bgp/manager.py e bgp/flowspec.suggest_mitigation)
MITIGATION_ACTION_LABELS = {
    "rtbh": "Blackhole (RTBH) — descarte total do prefixo na borda",
    "discard": "Descarte seletivo (FlowSpec)",
    "rate_limit": "Limitação de taxa (FlowSpec)",
}


def _fmt_dt(ts: int | None) -> str:
    if not ts:
        return "?"
    return time.strftime("%d/%m %H:%M", time.localtime(ts))


def _fmt_duration(seconds: int | None) -> str:
    if not seconds or seconds < 0:
        return "0min"
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, _s = divmod(rem, 60)
    if h:
        return f"{h}h{m:02d}min" if m else f"{h}h"
    return f"{m}min" if m else f"{seconds}s"

# Portas de destino a partir daqui são efêmeras (escolhidas aleatoriamente pelo lado
# cliente da conexão) — individualmente não caracterizam nada, mas como chave de
# agregação explodem a cardinalidade de flow_aggs: medido em produção, ~65 mil portas
# distintas/hora geravam ~2.8M de linhas/hora (18GB de banco em 2 dias).
EPHEMERAL_PORT_MIN = 1024

# Quantos prefixos /24 de fallback (destinos que NÃO são clientes) são gravados
# individualmente por ciclo; o resto vira uma linha agregada FALLBACK_REST_PREFIX
# por protocolo. Medido em produção: ~9.600 /24 distintos por ciclo, sendo que
# top_flows/top_prefixes exibem no máximo ~20 — a cauda longa só inflava a tabela.
# Os totais (KPIs de bps/pps, gráfico por protocolo) não mudam: a linha "outros"
# soma exatamente o que as linhas individuais somariam.
FALLBACK_TOP_N = 100
FALLBACK_REST_PREFIX = "outros"


def bucket_dst_port(dst_port: int, is_protected: bool) -> int:
    """Porta de destino usada como chave de agregação/gravação em flow_aggs.

    Prefixo NÃO protegido (fallback /24 dos destinos de saída dos clientes): sempre 0 —
    a detecção nunca olha esses grupos (usa proto_totals/amp_totals, calculados à
    parte em memória) e detalhe por porta de tráfego que não é de cliente não é
    acionável; era mais da metade das linhas gravadas.

    Prefixo protegido: mantém a porta real só se for well-known (<1024), que é o que
    attack_detail precisa pra caracterizar um ataque; o resto colapsa em 0 ("portas
    efêmeras", mesma convenção do dst_port=0 já usado na direção 'out')."""
    if not is_protected or dst_port >= EPHEMERAL_PORT_MIN:
        return 0
    return dst_port


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
        # referências das notificações em background (ver fire_and_forget) — sem isso
        # o GC pode recolher uma Task ainda em andamento
        self._bg_tasks: set[asyncio.Task] = set()
        # contagem de flows descartados por fila cheia desde o último warning logado
        self._dropped_flows = 0
        self._last_drop_warn = 0.0

    def fire_and_forget(self, coro, what: str) -> None:
        """Agenda uma corrotina de notificação (IA/WhatsApp/webhook) sem bloquear quem
        chama — o ciclo de agregação/detecção não pode esperar chamadas de rede com
        timeout de vários segundos, senão a fila de flows transborda exatamente
        durante um ataque (quando várias notificações saem de uma vez)."""
        task = asyncio.get_running_loop().create_task(coro)
        self._bg_tasks.add(task)

        def _done(t: asyncio.Task) -> None:
            self._bg_tasks.discard(t)
            if not t.cancelled() and t.exception() is not None:
                LOG.error("falha em notificação em background (%s)", what, exc_info=t.exception())

        task.add_done_callback(_done)

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

    def _wa_severity_ok(self, severity: str) -> bool:
        alerts_cfg = self.config.get("alerts", {})
        if not alerts_cfg.get("whatsapp"):
            return False
        severity_rank = {"info": 0, "medium": 1, "high": 2, "critical": 3}
        min_sev_wa = alerts_cfg.get("min_severity_wa", "high")
        return severity_rank.get(severity, 0) >= severity_rank.get(min_sev_wa, 2)

    async def _send_whatsapp(self, message: str) -> None:
        loop = asyncio.get_running_loop()
        ok = await loop.run_in_executor(None, notifier.send_whatsapp, message)
        if not ok:
            LOG.warning("falha ao enviar alerta WhatsApp")

    async def notify_attack(self, attack_id: int, prefix: str, attack_type: str, severity: str,
                             bps: int, pps: int, entry: dict, ts_start: int) -> None:
        alerts_cfg = self.config.get("alerts", {})

        # host /32 mais atacado NO MOMENTO da abertura — ts_start é o timestamp do
        # próprio ciclo que disparou o ataque, então a janela (ts_start, ts_start)
        # cai exatamente na linha de flow_aggs recém-gravada por esse ciclo (ver
        # storage.attack_top_host/attack_detail). Só existe para prefixos
        # protegidos de verdade (não /24 de fallback) — ver flowguard.py::_aggregate_once.
        target_host = await self.run_read_db(storage.attack_top_host, prefix, ts_start, None)
        ai_analysis = await self._maybe_analyze_attack(attack_id, prefix, attack_type, severity, bps, pps, entry)

        if self._wa_severity_ok(severity):
            host_line = f"{target_host} (prefixo {prefix})" if target_host else f"prefixo {prefix} inteiro (host específico não identificado ainda)"
            message = (
                f"🚨 FlowGuard: ataque {attack_type}"
                + (f" — {entry['customer']}" if entry.get("customer") else "")
                + f"\nHost: {host_line}"
                + f"\nInício: {_fmt_dt(ts_start)}"
                + f"\n{bps / 1e6:.1f} Mbps, {pps:,} pps — severidade {severity}".replace(",", ".")
                + (f"\nAnálise: {ai_analysis}" if ai_analysis else "")
            )
            await self._send_whatsapp(message)

        webhook_url = alerts_cfg.get("webhook_url")
        if webhook_url:
            payload = {
                "attack_id": attack_id, "dst_prefix": prefix, "target_host": target_host,
                "attack_type": attack_type, "severity": severity, "bps": bps, "pps": pps,
                "customer": entry.get("customer", ""), "ai_analysis": ai_analysis, "ts_start": ts_start,
            }
            try:
                async with aiohttp.ClientSession() as session:
                    await session.post(webhook_url, json=payload, timeout=aiohttp.ClientTimeout(total=5))
            except Exception:
                LOG.exception("falha ao enviar webhook de alerta para %s", webhook_url)

    async def notify_attack_closed(self, attack_id: int, prefix: str, attack_type: str, severity: str,
                                    bps_peak: int, ts_start: int, ts_end: int, target_host: str | None = None) -> None:
        if not self._wa_severity_ok(severity):
            return
        host_line = f"{target_host} (prefixo {prefix})" if target_host else f"prefixo {prefix}"
        message = (
            f"✅ FlowGuard: ataque {attack_type} encerrado"
            + f"\nHost: {host_line}"
            + f"\nInício: {_fmt_dt(ts_start)} — Fim: {_fmt_dt(ts_end)} (durou {_fmt_duration(ts_end - ts_start)})"
            + f"\nPico: {bps_peak / 1e6:.1f} Mbps"
        )
        await self._send_whatsapp(message)

    async def _mitigation_wa_ok(self, attack_id: int | None) -> tuple[bool, dict | None]:
        """Mesmo filtro de severidade (alerts.min_severity_wa) do alerta de ataque,
        aplicado à severidade do ataque associado à mitigação. Sem attack_id (bloqueio
        manual avulso, não ligado a um ataque detectado) sempre libera — é uma ação
        deliberada do operador, não um evento que faça sentido filtrar por severidade."""
        if not self.config.get("alerts", {}).get("whatsapp"):
            return False, None
        if attack_id is None:
            return True, None
        attack = await self.run_read_db(storage.get_attack, attack_id)
        if attack and not self._wa_severity_ok(attack["severity"]):
            return False, attack
        return True, attack

    async def notify_mitigation_applied(self, rule_id: int, attack_id: int | None, dst_prefix: str,
                                         action: str, trigger_type: str, ttl_s: int | None) -> None:
        ok, attack = await self._mitigation_wa_ok(attack_id)
        if not ok:
            return
        attack_type = attack["attack_type"] if attack else None
        target_host = attack.get("target_host") if attack else None
        if not target_host and attack:
            # attacks.target_host só é calculado no FECHAMENTO do ataque (ver
            # storage.apply_attack_changes) — na abertura, quando a auto-mitigação
            # dispara, ainda não existe; recalcula ao vivo pra não perder o host exato.
            target_host = await self.run_read_db(storage.attack_top_host, dst_prefix, attack["ts_start"], None)
        host_line = target_host or dst_prefix or "?"
        action_label = MITIGATION_ACTION_LABELS.get(action, action)
        origin_label = "automática" if trigger_type == "auto" else "manual"
        message = (
            "🛡️ FlowGuard: mitigação aplicada"
            + (f" — ataque {attack_type}" if attack_type else "")
            + f"\nHost/prefixo: {host_line}"
            + f"\nAção: {action_label} ({origin_label})"
            + f"\nInício: {_fmt_dt(int(time.time()))}"
            + (f"\nVálida por até {_fmt_duration(ttl_s)} (ou até reversão manual)" if ttl_s else "")
        )
        await self._send_whatsapp(message)

    async def notify_mitigation_reverted(self, rule_id: int, attack_id: int | None, dst_prefix: str,
                                          action: str, reason: str, applied_at: int | None) -> None:
        ok, attack = await self._mitigation_wa_ok(attack_id)
        if not ok:
            return
        attack_type = attack["attack_type"] if attack else None
        target_host = attack.get("target_host") if attack else None
        host_line = target_host or dst_prefix or "?"
        action_label = MITIGATION_ACTION_LABELS.get(action, action)
        now = int(time.time())
        duration_line = f"\nDuração da mitigação: {_fmt_duration(now - applied_at)}" if applied_at else ""
        message = (
            "✅ FlowGuard: mitigação encerrada"
            + (f" — ataque {attack_type}" if attack_type else "")
            + f"\nHost/prefixo: {host_line}"
            + f"\nAção revertida: {action_label}"
            + f"\nEncerrada: {_fmt_dt(now)} ({reason})"
            + duration_line
        )
        await self._send_whatsapp(message)

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
                        # 1 warning a cada 10s, não 1 por flow — sob sobrecarga real
                        # (fila de 100k cheia) logar cada descarte vira I/O de log
                        # massivo dentro do event loop e só piora a sobrecarga.
                        daemon._dropped_flows += 1
                        now = time.monotonic()
                        if now - daemon._last_drop_warn >= 10:
                            LOG.warning("fila interna cheia — %d flows descartados nos últimos %.0fs",
                                        daemon._dropped_flows, now - daemon._last_drop_warn if daemon._last_drop_warn else 10)
                            daemon._dropped_flows = 0
                            daemon._last_drop_warn = now

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
                    await self._close_stale_attacks()
                # ANALYZE 1x/dia, fora do prune horário — na tabela grande ele custa
                # caro e as estatísticas do planner não mudam a cada hora
                if self._cycle_count % (cycles_per_hour * 24) == 0:
                    await self.run_db(storage.analyze, self.conn)
            except Exception:
                LOG.exception("falha no ciclo de agregação/detecção — pulando este ciclo, coleta continua")

    async def _close_stale_attacks(self) -> None:
        stale_s = self.config.get("detection", {}).get("attack_stale_close_s", 21600)
        closed = await self.run_db(storage.close_stale_attacks, self.conn, stale_s)
        for row in closed:
            LOG.info(
                "ataque #%d encerrado por inatividade (rede de segurança): %s em %s, sem reconfirmação há mais de %ds",
                row["id"], row["attack_type"], row["dst_prefix"], stale_s,
            )
            self.fire_and_forget(
                self.notify_attack_closed(
                    row["id"], row["dst_prefix"], row["attack_type"], row["severity"], row["bps_peak"] or 0,
                    row["ts_start"], row["ts_end"], row["target_host"],
                ),
                f"ataque #{row['id']} encerrado (inatividade)",
            )

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
            lambda: {"bytes": 0, "packets": 0, "flow_count": 0, "src_ips": defaultdict(int),
                     "dst_ips": defaultdict(int), "protected": False}
        )
        # totais por (prefixo, protocolo) — usados pela detecção de DDoS volumétrico
        proto_totals: dict[tuple, dict] = defaultdict(lambda: {"bytes": 0, "packets": 0})
        # totais por (prefixo, src_port) só para portas de amplificação conhecidas — baixa
        # cardinalidade de propósito, não vale a pena rastrear src_port para todo o tráfego
        amp_totals: dict[tuple, dict] = defaultdict(lambda: {"bytes": 0, "packets": 0})
        # totais de SYN "puro" por prefixo (TCP com SYN setado e ACK não setado) —
        # usados pela detecção de SYN flood dedicada
        syn_totals: dict[str, dict] = defaultdict(lambda: {"bytes": 0, "packets": 0})
        # port scan de fora pra dentro: por (prefixo protegido, src_ip externo), hosts
        # distintos tocados (horizontal) e portas distintas por host (vertical) — usa
        # rec.dst_port CRU, não o bucket_dst_port já zerado pra portas efêmeras (a
        # imensa maioria de um scan real cai justamente nessa faixa). Só rastreado
        # dentro de prefixo DE FATO protegido, nunca no fallback — mantém a
        # cardinalidade limitada a "quem tocou minha rede", não "toda a internet".
        scan_totals: dict[tuple, dict] = {}
        scan_cfg = self.config.get("scan_detection", {})
        scan_max_tracked = scan_cfg.get("max_tracked_src_ips_per_cycle", 5000)
        scan_cap_hit = False
        # destino coordenado de fora pra dentro: por (prefixo protegido, dst_ip, dst_port,
        # protocolo), quantos src_ip externos distintos convergiram no ciclo — inverso do
        # scan (lá 1 IP -> N alvos; aqui N IPs -> 1 alvo). Também usa dst_port CRU, mesmo
        # motivo do scan (bucket_dst_port zeraria portas altas específicas que um ataque
        # coordenado pode mirar). Só dentro de prefixo DE FATO protegido.
        coord_totals: dict[tuple, dict] = {}
        coord_cfg = self.config.get("coordinated_destination", {})
        coord_max_tracked = coord_cfg.get("max_tracked_keys_per_cycle", 5000)
        # só TCP por padrão — achado real de 2026-07-10: UDP em pools CGNAT deu 100%
        # falso positivo (P2P/torrent/WebRTC/jogo recebendo peers na porta do host),
        # não ataque coordenado. Ver comentário em configio.DEFAULT_COORDINATED_DESTINATION.
        coord_allowed_protocols = set(coord_cfg.get("protocols", [6]))
        coord_cap_hit = False

        for rec in records:
            # a NE8000 exporta netstream inbound+outbound em toda interface, então cada
            # pacote real gera 2 registros (um ingress, um egress) representando o mesmo
            # tráfego visto em dois pontos do roteador — contar os dois dobraria tudo.
            # ingress (flow_direction=0) já vê cada pacote exatamente uma vez.
            if rec.flow_direction != 0:
                continue
            matched_dst_prefix = match_protected_prefix(rec.dst_ip, protected)
            prefix = matched_dst_prefix if matched_dst_prefix is not None else resolve_dst_prefix(rec.dst_ip, protected)
            dst_port = bucket_dst_port(rec.dst_port, matched_dst_prefix is not None)
            g = groups[(prefix, rec.protocol, dst_port, "in")]
            g["protected"] = matched_dst_prefix is not None
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

            if rec.protocol == PROTO_TCP and (rec.tcp_flags & TCP_FLAG_SYN) and not (rec.tcp_flags & TCP_FLAG_ACK):
                st = syn_totals[prefix]
                st["bytes"] += rec.real_bytes
                st["packets"] += rec.real_packets

            if matched_dst_prefix is not None:
                scan_key = (matched_dst_prefix, rec.src_ip)
                sc = scan_totals.get(scan_key)
                if sc is None:
                    if len(scan_totals) >= scan_max_tracked:
                        if not scan_cap_hit:
                            LOG.warning(
                                "scan_detection: limite de %d src_ips rastreados/ciclo atingido em %s — "
                                "novos src_ips não rastreados até o próximo ciclo",
                                scan_max_tracked, matched_dst_prefix,
                            )
                            scan_cap_hit = True
                    else:
                        sc = {
                            "dst_ips_by_port": defaultdict(set), "bytes_by_port": defaultdict(int),
                            "dst_ports": defaultdict(set), "dst_bytes": defaultdict(int), "packets": 0,
                        }
                        scan_totals[scan_key] = sc
                if sc is not None:
                    # horizontal só conta como scan se for a MESMA porta em vários hosts
                    # (achado real em produção: sem isso, CDN/big-tech respondendo a
                    # VÁRIOS clientes meus — cada um na sua porta efêmera de retorno —
                    # batia o limiar; mesmo requisito que o ClientGuard já documenta em
                    # detect_scan_horizontal: "mesma dst_port", senão navegação normal
                    # vira falso positivo). bytes_by_port/dst_bytes alimentam o filtro de
                    # bytes médios (achado real 2026-07-10: streaming/CDN — Google/YouTube
                    # — abre várias conexões paralelas pro mesmo cliente, cada uma numa
                    # porta efêmera DIFERENTE do lado do cliente, indistinguível de scan
                    # vertical de verdade só pela contagem de portas; sonda de
                    # reconhecimento manda poucos bytes por porta, streaming manda muito).
                    sc["dst_ips_by_port"][rec.dst_port].add(rec.dst_ip)
                    sc["bytes_by_port"][rec.dst_port] += rec.real_bytes
                    sc["dst_ports"][rec.dst_ip].add(rec.dst_port)
                    sc["dst_bytes"][rec.dst_ip] += rec.real_bytes
                    sc["packets"] += rec.real_packets

                if rec.protocol in coord_allowed_protocols:
                    coord_key = (matched_dst_prefix, rec.dst_ip, rec.dst_port, rec.protocol)
                    cd = coord_totals.get(coord_key)
                    if cd is None:
                        if len(coord_totals) >= coord_max_tracked:
                            if not coord_cap_hit:
                                LOG.warning(
                                    "coordinated_destination: limite de %d chaves rastreadas/ciclo atingido em %s — "
                                    "novos destinos não rastreados até o próximo ciclo",
                                    coord_max_tracked, matched_dst_prefix,
                                )
                                coord_cap_hit = True
                        else:
                            cd = {"src_ips": set(), "packets": 0}
                            coord_totals[coord_key] = cd
                    if cd is not None:
                        cd["src_ips"].add(rec.src_ip)
                        cd["packets"] += rec.real_packets

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

        # Cauda longa dos /24 de fallback: mantém os FALLBACK_TOP_N grupos mais
        # volumosos do ciclo individualmente e funde o resto numa linha "outros"
        # por protocolo — sem isso, os destinos de saída dos clientes geravam um
        # grupo por /24 da internet inteira (~9.6k/ciclo), dominando a tabela.
        fallback_in = [(key, g) for key, g in groups.items() if key[3] == "in" and not g["protected"]]
        if len(fallback_in) > FALLBACK_TOP_N:
            fallback_in.sort(key=lambda kg: kg[1]["bytes"], reverse=True)
            for key, g in fallback_in[FALLBACK_TOP_N:]:
                rest = groups[(FALLBACK_REST_PREFIX, key[1], 0, "in")]
                rest["bytes"] += g["bytes"]
                rest["packets"] += g["packets"]
                rest["flow_count"] += g["flow_count"]
                for ip, b in g["src_ips"].items():
                    rest["src_ips"][ip] += b
                del groups[key]

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
        syn_totals_bps = {
            prefix: {"bps": int(v["bytes"] * 8 / interval), "pps": int(v["packets"] / interval)}
            for prefix, v in syn_totals.items()
        }
        # roda mesmo sem tráfego no ciclo, para fechar ataques que já não estão mais ativos
        await self.detector.evaluate_cycle(now, proto_totals_bps, amp_totals_bps, syn_totals_bps)
        await self.detector.evaluate_scan_cycle(now, scan_totals, interval)
        await self.detector.evaluate_coordinated_destination_cycle(now, coord_totals, interval)
        await self.bgp_manager.expire_cycle()
        await self.bgp_manager.check_reconciliation()

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
