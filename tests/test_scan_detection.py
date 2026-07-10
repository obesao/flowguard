"""Testa DetectionEngine.evaluate_scan_cycle — detector de port scan de fora pra
dentro (Parte A do plano "scan detection + bloqueio progressivo"). Mesmo padrão de
FakeDaemon/FakeBgpManager de test_auto_mitigation.py."""

import asyncio
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzer.engine import DetectionEngine
from collector import configio, storage


class FakeBgpManager:
    def __init__(self, ok=True, rule_id=42):
        self.calls = []
        self.ok = ok
        self.rule_id = rule_id

    async def flowspec_add(self, rule, attack_id=None, ttl_s=None, origin="flowguard",
                            peer="main", trigger_type="manual"):
        self.calls.append({"rule": rule, "ttl_s": ttl_s, "peer": peer, "trigger_type": trigger_type})
        if not self.ok:
            return {"ok": False, "error": "falha simulada"}
        return {"ok": True, "rule_id": self.rule_id}


class FakeDaemon:
    def __init__(self, conn, config):
        self.conn = conn
        self.config = config
        self.bgp_manager = FakeBgpManager()
        self.fired = []

    async def run_db(self, func, *args, **kwargs):
        return func(*args, **kwargs)

    async def run_read_db(self, func, *args, **kwargs):
        return func(self.conn, *args, **kwargs)

    def fire_and_forget(self, coro, what):
        self.fired.append((what, coro))


def _scan_totals(prefix, src_ip, n_hosts=0, ports_per_host=None, same_port=22, avg_bytes=100):
    """Monta o dict no mesmo formato que flowguard.py::_aggregate_once produz.
    n_hosts simula 1 src_ip tocando N hosts distintos na MESMA porta (same_port) —
    requisito real do detector horizontal (achado de produção: CDN/big-tech
    respondendo em portas efêmeras distintas por cliente NÃO deve contar).
    avg_bytes controla a média de bytes por host/porta (default baixo — sonda de
    reconhecimento — pra não disparar o filtro de bytes médios sem querer nos
    testes que não são sobre ele)."""
    dst_ips_by_port = defaultdict(set)
    bytes_by_port = defaultdict(int)
    dst_ports = defaultdict(set)
    dst_bytes = defaultdict(int)
    if n_hosts:
        dst_ips_by_port[same_port] = set(f"177.86.16.{i}" for i in range(n_hosts))
        bytes_by_port[same_port] = avg_bytes * n_hosts
    if ports_per_host:
        host, n_ports = ports_per_host
        dst_ports[host] = set(range(1000, 1000 + n_ports))
        dst_bytes[host] = avg_bytes * n_ports
        dst_ips_by_port[1000].add(host)
        bytes_by_port[1000] += avg_bytes
    return {(prefix, src_ip): {
        "dst_ips_by_port": dst_ips_by_port, "bytes_by_port": bytes_by_port,
        "dst_ports": dst_ports, "dst_bytes": dst_bytes, "packets": 100,
    }}


def _cfg(**scan_overrides):
    scan_cfg = {**configio.DEFAULT_SCAN_DETECTION, **scan_overrides}
    return {
        "detection": {"min_attack_duration_s": 0},
        "whitelist": [],
        "mitigation_profiles": configio.DEFAULT_MITIGATION_PROFILES,
        "escalation": configio.DEFAULT_ESCALATION,
        "scan_detection": scan_cfg,
    }


async def _run(engine, daemon, scan_totals, interval=30):
    await engine.evaluate_scan_cycle(int(time.time()), scan_totals, interval)
    for _what, coro in daemon.fired:
        await coro
    daemon.fired.clear()


def test_scan_horizontal_detected_and_persisted(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = FakeDaemon(conn, _cfg(horizontal_hosts=5))
    engine = DetectionEngine(daemon)
    totals = _scan_totals("177.86.16.0/24", "203.0.113.1", n_hosts=8)

    asyncio.run(_run(engine, daemon, totals))

    offenders = storage.list_scan_offenders(conn)
    assert len(offenders) == 1
    assert offenders[0]["src_ip"] == "203.0.113.1"
    assert offenders[0]["scan_type"] == "horizontal"
    assert offenders[0]["dst_count"] == 8
    assert offenders[0]["ts_end"] is None


def test_scan_vertical_detected_and_persisted(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = FakeDaemon(conn, _cfg(vertical_ports=10))
    engine = DetectionEngine(daemon)
    totals = _scan_totals("177.86.16.0/24", "203.0.113.2", ports_per_host=("177.86.16.5", 15))

    asyncio.run(_run(engine, daemon, totals))

    offenders = [o for o in storage.list_scan_offenders(conn) if o["scan_type"] == "vertical"]
    assert len(offenders) == 1
    assert offenders[0]["src_ip"] == "203.0.113.2"
    assert offenders[0]["dst_count"] == 15


def test_scan_horizontal_ignores_same_ip_on_different_ports(tmp_path):
    """Achado real de produção: CDN/big-tech respondendo a vários clientes MEUS, cada
    um na sua porta efêmera de retorno, tocava muitos hosts distintos e batia o
    limiar de scan horizontal — falso positivo (Facebook/Fastly/Google flagados).
    Sem MESMA porta em comum, não é scan de reconhecimento de verdade."""
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = FakeDaemon(conn, _cfg(horizontal_hosts=5))
    engine = DetectionEngine(daemon)
    dst_ips_by_port = defaultdict(set)
    bytes_by_port = defaultdict(int)
    for i in range(8):
        dst_ips_by_port[50000 + i].add(f"177.86.16.{i}")  # porta efêmera DIFERENTE por cliente
        bytes_by_port[50000 + i] = 100
    totals = {("177.86.16.0/24", "157.240.22.13"): {
        "dst_ips_by_port": dst_ips_by_port, "bytes_by_port": bytes_by_port,
        "dst_ports": defaultdict(set), "dst_bytes": defaultdict(int), "packets": 100,
    }}

    asyncio.run(_run(engine, daemon, totals))

    assert storage.list_scan_offenders(conn) == []


def test_scan_below_threshold_not_detected(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = FakeDaemon(conn, _cfg(horizontal_hosts=20, vertical_ports=20))
    engine = DetectionEngine(daemon)
    totals = _scan_totals("177.86.16.0/24", "203.0.113.3", n_hosts=5)

    asyncio.run(_run(engine, daemon, totals))

    assert storage.list_scan_offenders(conn) == []


def test_scan_offender_closes_when_src_ip_stops(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = FakeDaemon(conn, _cfg(horizontal_hosts=5))
    engine = DetectionEngine(daemon)
    totals = _scan_totals("177.86.16.0/24", "203.0.113.4", n_hosts=8)

    asyncio.run(_run(engine, daemon, totals))
    assert storage.list_scan_offenders(conn)[0]["ts_end"] is None

    asyncio.run(_run(engine, daemon, {}))  # ciclo seguinte: nada mais chegou desse IP
    offenders = storage.list_scan_offenders(conn, active_only=False)
    assert offenders[0]["ts_end"] is not None


def test_scan_debounce_respects_min_duration(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    cfg = _cfg(horizontal_hosts=5)
    cfg["detection"]["min_attack_duration_s"] = 999999  # nunca sustenta o suficiente num teste síncrono
    daemon = FakeDaemon(conn, cfg)
    engine = DetectionEngine(daemon)
    totals = _scan_totals("177.86.16.0/24", "203.0.113.5", n_hosts=8)

    asyncio.run(_run(engine, daemon, totals))

    assert storage.list_scan_offenders(conn) == []


def test_scan_whitelisted_src_ip_ignored(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    cfg = _cfg(horizontal_hosts=5)
    cfg["whitelist"] = ["203.0.113.0/24"]
    daemon = FakeDaemon(conn, cfg)
    engine = DetectionEngine(daemon)
    totals = _scan_totals("177.86.16.0/24", "203.0.113.6", n_hosts=8)

    asyncio.run(_run(engine, daemon, totals))

    assert storage.list_scan_offenders(conn) == []


def test_scan_detection_disabled_skips_everything(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = FakeDaemon(conn, _cfg(horizontal_hosts=5, enabled=False))
    engine = DetectionEngine(daemon)
    totals = _scan_totals("177.86.16.0/24", "203.0.113.7", n_hosts=8)

    asyncio.run(_run(engine, daemon, totals))

    assert storage.list_scan_offenders(conn) == []


def test_scan_auto_block_calls_flowspec_add_when_enabled(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    cfg = _cfg(horizontal_hosts=5, auto_block=True)
    cfg["mitigation_profiles"] = {**configio.DEFAULT_MITIGATION_PROFILES,
                                   "port_scan_horizontal": {"auto_mode": "suggestion"}}
    daemon = FakeDaemon(conn, cfg)
    engine = DetectionEngine(daemon)
    totals = _scan_totals("177.86.16.0/24", "203.0.113.8", n_hosts=8)

    asyncio.run(_run(engine, daemon, totals))

    assert len(daemon.bgp_manager.calls) == 1
    call = daemon.bgp_manager.calls[0]
    assert call["rule"]["src_prefix"] == "203.0.113.8/32"
    assert call["rule"]["action"] == "discard"
    assert call["peer"] == "main"
    assert call["trigger_type"] == "auto"
    offenders = storage.list_scan_offenders(conn)
    assert offenders[0]["mitigated"] == 1
    assert offenders[0]["flowspec_rule_id"] == 42


def test_scan_auto_block_not_called_when_auto_mode_off(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    cfg = _cfg(horizontal_hosts=5, auto_block=True)  # scan_detection ligado, mas mitigation_profiles continua "off"
    daemon = FakeDaemon(conn, cfg)
    engine = DetectionEngine(daemon)
    totals = _scan_totals("177.86.16.0/24", "203.0.113.9", n_hosts=8)

    asyncio.run(_run(engine, daemon, totals))

    assert daemon.bgp_manager.calls == []


def test_scan_auto_block_not_called_when_flag_off_despite_auto_mode(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    cfg = _cfg(horizontal_hosts=5, auto_block=False)
    cfg["mitigation_profiles"] = {**configio.DEFAULT_MITIGATION_PROFILES,
                                   "port_scan_horizontal": {"auto_mode": "suggestion"}}
    daemon = FakeDaemon(conn, cfg)
    engine = DetectionEngine(daemon)
    totals = _scan_totals("177.86.16.0/24", "203.0.113.10", n_hosts=8)

    asyncio.run(_run(engine, daemon, totals))

    assert daemon.bgp_manager.calls == []


# --- filtro de bytes médios (achado real 2026-07-10: Google/YouTube bloqueados) --

def test_scan_vertical_ignores_high_bandwidth_streaming(tmp_path):
    """Achado real de produção: streaming/CDN (Google/YouTube) abre várias conexões
    paralelas pro MESMO cliente, cada uma numa porta efêmera diferente do lado do
    cliente — bate o limiar de scan vertical por contagem de portas sozinha. Sonda
    de reconhecimento manda pouco por porta; streaming manda muito — filtro de
    bytes médios deve distinguir os dois."""
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = FakeDaemon(conn, _cfg(vertical_ports=50, vertical_max_avg_bytes=10_000))
    engine = DetectionEngine(daemon)
    # 74 portas distintas no mesmo host, 500KB de média por porta — streaming real
    totals = _scan_totals("177.86.17.0/24", "104.237.171.21", ports_per_host=("177.86.17.5", 74),
                           avg_bytes=500_000)

    asyncio.run(_run(engine, daemon, totals))

    assert storage.list_scan_offenders(conn) == []


def test_scan_vertical_still_detects_low_bandwidth_probing(tmp_path):
    """Mesma contagem de portas do teste acima, mas bytes por porta BAIXOS (sonda de
    verdade) — precisa continuar detectando, o filtro não pode virar bypass geral."""
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = FakeDaemon(conn, _cfg(vertical_ports=50, vertical_max_avg_bytes=10_000))
    engine = DetectionEngine(daemon)
    totals = _scan_totals("177.86.17.0/24", "203.0.113.50", ports_per_host=("177.86.17.6", 74),
                           avg_bytes=60)  # poucos bytes por porta = sonda

    asyncio.run(_run(engine, daemon, totals))

    offenders = [o for o in storage.list_scan_offenders(conn) if o["scan_type"] == "vertical"]
    assert len(offenders) == 1


def test_scan_horizontal_ignores_high_bandwidth_same_port(tmp_path):
    """Mesmo filtro aplicado ao horizontal, defesa em profundidade (caso mais raro
    já que a porta é do lado do cliente, mas mesmo princípio)."""
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = FakeDaemon(conn, _cfg(horizontal_hosts=5, horizontal_max_avg_bytes=10_000))
    engine = DetectionEngine(daemon)
    totals = _scan_totals("177.86.16.0/24", "104.237.171.21", n_hosts=8, avg_bytes=500_000)

    asyncio.run(_run(engine, daemon, totals))

    assert storage.list_scan_offenders(conn) == []


def test_scan_max_avg_bytes_none_disables_filter(tmp_path):
    """None desativa o filtro por completo (mesma convenção do ClientGuard) — volta
    ao comportamento antigo (só contagem de portas/hosts)."""
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = FakeDaemon(conn, _cfg(vertical_ports=50, vertical_max_avg_bytes=None))
    engine = DetectionEngine(daemon)
    totals = _scan_totals("177.86.17.0/24", "104.237.171.21", ports_per_host=("177.86.17.5", 74),
                           avg_bytes=500_000)

    asyncio.run(_run(engine, daemon, totals))

    offenders = [o for o in storage.list_scan_offenders(conn) if o["scan_type"] == "vertical"]
    assert len(offenders) == 1
