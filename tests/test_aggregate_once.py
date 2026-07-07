"""Testa FlowGuardDaemon._aggregate_once — o coração da agregação de flows,
onde já viveram vários bugs reais documentados no CHANGELOG (explosão de
flow_aggs por porta efêmera/cauda longa de fallback, dupla contagem por
flow_direction, granularidade de host /32 só em prefixo protegido, ranking
de target_host sem decaimento por rank).

Instancia FlowGuardDaemon sem rodar __init__ (mesmo padrão de
test_wa_notifications.py/test_bgp_manager.py) — seta só o que
_aggregate_once de fato usa: queue, config, conn/run_db, e fakes gravando
chamada pro detector/bgp_manager (não testados aqui, só a agregação em si)."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import flowguard
from analyzer.engine import PROTO_TCP, TCP_FLAG_ACK, TCP_FLAG_SYN
from collector import storage
from collector.models import FlowRecord


def _rec(src_ip="200.1.2.3", dst_ip="177.86.16.10", protocol=6, src_port=54321,
         dst_port=80, tcp_flags=0, nbytes=1000, npkts=1, flow_direction=0,
         sampling_rate=1) -> FlowRecord:
    return FlowRecord(
        src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port,
        protocol=protocol, tcp_flags=tcp_flags, bytes=nbytes, packets=npkts,
        duration_ms=0, ts=1_700_000_000.0, ingress_if=0, egress_if=0,
        src_asn=0, dst_asn=0, nexthop="", sampling_rate=sampling_rate,
        flow_direction=flow_direction,
    )


class RecordingDetector:
    def __init__(self):
        self.calls = []

    async def evaluate_cycle(self, now, proto_totals_bps, amp_totals_bps, syn_totals_bps):
        self.calls.append((now, proto_totals_bps, amp_totals_bps, syn_totals_bps))


class RecordingBgpManager:
    def __init__(self):
        self.expire_calls = 0
        self.reconciliation_calls = 0

    async def expire_cycle(self):
        self.expire_calls += 1

    async def check_reconciliation(self):
        self.reconciliation_calls += 1


def _make_daemon(conn, protected_prefixes, interval=30):
    daemon = object.__new__(flowguard.FlowGuardDaemon)
    daemon.conn = conn
    daemon.config = {
        "protected_prefixes": protected_prefixes,
        "database": {"aggregate_interval_s": interval},
    }
    daemon.queue = asyncio.Queue()
    daemon.detector = RecordingDetector()
    daemon.bgp_manager = RecordingBgpManager()

    async def run_db(func, *args, **kwargs):
        return func(*args, **kwargs)

    daemon.run_db = run_db
    return daemon


def _flow_aggs_rows(conn):
    cur = conn.execute("SELECT * FROM flow_aggs")
    return [dict(row) for row in cur.fetchall()]


PROTECTED = [{"prefix": "177.86.16.0/24", "customer": "Cliente X"}]


def test_ingress_and_egress_of_same_packet_not_double_counted(tmp_path):
    """A NE8000 exporta netstream inbound+outbound em toda interface — cada
    pacote real gera 2 registros (ingress e egress) do MESMO tráfego. Só
    flow_direction=0 (ingress) deve ser contado, senão tudo dobra."""
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = _make_daemon(conn, PROTECTED)
    daemon.queue.put_nowait(_rec(flow_direction=0, nbytes=1000))
    daemon.queue.put_nowait(_rec(flow_direction=1, nbytes=1000))  # egress do mesmo pacote

    asyncio.run(daemon._aggregate_once())

    rows = [r for r in _flow_aggs_rows(conn) if r["direction"] == "in"]
    assert len(rows) == 1
    assert rows[0]["bps"] == int(1000 * 8 / 30)


def test_dst_port_bucketed_to_zero_for_unprotected_prefix(tmp_path):
    """Fallback (destino não é cliente protegido) sempre vira dst_port=0,
    mesmo que well-known — evita explosão de cardinalidade por porta
    efêmera (bug real documentado, ~65k portas/hora)."""
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = _make_daemon(conn, PROTECTED)
    daemon.queue.put_nowait(_rec(dst_ip="8.8.8.8", dst_port=53))

    asyncio.run(daemon._aggregate_once())

    rows = _flow_aggs_rows(conn)
    assert len(rows) == 1
    assert rows[0]["dst_prefix"] == "8.8.8.0/24"
    assert rows[0]["dst_port"] == 0


def test_dst_port_kept_for_protected_prefix_when_well_known(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = _make_daemon(conn, PROTECTED)
    daemon.queue.put_nowait(_rec(dst_ip="177.86.16.10", dst_port=80))

    asyncio.run(daemon._aggregate_once())

    rows = _flow_aggs_rows(conn)
    assert rows[0]["dst_prefix"] == "177.86.16.0/24"
    assert rows[0]["dst_port"] == 80


def test_dst_port_bucketed_to_zero_for_protected_prefix_when_ephemeral(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = _make_daemon(conn, PROTECTED)
    daemon.queue.put_nowait(_rec(dst_ip="177.86.16.10", dst_port=54321))

    asyncio.run(daemon._aggregate_once())

    rows = _flow_aggs_rows(conn)
    assert rows[0]["dst_port"] == 0


def test_top_dst_ips_only_tracked_for_protected_prefix(tmp_path):
    """Granularidade de host /32 só faz sentido (e só é rastreada) dentro de
    prefixo de fato protegido — nunca no fallback /24 de tráfego não-cliente."""
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = _make_daemon(conn, PROTECTED)
    daemon.queue.put_nowait(_rec(dst_ip="177.86.16.10", dst_port=80))
    daemon.queue.put_nowait(_rec(dst_ip="8.8.8.8", dst_port=53))

    asyncio.run(daemon._aggregate_once())

    rows = {r["dst_prefix"]: r for r in _flow_aggs_rows(conn)}
    assert rows["177.86.16.0/24"]["top_dst_ips"] == '["177.86.16.10"]'
    assert rows["8.8.8.0/24"]["top_dst_ips"] is None  # lista vazia -> NULL, não "[]"


def test_outbound_traffic_only_tracked_when_src_is_protected(tmp_path):
    """Tráfego de saída (cliente protegido como origem) só é agregado quando
    o SRC cai num prefixo protegido — sem fallback, pra não explodir
    cardinalidade com todo IP externo de destino."""
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = _make_daemon(conn, PROTECTED)
    daemon.queue.put_nowait(_rec(src_ip="177.86.16.10", dst_ip="8.8.8.8", nbytes=2000))
    daemon.queue.put_nowait(_rec(src_ip="9.9.9.9", dst_ip="8.8.4.4", nbytes=3000))

    asyncio.run(daemon._aggregate_once())

    out_rows = [r for r in _flow_aggs_rows(conn) if r["direction"] == "out"]
    assert len(out_rows) == 1
    assert out_rows[0]["dst_prefix"] == "177.86.16.0/24"
    assert out_rows[0]["bps"] == int(2000 * 8 / 30)


def test_fallback_long_tail_merged_into_outros_bucket(tmp_path, monkeypatch):
    """Só os FALLBACK_TOP_N grupos de fallback mais volumosos do ciclo ficam
    individuais; o resto vira uma linha 'outros' por protocolo, com os
    totais preservados — sem isso, tráfego de saída pra internet inteira
    gerava milhares de grupos /24 por ciclo (bug real corrigido)."""
    monkeypatch.setattr(flowguard, "FALLBACK_TOP_N", 2)
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = _make_daemon(conn, [])  # nenhum prefixo protegido -> tudo cai no fallback
    for i in range(5):
        daemon.queue.put_nowait(_rec(dst_ip=f"8.8.{i}.1", nbytes=(5 - i) * 1000))

    asyncio.run(daemon._aggregate_once())

    rows = {r["dst_prefix"]: r for r in _flow_aggs_rows(conn)}
    assert set(rows) == {"8.8.0.0/24", "8.8.1.0/24", "outros"}  # top 2 (5000,4000) + resto
    assert rows["8.8.0.0/24"]["bps"] == int(5000 * 8 / 30)
    assert rows["8.8.1.0/24"]["bps"] == int(4000 * 8 / 30)
    assert rows["outros"]["bps"] == int((3000 + 2000 + 1000) * 8 / 30)  # 3 menores fundidos


def test_amp_totals_only_for_udp_amplification_ports(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = _make_daemon(conn, PROTECTED)
    daemon.queue.put_nowait(_rec(protocol=17, src_port=53, nbytes=1000))  # DNS amp
    daemon.queue.put_nowait(_rec(protocol=17, src_port=12345, nbytes=1000))  # não é amp
    daemon.queue.put_nowait(_rec(protocol=6, src_port=53, nbytes=1000))  # TCP, não conta

    asyncio.run(daemon._aggregate_once())

    (now, proto_totals, amp_totals, syn_totals) = daemon.detector.calls[0]
    assert len(amp_totals) == 1
    prefix_key = next(iter(amp_totals))
    assert prefix_key[1] == 53


def test_syn_totals_only_for_pure_syn_packets(tmp_path):
    """SYN 'puro' (SYN setado, ACK não setado) isola o flood de SYN-ACK de
    handshake real — handshake normal (SYN+ACK) não deve contar."""
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = _make_daemon(conn, PROTECTED)
    daemon.queue.put_nowait(_rec(protocol=PROTO_TCP, tcp_flags=TCP_FLAG_SYN, nbytes=1000))
    daemon.queue.put_nowait(
        _rec(protocol=PROTO_TCP, tcp_flags=TCP_FLAG_SYN | TCP_FLAG_ACK, nbytes=1000)
    )

    asyncio.run(daemon._aggregate_once())

    (now, proto_totals, amp_totals, syn_totals) = daemon.detector.calls[0]
    assert list(syn_totals.values())[0]["bps"] == int(1000 * 8 / 30)


def test_sampling_rate_multiplies_bytes_and_packets(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = _make_daemon(conn, PROTECTED)
    daemon.queue.put_nowait(_rec(nbytes=1000, npkts=2, sampling_rate=10))

    asyncio.run(daemon._aggregate_once())

    rows = _flow_aggs_rows(conn)
    assert rows[0]["bps"] == int(10_000 * 8 / 30)
    assert rows[0]["pps"] == int(20 / 30)


def test_empty_queue_still_runs_detection_and_expiry(tmp_path):
    """Mesmo sem tráfego no ciclo, evaluate_cycle/expire_cycle rodam — é o
    que fecha ataques que já não estão mais ativos."""
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = _make_daemon(conn, PROTECTED)

    asyncio.run(daemon._aggregate_once())

    assert _flow_aggs_rows(conn) == []
    assert len(daemon.detector.calls) == 1
    assert daemon.bgp_manager.expire_calls == 1
    assert daemon.bgp_manager.reconciliation_calls == 1
