"""Testa daemon_stats() separando entrada e saída — ver collector/storage.py.
Motivo: KPI "Tráfego" só mostrava bps/pps de entrada, causando confusão ao
comparar com ferramentas externas (Grafana/SNMP) que mostram as duas direções
separadas."""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collector import storage


def _connect(tmp_path):
    return storage.connect(str(tmp_path / "flows.sqlite"))


def _insert_agg(conn, ts, bps, pps, direction):
    conn.execute(
        """INSERT INTO flow_aggs (ts, dst_prefix, protocol, dst_port, bps, pps, flow_count,
           avg_pkt_size, top_src_ips, top_dst_ips, direction)
           VALUES (?, '177.86.16.0/24', 6, 80, ?, ?, 1, 100, '[]', '[]', ?)""",
        (ts, bps, pps, direction),
    )
    conn.commit()


def test_daemon_stats_separates_in_and_out(tmp_path):
    conn = _connect(tmp_path)
    now = int(time.time())
    _insert_agg(conn, now - 5, 1000, 10, "in")
    _insert_agg(conn, now - 5, 300, 3, "out")

    stats = storage.daemon_stats(conn, window_s=30)
    assert stats["bps"] == 1000
    assert stats["pps"] == 10
    assert stats["bps_out"] == 300
    assert stats["pps_out"] == 3


def test_daemon_stats_out_defaults_to_zero_without_data(tmp_path):
    conn = _connect(tmp_path)
    stats = storage.daemon_stats(conn, window_s=30)
    assert stats["bps_out"] == 0
    assert stats["pps_out"] == 0
