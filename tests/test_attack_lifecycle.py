"""Testa o rastreio de ts_last_seen em attacks e a rede de segurança
close_stale_attacks — ver collector/storage.py. Cobre o bug relatado: ataque
fica "ativo" pra sempre quando a engine para de reavaliar sua chave (prefixo
removido de protected_prefixes, reload/restart no meio do ataque)."""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collector import storage


def _connect(tmp_path):
    return storage.connect(str(tmp_path / "flows.sqlite"))


def test_insert_sets_ts_last_seen_to_ts_start(tmp_path):
    conn = _connect(tmp_path)
    now = int(time.time())
    ids = storage.apply_attack_changes(conn, [{
        "ts_start": now, "dst_prefix": "177.86.16.0/24", "customer": "teste",
        "attack_type": "ddos_volumetrico", "severity": "critical", "bps_peak": 1, "pps_peak": 1,
    }], [], [])
    attack = storage.get_attack(conn, ids[0])
    assert attack["ts_last_seen"] == now


def test_update_bumps_ts_last_seen(tmp_path):
    conn = _connect(tmp_path)
    start = int(time.time()) - 100
    ids = storage.apply_attack_changes(conn, [{
        "ts_start": start, "dst_prefix": "177.86.16.0/24", "customer": "teste",
        "attack_type": "ddos_volumetrico", "severity": "critical", "bps_peak": 1, "pps_peak": 1,
    }], [], [])
    attack_id = ids[0]
    later = start + 60
    storage.apply_attack_changes(conn, [], [(attack_id, 2, 2, later)], [])
    attack = storage.get_attack(conn, attack_id)
    assert attack["ts_last_seen"] == later
    assert attack["bps_peak"] == 2


def test_close_stale_attacks_closes_only_past_cutoff(tmp_path):
    conn = _connect(tmp_path)
    now = int(time.time())
    stale_id = storage.apply_attack_changes(conn, [{
        "ts_start": now - 30000, "dst_prefix": "177.86.16.0/24", "customer": "teste",
        "attack_type": "ddos_volumetrico", "severity": "critical", "bps_peak": 1, "pps_peak": 1,
    }], [], [])[0]
    # simula que a engine parou de reavaliar essa chave há muito tempo
    conn.execute("UPDATE attacks SET ts_last_seen = ? WHERE id = ?", (now - 25000, stale_id))
    conn.commit()

    fresh_id = storage.apply_attack_changes(conn, [{
        "ts_start": now - 100, "dst_prefix": "177.86.17.0/24", "customer": "teste2",
        "attack_type": "ddos_volumetrico", "severity": "critical", "bps_peak": 1, "pps_peak": 1,
    }], [], [])[0]

    closed = storage.close_stale_attacks(conn, stale_s=21600)

    closed_ids = {row["id"] for row in closed}
    assert closed_ids == {stale_id}

    stale_attack = storage.get_attack(conn, stale_id)
    assert stale_attack["ts_end"] is not None

    fresh_attack = storage.get_attack(conn, fresh_id)
    assert fresh_attack["ts_end"] is None


def test_close_stale_attacks_no_candidates_returns_empty(tmp_path):
    conn = _connect(tmp_path)
    now = int(time.time())
    storage.apply_attack_changes(conn, [{
        "ts_start": now - 100, "dst_prefix": "177.86.16.0/24", "customer": "teste",
        "attack_type": "ddos_volumetrico", "severity": "critical", "bps_peak": 1, "pps_peak": 1,
    }], [], [])

    closed = storage.close_stale_attacks(conn, stale_s=21600)
    assert closed == []


def test_close_stale_attacks_sets_target_host(tmp_path):
    conn = _connect(tmp_path)
    now = int(time.time())
    stale_id = storage.apply_attack_changes(conn, [{
        "ts_start": now - 30000, "dst_prefix": "177.86.16.0/24", "customer": "teste",
        "attack_type": "ddos_volumetrico", "severity": "critical", "bps_peak": 1, "pps_peak": 1,
    }], [], [])[0]
    conn.execute("UPDATE attacks SET ts_last_seen = ? WHERE id = ?", (now - 25000, stale_id))
    conn.commit()
    conn.execute(
        """INSERT INTO flow_aggs (ts, dst_prefix, protocol, dst_port, bps, pps, flow_count, avg_pkt_size,
           top_src_ips, top_dst_ips, direction)
           VALUES (?, '177.86.16.0/24', 6, 80, 1000, 10, 1, 100, '[]', '["177.86.16.5"]', 'in')""",
        (now - 26000,),
    )
    conn.commit()

    storage.close_stale_attacks(conn, stale_s=21600)
    attack = storage.get_attack(conn, stale_id)
    assert attack["target_host"] == "177.86.16.5"
