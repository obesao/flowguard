"""Testa bgp/escalation.py — bloqueio progressivo por reincidência do detector de
scan. offense_no vem de storage.count_recent_flowspec_blocks (histórico de
flowspec_rules, nunca deletado)."""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bgp import escalation
from collector import configio, storage


def _cfg(**overrides):
    cfg = dict(configio.DEFAULT_ESCALATION)
    cfg.update(overrides)
    return cfg


def _add_block(conn, src_ip, created_ago=0):
    rule_id = storage.insert_flowspec_rule(conn, {
        "created_at": int(time.time()) - created_ago, "expires_at": int(time.time()) + 3600,
        "src_prefix": f"{src_ip}/32", "action": "discard", "origin": "flowguard", "trigger_type": "auto",
    })
    return rule_id


def test_next_ttl_s_no_history_uses_base(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    cfg = _cfg(factor=4, max_steps=5, max_ttl_s=10**9)
    assert escalation.next_ttl_s(conn, "203.0.113.1", cfg, base_ttl_s=100) == 100


def test_next_ttl_s_grows_with_prior_blocks(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    cfg = _cfg(factor=4, max_steps=5, max_ttl_s=10**9)
    src = "203.0.113.2"
    _add_block(conn, src)
    assert escalation.next_ttl_s(conn, src, cfg, base_ttl_s=100) == 400
    _add_block(conn, src)
    assert escalation.next_ttl_s(conn, src, cfg, base_ttl_s=100) == 1600


def test_next_ttl_s_caps_at_max_ttl_s(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    cfg = _cfg(factor=4, max_steps=5, max_ttl_s=500)
    src = "203.0.113.3"
    for _ in range(5):
        _add_block(conn, src)
    assert escalation.next_ttl_s(conn, src, cfg, base_ttl_s=100) == 500


def test_next_ttl_s_ignores_blocks_outside_tracking_window(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    cfg = _cfg(factor=4, tracking_window_s=3600)
    src = "203.0.113.4"
    _add_block(conn, src, created_ago=7200)
    assert escalation.next_ttl_s(conn, src, cfg, base_ttl_s=100) == 100


def test_next_ttl_s_disabled_returns_base_unchanged(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    cfg = _cfg(enabled=False, factor=4)
    src = "203.0.113.5"
    for _ in range(3):
        _add_block(conn, src)
    assert escalation.next_ttl_s(conn, src, cfg, base_ttl_s=100) == 100


def test_next_ttl_s_scoped_by_exact_src_prefix(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    cfg = _cfg(factor=4, max_steps=5, max_ttl_s=10**9)
    _add_block(conn, "203.0.113.6")  # outro IP, não deve contar
    assert escalation.next_ttl_s(conn, "203.0.113.7", cfg, base_ttl_s=100) == 100


# --- configio: load_scan_detection / save_scan_detection / load_escalation / save_escalation

def test_load_scan_detection_missing_file_returns_defaults(tmp_path):
    cfg = configio.load_scan_detection(str(tmp_path / "nao-existe.yaml"))
    assert cfg == configio.DEFAULT_SCAN_DETECTION


def test_save_scan_detection_roundtrip(tmp_path):
    path = str(tmp_path / "scan_detection.yaml")
    updated = configio.save_scan_detection(path, {"horizontal_hosts": 30, "auto_block": True})
    assert updated["horizontal_hosts"] == 30
    assert updated["auto_block"] is True
    assert configio.load_scan_detection(path)["horizontal_hosts"] == 30


def test_save_scan_detection_rejects_unknown_key(tmp_path):
    path = str(tmp_path / "scan_detection.yaml")
    try:
        configio.save_scan_detection(path, {"nao_existe": 1})
        assert False, "deveria ter levantado ValueError"
    except ValueError:
        pass


def test_save_scan_detection_rejects_non_positive_threshold(tmp_path):
    path = str(tmp_path / "scan_detection.yaml")
    try:
        configio.save_scan_detection(path, {"horizontal_hosts": 0})
        assert False, "deveria ter levantado ValueError"
    except ValueError:
        pass


def test_load_escalation_missing_file_returns_defaults(tmp_path):
    cfg = configio.load_escalation(str(tmp_path / "nao-existe.yaml"))
    assert cfg == configio.DEFAULT_ESCALATION


def test_save_escalation_roundtrip(tmp_path):
    path = str(tmp_path / "escalation.yaml")
    updated = configio.save_escalation(path, {"factor": 3, "base_ttl_s": 1800})
    assert updated["factor"] == 3
    assert configio.load_escalation(path)["base_ttl_s"] == 1800


def test_save_escalation_rejects_factor_not_greater_than_one(tmp_path):
    path = str(tmp_path / "escalation.yaml")
    try:
        configio.save_escalation(path, {"factor": 1})
        assert False, "deveria ter levantado ValueError"
    except ValueError:
        pass
