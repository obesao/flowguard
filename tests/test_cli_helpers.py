"""Testa os helpers puros de flowguard-cli.py (formatação/parsing) — os
cmd_* propriamente ditos são principalmente I/O (socket real + impressão de
tabelas rich) e ficam fora, mesmo raciocínio já aplicado ao resto do
FlowGuard: baixo valor por linha pra teste unitário nessa camada.

flowguard-cli.py não é um pacote Python normal (nome com hífen) — importado
via importlib a partir do caminho do arquivo, como já é preciso fazer pra
testar scripts standalone com hífen no nome."""

from __future__ import annotations

import importlib.util
import sys
import time
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent.parent / "flowguard-cli.py"
_spec = importlib.util.spec_from_file_location("flowguard_cli", MODULE_PATH)
cli = importlib.util.module_from_spec(_spec)
sys.modules["flowguard_cli"] = cli
_spec.loader.exec_module(cli)

import pytest


# --- resolve_socket_path ----------------------------------------------------------

def test_resolve_socket_path_reads_from_config(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text("daemon:\n  socket: /var/run/custom.sock\n")
    assert cli.resolve_socket_path(str(config)) == "/var/run/custom.sock"


def test_resolve_socket_path_falls_back_when_file_missing():
    assert cli.resolve_socket_path("/nao/existe/config.yaml") == cli.DEFAULT_SOCKET_PATH


def test_resolve_socket_path_falls_back_when_key_missing(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text("daemon: {}\n")
    assert cli.resolve_socket_path(str(config)) == cli.DEFAULT_SOCKET_PATH


# --- fmt_bps / fmt_bytes / fmt_duration / proto_name -------------------------------

@pytest.mark.parametrize("bps, expected", [
    (500, "500 bps"),
    (1_500, "2 Kbps"),
    (1_500_000, "1.5 Mbps"),
    (1_500_000_000, "1.50 Gbps"),
])
def test_fmt_bps(bps, expected):
    assert cli.fmt_bps(bps) == expected


@pytest.mark.parametrize("n, expected", [
    (500, "500.0 B"),
    (2048, "2.0 KB"),
    (5 * 1024 * 1024, "5.0 MB"),
    (3 * 1024 ** 4, "3.0 TB"),
])
def test_fmt_bytes(n, expected):
    assert cli.fmt_bytes(n) == expected


@pytest.mark.parametrize("seconds, expected", [
    (45, "45s"),
    (125, "2m05s"),
    (3725, "1h02m"),
])
def test_fmt_duration(seconds, expected):
    assert cli.fmt_duration(seconds) == expected


@pytest.mark.parametrize("proto, expected", [(6, "TCP"), (17, "UDP"), (1, "ICMP"), (47, "47")])
def test_proto_name(proto, expected):
    assert cli.proto_name(proto) == expected


# --- die_on_error -------------------------------------------------------------------

def test_die_on_error_does_nothing_when_ok():
    cli.die_on_error({"ok": True})  # não deve levantar


def test_die_on_error_exits_with_message_when_not_ok(capsys):
    with pytest.raises(SystemExit) as exc_info:
        cli.die_on_error({"ok": False, "error": "algo deu errado"})
    assert exc_info.value.code == 1
    assert "algo deu errado" in capsys.readouterr().out


def test_die_on_error_uses_default_message_when_error_key_missing(capsys):
    with pytest.raises(SystemExit):
        cli.die_on_error({"ok": False})
    assert "desconhecido" in capsys.readouterr().out


# --- fmt_bgp_state --------------------------------------------------------------------

def test_fmt_bgp_state_up():
    assert "Up" in cli.fmt_bgp_state({"peer_state": "up"})


def test_fmt_bgp_state_down_or_missing():
    assert "Down" in cli.fmt_bgp_state({"peer_state": "idle"})
    assert "Down" in cli.fmt_bgp_state({})


# --- _fmt_mitigation_action ------------------------------------------------------------

def test_fmt_mitigation_action_rtbh():
    assert cli._fmt_mitigation_action("rtbh") == "RTBH"


def test_fmt_mitigation_action_rate_limit():
    assert cli._fmt_mitigation_action("rate-limit:100000000") == "limitado a 100 Mbps"


def test_fmt_mitigation_action_discard_and_none():
    assert cli._fmt_mitigation_action("discard") == "discard"
    assert cli._fmt_mitigation_action(None) == "discard"


# --- _fmt_activity_freshness / _is_genuinely_active -------------------------------------
# Lógica com histórico real de bug (ver CHANGELOG v1.29.0 do flowguard: selo de
# mitigação mostrava "sem proteção" pra ataque que já tinha parado de verdade).

def test_activity_freshness_closed_row_shows_dash():
    assert cli._fmt_activity_freshness(int(time.time()), row_open=False) == "-"


def test_activity_freshness_no_ts_last_seen_shows_dash():
    assert cli._fmt_activity_freshness(None, row_open=True) == "-"


def test_activity_freshness_recent_shows_green():
    assert "em andamento" in cli._fmt_activity_freshness(int(time.time()) - 10, row_open=True)


def test_activity_freshness_stale_shows_yellow_with_duration():
    ts = int(time.time()) - 3725
    result = cli._fmt_activity_freshness(ts, row_open=True)
    assert "sem atividade" in result
    assert "1h02m" in result


def test_is_genuinely_active_false_when_closed():
    assert cli._is_genuinely_active(ts_end=int(time.time()), ts_last_seen=int(time.time())) is False


def test_is_genuinely_active_false_when_no_last_seen():
    assert cli._is_genuinely_active(ts_end=None, ts_last_seen=None) is False


def test_is_genuinely_active_true_when_open_and_fresh():
    assert cli._is_genuinely_active(ts_end=None, ts_last_seen=int(time.time()) - 5) is True


def test_is_genuinely_active_false_when_open_but_stale():
    assert cli._is_genuinely_active(ts_end=None, ts_last_seen=int(time.time()) - 200) is False


# --- _fmt_attack_mitigation_cell ------------------------------------------------------

def test_mitigation_cell_no_mitigation():
    assert "sem mitigação" in cli._fmt_attack_mitigation_cell(None)


def test_mitigation_cell_active_shows_shield():
    result = cli._fmt_attack_mitigation_cell({"action": "rtbh", "active": True})
    assert "🛡 ativa" in result
    assert "RTBH" in result


def test_mitigation_cell_inactive_and_row_open_shows_warning():
    """Ataque genuinamente ativo (row_open=True) sem mitigação em vigor = alarme real."""
    result = cli._fmt_attack_mitigation_cell({"action": "discard", "active": False}, row_open=True)
    assert "⚠ sem proteção" in result


def test_mitigation_cell_inactive_and_row_closed_shows_neutral_history():
    """Ataque já não genuinamente ativo (row_open=False) = neutro, não alarme."""
    result = cli._fmt_attack_mitigation_cell({"action": "discard", "active": False}, row_open=False)
    assert "encerrada" in result
    assert "⚠" not in result


# --- _fmt_rule_mechanism / _fmt_rule_trigger / _resolve_device_name -------------------

def test_fmt_rule_mechanism():
    assert cli._fmt_rule_mechanism("rtbh") == "RTBH"
    assert cli._fmt_rule_mechanism("discard") == "FlowSpec"


def test_fmt_rule_trigger():
    assert cli._fmt_rule_trigger("auto") == "automático"
    assert cli._fmt_rule_trigger("manual") == "manual"
    assert cli._fmt_rule_trigger(None) == "manual"


def test_resolve_device_name_main_peer_default():
    assert cli._resolve_device_name("main", {}) == "NE8000BGP"


def test_resolve_device_name_main_peer_configured():
    assert cli._resolve_device_name("main", {"peer_device_main": "Custom"}) == "Custom"


def test_resolve_device_name_other_peer_falls_back_to_peer_name():
    assert cli._resolve_device_name("pppoe", {}) == "pppoe"


def test_resolve_device_name_other_peer_configured():
    assert cli._resolve_device_name("pppoe", {"peer_device_pppoe": "NE8000-PPPOE"}) == "NE8000-PPPOE"


# --- _parse_set_args -------------------------------------------------------------------

def test_parse_set_args_empty_or_none():
    assert cli._parse_set_args(None) == {}
    assert cli._parse_set_args([]) == {}


def test_parse_set_args_parses_key_value_pairs():
    assert cli._parse_set_args(["a=1", "b=2"]) == {"a": "1", "b": "2"}


def test_parse_set_args_value_can_contain_equals_sign():
    assert cli._parse_set_args(["filtro=a=b"]) == {"filtro": "a=b"}


def test_parse_set_args_rejects_pair_without_equals():
    with pytest.raises(SystemExit):
        cli._parse_set_args(["sem_igual"])
