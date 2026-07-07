"""Testa build_command com/sem neighbor — sem neighbor mantém o comando exatamente
como antes (ExaBGP propaga pra todos os peers); com neighbor, prefixa "neighbor <ip>
<comando>" pra escopar a um peer só (necessário desde que existe mais de uma sessão
BGP no mesmo exabgp.conf — ver bgp/manager.py._peer_ip)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from bgp import flowspec


# --- parse_rule_string ------------------------------------------------------------
# discard/rtbh não levam valor — aceitos como palavra solta ("discard"), além do
# formato antigo "chave=valor" (mantido por compatibilidade — ver flowspec.py).

def test_parse_rule_string_bare_discard():
    rule = flowspec.parse_rule_string("dst=177.86.16.0/24 protocol=udp discard")
    assert rule == {"dst_prefix": "177.86.16.0/24", "protocol": "udp", "action": "discard"}


def test_parse_rule_string_bare_rtbh():
    rule = flowspec.parse_rule_string("dst=177.86.16.10/32 rtbh")
    assert rule == {"dst_prefix": "177.86.16.10/32", "action": "rtbh"}


def test_parse_rule_string_legacy_discard_with_dummy_value_still_works():
    rule = flowspec.parse_rule_string("dst=177.86.16.0/24 discard=1")
    assert rule["action"] == "discard"


def test_parse_rule_string_legacy_rtbh_with_dummy_value_still_works():
    rule = flowspec.parse_rule_string("dst=177.86.16.10/32 rtbh=1")
    assert rule["action"] == "rtbh"


def test_parse_rule_string_rate_limit_requires_value():
    rule = flowspec.parse_rule_string("dst=177.86.16.0/24 rate-limit=1M")
    assert rule["action"] == "rate-limit:1000000"


def test_parse_rule_string_redirect_requires_value():
    rule = flowspec.parse_rule_string("dst=177.86.16.0/24 redirect=9999:1")
    assert rule["action"] == "redirect:9999:1"


def test_parse_rule_string_missing_action_raises():
    with pytest.raises(ValueError, match="precisa de uma ação"):
        flowspec.parse_rule_string("dst=177.86.16.0/24 protocol=udp")


def test_parse_rule_string_unknown_field_raises():
    with pytest.raises(ValueError, match="campo desconhecido"):
        flowspec.parse_rule_string("dst=177.86.16.0/24 campo-invalido=x discard")


def test_parse_rule_string_token_without_equals_and_not_a_bare_action_raises():
    with pytest.raises(ValueError, match="token inválido"):
        flowspec.parse_rule_string("dst=177.86.16.0/24 isso_nao_e_nada discard")


def test_build_command_flowspec_announce_without_neighbor():
    rule = {"src_prefix": "100.64.1.2/32", "action": "discard", "label": "teste"}
    cmd = flowspec.build_command("announce", "flowspec", rule)
    assert cmd.startswith("announce flow route")
    assert "neighbor" not in cmd


def test_build_command_flowspec_announce_with_neighbor():
    rule = {"src_prefix": "100.64.1.2/32", "action": "discard", "label": "teste"}
    cmd = flowspec.build_command("announce", "flowspec", rule, neighbor="10.70.70.1")
    assert cmd.startswith("neighbor 10.70.70.1 announce flow route")


def test_build_command_flowspec_withdraw_with_neighbor():
    rule = {"src_prefix": "100.64.1.2/32", "action": "discard"}
    cmd = flowspec.build_command("withdraw", "flowspec", rule, neighbor="10.70.70.1")
    assert cmd.startswith("neighbor 10.70.70.1 withdraw flow route")


def test_build_command_rtbh_with_neighbor():
    rule = {"dst_prefix": "177.86.16.5/32", "community": "2626:669", "nexthop": "10.77.10.2"}
    cmd = flowspec.build_command("announce", "rtbh", rule, neighbor="10.77.10.1")
    assert cmd == "neighbor 10.77.10.1 announce route 177.86.16.5/32 next-hop 10.77.10.2 community [2626:669]"


# --- suggest_mitigation / _describe_match --------------------------------
# Sem teste nenhum antes desta feature (achado real ao adicionar syn_flood:
# _describe_match indexava match['src_port'] sem checar presença — quebrava
# na hora pra qualquer attack_type sem porta de origem fixa, ex: syn_flood,
# que usa tcp_flags em vez de src_port). O smoke test abaixo cobre qualquer
# tipo futuro que tenha o mesmo problema, não só o syn_flood de hoje.

def test_suggest_mitigation_syn_flood_uses_tcp_flags_match():
    result = flowspec.suggest_mitigation("syn_flood", "177.86.16.0/24", {"syn_flood": {"kind": "discard"}})
    assert result["kind"] == "flowspec"
    assert result["rule"]["protocol"] == "tcp"
    assert result["rule"]["tcp_flags"] == "[ syn ]"
    assert "SYN flood" in result["label"]


def test_suggest_mitigation_never_crashes_for_any_known_attack_type():
    from collector import configio

    for attack_type in configio.DEFAULT_MITIGATION_PROFILES:
        for kind in ("discard", "rate_limit", "rtbh"):
            result = flowspec.suggest_mitigation(attack_type, "177.86.16.0/24", {attack_type: {"kind": kind}})
            assert result["label"], attack_type
