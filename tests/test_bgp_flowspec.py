"""Testa build_command com/sem neighbor — sem neighbor mantém o comando exatamente
como antes (ExaBGP propaga pra todos os peers); com neighbor, prefixa "neighbor <ip>
<comando>" pra escopar a um peer só (necessário desde que existe mais de uma sessão
BGP no mesmo exabgp.conf — ver bgp/manager.py._peer_ip)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bgp import flowspec


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
