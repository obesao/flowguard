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
