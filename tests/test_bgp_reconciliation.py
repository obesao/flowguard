"""Testa BgpManager.check_reconciliation/_reconcile_peer — re-anuncia regras
ativas quando uma sessão BGP volta de down/desconhecida pra up, sinal de que
o flowguard-speaker (ExaBGP) reiniciou e perdeu a RIB (nenhuma rota anunciada
antes sobrevive, sem graceful restart configurado). Sem isso, um restart do
speaker deixava mitigação "ativa" no banco sem proteção real na borda —
pendência conhecida desde a revisão de flow_aggs (2026-07-02), nunca
implementada até agora.

Mocka _send (nunca fala com o ExaBGP de verdade) e as respostas de status
(monkeypatch em BgpManager.status), mesmo padrão de test_bgp_manager.py."""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bgp.manager import BgpManager
from collector import storage


class FakeDaemon:
    def __init__(self, conn, bgp_cfg=None):
        self.conn = conn
        self.config = {
            "bgp": bgp_cfg or {
                "exabgp_socket": "/fake.sock",
                "peer_ip": "10.77.10.1",
                "peer_ip_pppoe": "10.70.70.1",
                "rtbh_community": "2626:669",
                "nexthop_blackhole": "0.0.0.0",
            },
            "mitigation": {},
        }

    async def run_db(self, func, *args, **kwargs):
        return func(*args, **kwargs)

    async def run_read_db(self, func, *args, **kwargs):
        return func(self.conn, *args, **kwargs)


def _insert_rule(conn, action="discard", peer="main", dst_prefix="177.86.16.10/32", src_prefix=None):
    now = int(time.time())
    return storage.insert_flowspec_rule(conn, {
        "created_at": now, "expires_at": now + 3600, "attack_id": None,
        "dst_prefix": dst_prefix, "src_prefix": src_prefix, "protocol": "udp" if action != "rtbh" else None,
        "dst_port": None, "src_port": "53" if action != "rtbh" else None, "tcp_flags": None, "pkt_len": None,
        "action": action, "label": "teste", "origin": "flowguard", "peer": peer,
    })


def test_no_reconciliation_on_first_check_even_if_up(tmp_path, monkeypatch):
    """Primeira checagem (cold start do daemon) só estabelece a baseline — não
    dispara re-anúncio, mesmo que o peer já esteja up."""
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    _insert_rule(conn)
    manager = BgpManager(FakeDaemon(conn, bgp_cfg={
        "exabgp_socket": "/fake.sock", "peer_ip": "10.77.10.1",
        "rtbh_community": "2626:669", "nexthop_blackhole": "0.0.0.0",
    }))
    sent = []

    async def fake_status(self, peer="main"):
        return {"peer_state": "up", "peer_ip": self._peer_ip(peer)}

    async def fake_send(self, payload):
        sent.append(payload)
        return {"ok": True}

    monkeypatch.setattr(BgpManager, "status", fake_status)
    monkeypatch.setattr(BgpManager, "_send", fake_send)

    asyncio.run(manager.check_reconciliation())

    assert sent == []
    assert manager._last_peer_state["main"] == "up"


def test_reconciles_when_peer_transitions_from_down_to_up(tmp_path, monkeypatch):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    rule_id = _insert_rule(conn)
    manager = BgpManager(FakeDaemon(conn, bgp_cfg={
        "exabgp_socket": "/fake.sock", "peer_ip": "10.77.10.1",
        "rtbh_community": "2626:669", "nexthop_blackhole": "0.0.0.0",
    }))
    states = iter(["down", "up"])
    sent = []

    async def fake_status(self, peer="main"):
        return {"peer_state": next(states), "peer_ip": self._peer_ip(peer)}

    async def fake_send(self, payload):
        sent.append(payload)
        return {"ok": True}

    monkeypatch.setattr(BgpManager, "status", fake_status)
    monkeypatch.setattr(BgpManager, "_send", fake_send)

    asyncio.run(manager.check_reconciliation())  # baseline: down
    asyncio.run(manager.check_reconciliation())  # transição down -> up

    assert len(sent) == 1
    assert sent[0]["action"] == "announce"
    assert sent[0]["rule"]["dst_prefix"] == "177.86.16.10/32"


def test_does_not_reconcile_when_peer_stays_up(tmp_path, monkeypatch):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    _insert_rule(conn)
    manager = BgpManager(FakeDaemon(conn, bgp_cfg={
        "exabgp_socket": "/fake.sock", "peer_ip": "10.77.10.1",
        "rtbh_community": "2626:669", "nexthop_blackhole": "0.0.0.0",
    }))
    sent = []

    async def fake_status(self, peer="main"):
        return {"peer_state": "up", "peer_ip": self._peer_ip(peer)}

    async def fake_send(self, payload):
        sent.append(payload)
        return {"ok": True}

    monkeypatch.setattr(BgpManager, "status", fake_status)
    monkeypatch.setattr(BgpManager, "_send", fake_send)

    asyncio.run(manager.check_reconciliation())
    asyncio.run(manager.check_reconciliation())
    asyncio.run(manager.check_reconciliation())

    assert sent == []


def test_does_not_reconcile_when_peer_stays_down(tmp_path, monkeypatch):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    _insert_rule(conn)
    manager = BgpManager(FakeDaemon(conn, bgp_cfg={
        "exabgp_socket": "/fake.sock", "peer_ip": "10.77.10.1",
        "rtbh_community": "2626:669", "nexthop_blackhole": "0.0.0.0",
    }))
    sent = []

    async def fake_status(self, peer="main"):
        return {"peer_state": "down", "peer_ip": self._peer_ip(peer)}

    async def fake_send(self, payload):
        sent.append(payload)
        return {"ok": True}

    monkeypatch.setattr(BgpManager, "status", fake_status)
    monkeypatch.setattr(BgpManager, "_send", fake_send)

    asyncio.run(manager.check_reconciliation())
    asyncio.run(manager.check_reconciliation())

    assert sent == []


def test_reconciliation_skips_peer_with_no_active_rules(tmp_path, monkeypatch):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)  # sem regra nenhuma
    manager = BgpManager(FakeDaemon(conn, bgp_cfg={
        "exabgp_socket": "/fake.sock", "peer_ip": "10.77.10.1",
        "rtbh_community": "2626:669", "nexthop_blackhole": "0.0.0.0",
    }))
    states = iter(["down", "up"])
    sent = []

    async def fake_status(self, peer="main"):
        return {"peer_state": next(states), "peer_ip": self._peer_ip(peer)}

    async def fake_send(self, payload):
        sent.append(payload)
        return {"ok": True}

    monkeypatch.setattr(BgpManager, "status", fake_status)
    monkeypatch.setattr(BgpManager, "_send", fake_send)

    asyncio.run(manager.check_reconciliation())
    asyncio.run(manager.check_reconciliation())

    assert sent == []


def test_reconciliation_only_reannounces_rules_of_the_peer_that_reconnected(tmp_path, monkeypatch):
    """Com 2 peers configurados (main + pppoe), só as regras DAQUELE peer que
    reconectou devem ser re-anunciadas — a sessão do outro não foi afetada."""
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    _insert_rule(conn, peer="main", dst_prefix="177.86.16.10/32")
    _insert_rule(conn, peer="pppoe", action="discard", dst_prefix=None, src_prefix="100.64.1.1/32")
    manager = BgpManager(FakeDaemon(conn))  # main + pppoe configurados

    # main: down -> up (reconecta); pppoe: up -> up (nunca caiu)
    per_peer_sequences = {"main": iter(["down", "up"]), "pppoe": iter(["up", "up"])}
    sent = []

    async def fake_status(self, peer="main"):
        return {"peer_state": next(per_peer_sequences[peer]), "peer_ip": self._peer_ip(peer)}

    async def fake_send(self, payload):
        sent.append(payload)
        return {"ok": True}

    monkeypatch.setattr(BgpManager, "status", fake_status)
    monkeypatch.setattr(BgpManager, "_send", fake_send)

    asyncio.run(manager.check_reconciliation())
    asyncio.run(manager.check_reconciliation())

    assert len(sent) == 1
    assert sent[0]["rule"]["dst_prefix"] == "177.86.16.10/32"
    assert sent[0]["neighbor"] == "10.77.10.1"


def test_reconciliation_builds_rtbh_rule_with_community_and_nexthop(tmp_path, monkeypatch):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    _insert_rule(conn, action="rtbh", dst_prefix="177.86.16.55/32")
    manager = BgpManager(FakeDaemon(conn, bgp_cfg={
        "exabgp_socket": "/fake.sock", "peer_ip": "10.77.10.1",
        "rtbh_community": "2626:669", "nexthop_blackhole": "0.0.0.0",
    }))
    states = iter(["down", "up"])
    sent = []

    async def fake_status(self, peer="main"):
        return {"peer_state": next(states), "peer_ip": self._peer_ip(peer)}

    async def fake_send(self, payload):
        sent.append(payload)
        return {"ok": True}

    monkeypatch.setattr(BgpManager, "status", fake_status)
    monkeypatch.setattr(BgpManager, "_send", fake_send)

    asyncio.run(manager.check_reconciliation())
    asyncio.run(manager.check_reconciliation())

    assert sent[0]["kind"] == "rtbh"
    assert sent[0]["rule"] == {
        "dst_prefix": "177.86.16.55/32", "community": "2626:669", "nexthop": "0.0.0.0",
    }


def test_reconciliation_does_not_reannounce_expired_rules(tmp_path, monkeypatch):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    now = int(time.time())
    storage.insert_flowspec_rule(conn, {
        "created_at": now - 7200, "expires_at": now - 3600, "attack_id": None,
        "dst_prefix": "177.86.16.10/32", "src_prefix": None, "protocol": None,
        "dst_port": None, "src_port": None, "tcp_flags": None, "pkt_len": None,
        "action": "discard", "label": "expirada", "origin": "flowguard", "peer": "main",
    })
    storage.deactivate_flowspec_rule(conn, 1)  # expire_cycle já teria desativado
    manager = BgpManager(FakeDaemon(conn, bgp_cfg={
        "exabgp_socket": "/fake.sock", "peer_ip": "10.77.10.1",
        "rtbh_community": "2626:669", "nexthop_blackhole": "0.0.0.0",
    }))
    states = iter(["down", "up"])
    sent = []

    async def fake_status(self, peer="main"):
        return {"peer_state": next(states), "peer_ip": self._peer_ip(peer)}

    async def fake_send(self, payload):
        sent.append(payload)
        return {"ok": True}

    monkeypatch.setattr(BgpManager, "status", fake_status)
    monkeypatch.setattr(BgpManager, "_send", fake_send)

    asyncio.run(manager.check_reconciliation())
    asyncio.run(manager.check_reconciliation())

    assert sent == []


def test_reconciliation_logs_failure_but_does_not_raise(tmp_path, monkeypatch, caplog):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    _insert_rule(conn)
    manager = BgpManager(FakeDaemon(conn, bgp_cfg={
        "exabgp_socket": "/fake.sock", "peer_ip": "10.77.10.1",
        "rtbh_community": "2626:669", "nexthop_blackhole": "0.0.0.0",
    }))
    states = iter(["down", "up"])

    async def fake_status(self, peer="main"):
        return {"peer_state": next(states), "peer_ip": self._peer_ip(peer)}

    async def fake_send(self, payload):
        return {"ok": False, "error": "timeout ao falar com o speaker"}

    monkeypatch.setattr(BgpManager, "status", fake_status)
    monkeypatch.setattr(BgpManager, "_send", fake_send)

    asyncio.run(manager.check_reconciliation())
    asyncio.run(manager.check_reconciliation())  # não deve levantar exceção
