"""Testa BgpManager.withdraw_all — usado no shutdown gracioso e pelo comando
flowspec_del_all (botão "Apagar todas as regras" do portal). Mocka _send (nunca
fala com o ExaBGP de verdade), usa storage real (sqlite em arquivo temporário)."""

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bgp.manager import BgpManager
from collector import storage


class FakeDaemon:
    def __init__(self, conn):
        self.conn = conn
        self.config = {"bgp": {"exabgp_socket": "/fake.sock"}, "mitigation": {}}

    async def run_db(self, func, *args, **kwargs):
        return func(*args, **kwargs)

    async def run_read_db(self, func, *args, **kwargs):
        return func(self.conn, *args, **kwargs)


def _insert_rule(conn, src_prefix, action="discard"):
    now = int(time.time())
    return storage.insert_flowspec_rule(conn, {
        "created_at": now, "expires_at": now + 3600, "attack_id": None,
        "dst_prefix": None, "src_prefix": src_prefix, "protocol": None,
        "dst_port": None, "src_port": None, "tcp_flags": None, "pkt_len": None,
        "action": action, "label": "teste", "origin": "flowguard",
    })


def test_withdraw_all_deactivates_only_confirmed_rules(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    id_ok = _insert_rule(conn, "1.2.3.4/32")
    id_fail = _insert_rule(conn, "5.6.7.8/32")
    manager = BgpManager(FakeDaemon(conn))

    async def fake_send(payload):
        if payload["rule"]["src_prefix"] == "5.6.7.8/32":
            return {"ok": False, "error": "timeout"}
        return {"ok": True}

    manager._send = fake_send
    result = asyncio.run(manager.withdraw_all())

    assert result == {"ok": False, "removed": 1, "failed": 1}
    assert storage.get_flowspec_rule(conn, id_ok)["active"] == 0
    # não confirmado -> continua marcada ativa localmente, não perde o rastro
    # de uma regra que pode continuar anunciada de verdade no roteador
    assert storage.get_flowspec_rule(conn, id_fail)["active"] == 1


def test_withdraw_all_no_active_rules(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    manager = BgpManager(FakeDaemon(conn))
    manager._send = None  # não deve nem ser chamado
    result = asyncio.run(manager.withdraw_all())
    assert result == {"ok": True, "removed": 0, "failed": 0}


def test_withdraw_all_handles_rtbh_kind(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    _insert_rule(conn, None, action="rtbh")
    manager = BgpManager(FakeDaemon(conn))
    calls = []

    async def fake_send(payload):
        calls.append(payload)
        return {"ok": True}

    manager._send = fake_send
    result = asyncio.run(manager.withdraw_all())
    assert result == {"ok": True, "removed": 1, "failed": 0}
    assert calls[0]["kind"] == "rtbh"
