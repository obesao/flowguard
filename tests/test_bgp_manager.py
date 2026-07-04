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
    def __init__(self, conn, bgp_cfg=None):
        self.conn = conn
        self.config = {
            "bgp": bgp_cfg or {
                "exabgp_socket": "/fake.sock", "peer_ip": "10.77.10.1", "peer_ip_pppoe": "10.70.70.1",
            },
            "mitigation": {},
        }

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


def test_flowspec_add_targets_named_peer(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    manager = BgpManager(FakeDaemon(conn))
    calls = []

    async def fake_send(payload):
        calls.append(payload)
        return {"ok": True}

    manager._send = fake_send
    result = asyncio.run(manager.flowspec_add(
        {"src_prefix": "100.64.1.2/32", "action": "discard", "label": "cliente abusivo"}, peer="pppoe"))
    assert result["ok"]
    assert calls[0]["neighbor"] == "10.70.70.1"
    row = storage.get_flowspec_rule(conn, result["rule_id"])
    assert row["peer"] == "pppoe"


def test_flowspec_add_unconfigured_peer_errors_without_sending(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    manager = BgpManager(FakeDaemon(conn, bgp_cfg={"exabgp_socket": "/fake.sock", "peer_ip": "10.77.10.1"}))
    manager._send = None  # não deve nem ser chamado
    result = asyncio.run(manager.flowspec_add(
        {"src_prefix": "100.64.1.2/32", "action": "discard"}, peer="pppoe"))
    assert result == {"ok": False, "error": "peer BGP 'pppoe' não configurado (bgp.peer_ip_pppoe em config.yaml)"}


def test_flowspec_del_withdraws_from_the_peer_it_was_announced_to(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    manager = BgpManager(FakeDaemon(conn))
    calls = []

    async def fake_send(payload):
        calls.append(payload)
        return {"ok": True}

    manager._send = fake_send
    added = asyncio.run(manager.flowspec_add(
        {"src_prefix": "100.64.1.2/32", "action": "discard"}, peer="pppoe"))
    deleted = asyncio.run(manager.flowspec_del(added["rule_id"]))
    assert deleted["ok"]
    assert calls[-1]["neighbor"] == "10.70.70.1"


def _insert_flowspec_rule(conn, src_prefix=None, dst_prefix=None, action="discard", peer="main"):
    now = int(time.time())
    return storage.insert_flowspec_rule(conn, {
        "created_at": now, "expires_at": now + 3600, "attack_id": None,
        "dst_prefix": dst_prefix, "src_prefix": src_prefix, "protocol": None,
        "dst_port": None, "src_port": None, "tcp_flags": None, "pkt_len": None,
        "action": action, "label": "teste", "origin": "flowguard", "peer": peer,
    })


def test_verify_rule_unknown_id(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    manager = BgpManager(FakeDaemon(conn))
    result = asyncio.run(manager.verify_rule(999))
    assert result == {"ok": False, "error": "regra não encontrada"}


def test_verify_rule_pppoe_without_device_mapping_errors_without_probing(tmp_path, monkeypatch):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    rule_id = _insert_flowspec_rule(conn, src_prefix="100.64.1.2/32", peer="pppoe")
    manager = BgpManager(FakeDaemon(conn))  # bgp_cfg default não tem peer_device_pppoe

    called = []
    monkeypatch.setattr("routercfg.verify.verify_rule", lambda *a, **kw: called.append(1))

    result = asyncio.run(manager.verify_rule(rule_id))
    assert result["ok"] is False
    assert "peer_device_pppoe" in result["error"]
    assert not called


def test_verify_rule_success_main_peer_defaults_device_name(tmp_path, monkeypatch):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    rule_id = _insert_flowspec_rule(conn, src_prefix="1.2.3.4/32")  # peer='main' (default)
    manager = BgpManager(FakeDaemon(conn))

    async def fake_send(payload):
        return {"ok": True, "neighbors": {"10.77.10.1": {"state": "up"}}}
    manager._send = fake_send

    captured = {}

    def fake_verify_rule(rule, device_name, bgp_cfg):
        captured["device_name"] = device_name
        return {"match_status": "found", "command": "display ...", "raw_output": "...", "detail": "ok"}
    monkeypatch.setattr("routercfg.verify.verify_rule", fake_verify_rule)

    result = asyncio.run(manager.verify_rule(rule_id))
    assert result["ok"] is True
    assert result["peer"] == "main"
    assert result["device_name"] == "NE8000BGP"  # fallback, sem override em bgp.peer_device_main
    assert captured["device_name"] is None  # routercfg.apply._device_for(None) que aplica o default
    assert result["bgp_session"]["peer_state"] == "up"
    assert result["router_check"]["match_status"] == "found"
    assert result["rule"]["id"] == rule_id


def test_verify_rule_pppoe_with_device_mapping_passes_it_through(tmp_path, monkeypatch):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    rule_id = _insert_flowspec_rule(conn, src_prefix="100.64.1.2/32", peer="pppoe")
    bgp_cfg = {
        "exabgp_socket": "/fake.sock", "peer_ip": "10.77.10.1", "peer_ip_pppoe": "10.70.70.1",
        "peer_device_pppoe": "HUAWEI-PPPOE-222",
    }
    manager = BgpManager(FakeDaemon(conn, bgp_cfg=bgp_cfg))

    async def fake_send(payload):
        return {"ok": True, "neighbors": {"10.70.70.1": {"state": "down"}}}
    manager._send = fake_send

    captured = {}

    def fake_verify_rule(rule, device_name, bgp_cfg_arg):
        captured["device_name"] = device_name
        return {"match_status": "not_found", "command": "x", "raw_output": "y", "detail": "z"}
    monkeypatch.setattr("routercfg.verify.verify_rule", fake_verify_rule)

    result = asyncio.run(manager.verify_rule(rule_id))
    assert result["ok"] is True
    assert result["device_name"] == "HUAWEI-PPPOE-222"
    assert captured["device_name"] == "HUAWEI-PPPOE-222"
    assert result["bgp_session"]["peer_state"] == "down"


def test_verify_rule_works_on_inactive_rule(tmp_path, monkeypatch):
    # cenário que motiva a feature: regra já revertida/expirada localmente —
    # a verificação tem que rodar igual, é isso que descobre o mismatch.
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    rule_id = _insert_flowspec_rule(conn, src_prefix="1.2.3.4/32")
    storage.deactivate_flowspec_rule(conn, rule_id)
    manager = BgpManager(FakeDaemon(conn))

    async def fake_send(payload):
        return {"ok": True, "neighbors": {"10.77.10.1": {"state": "up"}}}
    manager._send = fake_send
    monkeypatch.setattr("routercfg.verify.verify_rule",
                         lambda rule, device_name, bgp_cfg: {"match_status": "found", "command": "x", "raw_output": "y", "detail": "z"})

    result = asyncio.run(manager.verify_rule(rule_id))
    assert result["ok"] is True
    assert result["rule"]["active"] == 0
    assert result["router_check"]["match_status"] == "found"  # banco diz inativa, roteador diz que ainda existe


def test_verify_rule_netmiko_auth_failure_becomes_match_error(tmp_path, monkeypatch):
    from netmiko.exceptions import NetmikoAuthenticationException

    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    rule_id = _insert_flowspec_rule(conn, src_prefix="1.2.3.4/32")
    manager = BgpManager(FakeDaemon(conn))

    async def fake_send(payload):
        return {"ok": True, "neighbors": {"10.77.10.1": {"state": "up"}}}
    manager._send = fake_send

    def raise_auth(rule, device_name, bgp_cfg):
        raise NetmikoAuthenticationException("usuário/senha incorretos")
    monkeypatch.setattr("routercfg.verify.verify_rule", raise_auth)

    result = asyncio.run(manager.verify_rule(rule_id))
    assert result["ok"] is True  # a sonda falhou, mas a resposta em si não quebra
    assert result["router_check"]["match_status"] == "error"
    assert "usuário/senha" in result["router_check"]["detail"]


def test_verify_rule_validation_error_becomes_match_error(tmp_path, monkeypatch):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    rule_id = _insert_flowspec_rule(conn, src_prefix=None, dst_prefix=None, action="rtbh")
    manager = BgpManager(FakeDaemon(conn))

    async def fake_send(payload):
        return {"ok": True, "neighbors": {"10.77.10.1": {"state": "up"}}}
    manager._send = fake_send

    from routercfg.templates import ValidationError

    def raise_validation(rule, device_name, bgp_cfg):
        raise ValidationError("prefixo inválido pra verificação: None")
    monkeypatch.setattr("routercfg.verify.verify_rule", raise_validation)

    result = asyncio.run(manager.verify_rule(rule_id))
    assert result["ok"] is True
    assert result["router_check"]["match_status"] == "error"


def test_ban_always_targets_main_peer_regardless_of_config(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    bgp_cfg = {
        "exabgp_socket": "/fake.sock", "peer_ip": "10.77.10.1", "peer_ip_pppoe": "10.70.70.1",
        "rtbh_community": "2626:669", "nexthop_blackhole": "10.77.10.2",
    }
    manager = BgpManager(FakeDaemon(conn, bgp_cfg=bgp_cfg))
    calls = []

    async def fake_send(payload):
        calls.append(payload)
        return {"ok": True}

    manager._send = fake_send
    result = asyncio.run(manager.ban("1.2.3.4"))
    assert result["ok"]
    assert calls[0]["neighbor"] == "10.77.10.1"
