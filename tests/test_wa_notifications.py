"""Testa o conteúdo dos alertas de WhatsApp (ataque aberto/fechado, mitigação
aplicada/revertida) — motivado pelo pedido do usuário de mostrar o host exato
atacado (não só o prefixo/bloco), horários de início/fim, e a ação de segurança
tomada (ex: RTBH/blackhole) com seus próprios horários de início/fim.

Instancia FlowGuardDaemon sem rodar __init__ (que abre sockets/filas) — só seta
os atributos que os métodos de notificação de fato usam (config, conn, ai,
run_read_db, _send_whatsapp), no mesmo espírito das FakeDaemon dos outros
testes de bgp_manager/auto_mitigation, mas testando os métodos REAIS da classe
em vez de mocká-los."""

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import flowguard
from ai.client import AIClient
from bgp.manager import BgpManager
from collector import storage


def _make_daemon(conn, alerts_overrides=None, mitigation_profiles=None):
    daemon = object.__new__(flowguard.FlowGuardDaemon)
    daemon.conn = conn
    daemon.config = {
        "alerts": {"whatsapp": True, "min_severity_wa": "high", **(alerts_overrides or {})},
        "ai": {"enabled": False},
        "mitigation_profiles": mitigation_profiles or {},
    }
    daemon.ai = AIClient({})
    daemon.wa_messages = []

    async def _send_whatsapp(message):
        daemon.wa_messages.append(message)

    async def run_read_db(func, *args, **kwargs):
        return func(conn, *args, **kwargs)

    daemon._send_whatsapp = _send_whatsapp
    daemon.run_read_db = run_read_db
    return daemon


def _insert_flow_agg(conn, dst_prefix, ts, top_dst_ips):
    storage.insert_flow_aggs_batch(conn, [{
        "ts": ts, "dst_prefix": dst_prefix, "protocol": 6, "dst_port": 0,
        "bps": 900_000_000, "pps": 200_000, "flow_count": 10, "avg_pkt_size": 500,
        "top_src_ips": [], "src_countries": {}, "direction": "in", "top_dst_ips": top_dst_ips,
    }])


def _insert_attack(conn, dst_prefix="177.86.18.0/24", attack_type="ddos_volumetrico",
                    severity="critical", ts_start=None, target_host=None):
    ts_start = ts_start or int(time.time())
    ids = storage.apply_attack_changes(conn, [{
        "ts_start": ts_start, "dst_prefix": dst_prefix, "customer": "Cliente X",
        "attack_type": attack_type, "severity": severity, "bps_peak": 1, "pps_peak": 1,
    }], [], [])
    attack_id = ids[0]
    if target_host:
        conn.execute("UPDATE attacks SET target_host = ? WHERE id = ?", (target_host, attack_id))
        conn.commit()
    return attack_id


# --- notify_attack (abertura) --------------------------------------------

def test_notify_attack_includes_target_host_and_start_time(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = _make_daemon(conn)
    now = int(time.time())
    _insert_flow_agg(conn, "177.86.18.0/24", now, ["177.86.18.55", "177.86.18.9"])

    asyncio.run(daemon.notify_attack(
        1, "177.86.18.0/24", "ddos_volumetrico", "critical", 900_000_000, 200_000,
        {"customer": "Cliente X"}, now,
    ))

    assert len(daemon.wa_messages) == 1
    msg = daemon.wa_messages[0]
    assert "177.86.18.55" in msg
    assert "177.86.18.0/24" in msg
    assert "Início:" in msg
    assert "Cliente X" in msg


def test_notify_attack_without_flow_data_falls_back_to_prefix_only(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = _make_daemon(conn)
    now = int(time.time())

    asyncio.run(daemon.notify_attack(
        1, "177.86.18.0/24", "ddos_volumetrico", "critical", 900_000_000, 200_000, {}, now,
    ))

    assert len(daemon.wa_messages) == 1
    assert "não identificado ainda" in daemon.wa_messages[0]


def test_notify_attack_respects_min_severity_wa(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = _make_daemon(conn)
    now = int(time.time())

    asyncio.run(daemon.notify_attack(
        1, "177.86.18.0/24", "anomalia_baseline", "medium", 1, 1, {}, now,
    ))

    assert daemon.wa_messages == []


# --- notify_attack_closed (encerramento) ----------------------------------

def test_notify_attack_closed_includes_host_and_duration(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = _make_daemon(conn)
    ts_start = 1000
    ts_end = 1000 + 3725  # 1h02min05s

    asyncio.run(daemon.notify_attack_closed(
        1, "177.86.18.0/24", "ddos_volumetrico", "critical", 900_000_000,
        ts_start, ts_end, "177.86.18.55",
    ))

    assert len(daemon.wa_messages) == 1
    msg = daemon.wa_messages[0]
    assert "177.86.18.55" in msg
    assert "Início:" in msg and "Fim:" in msg
    assert "1h02min" in msg


def test_notify_attack_closed_without_target_host_shows_only_prefix(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = _make_daemon(conn)

    asyncio.run(daemon.notify_attack_closed(
        1, "177.86.18.0/24", "ddos_volumetrico", "critical", 1, 1000, 1030, None,
    ))

    assert "Host: prefixo 177.86.18.0/24" in daemon.wa_messages[0]


# --- notify_mitigation_applied / notify_mitigation_reverted ---------------

def test_notify_mitigation_applied_uses_attack_severity_and_action_label(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = _make_daemon(conn)
    attack_id = _insert_attack(conn, severity="critical", target_host="177.86.18.55")

    asyncio.run(daemon.notify_mitigation_applied(
        10, attack_id, "177.86.18.0/24", "rtbh", "auto", 3600,
    ))

    assert len(daemon.wa_messages) == 1
    msg = daemon.wa_messages[0]
    assert "177.86.18.55" in msg
    assert "Blackhole (RTBH)" in msg
    assert "automática" in msg
    assert "1h" in msg


def test_notify_mitigation_applied_computes_host_live_when_attack_still_open(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = _make_daemon(conn)
    now = int(time.time())
    attack_id = _insert_attack(conn, ts_start=now, target_host=None)
    _insert_flow_agg(conn, "177.86.18.0/24", now, ["177.86.18.55"])

    asyncio.run(daemon.notify_mitigation_applied(
        10, attack_id, "177.86.18.0/24", "discard", "auto", 1800,
    ))

    assert "177.86.18.55" in daemon.wa_messages[0]


def test_notify_mitigation_applied_gated_by_attack_severity(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = _make_daemon(conn)
    attack_id = _insert_attack(conn, severity="medium")

    asyncio.run(daemon.notify_mitigation_applied(
        10, attack_id, "177.86.18.0/24", "rtbh", "auto", 3600,
    ))

    assert daemon.wa_messages == []


def test_notify_mitigation_applied_without_attack_id_always_fires(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = _make_daemon(conn)

    asyncio.run(daemon.notify_mitigation_applied(
        10, None, "9.9.9.9/32", "rtbh", "manual", None,
    ))

    assert len(daemon.wa_messages) == 1
    assert "9.9.9.9/32" in daemon.wa_messages[0]
    assert "manual" in daemon.wa_messages[0]


def test_notify_mitigation_reverted_includes_duration_and_reason(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = _make_daemon(conn)
    attack_id = _insert_attack(conn, severity="critical", target_host="177.86.18.55")
    applied_at = int(time.time()) - 3600

    asyncio.run(daemon.notify_mitigation_reverted(
        10, attack_id, "177.86.18.0/24", "rtbh", "TTL expirado", applied_at,
    ))

    msg = daemon.wa_messages[0]
    assert "177.86.18.55" in msg
    assert "TTL expirado" in msg
    assert "Duração da mitigação: 1h" in msg


def test_notify_mitigation_reverted_gated_by_attack_severity(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = _make_daemon(conn)
    attack_id = _insert_attack(conn, severity="medium")

    asyncio.run(daemon.notify_mitigation_reverted(
        10, attack_id, "177.86.18.0/24", "rtbh", "revertida manualmente", int(time.time()),
    ))

    assert daemon.wa_messages == []


def test_notify_mitigation_disabled_when_whatsapp_off(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = _make_daemon(conn, alerts_overrides={"whatsapp": False})

    asyncio.run(daemon.notify_mitigation_applied(10, None, "9.9.9.9/32", "rtbh", "manual", None))

    assert daemon.wa_messages == []


# --- wiring: BgpManager dispara as notificações certas nos pontos certos --

class RecordingFakeDaemon:
    """Mesmo padrão de EngineFakeDaemon (test_auto_mitigation.py): fire_and_forget
    só enfileira, quem chama decide quando (e se) drenar — permite checar tanto
    que o disparo aconteceu quanto os argumentos exatos, sem depender de timing
    de scheduler real."""

    def __init__(self, conn, config=None):
        self.conn = conn
        self.config = config or {
            "bgp": {"exabgp_socket": "/fake.sock", "peer_ip": "10.77.10.1",
                     "rtbh_community": "262620:666", "nexthop_blackhole": "0.0.0.0"},
            "mitigation": {},
        }
        self.fired = []
        self.applied_calls = []
        self.reverted_calls = []

    async def run_db(self, func, *args, **kwargs):
        return func(*args, **kwargs)

    async def run_read_db(self, func, *args, **kwargs):
        return func(self.conn, *args, **kwargs)

    def fire_and_forget(self, coro, what):
        self.fired.append((what, coro))

    async def drain(self):
        fired, self.fired = self.fired, []
        for _what, coro in fired:
            await coro

    async def notify_mitigation_applied(self, rule_id, attack_id, dst_prefix, action, trigger_type, ttl_s):
        self.applied_calls.append((rule_id, attack_id, dst_prefix, action, trigger_type, ttl_s))

    async def notify_mitigation_reverted(self, rule_id, attack_id, dst_prefix, action, reason, applied_at):
        self.reverted_calls.append((rule_id, attack_id, dst_prefix, action, reason, applied_at))


async def _drain(daemon):
    await daemon.drain()


def test_ban_fires_mitigation_applied_with_rtbh_action(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = RecordingFakeDaemon(conn)
    manager = BgpManager(daemon)

    async def fake_send(payload):
        return {"ok": True}
    manager._send = fake_send

    async def scenario():
        await manager.ban("177.86.18.55/32", attack_id=42, trigger_type="auto")
        await _drain(daemon)
    asyncio.run(scenario())

    assert len(daemon.applied_calls) == 1
    rule_id, attack_id, dst_prefix, action, trigger_type, ttl_s = daemon.applied_calls[0]
    assert attack_id == 42
    assert dst_prefix == "177.86.18.55/32"
    assert action == "rtbh"
    assert trigger_type == "auto"


def test_flowspec_add_fires_mitigation_applied_with_discard_action(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = RecordingFakeDaemon(conn)
    manager = BgpManager(daemon)

    async def fake_send(payload):
        return {"ok": True}
    manager._send = fake_send

    rule = {"dst_prefix": "177.86.18.0/24", "action": "discard", "protocol": "udp", "src_port": "53"}

    async def scenario():
        await manager.flowspec_add(rule, attack_id=7, trigger_type="manual")
        await _drain(daemon)
    asyncio.run(scenario())

    assert len(daemon.applied_calls) == 1
    _rule_id, attack_id, dst_prefix, action, trigger_type, _ttl = daemon.applied_calls[0]
    assert (attack_id, dst_prefix, action, trigger_type) == (7, "177.86.18.0/24", "discard", "manual")


def test_unban_fires_mitigation_reverted_with_created_at(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = RecordingFakeDaemon(conn)
    manager = BgpManager(daemon)

    async def fake_send(payload):
        return {"ok": True}
    manager._send = fake_send

    async def scenario():
        ban_resp = await manager.ban("177.86.18.55/32", attack_id=42)
        await _drain(daemon)
        daemon.applied_calls.clear()
        await manager.unban("177.86.18.55/32")
        await _drain(daemon)
        return ban_resp
    asyncio.run(scenario())

    assert len(daemon.reverted_calls) == 1
    rule_id, attack_id, dst_prefix, action, reason, applied_at = daemon.reverted_calls[0]
    assert attack_id == 42
    assert action == "rtbh"
    assert reason == "revertida manualmente"
    assert applied_at is not None


def test_flowspec_del_fires_mitigation_reverted(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = RecordingFakeDaemon(conn)
    manager = BgpManager(daemon)

    async def fake_send(payload):
        return {"ok": True}
    manager._send = fake_send

    rule = {"dst_prefix": "177.86.18.0/24", "action": "discard", "protocol": "udp", "src_port": "53"}

    async def scenario():
        resp = await manager.flowspec_add(rule, attack_id=7)
        await _drain(daemon)
        daemon.applied_calls.clear()
        await manager.flowspec_del(resp["rule_id"])
        await _drain(daemon)
    asyncio.run(scenario())

    assert len(daemon.reverted_calls) == 1
    _rule_id, attack_id, dst_prefix, action, reason, _applied_at = daemon.reverted_calls[0]
    assert (attack_id, dst_prefix, action, reason) == (7, "177.86.18.0/24", "discard", "revertida manualmente")


def test_expire_cycle_fires_mitigation_reverted_with_ttl_expired_reason(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = RecordingFakeDaemon(conn)
    manager = BgpManager(daemon)

    async def fake_send(payload):
        return {"ok": True}
    manager._send = fake_send

    async def scenario():
        await manager.ban("177.86.18.55/32", attack_id=42, ttl_s=-10)  # já nasce expirado
        await _drain(daemon)
        daemon.applied_calls.clear()
        await manager.expire_cycle()
        await _drain(daemon)
    asyncio.run(scenario())

    assert len(daemon.reverted_calls) == 1
    _rule_id, attack_id, _dst_prefix, action, reason, _applied_at = daemon.reverted_calls[0]
    assert (attack_id, action, reason) == (42, "rtbh", "TTL expirado")
