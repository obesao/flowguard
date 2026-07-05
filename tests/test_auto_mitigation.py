"""Testa a opção de mitigação automática: configio (validação/roundtrip do campo
auto_mode), BgpManager.auto_mitigate/mark_attack_mitigated, e o ponto de disparo
na engine de detecção (só na abertura do ataque, nunca em atualização)."""

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from analyzer.engine import DetectionEngine
from bgp.manager import BgpManager
from collector import configio, storage


class FakeDaemon:
    def __init__(self, conn, config=None):
        self.conn = conn
        self.config = config or {
            "bgp": {"exabgp_socket": "/fake.sock", "peer_ip": "10.77.10.1",
                     "rtbh_community": "262620:666", "nexthop_blackhole": "0.0.0.0"},
            "mitigation": {},
            "mitigation_profiles": configio.DEFAULT_MITIGATION_PROFILES,
        }

    async def run_db(self, func, *args, **kwargs):
        return func(*args, **kwargs)

    async def run_read_db(self, func, *args, **kwargs):
        return func(self.conn, *args, **kwargs)

    def fire_and_forget(self, coro, what):
        # testes deste nível checam retorno/estado no banco, não o conteúdo dos
        # alertas — fecha a corrotina sem executá-la pra não vazar warning de
        # "coroutine never awaited"
        coro.close()

    async def notify_mitigation_applied(self, *args, **kwargs):
        return None

    async def notify_mitigation_reverted(self, *args, **kwargs):
        return None


def _insert_attack(conn, dst_prefix="177.86.16.0/24", attack_type="ddos_volumetrico", target_host="177.86.16.5"):
    now = int(time.time())
    ids = storage.apply_attack_changes(conn, [{
        "ts_start": now, "dst_prefix": dst_prefix, "customer": "teste",
        "attack_type": attack_type, "severity": "critical", "bps_peak": 1, "pps_peak": 1,
    }], [], [])
    attack_id = ids[0]
    if target_host:
        # ban() agora sempre resolve RTBH pro host /32 (ver bgp/manager.py) — a maioria
        # dos testes precisa de um target_host já pronto pra não depender de flow_aggs
        conn.execute("UPDATE attacks SET target_host = ? WHERE id = ?", (target_host, attack_id))
        conn.commit()
    return attack_id


# --- configio: auto_mode ------------------------------------------------

def test_default_mitigation_profiles_have_auto_mode_off():
    for attack_type, profile in configio.DEFAULT_MITIGATION_PROFILES.items():
        assert profile["auto_mode"] == "off", attack_type


def test_validate_mitigation_changes_rejects_invalid_auto_mode():
    with pytest.raises(ValueError, match="auto_mode inválido"):
        configio._validate_mitigation_changes({"dns_amp": {"auto_mode": "nuke"}})


def test_save_and_load_mitigation_profiles_roundtrip_auto_mode(tmp_path):
    path = str(tmp_path / "mitigation_profiles.yaml")
    updated = configio.save_mitigation_profiles(path, {"dns_amp": {"auto_mode": "suggestion"}})
    assert updated["dns_amp"]["auto_mode"] == "suggestion"
    # outros tipos continuam com o default
    assert updated["ntp_amp"]["auto_mode"] == "off"
    reloaded = configio.load_mitigation_profiles(path)
    assert reloaded["dns_amp"]["auto_mode"] == "suggestion"


# --- configio: rtbh_default_ttl_s (chave global, não por tipo de ataque) --

def test_load_mitigation_profiles_defaults_rtbh_ttl(tmp_path):
    reloaded = configio.load_mitigation_profiles(str(tmp_path / "nao-existe.yaml"))
    assert reloaded[configio.RTBH_TTL_KEY] == configio.DEFAULT_RTBH_TTL_S


def test_save_and_load_rtbh_ttl_roundtrip(tmp_path):
    path = str(tmp_path / "mitigation_profiles.yaml")
    updated = configio.save_mitigation_profiles(path, {configio.RTBH_TTL_KEY: 600})
    assert updated[configio.RTBH_TTL_KEY] == 600
    # tipos de ataque não são afetados
    assert updated["dns_amp"]["kind"] == "discard"
    reloaded = configio.load_mitigation_profiles(path)
    assert reloaded[configio.RTBH_TTL_KEY] == 600


def test_validate_mitigation_changes_rejects_non_positive_rtbh_ttl():
    with pytest.raises(ValueError, match="rtbh_default_ttl_s"):
        configio._validate_mitigation_changes({configio.RTBH_TTL_KEY: 0})


def test_validate_mitigation_changes_rejects_non_numeric_rtbh_ttl():
    with pytest.raises(ValueError, match="rtbh_default_ttl_s"):
        configio._validate_mitigation_changes({configio.RTBH_TTL_KEY: "dez minutos"})


def test_ban_uses_configured_rtbh_default_ttl(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    config = {
        "bgp": {"exabgp_socket": "/fake.sock", "peer_ip": "10.77.10.1",
                 "rtbh_community": "262620:666", "nexthop_blackhole": "0.0.0.0"},
        "mitigation": {},
        "mitigation_profiles": {**configio.DEFAULT_MITIGATION_PROFILES, configio.RTBH_TTL_KEY: 600},
    }
    manager = BgpManager(FakeDaemon(conn, config))

    async def fake_send(payload):
        return {"ok": True}
    manager._send = fake_send

    before = int(time.time())
    result = asyncio.run(manager.ban("177.86.16.5/32"))
    row = storage.get_flowspec_rule(conn, result["rule_id"])
    assert 595 <= row["expires_at"] - before <= 605  # ~600s, não os 3600s do default antigo


def test_ban_explicit_ttl_overrides_configured_default(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    config = {
        "bgp": {"exabgp_socket": "/fake.sock", "peer_ip": "10.77.10.1",
                 "rtbh_community": "262620:666", "nexthop_blackhole": "0.0.0.0"},
        "mitigation": {},
        "mitigation_profiles": {**configio.DEFAULT_MITIGATION_PROFILES, configio.RTBH_TTL_KEY: 600},
    }
    manager = BgpManager(FakeDaemon(conn, config))

    async def fake_send(payload):
        return {"ok": True}
    manager._send = fake_send

    before = int(time.time())
    result = asyncio.run(manager.ban("177.86.16.5/32", ttl_s=120))
    row = storage.get_flowspec_rule(conn, result["rule_id"])
    assert 115 <= row["expires_at"] - before <= 125  # respeita o override pontual, não os 600s do default


# --- BgpManager: mark_attack_mitigated + auto_mitigate ------------------

def test_ban_with_attack_id_marks_attack_mitigated(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    attack_id = _insert_attack(conn)
    manager = BgpManager(FakeDaemon(conn))

    async def fake_send(payload):
        return {"ok": True}
    manager._send = fake_send

    asyncio.run(manager.ban("177.86.16.0/24", attack_id=attack_id))
    assert storage.get_attack(conn, attack_id)["mitigated"] == 1


def test_ban_without_attack_id_does_not_touch_mitigated(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    attack_id = _insert_attack(conn)
    manager = BgpManager(FakeDaemon(conn))

    async def fake_send(payload):
        return {"ok": True}
    manager._send = fake_send

    asyncio.run(manager.ban("177.86.17.5/32"))  # sem attack_id
    assert storage.get_attack(conn, attack_id)["mitigated"] == 0


def test_ban_failure_does_not_mark_mitigated(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    attack_id = _insert_attack(conn)
    manager = BgpManager(FakeDaemon(conn))

    async def fake_send(payload):
        return {"ok": False, "error": "timeout"}
    manager._send = fake_send

    asyncio.run(manager.ban("177.86.16.0/24", attack_id=attack_id))
    assert storage.get_attack(conn, attack_id)["mitigated"] == 0


# --- RTBH sempre por host /32 -------------------------------------------
# Achado real em produção: o roteador (NE8000BGP) só aceita RTBH anunciado
# como host /32 (route-policy flowguard-import-v4 filtra por ip-prefix
# "ge 32 le 32", desenho herdado de FastNetMon) — anunciar o prefixo inteiro
# do cliente é rejeitado SILENCIOSAMENTE ("Received total routes: 0" no
# peer), então o RTBH nunca protegia nada de verdade apesar do sistema achar
# que tinha aplicado. ban() agora sempre resolve pro host /32 mais atacado
# antes de anunciar.

def _insert_flow_agg(conn, dst_prefix, ts, top_dst_ips):
    storage.insert_flow_aggs_batch(conn, [{
        "ts": ts, "dst_prefix": dst_prefix, "protocol": 6, "dst_port": 0,
        "bps": 900_000_000, "pps": 200_000, "flow_count": 10, "avg_pkt_size": 500,
        "top_src_ips": [], "src_countries": {}, "direction": "in", "top_dst_ips": top_dst_ips,
    }])


def test_ban_with_attack_id_announces_target_host_not_whole_prefix(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    attack_id = _insert_attack(conn, target_host="177.86.16.42")
    manager = BgpManager(FakeDaemon(conn))
    calls = []

    async def fake_send(payload):
        calls.append(payload)
        return {"ok": True}
    manager._send = fake_send

    result = asyncio.run(manager.ban("177.86.16.0/24", attack_id=attack_id))
    assert result["ok"]
    assert calls[0]["rule"]["dst_prefix"] == "177.86.16.42/32"
    row = storage.get_flowspec_rule(conn, result["rule_id"])
    assert row["dst_prefix"] == "177.86.16.42/32"


def test_ban_computes_host_live_when_target_host_not_yet_persisted(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    now = int(time.time())
    attack_id = _insert_attack(conn, target_host=None)
    conn.execute("UPDATE attacks SET ts_start = ? WHERE id = ?", (now, attack_id))
    conn.commit()
    _insert_flow_agg(conn, "177.86.16.0/24", now, ["177.86.16.77"])
    manager = BgpManager(FakeDaemon(conn))

    async def fake_send(payload):
        return {"ok": True}
    manager._send = fake_send

    result = asyncio.run(manager.ban("177.86.16.0/24", attack_id=attack_id))
    assert result["ok"]
    row = storage.get_flowspec_rule(conn, result["rule_id"])
    assert row["dst_prefix"] == "177.86.16.77/32"


def test_ban_without_attack_id_falls_back_to_recent_top_host(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    now = int(time.time())
    _insert_flow_agg(conn, "177.86.16.0/24", now, ["177.86.16.99"])
    manager = BgpManager(FakeDaemon(conn))

    async def fake_send(payload):
        return {"ok": True}
    manager._send = fake_send

    result = asyncio.run(manager.ban("177.86.16.0/24"))
    assert result["ok"]
    row = storage.get_flowspec_rule(conn, result["rule_id"])
    assert row["dst_prefix"] == "177.86.16.99/32"


def test_ban_without_resolvable_host_fails_clearly_instead_of_silently_blackholing_prefix(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    manager = BgpManager(FakeDaemon(conn))
    calls = []

    async def fake_send(payload):
        calls.append(payload)
        return {"ok": True}
    manager._send = fake_send

    result = asyncio.run(manager.ban("177.86.16.0/24"))
    assert result["ok"] is False
    assert "/32" in result["error"]
    assert calls == []  # nunca chegou a anunciar nada pro roteador


def test_ban_with_explicit_host32_target_skips_resolution(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    manager = BgpManager(FakeDaemon(conn))
    calls = []

    async def fake_send(payload):
        calls.append(payload)
        return {"ok": True}
    manager._send = fake_send

    result = asyncio.run(manager.ban("177.86.16.42/32"))
    assert result["ok"]
    assert calls[0]["rule"]["dst_prefix"] == "177.86.16.42/32"


def test_unban_with_customer_prefix_finds_and_removes_the_resolved_host_rule(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    attack_id = _insert_attack(conn, target_host="177.86.16.42")
    manager = BgpManager(FakeDaemon(conn))

    async def fake_send(payload):
        return {"ok": True}
    manager._send = fake_send

    ban_result = asyncio.run(manager.ban("177.86.16.0/24", attack_id=attack_id))
    unban_result = asyncio.run(manager.unban("177.86.16.0/24"))  # prefixo do cliente, não o host

    assert unban_result == {"ok": True, "removed": 1}
    assert storage.get_flowspec_rule(conn, ban_result["rule_id"])["active"] == 0


def test_unban_with_no_active_rule_in_prefix_fails_clearly(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    manager = BgpManager(FakeDaemon(conn))

    async def fake_send(payload):
        return {"ok": True}
    manager._send = fake_send

    result = asyncio.run(manager.unban("177.86.16.0/24"))
    assert result == {"ok": False, "error": "nenhuma regra RTBH ativa encontrada em 177.86.16.0/24"}


def test_flowspec_add_with_attack_id_marks_attack_mitigated(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    attack_id = _insert_attack(conn, attack_type="dns_amp")
    manager = BgpManager(FakeDaemon(conn))

    async def fake_send(payload):
        return {"ok": True}
    manager._send = fake_send

    asyncio.run(manager.flowspec_add(
        {"dst_prefix": "177.86.16.0/24", "action": "discard"}, attack_id=attack_id))
    assert storage.get_attack(conn, attack_id)["mitigated"] == 1


# --- trigger_type: manual (padrão) vs auto — pedido do usuário pra sinalizar
# na aba Regras se uma regra foi disparada manualmente ou pela engine ----------

def test_ban_defaults_to_manual_trigger_type(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    manager = BgpManager(FakeDaemon(conn))

    async def fake_send(payload):
        return {"ok": True}
    manager._send = fake_send

    result = asyncio.run(manager.ban("177.86.16.5/32"))
    row = storage.get_flowspec_rule(conn, result["rule_id"])
    assert row["trigger_type"] == "manual"


def test_ban_accepts_explicit_trigger_type(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    manager = BgpManager(FakeDaemon(conn))

    async def fake_send(payload):
        return {"ok": True}
    manager._send = fake_send

    result = asyncio.run(manager.ban("177.86.16.5/32", trigger_type="auto"))
    row = storage.get_flowspec_rule(conn, result["rule_id"])
    assert row["trigger_type"] == "auto"


def test_flowspec_add_defaults_to_manual_trigger_type(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    manager = BgpManager(FakeDaemon(conn))

    async def fake_send(payload):
        return {"ok": True}
    manager._send = fake_send

    result = asyncio.run(manager.flowspec_add({"dst_prefix": "177.86.16.0/24", "action": "discard"}))
    row = storage.get_flowspec_rule(conn, result["rule_id"])
    assert row["trigger_type"] == "manual"


def test_auto_mitigate_rtbh_mode_marks_trigger_type_auto(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    attack_id = _insert_attack(conn, attack_type="dns_amp")
    manager = BgpManager(FakeDaemon(conn))

    async def fake_send(payload):
        return {"ok": True}
    manager._send = fake_send

    result = asyncio.run(manager.auto_mitigate(attack_id, "dns_amp", "177.86.16.0/24", "rtbh"))
    row = storage.get_flowspec_rule(conn, result["rule_id"])
    assert row["trigger_type"] == "auto"


def test_auto_mitigate_suggestion_mode_marks_trigger_type_auto(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    attack_id = _insert_attack(conn, attack_type="dns_amp")  # perfil default é 'discard'
    manager = BgpManager(FakeDaemon(conn))

    async def fake_send(payload):
        return {"ok": True}
    manager._send = fake_send

    result = asyncio.run(manager.auto_mitigate(attack_id, "dns_amp", "177.86.16.0/24", "suggestion"))
    row = storage.get_flowspec_rule(conn, result["rule_id"])
    assert row["trigger_type"] == "auto"


# --- storage.get_latest_flowspec_rule_for_attack (mesmo padrão do ClientGuard,
# ver storage.get_latest_edge_mitigation lá) — usado pra sinalizar na aba
# Ataques do portal se aquele ataque já tem regra de mitigação e se está em
# vigor agora ----------------------------------------------------------------

def test_get_latest_flowspec_rule_for_attack_returns_none_when_never_mitigated(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    attack_id = _insert_attack(conn)
    assert storage.get_latest_flowspec_rule_for_attack(conn, attack_id) is None


def test_get_latest_flowspec_rule_for_attack_returns_active_rule(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    attack_id = _insert_attack(conn)
    manager = BgpManager(FakeDaemon(conn))

    async def fake_send(payload):
        return {"ok": True}
    manager._send = fake_send

    asyncio.run(manager.ban("177.86.16.0/24", attack_id=attack_id))
    mitigation = storage.get_latest_flowspec_rule_for_attack(conn, attack_id)
    assert mitigation["action"] == "rtbh"
    assert mitigation["active"] == 1


def test_get_latest_flowspec_rule_for_attack_returns_most_recent(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    attack_id = _insert_attack(conn)
    manager = BgpManager(FakeDaemon(conn))

    async def fake_send(payload):
        return {"ok": True}
    manager._send = fake_send

    first = asyncio.run(manager.ban("177.86.16.0/24", attack_id=attack_id))
    asyncio.run(manager.unban("177.86.16.0/24"))  # encerra a primeira
    second = asyncio.run(manager.ban("177.86.16.0/24", attack_id=attack_id))

    mitigation = storage.get_latest_flowspec_rule_for_attack(conn, attack_id)
    assert mitigation["id"] == second["rule_id"]
    assert mitigation["id"] != first["rule_id"]
    assert mitigation["active"] == 1


def test_get_latest_flowspec_rule_for_attack_scoped_by_attack_id(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    attack_id_a = _insert_attack(conn, dst_prefix="177.86.16.0/24")
    attack_id_b = _insert_attack(conn, dst_prefix="177.86.17.0/24")
    manager = BgpManager(FakeDaemon(conn))

    async def fake_send(payload):
        return {"ok": True}
    manager._send = fake_send

    asyncio.run(manager.ban("177.86.16.0/24", attack_id=attack_id_a))
    assert storage.get_latest_flowspec_rule_for_attack(conn, attack_id_b) is None
    assert storage.get_latest_flowspec_rule_for_attack(conn, attack_id_a) is not None


def test_auto_mitigate_rtbh_mode_calls_ban_ignoring_profile_kind(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    attack_id = _insert_attack(conn, attack_type="dns_amp")  # perfil default é 'discard'
    manager = BgpManager(FakeDaemon(conn))
    calls = []

    async def fake_send(payload):
        calls.append(payload)
        return {"ok": True}
    manager._send = fake_send

    result = asyncio.run(manager.auto_mitigate(attack_id, "dns_amp", "177.86.16.0/24", "rtbh"))
    assert result["ok"]
    assert calls[0]["kind"] == "rtbh"  # RTBH direto, não olhou o kind=discard do perfil


def test_auto_mitigate_suggestion_mode_uses_profile_kind(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    attack_id = _insert_attack(conn, attack_type="dns_amp")  # perfil default é 'discard'
    manager = BgpManager(FakeDaemon(conn))
    calls = []

    async def fake_send(payload):
        calls.append(payload)
        return {"ok": True}
    manager._send = fake_send

    result = asyncio.run(manager.auto_mitigate(attack_id, "dns_amp", "177.86.16.0/24", "suggestion"))
    assert result["ok"]
    assert calls[0]["kind"] == "flowspec"  # discard = flowspec, não rtbh


def test_auto_mitigate_suggestion_mode_still_uses_rtbh_when_profile_says_rtbh(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    attack_id = _insert_attack(conn, attack_type="ddos_volumetrico")  # perfil default é 'rtbh'
    manager = BgpManager(FakeDaemon(conn))
    calls = []

    async def fake_send(payload):
        calls.append(payload)
        return {"ok": True}
    manager._send = fake_send

    result = asyncio.run(manager.auto_mitigate(attack_id, "ddos_volumetrico", "177.86.16.0/24", "suggestion"))
    assert result["ok"]
    assert calls[0]["kind"] == "rtbh"


# --- engine: só dispara na abertura, e só com as duas travas ligadas ----

class FakeBgpManager:
    def __init__(self):
        self.calls = []

    async def auto_mitigate(self, attack_id, attack_type, dst_prefix, auto_mode):
        self.calls.append((attack_id, attack_type, dst_prefix, auto_mode))
        return {"ok": True}


class EngineFakeDaemon(FakeDaemon):
    def __init__(self, conn, config):
        super().__init__(conn, config)
        self.bgp_manager = FakeBgpManager()
        self.fired = []

    def fire_and_forget(self, coro, what):
        self.fired.append((what, coro))

    async def notify_attack(self, *args, **kwargs):
        return None

    async def notify_attack_closed(self, *args, **kwargs):
        return None


def _base_cfg(auto_mode="rtbh", prefix_auto_mitigate=True):
    return {
        "detection": {"min_attack_duration_s": 0, "ddos_bps_threshold": 1000, "ddos_pps_threshold": 1000,
                      "baseline_enabled": False},
        "protected_prefixes": [{"prefix": "177.86.16.0/24", "customer": "teste",
                                 "auto_mitigate": prefix_auto_mitigate}],
        "whitelist": [],
        "detection_toggles": {},
        "mitigation_profiles": {**configio.DEFAULT_MITIGATION_PROFILES,
                                 "ddos_volumetrico": {**configio.DEFAULT_MITIGATION_PROFILES["ddos_volumetrico"],
                                                       "auto_mode": auto_mode}},
        "database": {"aggregate_interval_s": 30},
    }


async def _run_cycle(engine, daemon):
    await engine.evaluate_cycle(int(time.time()), {"177.86.16.0/24": {"tcp": {"bps": 2000, "pps": 2000}}}, {})
    for _what, coro in daemon.fired:
        await coro
    daemon.fired.clear()


def test_engine_auto_mitigates_only_once_on_attack_open(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = EngineFakeDaemon(conn, _base_cfg())
    engine = DetectionEngine(daemon)

    asyncio.run(_run_cycle(engine, daemon))
    assert len(daemon.bgp_manager.calls) == 1
    assert daemon.bgp_manager.calls[0][1:] == ("ddos_volumetrico", "177.86.16.0/24", "rtbh")

    # ciclo seguinte: ataque continua aberto -> to_update, não to_insert -> não repete
    asyncio.run(_run_cycle(engine, daemon))
    assert len(daemon.bgp_manager.calls) == 1


def test_engine_does_not_auto_mitigate_when_prefix_flag_is_off(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = EngineFakeDaemon(conn, _base_cfg(prefix_auto_mitigate=False))
    engine = DetectionEngine(daemon)

    asyncio.run(_run_cycle(engine, daemon))
    assert daemon.bgp_manager.calls == []


def test_engine_does_not_auto_mitigate_when_type_auto_mode_is_off(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = EngineFakeDaemon(conn, _base_cfg(auto_mode="off"))
    engine = DetectionEngine(daemon)

    asyncio.run(_run_cycle(engine, daemon))
    assert daemon.bgp_manager.calls == []


# --- resolução de limiar por template (protected_prefixes.yaml::template ->
# detection_templates.yaml) — ver analyzer/engine.py::evaluate_cycle -----------

def _cfg_with_template(template=None, thresholds=None, templates=None):
    cfg = _base_cfg()
    cfg["detection"]["ddos_bps_threshold"] = 1000  # global baixo, pra o template/threshold vencerem
    cfg["detection"]["ddos_pps_threshold"] = 10_000  # alto o bastante pra não disparar sozinho (OR com bps)
    entry = cfg["protected_prefixes"][0]
    if template:
        entry["template"] = template
    if thresholds:
        entry["thresholds"] = thresholds
    cfg["detection_templates"] = templates or {}
    return cfg


def test_engine_suppresses_detection_below_template_threshold(tmp_path):
    # tráfego de 2000bps ultrapassa o global (1000) mas fica abaixo do template
    # 'cgnat' (5000) — não deve abrir ataque
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    cfg = _cfg_with_template(template="cgnat", templates={"cgnat": {"ddos_bps_threshold": 5000}})
    daemon = EngineFakeDaemon(conn, cfg)
    engine = DetectionEngine(daemon)

    asyncio.run(_run_cycle(engine, daemon))
    assert daemon.bgp_manager.calls == []


def test_engine_detects_above_template_threshold(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    cfg = _cfg_with_template(template="cgnat", templates={"cgnat": {"ddos_bps_threshold": 1500}})
    daemon = EngineFakeDaemon(conn, cfg)
    engine = DetectionEngine(daemon)

    asyncio.run(_run_cycle(engine, daemon))
    assert len(daemon.bgp_manager.calls) == 1


def test_engine_explicit_thresholds_win_over_template(tmp_path):
    # thresholds explícito (5000) > template (1500) — tráfego de 2000bps fica
    # abaixo do explícito, não deve abrir ataque mesmo com o template mais baixo
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    cfg = _cfg_with_template(
        template="cgnat", thresholds={"ddos_bps_threshold": 5000},
        templates={"cgnat": {"ddos_bps_threshold": 1500}},
    )
    daemon = EngineFakeDaemon(conn, cfg)
    engine = DetectionEngine(daemon)

    asyncio.run(_run_cycle(engine, daemon))
    assert daemon.bgp_manager.calls == []


def test_engine_unknown_template_falls_back_to_global(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    cfg = _cfg_with_template(template="nao_existe", templates={})
    daemon = EngineFakeDaemon(conn, cfg)
    engine = DetectionEngine(daemon)

    # tráfego de 2000bps > global (1000) -> abre normalmente, sem erro por
    # template desconhecido
    asyncio.run(_run_cycle(engine, daemon))
    assert len(daemon.bgp_manager.calls) == 1


# --- engine: syn_flood (proporção de SYN puro / TCP total, com piso de volume) ---
# proto_totals aqui usa a chave real do protocolo (6 = TCP), diferente do "tcp"
# ilustrativo usado nos testes de ddos_volumetrico acima — o volumétrico soma
# todos os valores de by_proto.values() sem se importar com o tipo da chave, mas
# a checagem de syn_flood precisa achar especificamente by_proto[PROTO_TCP], então
# só funciona com a chave de verdade (mesmo formato que flowguard.py::_aggregate_once
# produz em produção).

def _syn_cfg(**detection_overrides):
    cfg = _base_cfg()
    # limiares volumétricos altíssimos pra não competir/mascarar o syn_flood
    cfg["detection"]["ddos_bps_threshold"] = 10**12
    cfg["detection"]["ddos_pps_threshold"] = 10**9
    cfg["detection"].update(detection_overrides)
    return cfg


def test_engine_detects_syn_flood_above_ratio_and_floor(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = EngineFakeDaemon(conn, _syn_cfg(syn_ratio_threshold=0.9, syn_min_pps_floor=500))
    engine = DetectionEngine(daemon)

    proto_totals = {"177.86.16.0/24": {6: {"bps": 500_000, "pps": 1000}}}
    syn_totals = {"177.86.16.0/24": {"bps": 480_000, "pps": 950}}  # 95% do TCP total é SYN puro

    asyncio.run(engine.evaluate_cycle(int(time.time()), proto_totals, {}, syn_totals))

    attacks = [a for a in storage.list_attacks(conn, active_only=True) if a["attack_type"] == "syn_flood"]
    assert len(attacks) == 1
    assert attacks[0]["severity"] == "high"


def test_engine_does_not_detect_syn_flood_below_volume_floor(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = EngineFakeDaemon(conn, _syn_cfg(syn_min_pps_floor=500))
    engine = DetectionEngine(daemon)

    # 100% SYN, mas só 10 pps de TCP total no ciclo — abaixo do piso, não é ataque de verdade
    proto_totals = {"177.86.16.0/24": {6: {"bps": 5_000, "pps": 10}}}
    syn_totals = {"177.86.16.0/24": {"bps": 5_000, "pps": 10}}

    asyncio.run(engine.evaluate_cycle(int(time.time()), proto_totals, {}, syn_totals))

    attacks = [a for a in storage.list_attacks(conn, active_only=True) if a["attack_type"] == "syn_flood"]
    assert attacks == []


def test_engine_does_not_detect_syn_flood_below_ratio(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = EngineFakeDaemon(conn, _syn_cfg())
    engine = DetectionEngine(daemon)

    # volume acima do piso, mas só 20% dos pacotes são SYN puro — tráfego TCP normal
    proto_totals = {"177.86.16.0/24": {6: {"bps": 500_000, "pps": 1000}}}
    syn_totals = {"177.86.16.0/24": {"bps": 100_000, "pps": 200}}

    asyncio.run(engine.evaluate_cycle(int(time.time()), proto_totals, {}, syn_totals))

    attacks = [a for a in storage.list_attacks(conn, active_only=True) if a["attack_type"] == "syn_flood"]
    assert attacks == []


def test_engine_syn_flood_toggle_off_suppresses_detection(tmp_path):
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    cfg = _syn_cfg()
    cfg["detection_toggles"] = {"syn_flood": False}
    daemon = EngineFakeDaemon(conn, cfg)
    engine = DetectionEngine(daemon)

    proto_totals = {"177.86.16.0/24": {6: {"bps": 500_000, "pps": 1000}}}
    syn_totals = {"177.86.16.0/24": {"bps": 480_000, "pps": 950}}

    asyncio.run(engine.evaluate_cycle(int(time.time()), proto_totals, {}, syn_totals))

    attacks = [a for a in storage.list_attacks(conn, active_only=True) if a["attack_type"] == "syn_flood"]
    assert attacks == []


def test_engine_evaluate_cycle_backward_compatible_without_syn_totals(tmp_path):
    """evaluate_cycle(now, proto_totals, amp_totals) sem o 4º argumento continua
    funcionando (syn_totals é opcional) — não quebra nenhum chamador antigo."""
    conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
    daemon = EngineFakeDaemon(conn, _base_cfg())
    engine = DetectionEngine(daemon)

    asyncio.run(_run_cycle(engine, daemon))
    assert len(daemon.bgp_manager.calls) == 1
