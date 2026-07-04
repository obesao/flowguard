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


def _insert_attack(conn, dst_prefix="177.86.16.0/24", attack_type="ddos_volumetrico"):
    now = int(time.time())
    ids = storage.apply_attack_changes(conn, [{
        "ts_start": now, "dst_prefix": dst_prefix, "customer": "teste",
        "attack_type": attack_type, "severity": "critical", "bps_peak": 1, "pps_peak": 1,
    }], [], [])
    return ids[0]


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

    asyncio.run(manager.ban("177.86.17.0/24"))  # sem attack_id
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
