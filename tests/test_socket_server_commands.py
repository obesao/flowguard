"""Testa os comandos "clássicos" do socket (status/top/flows/attacks/rules/ban/
toggles/mitigation/whitelist/monitor/dashboard) chamando SocketServer._dispatch
diretamente — complementa test_socket_server.py, que já cobre os comandos de
ajuste fino de detecção (detection_cfg/detection_templates).

FakeDaemon aqui grava num SQLite real (mesmo padrão de test_wa_notifications.py)
e usa um FakeBgpManager que só registra as chamadas — o comportamento REAL de
BGP/FlowSpec já é coberto por test_bgp_manager.py; o que interessa aqui é que
o socket valida entrada e delega pro método certo com os argumentos certos."""

from __future__ import annotations

import asyncio
import time

from api.socket_server import SocketServer
from collector import configio, storage


class FakeBgpManager:
    def __init__(self):
        self.calls = []

    async def ban(self, target, attack_id=None, ttl_s=None, origin="flowguard", trigger_type="manual"):
        self.calls.append(("ban", target, attack_id, ttl_s, origin, trigger_type))
        return {"ok": True, "action": "ban"}

    async def unban(self, target):
        self.calls.append(("unban", target))
        return {"ok": True, "action": "unban"}

    async def flowspec_add(self, rule, attack_id=None, ttl_s=None, origin="flowguard", peer="main", trigger_type="manual"):
        self.calls.append(("flowspec_add", rule, attack_id, ttl_s, origin, peer, trigger_type))
        return {"ok": True, "action": "flowspec_add"}

    async def flowspec_del(self, rule_id):
        self.calls.append(("flowspec_del", rule_id))
        return {"ok": True, "action": "flowspec_del"}

    async def withdraw_all(self):
        self.calls.append(("withdraw_all",))
        return {"ok": True, "removed": 0}

    async def verify_rule(self, rule_id):
        self.calls.append(("verify_rule", rule_id))
        return {"ok": True, "matches": True}

    async def status(self, peer="main"):
        self.calls.append(("status", peer))
        return {"peer": peer, "state": "Established"}

    def _device_for_peer(self, peer):
        return "NE8000BGP" if peer == "main" else None


class FakeDaemon:
    def __init__(self, tmp_path, protected_prefixes=None):
        self.conn = storage.connect(str(tmp_path / "flow.sqlite"), check_same_thread=False)
        self.config = {
            "database": {"aggregate_interval_s": 30},
            "protected_prefixes": protected_prefixes or [],
            "detection_toggles": {"dns_amp": True},
            "mitigation_profiles": {"dns_amp": {"kind": "discard"}},
            "_protected_prefixes_file": str(tmp_path / "protected_prefixes.yaml"),
            "_whitelist_file": str(tmp_path / "whitelist.yaml"),
            "_detection_toggles_file": str(tmp_path / "detection_toggles.yaml"),
            "_mitigation_profiles_file": str(tmp_path / "mitigation_profiles.yaml"),
            "_detection_templates_file": str(tmp_path / "detection_templates.yaml"),
        }
        self.started_at = time.time()
        self.bgp_manager = FakeBgpManager()
        self.reload_calls = 0
        self.stopped = False

    async def run_db(self, func, *args, **kwargs):
        return func(*args, **kwargs)

    async def run_read_db(self, func, *args, **kwargs):
        return func(self.conn, *args, **kwargs)

    def reload_config(self):
        self.reload_calls += 1
        self.config["protected_prefixes"] = configio.load_yaml_list(self.config["_protected_prefixes_file"])
        self.config["detection_toggles"] = configio.load_feature_toggles(self.config["_detection_toggles_file"])
        self.config["mitigation_profiles"] = configio.load_mitigation_profiles(self.config["_mitigation_profiles_file"])

    def stop(self):
        self.stopped = True


def make_server(tmp_path, **kwargs):
    srv = SocketServer.__new__(SocketServer)
    srv.daemon = FakeDaemon(tmp_path, **kwargs)
    return srv


def dispatch(server, request):
    return asyncio.run(server._dispatch(request))


def _insert_attack(conn, dst_prefix="177.86.16.0/24", attack_type="ddos_volumetrico", severity="critical"):
    ts_start = int(time.time()) - 60
    ids = storage.apply_attack_changes(conn, [{
        "ts_start": ts_start, "dst_prefix": dst_prefix, "customer": "Cliente X",
        "attack_type": attack_type, "severity": severity, "bps_peak": 1, "pps_peak": 1,
    }], [], [])
    return ids[0]


# --- _dispatch: roteamento e tratamento de erro genérico -----------------------

def test_dispatch_unknown_command_returns_error(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "isso_nao_existe"})
    assert resp == {"ok": False, "error": "comando desconhecido: isso_nao_existe"}


def test_dispatch_catches_handler_exception(tmp_path):
    server = make_server(tmp_path)

    async def _boom(request):
        raise RuntimeError("falhou de propósito")

    server._cmd_boom = _boom
    resp = dispatch(server, {"cmd": "boom"})
    assert resp == {"ok": False, "error": "falhou de propósito"}


def test_dispatch_missing_cmd_key_returns_error(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {})
    assert resp["ok"] is False


# --- status/top/flows: passthrough pro storage via run_read_db -----------------

def test_status_returns_pid_and_uptime(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "status"})
    assert resp["ok"] is True
    assert "pid" in resp
    assert resp["uptime_s"] >= 0


def test_top_respects_limit(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "top", "limit": 5})
    assert resp == {"ok": True, "top_prefixes": []}


def test_flows_empty_database(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "flows"})
    assert resp == {"ok": True, "flows": []}


def test_bgp_status_passes_peer_through(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "bgp_status", "peer": "pppoe"})
    assert resp == {"ok": True, "peer": "pppoe", "state": "Established"}


# --- attacks / attack_detail ----------------------------------------------------

def test_attacks_lists_active_by_default(tmp_path):
    server = make_server(tmp_path)
    _insert_attack(server.daemon.conn)
    resp = dispatch(server, {"cmd": "attacks"})
    assert resp["ok"] is True
    assert len(resp["attacks"]) == 1
    assert resp["attacks"][0]["dst_prefix"] == "177.86.16.0/24"


def test_attack_detail_requires_attack_id(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "attack_detail"})
    assert resp == {"ok": False, "error": "attack_id obrigatório"}


def test_attack_detail_unknown_id_returns_error(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "attack_detail", "attack_id": 999})
    assert resp["ok"] is False
    assert "não encontrado" in resp["error"]


def test_attack_detail_returns_attack_and_detail(tmp_path):
    server = make_server(tmp_path)
    attack_id = _insert_attack(server.daemon.conn)
    resp = dispatch(server, {"cmd": "attack_detail", "attack_id": attack_id})
    assert resp["ok"] is True
    assert resp["attack"]["id"] == attack_id
    assert "detail" in resp and "timeseries" in resp


# --- rules: resolução de nome de equipamento por peer ---------------------------

def test_rules_resolves_device_name_for_main_peer(tmp_path):
    server = make_server(tmp_path)
    storage.apply_attack_changes(server.daemon.conn, [], [], [])  # garante schema ok
    server.daemon.conn.execute(
        "INSERT INTO flowspec_rules (dst_prefix, action, peer, active, created_at, expires_at) "
        "VALUES ('177.86.16.0/24', 'discard', 'main', 1, 0, 0)"
    )
    server.daemon.conn.commit()
    resp = dispatch(server, {"cmd": "rules"})
    assert resp["ok"] is True
    assert resp["rules"][0]["device_name"] == "NE8000BGP"


def test_rules_falls_back_to_peer_name_when_unresolved(tmp_path):
    server = make_server(tmp_path)
    server.daemon.conn.execute(
        "INSERT INTO flowspec_rules (dst_prefix, action, peer, active, created_at, expires_at) "
        "VALUES ('177.86.16.0/24', 'discard', 'pppoe', 1, 0, 0)"
    )
    server.daemon.conn.commit()
    resp = dispatch(server, {"cmd": "rules"})
    assert resp["rules"][0]["device_name"] == "pppoe"


# --- ban/unban/flowspec_add/del/del_all/rule_verify: validação + delegação -----

def test_ban_requires_target(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "ban"})
    assert resp == {"ok": False, "error": "target obrigatório"}


def test_ban_delegates_to_bgp_manager(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "ban", "target": "1.2.3.4/32", "attack_id": 7})
    assert resp["ok"] is True
    assert server.daemon.bgp_manager.calls == [("ban", "1.2.3.4/32", 7, None, "flowguard", "manual")]


def test_unban_requires_target(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "unban"})
    assert resp == {"ok": False, "error": "target obrigatório"}


def test_unban_delegates_to_bgp_manager(tmp_path):
    server = make_server(tmp_path)
    dispatch(server, {"cmd": "unban", "target": "1.2.3.4/32"})
    assert server.daemon.bgp_manager.calls == [("unban", "1.2.3.4/32")]


def test_flowspec_add_requires_rule(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "flowspec_add"})
    assert resp == {"ok": False, "error": "rule obrigatório"}


def test_flowspec_add_rejects_invalid_rule_type(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "flowspec_add", "rule": 123})
    assert resp == {"ok": False, "error": "rule deve ser string ou objeto"}


def test_flowspec_add_accepts_dict_rule(tmp_path):
    server = make_server(tmp_path)
    rule = {"dst_prefix": "177.86.16.0/24", "action": "discard"}
    resp = dispatch(server, {"cmd": "flowspec_add", "rule": rule, "peer": "pppoe"})
    assert resp["ok"] is True
    call = server.daemon.bgp_manager.calls[0]
    assert call[0] == "flowspec_add"
    assert call[1] == rule
    assert call[5] == "pppoe"


def test_flowspec_add_parses_string_rule(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "flowspec_add", "rule": "dst=177.86.16.0/24 protocol=udp discard=1"})
    assert resp["ok"] is True
    parsed_rule = server.daemon.bgp_manager.calls[0][1]
    assert parsed_rule["dst_prefix"] == "177.86.16.0/24"


def test_flowspec_add_invalid_string_rule_returns_parse_error(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "flowspec_add", "rule": "isso nao e uma regra valida"})
    assert resp["ok"] is False
    assert server.daemon.bgp_manager.calls == []


def test_flowspec_del_requires_rule_id(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "flowspec_del"})
    assert resp == {"ok": False, "error": "rule_id obrigatório"}


def test_flowspec_del_rejects_non_integer_rule_id(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "flowspec_del", "rule_id": "abc"})
    assert resp == {"ok": False, "error": "rule_id inválido"}


def test_flowspec_del_delegates_with_int_rule_id(tmp_path):
    server = make_server(tmp_path)
    dispatch(server, {"cmd": "flowspec_del", "rule_id": "42"})
    assert server.daemon.bgp_manager.calls == [("flowspec_del", 42)]


def test_flowspec_del_all_delegates(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "flowspec_del_all"})
    assert resp["ok"] is True
    assert server.daemon.bgp_manager.calls == [("withdraw_all",)]


def test_rule_verify_requires_rule_id(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "rule_verify"})
    assert resp == {"ok": False, "error": "rule_id obrigatório"}


def test_rule_verify_rejects_non_integer_rule_id(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "rule_verify", "rule_id": "abc"})
    assert resp == {"ok": False, "error": "rule_id inválido"}


def test_rule_verify_delegates_with_int_rule_id(tmp_path):
    server = make_server(tmp_path)
    dispatch(server, {"cmd": "rule_verify", "rule_id": "7"})
    assert server.daemon.bgp_manager.calls == [("verify_rule", 7)]


# --- dismiss_attack / dismiss_all_attacks ---------------------------------------

def test_dismiss_attack_requires_attack_id(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "dismiss_attack"})
    assert resp == {"ok": False, "error": "attack_id obrigatório"}


def test_dismiss_attack_unknown_id_returns_error(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "dismiss_attack", "attack_id": 999})
    assert resp["ok"] is False


def test_dismiss_attack_marks_active_attack(tmp_path):
    server = make_server(tmp_path)
    attack_id = _insert_attack(server.daemon.conn)
    resp = dispatch(server, {"cmd": "dismiss_attack", "attack_id": attack_id})
    assert resp == {"ok": True}
    attacks_after = dispatch(server, {"cmd": "attacks"})
    assert attacks_after["attacks"] == []  # dismissed some fora da lista de ativos


def test_dismiss_all_attacks_clears_every_active_attack(tmp_path):
    server = make_server(tmp_path)
    _insert_attack(server.daemon.conn, dst_prefix="177.86.16.0/24")
    _insert_attack(server.daemon.conn, dst_prefix="177.86.17.0/24")
    resp = dispatch(server, {"cmd": "dismiss_all_attacks"})
    assert resp == {"ok": True, "cleared": 2}


# --- toggles ---------------------------------------------------------------------

def test_toggles_returns_current_config(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "toggles"})
    assert resp == {"ok": True, "toggles": {"dns_amp": True}}


def test_set_toggles_requires_non_empty_dict(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "set_toggles", "toggles": {}})
    assert resp["ok"] is False


def test_set_toggles_applies_and_reloads(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "set_toggles", "toggles": {"dns_amp": False, "syn_flood": True}})
    assert resp["ok"] is True
    assert server.daemon.reload_calls == 1
    assert server.daemon.config["detection_toggles"]["dns_amp"] is False


def test_set_toggles_rejects_unknown_key(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "set_toggles", "toggles": {"nao_existe": True}})
    assert resp["ok"] is False
    assert server.daemon.reload_calls == 0


def test_set_toggle_singular_delegates_to_plural(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "set_toggle", "key": "dns_amp", "value": False})
    assert resp["ok"] is True
    assert server.daemon.config["detection_toggles"]["dns_amp"] is False


# --- mitigation_profiles ----------------------------------------------------------

def test_mitigation_profiles_returns_current_config(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "mitigation_profiles"})
    assert resp == {"ok": True, "profiles": {"dns_amp": {"kind": "discard"}}}


def test_set_mitigation_profiles_requires_non_empty_dict(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "set_mitigation_profiles", "profiles": {}})
    assert resp["ok"] is False


def test_set_mitigation_profiles_rejects_unknown_attack_type(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "set_mitigation_profiles", "profiles": {"nao_existe": {"kind": "discard"}}})
    assert resp["ok"] is False
    assert server.daemon.reload_calls == 0


def test_set_mitigation_profiles_applies_and_reloads(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {
        "cmd": "set_mitigation_profiles",
        "profiles": {"dns_amp": {"kind": "rate_limit", "rate_limit_mbps": 100}},
    })
    assert resp["ok"] is True
    assert server.daemon.reload_calls == 1
    assert server.daemon.config["mitigation_profiles"]["dns_amp"]["kind"] == "rate_limit"


# --- whitelist ---------------------------------------------------------------------

def test_whitelist_add_requires_prefix(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "whitelist_add"})
    assert resp == {"ok": False, "error": "prefixo obrigatório"}


def test_whitelist_add_and_del_roundtrip(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "whitelist_add", "prefix": "177.86.17.48/29"})
    assert resp == {"ok": True}
    assert server.daemon.reload_calls == 1

    resp = dispatch(server, {"cmd": "whitelist_del", "prefix": "177.86.17.48/29"})
    assert resp == {"ok": True}


def test_whitelist_add_rejects_duplicate(tmp_path):
    server = make_server(tmp_path)
    dispatch(server, {"cmd": "whitelist_add", "prefix": "177.86.17.48/29"})
    resp = dispatch(server, {"cmd": "whitelist_add", "prefix": "177.86.17.48/29"})
    assert resp["ok"] is False


def test_whitelist_del_requires_prefix(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "whitelist_del"})
    assert resp == {"ok": False, "error": "prefixo obrigatório"}


def test_whitelist_del_unknown_prefix_fails(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "whitelist_del", "prefix": "não está lá"})
    assert resp["ok"] is False


# --- monitor add/set/del -----------------------------------------------------------

def test_monitor_add_requires_prefix(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "monitor_add"})
    assert resp == {"ok": False, "error": "prefixo obrigatório"}


def test_monitor_add_rejects_duplicate_prefix(tmp_path):
    server = make_server(tmp_path)
    dispatch(server, {"cmd": "monitor_add", "prefix": "177.86.16.0/24"})
    resp = dispatch(server, {"cmd": "monitor_add", "prefix": "177.86.16.0/24"})
    assert resp["ok"] is False


def test_monitor_add_stores_thresholds_only_when_present(tmp_path):
    server = make_server(tmp_path)
    dispatch(server, {"cmd": "monitor_add", "prefix": "177.86.16.0/24",
                       "thresholds": {"ddos_bps_threshold": 35_000_000_000}})
    items = configio.load_yaml_list(server.daemon.config["_protected_prefixes_file"])
    assert items[0]["thresholds"] == {"ddos_bps_threshold": 35_000_000_000}


def test_monitor_set_requires_prefix(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "monitor_set"})
    assert resp == {"ok": False, "error": "prefixo obrigatório"}


def test_monitor_set_rejects_unknown_template(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "monitor_set", "prefix": "177.86.16.0/24", "template": "nao_existe"})
    assert resp["ok"] is False


def test_monitor_set_creates_when_not_existing(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "monitor_set", "prefix": "177.86.16.0/24", "customer": "X"})
    assert resp["ok"] is True
    items = configio.load_yaml_list(server.daemon.config["_protected_prefixes_file"])
    assert len(items) == 1


def test_monitor_set_updates_existing_in_place(tmp_path):
    server = make_server(tmp_path)
    dispatch(server, {"cmd": "monitor_add", "prefix": "177.86.16.0/24", "customer": "Antigo"})
    dispatch(server, {"cmd": "monitor_set", "prefix": "177.86.16.0/24", "customer": "Novo"})
    items = configio.load_yaml_list(server.daemon.config["_protected_prefixes_file"])
    assert len(items) == 1
    assert items[0]["customer"] == "Novo"


def test_monitor_del_requires_prefix(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "monitor_del"})
    assert resp == {"ok": False, "error": "prefixo obrigatório"}


def test_monitor_del_unknown_prefix_fails(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "monitor_del", "prefix": "177.86.16.0/24"})
    assert resp["ok"] is False


def test_monitor_del_removes_existing(tmp_path):
    server = make_server(tmp_path)
    dispatch(server, {"cmd": "monitor_add", "prefix": "177.86.16.0/24"})
    resp = dispatch(server, {"cmd": "monitor_del", "prefix": "177.86.16.0/24"})
    assert resp == {"ok": True}
    assert configio.load_yaml_list(server.daemon.config["_protected_prefixes_file"]) == []


def test_monitor_list_reflects_config_entries(tmp_path):
    server = make_server(tmp_path, protected_prefixes=[
        {"prefix": "177.86.16.0/24", "customer": "X", "capacity_mbps": 1000},
    ])
    resp = dispatch(server, {"cmd": "monitor_list"})
    assert resp["ok"] is True
    assert resp["monitor"] == [{
        "prefix": "177.86.16.0/24", "customer": "X", "capacity_mbps": 1000,
        "bps": 0, "pps": 0, "flows": 0,
    }]


# --- reload / stop / dashboard ------------------------------------------------------

def test_reload_calls_daemon_reload_config(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "reload"})
    assert resp == {"ok": True}
    assert server.daemon.reload_calls == 1


def test_stop_schedules_daemon_stop_and_replies_immediately():
    async def _run():
        server = SocketServer.__new__(SocketServer)
        server.daemon = type("D", (), {"stop": lambda self: setattr(server.daemon, "stopped", True)})()
        server.daemon.stopped = False
        resp = await server._dispatch({"cmd": "stop"})
        assert resp["ok"] is True
        assert server.daemon.stopped is False  # agendado com call_later, não imediato
        await asyncio.sleep(0.3)
        assert server.daemon.stopped is True

    asyncio.run(_run())


def test_dashboard_aggregates_all_sub_commands(tmp_path):
    server = make_server(tmp_path)
    resp = dispatch(server, {"cmd": "dashboard"})
    assert resp["ok"] is True
    assert set(resp.keys()) == {"ok", "status", "top", "attacks", "monitor", "bgp"}
    assert resp["status"]["ok"] is True
    assert resp["bgp"]["state"] == "Established"
