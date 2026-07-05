"""Testa os comandos novos do socket (_cmd_detection_*, template em monitor_add/set)
chamando SocketServer._dispatch diretamente, sem abrir um socket Unix de verdade."""

from __future__ import annotations

import asyncio

import pytest

from api.socket_server import SocketServer
from collector import configio


class FakeDaemon:
    """Snapshot mínimo do que os comandos testados aqui realmente usam — reload_config
    recomputa só os campos afetados (mesmo espírito de configio.load_config, sem reler
    o config.yaml inteiro de um arquivo real)."""

    def __init__(self, tmp_path):
        self.config = {
            "_protected_prefixes_file": str(tmp_path / "protected_prefixes.yaml"),
            "_whitelist_file": str(tmp_path / "whitelist.yaml"),
            "_detection_templates_file": str(tmp_path / "detection_templates.yaml"),
            "_detection_overrides_file": str(tmp_path / "detection_overrides.yaml"),
            "protected_prefixes": [],
            "detection": {"ddos_bps_threshold": 500_000_000, "ddos_pps_threshold": 100_000},
        }
        self._detection_base = dict(self.config["detection"])
        self.config["detection_templates"] = configio.load_detection_templates(
            self.config["_detection_templates_file"])
        self.reload_calls = 0

    def reload_config(self):
        self.reload_calls += 1
        self.config["protected_prefixes"] = configio.load_yaml_list(self.config["_protected_prefixes_file"])
        self.config["detection_templates"] = configio.load_detection_templates(
            self.config["_detection_templates_file"])
        self.config["detection"] = {
            **self._detection_base,
            **configio.load_detection_overrides(self.config["_detection_overrides_file"]),
        }


@pytest.fixture
def server(tmp_path):
    srv = SocketServer.__new__(SocketServer)
    srv.daemon = FakeDaemon(tmp_path)
    return srv


def dispatch(server, request):
    return asyncio.run(server._dispatch(request))


# --- ajuste fino dos limiares de detecção (config.yaml::detection) ------------

def test_detection_cfg_returns_effective_values(server):
    resp = dispatch(server, {"cmd": "detection_cfg"})
    assert resp == {"ok": True, "detection": {"ddos_bps_threshold": 500_000_000, "ddos_pps_threshold": 100_000}}


def test_detection_cfg_set_applies_override_and_reloads(server):
    resp = dispatch(server, {"cmd": "detection_cfg_set", "changes": {"ddos_bps_threshold": 800_000_000}})
    assert resp["ok"] is True
    assert resp["detection"]["ddos_bps_threshold"] == 800_000_000
    assert resp["detection"]["ddos_pps_threshold"] == 100_000  # não mexido, continua o global
    assert server.daemon.reload_calls == 1


def test_detection_cfg_set_requires_non_empty_changes(server):
    resp = dispatch(server, {"cmd": "detection_cfg_set", "changes": {}})
    assert resp["ok"] is False


def test_detection_cfg_set_rejects_unknown_key(server):
    resp = dispatch(server, {"cmd": "detection_cfg_set", "changes": {"nao_existe": 1}})
    assert resp["ok"] is False
    assert server.daemon.reload_calls == 0


def test_detection_cfg_set_persists_across_dispatches(server):
    dispatch(server, {"cmd": "detection_cfg_set", "changes": {"ddos_bps_threshold": 800_000_000}})
    resp = dispatch(server, {"cmd": "detection_cfg"})
    assert resp["detection"]["ddos_bps_threshold"] == 800_000_000


# --- templates de perfil de rede (detection_templates.yaml) -------------------

def test_detection_templates_empty_by_default(server):
    resp = dispatch(server, {"cmd": "detection_templates"})
    assert resp == {"ok": True, "templates": {}}


def test_detection_templates_set_creates_and_reloads(server):
    resp = dispatch(server, {
        "cmd": "detection_templates_set", "name": "cgnat",
        "values": {"ddos_bps_threshold": 5_000_000_000, "ddos_pps_threshold": 1_000_000},
        "description": "pool CGNAT",
    })
    assert resp["ok"] is True
    assert resp["templates"]["cgnat"]["ddos_bps_threshold"] == 5_000_000_000
    assert server.daemon.reload_calls == 1
    assert server.daemon.config["detection_templates"]["cgnat"]["ddos_bps_threshold"] == 5_000_000_000


def test_detection_templates_set_rejects_bad_values(server):
    resp = dispatch(server, {
        "cmd": "detection_templates_set", "name": "cgnat", "values": {"ddos_bps_threshold": -1},
    })
    assert resp["ok"] is False


def test_detection_templates_del_removes_and_reloads(server):
    dispatch(server, {"cmd": "detection_templates_set", "name": "cgnat",
                       "values": {"ddos_bps_threshold": 5_000_000_000}})
    resp = dispatch(server, {"cmd": "detection_templates_del", "name": "cgnat"})
    assert resp["ok"] is True
    assert "cgnat" not in resp["templates"]
    assert "cgnat" not in server.daemon.config["detection_templates"]


def test_detection_templates_del_unknown_fails(server):
    resp = dispatch(server, {"cmd": "detection_templates_del", "name": "nao_existe"})
    assert resp["ok"] is False


# --- monitor_add/monitor_set com template ---------------------------------------

def test_monitor_add_with_template(server):
    dispatch(server, {"cmd": "detection_templates_set", "name": "cgnat",
                       "values": {"ddos_bps_threshold": 5_000_000_000}})
    resp = dispatch(server, {"cmd": "monitor_add", "prefix": "100.64.0.0/10", "template": "cgnat"})
    assert resp["ok"] is True
    items = configio.load_yaml_list(server.daemon.config["_protected_prefixes_file"])
    assert items[0]["template"] == "cgnat"


def test_monitor_add_rejects_unknown_template(server):
    resp = dispatch(server, {"cmd": "monitor_add", "prefix": "100.64.0.0/10", "template": "nao_existe"})
    assert resp["ok"] is False


def test_monitor_set_upserts_template_on_existing_prefix(server):
    dispatch(server, {"cmd": "monitor_add", "prefix": "177.86.16.0/24"})
    dispatch(server, {"cmd": "detection_templates_set", "name": "cdn",
                       "values": {"ddos_bps_threshold": 30_000_000_000}})
    resp = dispatch(server, {"cmd": "monitor_set", "prefix": "177.86.16.0/24", "template": "cdn"})
    assert resp["ok"] is True
    items = configio.load_yaml_list(server.daemon.config["_protected_prefixes_file"])
    assert items[0]["template"] == "cdn"
