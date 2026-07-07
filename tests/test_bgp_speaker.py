"""Testa bgp/speaker.py: parsing das notificações do ExaBGP (drain_exabgp_stdin/
_handle_exabgp_message/get_neighbor_state) e o CommandHandler do socket de
controle — sem subir processo real do ExaBGP nem socket Unix de verdade.

main()/ThreadedUnixServer ficam fora (wiring de I/O: config, threads, socket
real) — baixo valor por linha pra teste unitário, mesmo raciocínio já aplicado
a flowguard.py/socket_server.py."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from bgp import speaker


@pytest.fixture(autouse=True)
def _reset_neighbor_state():
    """_neighbor_state é global no módulo — sem isolar entre testes, um teste
    vaza estado pro próximo."""
    speaker._neighbor_state.clear()
    yield
    speaker._neighbor_state.clear()


# --- _handle_exabgp_message / get_neighbor_state --------------------------------

def test_state_message_updates_neighbor_state():
    speaker._handle_exabgp_message({
        "type": "state",
        "neighbor": {"address": {"peer": "10.77.10.1"}, "state": "up"},
    })
    state = speaker.get_neighbor_state()
    assert state["10.77.10.1"]["state"] == "up"
    assert "updated_at" in state["10.77.10.1"]


def test_state_message_records_reason_when_present():
    speaker._handle_exabgp_message({
        "type": "state",
        "neighbor": {"address": {"peer": "10.77.10.1"}, "state": "down", "reason": "connection reset"},
    })
    assert speaker.get_neighbor_state()["10.77.10.1"]["reason"] == "connection reset"


def test_non_state_message_ignored():
    speaker._handle_exabgp_message({"type": "notification", "neighbor": {}})
    assert speaker.get_neighbor_state() == {}


def test_state_message_missing_peer_ignored():
    speaker._handle_exabgp_message({"type": "state", "neighbor": {"address": {}, "state": "up"}})
    assert speaker.get_neighbor_state() == {}


def test_state_message_missing_state_ignored():
    speaker._handle_exabgp_message({
        "type": "state", "neighbor": {"address": {"peer": "10.77.10.1"}},
    })
    assert speaker.get_neighbor_state() == {}


def test_get_neighbor_state_returns_a_shallow_copy_of_the_top_level_dict():
    """dict(_neighbor_state) é cópia rasa: adicionar/remover uma CHAVE no snapshot
    não deve vazar pro estado real (só o dict aninhado por peer é compartilhado,
    o que é seguro porque nada além de _handle_exabgp_message o modifica, sob
    lock)."""
    speaker._handle_exabgp_message({
        "type": "state", "neighbor": {"address": {"peer": "10.77.10.1"}, "state": "up"},
    })
    snapshot = speaker.get_neighbor_state()
    snapshot["10.70.70.1"] = {"state": "injetado"}
    assert "10.70.70.1" not in speaker.get_neighbor_state()


def test_second_peer_does_not_overwrite_first():
    speaker._handle_exabgp_message({
        "type": "state", "neighbor": {"address": {"peer": "10.77.10.1"}, "state": "up"},
    })
    speaker._handle_exabgp_message({
        "type": "state", "neighbor": {"address": {"peer": "10.70.70.1"}, "state": "connected"},
    })
    state = speaker.get_neighbor_state()
    assert state["10.77.10.1"]["state"] == "up"
    assert state["10.70.70.1"]["state"] == "connected"


# --- drain_exabgp_stdin ----------------------------------------------------------

def test_drain_stdin_processes_valid_json_lines(monkeypatch):
    lines = [
        json.dumps({"type": "state", "neighbor": {"address": {"peer": "10.77.10.1"}, "state": "up"}}) + "\n",
    ]
    monkeypatch.setattr(sys, "stdin", io.StringIO("".join(lines)))
    speaker.drain_exabgp_stdin()
    assert speaker.get_neighbor_state()["10.77.10.1"]["state"] == "up"


def test_drain_stdin_skips_blank_lines(monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO("\n   \n\n"))
    speaker.drain_exabgp_stdin()  # não deve levantar exceção
    assert speaker.get_neighbor_state() == {}


def test_drain_stdin_skips_malformed_json_without_crashing(monkeypatch):
    valid = json.dumps({"type": "state", "neighbor": {"address": {"peer": "10.77.10.1"}, "state": "up"}})
    monkeypatch.setattr(sys, "stdin", io.StringIO("isso nao e json\n" + valid + "\n"))
    speaker.drain_exabgp_stdin()
    assert speaker.get_neighbor_state()["10.77.10.1"]["state"] == "up"


def test_drain_stdin_ignores_non_state_notifications(monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"type": "notification"}) + "\n"))
    speaker.drain_exabgp_stdin()
    assert speaker.get_neighbor_state() == {}


# --- send_to_exabgp ---------------------------------------------------------------

def test_send_to_exabgp_writes_command_with_newline(capsys):
    speaker.send_to_exabgp("announce flow route { ... }")
    captured = capsys.readouterr()
    assert captured.out == "announce flow route { ... }\n"


# --- CommandHandler.handle ---------------------------------------------------------

class _FakeRequest:
    """Fake do socket usado por BaseRequestHandler.handle() — recv/sendall só."""

    def __init__(self, payload: bytes):
        self._payload = payload
        self.sent = b""

    def recv(self, n):
        data, self._payload = self._payload, b""
        return data

    def sendall(self, data):
        self.sent += data


def _run_handler(payload: dict) -> dict:
    handler = object.__new__(speaker.CommandHandler)
    handler.request = _FakeRequest(json.dumps(payload).encode("utf-8"))
    handler.handle()
    return json.loads(handler.request.sent.decode("utf-8").strip())


def test_command_handler_status_action_returns_neighbor_state():
    speaker._handle_exabgp_message({
        "type": "state", "neighbor": {"address": {"peer": "10.77.10.1"}, "state": "up"},
    })
    resp = _run_handler({"action": "status"})
    assert resp["ok"] is True
    assert resp["neighbors"]["10.77.10.1"]["state"] == "up"


def test_command_handler_announce_flowspec_sends_command_to_exabgp(monkeypatch, capsys):
    resp = _run_handler({
        "action": "announce", "kind": "flowspec",
        "rule": {"dst_prefix": "177.86.16.10/32", "protocol": "udp", "action": "discard"},
    })
    assert resp["ok"] is True
    out = capsys.readouterr().out
    assert out.startswith("announce flow route")
    assert "discard" in out


def test_command_handler_targets_specific_neighbor_when_given():
    resp = _run_handler({
        "action": "announce", "kind": "flowspec", "neighbor": "10.70.70.1",
        "rule": {"dst_prefix": "177.86.16.10/32", "protocol": "udp", "action": "discard"},
    })
    assert resp["ok"] is True


def test_command_handler_unknown_kind_returns_error_response():
    resp = _run_handler({"action": "announce", "kind": "nao_existe", "rule": {}})
    assert resp["ok"] is False
    assert "nao_existe" in resp["error"]


def test_command_handler_malformed_request_returns_error_without_crashing():
    handler = object.__new__(speaker.CommandHandler)
    handler.request = _FakeRequest(b"isso nao e json")
    handler.handle()
    resp = json.loads(handler.request.sent.decode("utf-8").strip())
    assert resp["ok"] is False


def test_command_handler_empty_payload_returns_without_response():
    handler = object.__new__(speaker.CommandHandler)
    handler.request = _FakeRequest(b"")
    handler.handle()
    assert handler.request.sent == b""
