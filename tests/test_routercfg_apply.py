import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from routercfg import apply as routercfg_apply
from routercfg.templates import ValidationError

FAKE_DEVICE = {
    "name": "NE8000BGP", "host": "10.77.10.1", "port": 22,
    "device_type": "huawei_vrp", "username": "admin", "password": "x",
}


class FakeConn:
    def __init__(self):
        self.sent = []
        self.disconnected = False

    def send_config_set(self, commands):
        self.sent.append(("config_set", list(commands)))
        if any("rollback point create" in c for c in commands):
            return "Info: Succeeded in creating configuration rollback point, whose ID is 7."
        return "ok"

    def send_command(self, cmd, read_timeout=None, **kw):
        self.sent.append(("command", cmd))
        return "ok"

    def disconnect(self):
        self.disconnected = True


@pytest.fixture(autouse=True)
def isolate_jobs_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(routercfg_apply, "JOBS_DIR", tmp_path / "jobs")
    monkeypatch.setattr(routercfg_apply, "AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setattr(routercfg_apply, "_device_for", lambda name=None: FAKE_DEVICE)
    monkeypatch.setattr(routercfg_apply, "_notify", lambda msg: None)
    monkeypatch.setattr(routercfg_apply, "_spawn_auto_revert_worker", lambda job_id: None)
    fake_conn = FakeConn()
    monkeypatch.setattr(routercfg_apply, "_connect", lambda device: fake_conn)
    yield fake_conn


def test_apply_creates_pending_job_with_rollback_point(isolate_jobs_dir):
    job = routercfg_apply.apply_template("netflow_export", {
        "collector_ip": "10.77.10.2", "collector_port": "2055", "interface": "GigabitEthernet0/0/1",
    })
    assert job["status"] == "pending_confirm"
    assert job["rollback_point"] == "7"
    assert job["commands"]
    assert job["undo_commands"]
    loaded = routercfg_apply._load_job(job["id"])
    assert loaded["id"] == job["id"]


def test_apply_with_invalid_values_raises_before_touching_network(isolate_jobs_dir):
    with pytest.raises(ValidationError):
        routercfg_apply.apply_template("netflow_export", {"collector_ip": "not-an-ip", "collector_port": "2055", "interface": "GigabitEthernet0/0/1"})
    assert isolate_jobs_dir.sent == []


def test_confirm_job_then_cannot_confirm_twice(isolate_jobs_dir):
    job = routercfg_apply.apply_template("static_route", {"dest": "203.0.113.0/24", "next_hop": "10.77.10.1"})
    confirmed = routercfg_apply.confirm_job(job["id"])
    assert confirmed["status"] == "confirmed"
    with pytest.raises(ValidationError):
        routercfg_apply.confirm_job(job["id"])


def test_manual_revert_prefers_rollback_point(isolate_jobs_dir):
    job = routercfg_apply.apply_template("static_route", {"dest": "203.0.113.0/24", "next_hop": "10.77.10.1"})
    reverted = routercfg_apply.revert_job(job["id"], trigger="manual")
    assert reverted["status"] == "reverted"
    assert reverted["revert_result"]["method"] == "rollback_point"


def test_revert_falls_back_to_undo_commands_when_rollback_point_missing(isolate_jobs_dir, monkeypatch):
    job = routercfg_apply.apply_template("static_route", {"dest": "203.0.113.0/24", "next_hop": "10.77.10.1"})
    job["rollback_point"] = None
    routercfg_apply._save_job(job)
    reverted = routercfg_apply.revert_job(job["id"], trigger="manual")
    assert reverted["revert_result"]["method"] == "undo_commands"


def test_auto_revert_worker_reverts_if_not_confirmed(isolate_jobs_dir):
    job = routercfg_apply.apply_template("static_route", {"dest": "203.0.113.0/24", "next_hop": "10.77.10.1"},
                                          confirm_window_s=0)
    routercfg_apply._auto_revert_worker(job["id"])
    reloaded = routercfg_apply._load_job(job["id"])
    assert reloaded["status"] == "auto_reverted"


def test_auto_revert_worker_skips_if_already_confirmed(isolate_jobs_dir):
    job = routercfg_apply.apply_template("static_route", {"dest": "203.0.113.0/24", "next_hop": "10.77.10.1"},
                                          confirm_window_s=0)
    routercfg_apply.confirm_job(job["id"])
    routercfg_apply._auto_revert_worker(job["id"])
    reloaded = routercfg_apply._load_job(job["id"])
    assert reloaded["status"] == "confirmed"


def test_history_lists_most_recent_first(isolate_jobs_dir):
    j1 = routercfg_apply.apply_template("static_route", {"dest": "203.0.113.0/24", "next_hop": "10.77.10.1"})
    time.sleep(0.01)
    j2 = routercfg_apply.apply_template("static_route", {"dest": "198.51.100.0/24", "next_hop": "10.77.10.1"})
    hist = routercfg_apply.list_history()
    assert hist[0]["id"] == j2["id"]
    assert hist[1]["id"] == j1["id"]
