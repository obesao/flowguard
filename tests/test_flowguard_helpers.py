"""Testa os helpers puros de flowguard.py: _fmt_dt, _fmt_duration, bucket_dst_port."""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from flowguard import EPHEMERAL_PORT_MIN, _fmt_dt, _fmt_duration, bucket_dst_port


def test_fmt_dt_none_returns_placeholder():
    assert _fmt_dt(None) == "?"


def test_fmt_dt_zero_returns_placeholder():
    assert _fmt_dt(0) == "?"


def test_fmt_dt_formats_real_timestamp():
    ts = int(time.mktime(time.strptime("2026-07-07 14:30", "%Y-%m-%d %H:%M")))
    assert _fmt_dt(ts) == "07/07 14:30"


def test_fmt_duration_none_or_negative_returns_zero():
    assert _fmt_duration(None) == "0min"
    assert _fmt_duration(-5) == "0min"


def test_fmt_duration_seconds_only():
    assert _fmt_duration(45) == "45s"


def test_fmt_duration_minutes_only():
    assert _fmt_duration(125) == "2min"


def test_fmt_duration_hours_and_minutes():
    assert _fmt_duration(3725) == "1h02min"


def test_fmt_duration_exact_hour_no_minutes():
    assert _fmt_duration(7200) == "2h"


def test_bucket_dst_port_unprotected_prefix_always_zero_even_if_well_known():
    assert bucket_dst_port(80, is_protected=False) == 0


def test_bucket_dst_port_protected_prefix_keeps_well_known_port():
    assert bucket_dst_port(80, is_protected=True) == 80


def test_bucket_dst_port_protected_prefix_zeroes_ephemeral_port():
    assert bucket_dst_port(EPHEMERAL_PORT_MIN, is_protected=True) == 0
    assert bucket_dst_port(EPHEMERAL_PORT_MIN + 1000, is_protected=True) == 0


def test_bucket_dst_port_boundary_just_below_ephemeral_is_kept():
    assert bucket_dst_port(EPHEMERAL_PORT_MIN - 1, is_protected=True) == EPHEMERAL_PORT_MIN - 1
