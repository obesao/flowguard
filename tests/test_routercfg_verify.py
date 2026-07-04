import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from routercfg import verify
from routercfg.templates import ValidationError

FAKE_DEVICE = {
    "name": "NE8000BGP", "host": "10.77.10.1", "port": 22,
    "device_type": "huawei_vrpv8", "username": "admin", "password": "x",
}

# Amostras reais (sanitizadas) capturadas via SSH nos dois equipamentos de
# produção antes de escrever os regexes — ver docstring de routercfg/verify.py.
SAMPLE_RTBH_FOUND = """ BGP local router ID : 192.168.0.251
 Local AS number : 262620
 Paths:   1 available, 1 best, 1 select, 0 best-external, 0 add-path
 BGP routing table entry information of 203.0.113.20/32:
 From: 10.77.10.2 (10.77.10.2)
 Route Duration: 0d00h02m02s
 Relay IP Nexthop: 10.77.10.2
 Relay IP Out-Interface: 25GE0/1/33
 Original nexthop: 10.77.10.2
 Qos information : 0x0
 Community: <2626:669>
 AS-path Nil, origin igp, localpref 999, pref-val 0, valid, internal, best, select, pre 255
"""

SAMPLE_RTBH_NOT_FOUND = "Info: The network does not exist."

SAMPLE_FLOWSPEC = """ BGP Local router ID is 192.168.0.251
 Total Number of Routes: 2
 * >  ReIndex : 1
      Dissemination Rules:
       Source IP      : 100.64.126.111/32
       MED      :                     PrefVal  : 0
       LocalPref: 100
       Path/Ogn :  i
 * >  ReIndex : 9
      Dissemination Rules:
       Destination IP : 110.42.64.33/32
       Source IP      : 177.86.18.236/32
       Protocol       : eq 17
       Dest. Port     : eq 4790
       MED      :                     PrefVal  : 0
       LocalPref: 100
       Path/Ogn :  i
"""

SAMPLE_UNRECOGNIZED = "                            ^\nError: Unrecognized command found at '^' position.\n"


class FakeConn:
    def __init__(self, output):
        self.output = output
        self.disconnected = False
        self.sent = None

    def send_command(self, command, read_timeout=None):
        self.sent = command
        return self.output

    def disconnect(self):
        self.disconnected = True


@pytest.fixture
def patch_ssh(monkeypatch):
    def _patch(output):
        fake_conn = FakeConn(output)
        monkeypatch.setattr(verify, "_device_for", lambda name=None: FAKE_DEVICE)
        monkeypatch.setattr(verify, "_connect", lambda device: fake_conn)
        return fake_conn

    return _patch


# --- parse_rtbh_route --------------------------------------------------

def test_parse_rtbh_route_found_matches_expected():
    result = verify.parse_rtbh_route(SAMPLE_RTBH_FOUND, "203.0.113.20/32", "2626:669", "10.77.10.2")
    assert result["match_status"] == verify.MATCH_FOUND
    assert result["matched"]["community"] == ["2626:669"]
    assert result["matched"]["nexthop"] == "10.77.10.2"


def test_parse_rtbh_route_found_but_community_mismatch():
    # achado real em produção: o roteador reescreveu a community da linha
    # (2626:669 configurado -> valor diferente no display) — a feature existe
    # justamente pra pegar esse tipo de discrepância, não pra escondê-la.
    result = verify.parse_rtbh_route(SAMPLE_RTBH_FOUND, "203.0.113.20/32", "9999:1", "10.77.10.2")
    assert result["match_status"] == verify.MATCH_FOUND_MISMATCH
    assert "9999:1" in result["detail"]


def test_parse_rtbh_route_nexthop_mismatch():
    result = verify.parse_rtbh_route(SAMPLE_RTBH_FOUND, "203.0.113.20/32", "2626:669", "192.0.2.9")
    assert result["match_status"] == verify.MATCH_FOUND_MISMATCH
    assert "nexthop" in result["detail"]


def test_parse_rtbh_route_not_found():
    result = verify.parse_rtbh_route(SAMPLE_RTBH_NOT_FOUND, "198.51.100.1/32", "2626:669", "10.77.10.2")
    assert result["match_status"] == verify.MATCH_NOT_FOUND


def test_parse_rtbh_route_unrecognized_output_is_inconclusive_not_false_negative():
    result = verify.parse_rtbh_route("saída totalmente inesperada, sem os campos usuais",
                                      "203.0.113.20/32", "2626:669", "10.77.10.2")
    assert result["match_status"] == verify.MATCH_INCONCLUSIVE


def test_parse_rtbh_route_wrong_prefix_echoed_is_inconclusive():
    result = verify.parse_rtbh_route(SAMPLE_RTBH_FOUND, "9.9.9.9/32", "2626:669", "10.77.10.2")
    assert result["match_status"] == verify.MATCH_INCONCLUSIVE


# --- parse_flowspec_match -----------------------------------------------

def test_parse_flowspec_match_found_by_src_prefix():
    rule = {"src_prefix": "100.64.126.111/32", "dst_prefix": None, "action": "discard"}
    result = verify.parse_flowspec_match(SAMPLE_FLOWSPEC, rule)
    assert result["match_status"] == verify.MATCH_FOUND


def test_parse_flowspec_match_found_by_src_and_dst_prefix():
    rule = {"src_prefix": "177.86.18.236/32", "dst_prefix": "110.42.64.33/32", "action": "discard"}
    result = verify.parse_flowspec_match(SAMPLE_FLOWSPEC, rule)
    assert result["match_status"] == verify.MATCH_FOUND


def test_parse_flowspec_match_not_found():
    rule = {"src_prefix": "9.9.9.9/32", "dst_prefix": None, "action": "discard"}
    result = verify.parse_flowspec_match(SAMPLE_FLOWSPEC, rule)
    assert result["match_status"] == verify.MATCH_NOT_FOUND


def test_parse_flowspec_match_unrecognized_command_is_inconclusive():
    rule = {"src_prefix": "100.64.126.111/32", "dst_prefix": None, "action": "discard"}
    result = verify.parse_flowspec_match(SAMPLE_UNRECOGNIZED, rule)
    assert result["match_status"] == verify.MATCH_INCONCLUSIVE


# --- _split_prefix --------------------------------------------------------

def test_split_prefix_rejects_missing_mask():
    with pytest.raises(ValidationError):
        verify._split_prefix("203.0.113.20")


def test_split_prefix_rejects_garbage():
    with pytest.raises(ValidationError):
        verify._split_prefix("not-an-ip/32")


# --- verify_rtbh / verify_flowspec / verify_rule (SSH mockado) -----------

def test_verify_rtbh_sends_exact_match_command(patch_ssh):
    fake_conn = patch_ssh(SAMPLE_RTBH_FOUND)
    result = verify.verify_rtbh("203.0.113.20/32", "2626:669", "10.77.10.2", "NE8000BGP")
    assert fake_conn.sent == "display bgp routing-table 203.0.113.20 32"
    assert fake_conn.disconnected is True
    assert result["match_status"] == verify.MATCH_FOUND
    assert result["command"] == "display bgp routing-table 203.0.113.20 32"
    assert result["raw_output"] == SAMPLE_RTBH_FOUND


def test_verify_flowspec_sends_full_table_command(patch_ssh):
    fake_conn = patch_ssh(SAMPLE_FLOWSPEC)
    rule = {"src_prefix": "100.64.126.111/32", "dst_prefix": None, "action": "discard"}
    result = verify.verify_flowspec(rule, "NE8000BGP")
    assert fake_conn.sent == "display bgp flow routing-table"
    assert result["match_status"] == verify.MATCH_FOUND


def test_verify_rule_dispatches_rtbh_vs_flowspec_by_action(patch_ssh):
    patch_ssh(SAMPLE_RTBH_FOUND)
    bgp_cfg = {"rtbh_community": "2626:669", "nexthop_blackhole": "10.77.10.2"}
    rtbh_rule = {"action": "rtbh", "dst_prefix": "203.0.113.20/32"}
    result = verify.verify_rule(rtbh_rule, "NE8000BGP", bgp_cfg)
    assert result["match_status"] == verify.MATCH_FOUND

    patch_ssh(SAMPLE_FLOWSPEC)
    flow_rule = {"action": "discard", "src_prefix": "100.64.126.111/32", "dst_prefix": None}
    result2 = verify.verify_rule(flow_rule, "NE8000BGP", bgp_cfg)
    assert result2["match_status"] == verify.MATCH_FOUND
