import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from routercfg.discovery import parse_bgp_config

SAMPLE_CONFIG = """
#
bgp 65000
 router-id 10.77.10.1
 peer 200.201.202.1 as-number 65001
 peer 200.201.202.1 description Operadora-A
 peer 200.201.202.2 as-number 65002
 peer 200.201.202.2 description Operadora-B
 peer 200.201.202.2 ignore
 peer 200.201.202.3 group upstreams
 network 203.0.113.0 255.255.255.0
 network 198.51.100.0 255.255.255.0 route-policy SET-MED
 #
 ipv4-family unicast
  peer 200.201.202.1 enable
  peer 200.201.202.2 enable
  peer 200.201.202.3 enable
#
return
"""


def test_parses_local_as():
    result = parse_bgp_config(SAMPLE_CONFIG)
    assert result["local_as"] == "65000"


def test_parses_peers_with_as_number_and_description():
    result = parse_bgp_config(SAMPLE_CONFIG)
    by_ip = {p["peer_ip"]: p for p in result["peers"]}
    assert by_ip["200.201.202.1"]["remote_as"] == "65001"
    assert by_ip["200.201.202.1"]["description"] == "Operadora-A"
    assert by_ip["200.201.202.1"]["state"] == "up"


def test_parses_ignored_peer_as_down():
    result = parse_bgp_config(SAMPLE_CONFIG)
    by_ip = {p["peer_ip"]: p for p in result["peers"]}
    assert by_ip["200.201.202.2"]["state"] == "down"


def test_parses_group_based_peer_without_as_number():
    result = parse_bgp_config(SAMPLE_CONFIG)
    by_ip = {p["peer_ip"]: p for p in result["peers"]}
    assert by_ip["200.201.202.3"]["group"] == "upstreams"
    assert by_ip["200.201.202.3"]["remote_as"] is None
    assert by_ip["200.201.202.3"]["state"] == "up"


def test_parses_network_statements_with_cidr():
    result = parse_bgp_config(SAMPLE_CONFIG)
    cidrs = {n["cidr"] for n in result["networks"]}
    assert "203.0.113.0/24" in cidrs
    assert "198.51.100.0/24" in cidrs


def test_empty_config_returns_empty_lists():
    result = parse_bgp_config("")
    assert result == {"local_as": None, "peers": [], "networks": []}
