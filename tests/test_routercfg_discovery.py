import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from routercfg.discovery import parse_bgp_config, parse_interfaces, parse_peer_routes, parse_vlans
from routercfg.templates import ValidationError

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


# Formato real observado (validado contra um NE8000 em produção): nomes de
# interface podem começar com dígito ("100GE0/1/54", não só "GigabitEthernet"),
# tem uma 5a coluna (VPN) depois de Physical/Protocol, e "*down" aparece de
# fato nos dados (não só na legenda).
SAMPLE_IF_BRIEF = """
*down: administratively down
^down: standby
(l): loopback

The number of interface that is UP in Physical is 3

Interface                         IP Address/Mask      Physical   Protocol VPN
100GE0/1/54                       177.86.23.193/30      up         up       --
25GE0/1/29(10G)                   unassigned             down       down    --
Eth-Trunk0.4001                   10.195.195.1/30       *down       down    --
GigabitEthernet0/0/1.100          192.168.100.1/24       up         up      --
"""


def test_parse_interfaces_extracts_name_ip_and_status():
    result = parse_interfaces(SAMPLE_IF_BRIEF)
    by_name = {i["name"]: i for i in result}
    assert by_name["100GE0/1/54"]["ip"] == "177.86.23.193/30"
    assert by_name["100GE0/1/54"]["physical"] == "up"
    assert by_name["GigabitEthernet0/0/1.100"]["ip"] == "192.168.100.1/24"


def test_parse_interfaces_handles_digit_leading_and_hyphenated_names():
    result = parse_interfaces(SAMPLE_IF_BRIEF)
    names = {i["name"] for i in result}
    assert "25GE0/1/29(10G)" in names
    assert "Eth-Trunk0.4001" in names


def test_parse_interfaces_marks_unassigned_ip_as_none():
    result = parse_interfaces(SAMPLE_IF_BRIEF)
    by_name = {i["name"]: i for i in result}
    assert by_name["25GE0/1/29(10G)"]["ip"] is None


def test_parse_interfaces_detects_admin_down():
    result = parse_interfaces(SAMPLE_IF_BRIEF)
    by_name = {i["name"]: i for i in result}
    assert by_name["Eth-Trunk0.4001"]["admin_down"] is True
    assert by_name["Eth-Trunk0.4001"]["physical"] == "down"
    assert by_name["100GE0/1/54"]["admin_down"] is False


def test_parse_interfaces_ignores_header_line():
    result = parse_interfaces(SAMPLE_IF_BRIEF)
    names = {i["name"] for i in result}
    assert "Interface" not in names


def test_parse_interfaces_does_not_bleed_across_lines():
    # regressão: um "\s*"/"\s+" antes de um grupo de captura casava através
    # da quebra de linha (\s inclui \n) e o próximo registro "vazava" pro
    # anterior — achado testando contra hardware real (ver comentário em
    # discovery.py acima de _IF_LINE_RE/_VLAN_LINE_RE).
    result = parse_interfaces(SAMPLE_IF_BRIEF)
    assert len(result) == 4
    for i in result:
        assert "\n" not in i["name"]
        assert i["ip"] is None or "\n" not in i["ip"]


# Formato real observado: cabeçalho é "VID  Name  Status  Ports" (não "Type"),
# e é comum "Name"/"Ports" virem em branco (só espaços) — foi exatamente esse
# caso que expôs o bug de linhas se misturando.
SAMPLE_VLAN_BRIEF = """
U:Up;D:Down;TG:Tagged;UT:Untagged;

VID  Name             Status  Ports
--------------------------------------------------------------------------------
100                  enable
200  CUSTOMER-200     enable  UT:GE0/0/2(U)  TG:GE0/0/3(U)
300                  disable
"""


def test_parse_vlans_extracts_vlan_id_and_status():
    result = parse_vlans(SAMPLE_VLAN_BRIEF)
    by_id = {v["vlan_id"]: v for v in result}
    assert by_id["100"]["status"] == "enable"
    assert by_id["300"]["status"] == "disable"


def test_parse_vlans_extracts_optional_name_and_ports():
    result = parse_vlans(SAMPLE_VLAN_BRIEF)
    by_id = {v["vlan_id"]: v for v in result}
    assert by_id["200"]["name"] == "CUSTOMER-200"
    assert "GE0/0/2" in by_id["200"]["ports"]
    assert by_id["100"]["name"] is None
    assert by_id["100"]["ports"] == ""


def test_parse_vlans_ignores_header_line():
    result = parse_vlans(SAMPLE_VLAN_BRIEF)
    ids = {v["vlan_id"] for v in result}
    assert "VID" not in ids


def test_parse_vlans_does_not_bleed_across_lines():
    # mesma regressão do teste de interfaces, mas foi aqui que o bug foi
    # encontrado primeiro: VLAN sem nome/portas (só espaços em branco depois
    # do status) fazia o VID/status da PRÓXIMA vlan aparecer dentro de
    # "ports" da vlan atual.
    result = parse_vlans(SAMPLE_VLAN_BRIEF)
    assert len(result) == 3
    by_id = {v["vlan_id"]: v for v in result}
    assert by_id["100"]["ports"] == ""
    assert "300" not in by_id["100"]["ports"]


SAMPLE_ADVERTISED_ROUTES = """
 Total Number of Routes: 2
     Network            NextHop        MED        LocPrf    PrefVal Path/Ogn
*>   203.0.113.0/24     0.0.0.0        0                     0       ?
*>   198.51.100.0/24    0.0.0.0        0                     0       ?
"""


def test_parse_peer_routes_extracts_prefixes_and_total():
    result = parse_peer_routes(SAMPLE_ADVERTISED_ROUTES, "200.201.202.1", "advertised")
    assert result["prefixes"] == ["198.51.100.0/24", "203.0.113.0/24"]
    assert result["total_reported"] == 2
    assert result["peer_ip"] == "200.201.202.1"
    assert result["direction"] == "advertised"


def test_parse_peer_routes_empty_output():
    result = parse_peer_routes("Total Number of Routes: 0\n", "200.201.202.1", "received")
    assert result["prefixes"] == []
    assert result["total_reported"] == 0


def test_discover_peer_routes_rejects_invalid_direction():
    from routercfg.discovery import discover_peer_routes
    with pytest.raises(ValidationError):
        discover_peer_routes("200.201.202.1", direction="both")


def test_discover_peer_routes_rejects_injection_in_peer_ip():
    from routercfg.discovery import discover_peer_routes
    with pytest.raises(ValidationError):
        discover_peer_routes("200.201.202.1; reboot", direction="advertised")
