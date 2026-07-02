import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from routercfg.templates import build_commands, load_templates, validate_field, ValidationError


def test_router_templates_yaml_loads_and_every_template_has_undo():
    templates = load_templates()
    assert templates, "router_templates.yaml deveria ter pelo menos um template"
    for t in templates:
        assert t["commands"]
        assert t["undo_commands"]


def test_netflow_export_happy_path():
    built = build_commands("netflow_export", {
        "collector_ip": "10.77.10.2",
        "collector_port": "2055",
        "interface": "GigabitEthernet0/0/1",
    })
    assert "ip netstream export host 10.77.10.2 2055" in built["commands"]
    assert "interface GigabitEthernet0/0/1" in built["commands"]
    assert any("undo ip netstream export host 10.77.10.2 2055" in c for c in built["undo_commands"])


def test_static_route_cidr_expands_to_network_and_mask():
    built = build_commands("static_route", {"dest": "203.0.113.0/24", "next_hop": "10.77.10.1"})
    assert "ip route-static 203.0.113.0 255.255.255.0 10.77.10.1" in built["commands"]
    assert "undo ip route-static 203.0.113.0 255.255.255.0 10.77.10.1" in built["undo_commands"]


def test_prefix_acl_wildcard_is_inverse_of_mask():
    built = build_commands("prefix_acl", {"acl_number": "2010", "action": "deny", "source": "198.51.100.0/24"})
    assert "rule deny source 198.51.100.0 0.0.0.255" in built["commands"]


def test_interface_admin_state_command_map():
    built = build_commands("interface_desc_state", {
        "interface": "GigabitEthernet0/0/2", "description": "link cliente X", "admin_state": "down",
    })
    assert "shutdown" in built["commands"]
    built_up = build_commands("interface_desc_state", {
        "interface": "GigabitEthernet0/0/2", "description": "link cliente X", "admin_state": "up",
    })
    assert "undo shutdown" in built_up["commands"]


@pytest.mark.parametrize("bad_value", [
    "10.0.0.1\nsystem-view",
    "10.0.0.1; reboot",
    "10.0.0.1 | reboot",
    "10.0.0.1\rreboot",
])
def test_newline_and_command_separators_are_rejected(bad_value):
    with pytest.raises(ValidationError):
        build_commands("netflow_export", {
            "collector_ip": bad_value, "collector_port": "2055", "interface": "GigabitEthernet0/0/1",
        })


def test_invalid_interface_name_rejected():
    with pytest.raises(ValidationError):
        build_commands("netflow_export", {
            "collector_ip": "10.77.10.2", "collector_port": "2055",
            "interface": "GigabitEthernet0/0/1; undo netstream inbound",
        })


def test_port_out_of_range_rejected():
    with pytest.raises(ValidationError):
        build_commands("netflow_export", {
            "collector_ip": "10.77.10.2", "collector_port": "999999", "interface": "GigabitEthernet0/0/1",
        })


def test_enum_rejects_unlisted_value():
    with pytest.raises(ValidationError):
        build_commands("prefix_acl", {"acl_number": "2010", "action": "drop", "source": "198.51.100.0/24"})


def test_required_field_missing_rejected():
    with pytest.raises(ValidationError):
        build_commands("static_route", {"dest": "203.0.113.0/24"})


def test_unknown_template_rejected():
    with pytest.raises(ValidationError):
        build_commands("does_not_exist", {})


def test_text_safe_rejects_shell_metacharacters():
    field = {"name": "description", "type": "text_safe", "required": True}
    with pytest.raises(ValidationError):
        validate_field(field, "ok`whoami`")
    assert validate_field(field, "link cliente X") == "link cliente X"
