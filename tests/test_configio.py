"""Testa detection_templates.yaml/detection_overrides.yaml (ajuste fino de limiares
via portal/CLI) e a mesclagem deles em load_config — o resto de configio.py
(protected_prefixes/whitelist/toggles/mitigation_profiles) já é exercitado
indiretamente pelos outros testes que usam load_config."""

from __future__ import annotations

import pytest

from collector import configio


# --- detection_templates.yaml -------------------------------------------------

def test_load_detection_templates_missing_file_returns_empty(tmp_path):
    assert configio.load_detection_templates(str(tmp_path / "nao-existe.yaml")) == {}


def test_save_detection_template_creates_new(tmp_path):
    path = tmp_path / "detection_templates.yaml"
    result = configio.save_detection_template(
        str(path), "cgnat", {"ddos_bps_threshold": 5_000_000_000, "ddos_pps_threshold": 1_000_000},
        description="pool CGNAT",
    )
    assert result["cgnat"]["ddos_bps_threshold"] == 5_000_000_000
    assert result["cgnat"]["description"] == "pool CGNAT"
    assert configio.load_detection_templates(str(path)) == result


def test_save_detection_template_overwrites_existing_fully(tmp_path):
    path = tmp_path / "detection_templates.yaml"
    configio.save_detection_template(str(path), "cgnat", {"ddos_bps_threshold": 5_000_000_000, "ddos_pps_threshold": 1_000_000})
    result = configio.save_detection_template(str(path), "cgnat", {"ddos_bps_threshold": 8_000_000_000})
    assert result["cgnat"] == {"ddos_bps_threshold": 8_000_000_000}  # ddos_pps_threshold não sobrevive


def test_save_detection_template_preserves_other_templates(tmp_path):
    path = tmp_path / "detection_templates.yaml"
    configio.save_detection_template(str(path), "cgnat", {"ddos_bps_threshold": 5_000_000_000})
    result = configio.save_detection_template(str(path), "cdn", {"ddos_bps_threshold": 30_000_000_000})
    assert "cgnat" in result and "cdn" in result


def test_save_detection_template_rejects_unknown_key(tmp_path):
    path = tmp_path / "detection_templates.yaml"
    with pytest.raises(ValueError):
        configio.save_detection_template(str(path), "cgnat", {"nao_existe": 1})
    assert not path.exists()


def test_save_detection_template_rejects_non_positive_int(tmp_path):
    path = tmp_path / "detection_templates.yaml"
    with pytest.raises(ValueError):
        configio.save_detection_template(str(path), "cgnat", {"ddos_bps_threshold": 0})
    with pytest.raises(ValueError):
        configio.save_detection_template(str(path), "cgnat", {"ddos_bps_threshold": "500"})


def test_save_detection_template_rejects_bad_name(tmp_path):
    path = tmp_path / "detection_templates.yaml"
    with pytest.raises(ValueError):
        configio.save_detection_template(str(path), "CGNAT Ruim!", {"ddos_bps_threshold": 5_000_000_000})


def test_delete_detection_template_removes_entry(tmp_path):
    path = tmp_path / "detection_templates.yaml"
    configio.save_detection_template(str(path), "cgnat", {"ddos_bps_threshold": 5_000_000_000})
    configio.save_detection_template(str(path), "cdn", {"ddos_bps_threshold": 30_000_000_000})
    result = configio.delete_detection_template(str(path), "cgnat")
    assert result == {"cdn": {"ddos_bps_threshold": 30_000_000_000}}


def test_delete_detection_template_unknown_raises(tmp_path):
    path = tmp_path / "detection_templates.yaml"
    configio.save_detection_template(str(path), "cgnat", {"ddos_bps_threshold": 5_000_000_000})
    with pytest.raises(ValueError):
        configio.delete_detection_template(str(path), "nao_existe")


# --- detection_overrides.yaml (ajuste fino via portal/CLI) ---------------------

def test_load_detection_overrides_missing_file_returns_empty(tmp_path):
    assert configio.load_detection_overrides(str(tmp_path / "nao-existe.yaml")) == {}


def test_save_detection_overrides_roundtrip(tmp_path):
    path = tmp_path / "detection_overrides.yaml"
    result = configio.save_detection_overrides(str(path), {"ddos_bps_threshold": 800_000_000})
    assert result == {"ddos_bps_threshold": 800_000_000}
    assert configio.load_detection_overrides(str(path)) == {"ddos_bps_threshold": 800_000_000}


def test_save_detection_overrides_applies_all_in_one_write(tmp_path):
    path = tmp_path / "detection_overrides.yaml"
    result = configio.save_detection_overrides(str(path), {
        "ddos_bps_threshold": 800_000_000, "ddos_pps_threshold": 150_000, "baseline_enabled": False,
    })
    assert result["ddos_bps_threshold"] == 800_000_000
    assert result["baseline_enabled"] is False


def test_save_detection_overrides_none_value_removes_key(tmp_path):
    path = tmp_path / "detection_overrides.yaml"
    configio.save_detection_overrides(str(path), {"ddos_bps_threshold": 800_000_000})
    result = configio.save_detection_overrides(str(path), {"ddos_bps_threshold": None})
    assert "ddos_bps_threshold" not in result


def test_save_detection_overrides_rejects_unknown_key(tmp_path):
    path = tmp_path / "detection_overrides.yaml"
    with pytest.raises(ValueError):
        configio.save_detection_overrides(str(path), {"nao_existe": 1})
    assert not path.exists()


def test_load_detection_overrides_ignores_unknown_keys_from_hand_edited_file(tmp_path):
    path = tmp_path / "detection_overrides.yaml"
    path.write_text("ddos_bps_threshold: 800000000\nlixo_desconhecido: 1\n")
    assert configio.load_detection_overrides(str(path)) == {"ddos_bps_threshold": 800000000}


# --- load_config: mescla templates + overrides ---------------------------------

def test_load_config_merges_detection_overrides_over_yaml_defaults(tmp_path):
    config_path = tmp_path / "config.yaml"
    overrides_path = tmp_path / "detection_overrides.yaml"
    configio.save_detection_overrides(str(overrides_path), {"ddos_bps_threshold": 800_000_000})
    config_path.write_text(
        f"daemon: {{socket: /tmp/x.sock}}\n"
        f"database: {{path: {tmp_path}/db.sqlite, aggregate_interval_s: 30, retention_days: 1}}\n"
        f"detection: {{ddos_bps_threshold: 500000000, ddos_pps_threshold: 100000}}\n"
        f"detection_overrides_file: {overrides_path}\n"
        f"protected_prefixes_file: {tmp_path}/protected_prefixes.yaml\n"
        f"whitelist_file: {tmp_path}/whitelist.yaml\n"
        f"detection_toggles_file: {tmp_path}/detection_toggles.yaml\n"
        f"mitigation_profiles_file: {tmp_path}/mitigation_profiles.yaml\n"
        f"detection_templates_file: {tmp_path}/detection_templates.yaml\n",
    )
    cfg = configio.load_config(str(config_path))
    assert cfg["detection"]["ddos_bps_threshold"] == 800_000_000  # veio do override
    assert cfg["detection"]["ddos_pps_threshold"] == 100_000  # não mexido, veio do config.yaml


def test_load_config_loads_detection_templates(tmp_path):
    config_path = tmp_path / "config.yaml"
    templates_path = tmp_path / "detection_templates.yaml"
    configio.save_detection_template(str(templates_path), "cgnat", {"ddos_bps_threshold": 5_000_000_000})
    config_path.write_text(
        f"daemon: {{socket: /tmp/x.sock}}\n"
        f"database: {{path: {tmp_path}/db.sqlite, aggregate_interval_s: 30, retention_days: 1}}\n"
        f"detection: {{}}\n"
        f"detection_templates_file: {templates_path}\n"
        f"protected_prefixes_file: {tmp_path}/protected_prefixes.yaml\n"
        f"whitelist_file: {tmp_path}/whitelist.yaml\n"
        f"detection_toggles_file: {tmp_path}/detection_toggles.yaml\n"
        f"mitigation_profiles_file: {tmp_path}/mitigation_profiles.yaml\n"
        f"detection_overrides_file: {tmp_path}/detection_overrides.yaml\n",
    )
    cfg = configio.load_config(str(config_path))
    assert cfg["detection_templates"]["cgnat"]["ddos_bps_threshold"] == 5_000_000_000
