"""Testa _cmd_learn_templates — deriva ddos_bps_threshold E ddos_pps_threshold do
baseline EWMA já acumulado (prefix_baseline) e agrupa prefixos parecidos num
template reutilizável, em vez de copiar o mesmo número pra todo prefixo (achado
real 2026-07-10: 30 Gbps repetido em 7 dos 8 prefixos, com tráfego real variando
de ~0.02 a ~10 Gbps).

Achado real 2026-07-10 (2ª rodada): a 1ª versão só ajustava bps — um prefixo com
pps_mean real acima do default global (100k) continuava disparando ataque falso
só pelo pps, mesmo com o bps já corrigido. Os testes abaixo cobrem os dois."""

from __future__ import annotations

import asyncio

from collector import configio

from test_socket_server_commands import FakeDaemon, dispatch, make_server


def _insert_baseline(conn, dst_prefix, bps_mean, bps_std, samples, pps_mean=0, pps_std=0):
    conn.execute(
        """INSERT INTO prefix_baseline (dst_prefix, bps_mean, bps_var, pps_mean, pps_var, samples, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, 0)""",
        (dst_prefix, bps_mean, bps_std ** 2, pps_mean, pps_std ** 2, samples),
    )
    conn.commit()


def _server(tmp_path, protected):
    srv = make_server(tmp_path, protected_prefixes=protected)
    srv.daemon.config["detection"] = {"baseline_sigma": 4, "baseline_min_samples": 120}
    srv.daemon.config["detection_templates"] = {}
    return srv


def test_dry_run_does_not_write_anything(tmp_path):
    protected = [{"prefix": "177.86.17.0/24", "customer": "X", "capacity_mbps": 100000}]
    server = _server(tmp_path, protected)
    _insert_baseline(server.daemon.conn, "177.86.17.0/24", bps_mean=2.36e9, bps_std=0.71e9, samples=7000)

    resp = dispatch(server, {"cmd": "learn_templates"})

    assert resp["ok"] is True
    assert resp["applied"] is False
    assert resp["results"][0]["ready"] is True
    assert resp["results"][0]["new_threshold"] == 5_200_000_000  # 2.36e9 + 4*0.71e9, arredondado
    assert configio.load_detection_templates(server.daemon.config["_detection_templates_file"]) == {}
    assert server.daemon.reload_calls == 0


def test_prefix_without_enough_samples_is_not_ready(tmp_path):
    protected = [{"prefix": "177.86.19.0/24", "customer": "", "capacity_mbps": 100000}]
    server = _server(tmp_path, protected)
    _insert_baseline(server.daemon.conn, "177.86.19.0/24", bps_mean=0.08e9, bps_std=0.04e9, samples=50)

    resp = dispatch(server, {"cmd": "learn_templates"})

    assert resp["results"][0]["ready"] is False
    assert resp["results"][0]["samples"] == 50
    assert "new_threshold" not in resp["results"][0]


def test_prefix_without_any_baseline_row_is_not_ready(tmp_path):
    protected = [{"prefix": "203.0.113.0/24", "customer": "", "capacity_mbps": 1000}]
    server = _server(tmp_path, protected)

    resp = dispatch(server, {"cmd": "learn_templates"})

    assert resp["results"][0]["ready"] is False
    assert resp["results"][0]["samples"] == 0


def test_similar_prefixes_group_into_the_same_template(tmp_path):
    protected = [
        {"prefix": "177.86.16.0/24", "customer": "A", "capacity_mbps": 100000},
        {"prefix": "177.86.19.0/24", "customer": "B", "capacity_mbps": 100000},
        {"prefix": "177.86.22.0/24", "customer": "C", "capacity_mbps": 100000},
    ]
    server = _server(tmp_path, protected)
    # os 3 têm tráfego bem baixo -> todos batem no piso (500 Mbps) -> mesmo template
    _insert_baseline(server.daemon.conn, "177.86.16.0/24", bps_mean=0.02e9, bps_std=0.01e9, samples=24000)
    _insert_baseline(server.daemon.conn, "177.86.19.0/24", bps_mean=0.08e9, bps_std=0.04e9, samples=24000)
    _insert_baseline(server.daemon.conn, "177.86.22.0/24", bps_mean=0.0, bps_std=0.0, samples=24000)

    resp = dispatch(server, {"cmd": "learn_templates"})

    names = {r["new_template"] for r in resp["results"]}
    assert len(names) == 1
    assert all(r["new_threshold"] == 500_000_000 for r in resp["results"])


def test_dissimilar_prefixes_get_separate_templates(tmp_path):
    protected = [
        {"prefix": "177.86.20.0/24", "customer": "A", "capacity_mbps": 100000},
        {"prefix": "177.86.21.0/24", "customer": "B", "capacity_mbps": 100000},
    ]
    server = _server(tmp_path, protected)
    _insert_baseline(server.daemon.conn, "177.86.20.0/24", bps_mean=8.92e9, bps_std=2.39e9, samples=7000)
    _insert_baseline(server.daemon.conn, "177.86.21.0/24", bps_mean=10.04e9, bps_std=2.63e9, samples=7000)

    resp = dispatch(server, {"cmd": "learn_templates"})

    names = {r["new_template"] for r in resp["results"]}
    assert len(names) == 2


def test_apply_writes_template_and_reassigns_prefix(tmp_path):
    protected = [{"prefix": "177.86.17.0/24", "customer": "POX Network Core",
                  "capacity_mbps": 100000, "auto_mitigate": False, "notify_wa": False}]
    server = _server(tmp_path, protected)
    _insert_baseline(server.daemon.conn, "177.86.17.0/24", bps_mean=2.36e9, bps_std=0.71e9, samples=7000)

    resp = dispatch(server, {"cmd": "learn_templates", "apply": True})

    assert resp["applied"] is True
    templates = configio.load_detection_templates(server.daemon.config["_detection_templates_file"])
    template_name = resp["results"][0]["new_template"]
    assert templates[template_name]["ddos_bps_threshold"] == 5_200_000_000

    items = configio.load_yaml_list(server.daemon.config["_protected_prefixes_file"])
    entry = next(i for i in items if i["prefix"] == "177.86.17.0/24")
    assert entry["template"] == template_name
    assert "thresholds" not in entry
    assert server.daemon.reload_calls == 1


def test_apply_preserves_customer_capacity_auto_mitigate_notify_wa(tmp_path):
    protected = [{"prefix": "177.86.20.0/24", "customer": "Cliente Importante",
                  "capacity_mbps": 100000, "auto_mitigate": True, "notify_wa": True}]
    server = _server(tmp_path, protected)
    _insert_baseline(server.daemon.conn, "177.86.20.0/24", bps_mean=8.92e9, bps_std=2.39e9, samples=7000)

    dispatch(server, {"cmd": "learn_templates", "apply": True})

    items = configio.load_yaml_list(server.daemon.config["_protected_prefixes_file"])
    entry = next(i for i in items if i["prefix"] == "177.86.20.0/24")
    assert entry["customer"] == "Cliente Importante"
    assert entry["capacity_mbps"] == 100000
    assert entry["auto_mitigate"] is True
    assert entry["notify_wa"] is True


def test_apply_only_touches_ready_prefixes(tmp_path):
    protected = [
        {"prefix": "177.86.17.0/24", "customer": "A", "capacity_mbps": 100000},
        {"prefix": "177.86.19.0/24", "customer": "B", "capacity_mbps": 100000},
    ]
    server = _server(tmp_path, protected)
    _insert_baseline(server.daemon.conn, "177.86.17.0/24", bps_mean=2.36e9, bps_std=0.71e9, samples=7000)
    # 177.86.19.0/24 sem baseline suficiente -> não deve ser tocado

    dispatch(server, {"cmd": "learn_templates", "apply": True})

    items = configio.load_yaml_list(server.daemon.config["_protected_prefixes_file"])
    entry_19 = next(i for i in items if i["prefix"] == "177.86.19.0/24")
    assert "template" not in entry_19


def test_min_threshold_bps_overridable(tmp_path):
    protected = [{"prefix": "177.86.22.0/24", "customer": "", "capacity_mbps": 100000}]
    server = _server(tmp_path, protected)
    _insert_baseline(server.daemon.conn, "177.86.22.0/24", bps_mean=0.0, bps_std=0.0, samples=24000)

    resp = dispatch(server, {"cmd": "learn_templates", "min_threshold_bps": 100_000_000})

    assert resp["results"][0]["new_threshold"] == 100_000_000


# --- ddos_pps_threshold (achado real 2026-07-10, 2ª rodada) -----------------

def test_pps_threshold_derived_from_baseline(tmp_path):
    """Achado real: prefixo com pps_mean real (211.383) bem acima do default global
    (100.000) disparava ataque falso só pelo pps, mesmo com bps já corrigido."""
    protected = [{"prefix": "177.86.17.0/24", "customer": "", "capacity_mbps": 100000}]
    server = _server(tmp_path, protected)
    server.daemon.config["detection"]["baseline_sigma"] = 8
    _insert_baseline(server.daemon.conn, "177.86.17.0/24", bps_mean=2.35e9, bps_std=0.72e9,
                      samples=7000, pps_mean=211_383, pps_std=64_159)

    resp = dispatch(server, {"cmd": "learn_templates"})

    r = resp["results"][0]
    # 211383 + 8*64159 = 724655 -> arredonda pra cima em passos de 10k
    assert r["new_pps_threshold"] == 730_000
    assert r["old_effective_pps_threshold"] == 100_000  # default global, nunca configurado pra esse prefixo


def test_pps_threshold_uses_max_within_bps_group(tmp_path):
    """2 prefixos caem no MESMO template por bps, mas com pps bem diferentes — o
    template precisa usar o pps MAIOR dos dois, senão um deles fica sub-protegido."""
    protected = [
        {"prefix": "177.86.16.0/24", "customer": "A", "capacity_mbps": 100000},
        {"prefix": "177.86.19.0/24", "customer": "B", "capacity_mbps": 100000},
    ]
    server = _server(tmp_path, protected)
    # mesmo bps baixo (ambos batem no piso de 500Mbps) -> mesmo template
    _insert_baseline(server.daemon.conn, "177.86.16.0/24", bps_mean=0.02e9, bps_std=0.01e9,
                      samples=24000, pps_mean=1_000, pps_std=100)
    _insert_baseline(server.daemon.conn, "177.86.19.0/24", bps_mean=0.02e9, bps_std=0.01e9,
                      samples=24000, pps_mean=50_000, pps_std=5_000)

    resp = dispatch(server, {"cmd": "learn_templates"})

    by_prefix = {r["prefix"]: r for r in resp["results"]}
    assert by_prefix["177.86.16.0/24"]["new_template"] == by_prefix["177.86.19.0/24"]["new_template"]
    # os dois usam o MESMO pps no template — o maior dos dois sugeridos
    assert by_prefix["177.86.16.0/24"]["new_pps_threshold"] == by_prefix["177.86.19.0/24"]["new_pps_threshold"]
    # 50000 + 4*5000 = 70000 (sigma default=4) -> veio do prefixo de pps mais alto
    # (o outro sozinho sugeriria só 1000+4*100=1400, arredondado 10000)
    assert by_prefix["177.86.16.0/24"]["new_pps_threshold"] == 70_000


def test_apply_writes_pps_threshold_into_template(tmp_path):
    protected = [{"prefix": "177.86.17.0/24", "customer": "", "capacity_mbps": 100000}]
    server = _server(tmp_path, protected)
    server.daemon.config["detection"]["baseline_sigma"] = 8
    _insert_baseline(server.daemon.conn, "177.86.17.0/24", bps_mean=2.35e9, bps_std=0.72e9,
                      samples=7000, pps_mean=211_383, pps_std=64_159)

    resp = dispatch(server, {"cmd": "learn_templates", "apply": True})

    templates = configio.load_detection_templates(server.daemon.config["_detection_templates_file"])
    name = resp["results"][0]["new_template"]
    assert templates[name]["ddos_pps_threshold"] == 730_000
    assert templates[name]["ddos_bps_threshold"] > 0


def test_min_threshold_pps_overridable(tmp_path):
    protected = [{"prefix": "177.86.22.0/24", "customer": "", "capacity_mbps": 100000}]
    server = _server(tmp_path, protected)
    _insert_baseline(server.daemon.conn, "177.86.22.0/24", bps_mean=0.0, bps_std=0.0,
                      samples=24000, pps_mean=0, pps_std=0)

    resp = dispatch(server, {"cmd": "learn_templates", "min_threshold_pps": 50_000})

    assert resp["results"][0]["new_pps_threshold"] == 50_000
