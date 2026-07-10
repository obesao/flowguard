#!/root/flowguard/venv/bin/python3
"""flowguard-cli — cliente de terminal para o FlowGuard (status, ataques, regras, monitor interativo)."""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from pathlib import Path

import yaml
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table

from collector import configio
from warmode.executor import list_devices, run_war_mode, run_war_mode_revert

DEFAULT_CONFIG_PATH = "/root/flowguard/config.yaml"
DEFAULT_SOCKET_PATH = "/var/run/flowguard.sock"

console = Console()


def resolve_socket_path(config_path: str) -> str:
    try:
        with open(config_path, "r", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        return cfg["daemon"]["socket"]
    except (OSError, KeyError, TypeError):
        return DEFAULT_SOCKET_PATH


def send_command(sock_path: str, payload: dict, timeout: float = 6.0) -> dict:
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(sock_path)
            sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))
            sock.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        data = b"".join(chunks).decode("utf-8").strip()
        return json.loads(data) if data else {"ok": False, "error": "resposta vazia do daemon"}
    except FileNotFoundError:
        return {"ok": False, "error": f"socket não encontrado em {sock_path} — o daemon está rodando?"}
    except ConnectionRefusedError:
        return {"ok": False, "error": "conexão recusada — daemon não está escutando no socket"}
    except PermissionError:
        return {"ok": False, "error": "permissão negada ao acessar o socket (rode como root)"}
    except socket.timeout:
        return {"ok": False, "error": "timeout ao falar com o daemon"}
    except json.JSONDecodeError:
        return {"ok": False, "error": "resposta inválida do daemon"}


def fmt_bps(bps: float) -> str:
    bps = float(bps)
    if bps >= 1e9:
        return f"{bps / 1e9:.2f} Gbps"
    if bps >= 1e6:
        return f"{bps / 1e6:.1f} Mbps"
    if bps >= 1e3:
        return f"{bps / 1e3:.0f} Kbps"
    return f"{bps:.0f} bps"


def fmt_bytes(n: float) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def fmt_duration(seconds: int) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"


PROTO_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP"}


def proto_name(proto: int) -> str:
    return PROTO_NAMES.get(int(proto), str(proto))


def die_on_error(resp: dict) -> None:
    if not resp.get("ok"):
        console.print(f"[red]Erro:[/red] {resp.get('error', 'desconhecido')}")
        sys.exit(1)


# --- subcomandos ---------------------------------------------------------

def fmt_bgp_state(bgp: dict) -> str:
    if bgp.get("peer_state") == "up":
        return "[bold green]Up[/bold green]"
    return "[bold red]Down/Idle[/bold red]"


def cmd_status(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "status"})
    die_on_error(resp)
    bgp = send_command(sock_path, {"cmd": "bgp_status"})
    bgp_pppoe = send_command(sock_path, {"cmd": "bgp_status", "peer": "pppoe"})
    table = Table(title="FlowGuard — Status do Daemon", show_header=False)
    table.add_row("PID", str(resp["pid"]))
    table.add_row("Uptime", f"{resp['uptime_s']:.0f}s")
    table.add_row("Tráfego agregado", fmt_bps(resp["bps"]))
    table.add_row("Pacotes/s", f"{resp['pps']:,}".replace(",", "."))
    table.add_row("Flows agregados", str(resp["flows"]))
    table.add_row("Ataques ativos", str(resp["active_attacks"]))
    table.add_row("Regras FlowSpec ativas", str(resp["active_rules"]))
    if bgp.get("ok"):
        peer_line = fmt_bgp_state(bgp)
        if bgp.get("peer_ip"):
            peer_line += f"  ({bgp['peer_ip']})"
        table.add_row("BGP (ExaBGP) — NE8000BGP", peer_line)
    else:
        table.add_row("BGP (ExaBGP) — NE8000BGP", f"[dim]indisponível: {bgp.get('error')}[/dim]")
    if bgp_pppoe.get("ok") and bgp_pppoe.get("peer_state") != "unconfigured":
        peer_line = fmt_bgp_state(bgp_pppoe)
        if bgp_pppoe.get("peer_ip"):
            peer_line += f"  ({bgp_pppoe['peer_ip']})"
        table.add_row("BGP (ExaBGP) — NE8000-PPPOE", peer_line)
    console.print(table)


def cmd_top(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "top", "limit": 20})
    die_on_error(resp)
    table = Table(title="Top 20 Prefixos (inbound)")
    table.add_column("Prefixo")
    table.add_column("Tráfego", justify="right")
    table.add_column("Pacotes/s", justify="right")
    for row in resp["top_prefixes"]:
        table.add_row(row["dst_prefix"], fmt_bps(row["bps"]), f"{row['pps']:,}".replace(",", "."))
    console.print(table)


def cmd_flows(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "flows", "limit": 20})
    die_on_error(resp)
    table = Table(title="Top 20 Flows por Volume")
    table.add_column("Prefixo")
    table.add_column("Proto")
    table.add_column("Porta")
    table.add_column("Tráfego", justify="right")
    table.add_column("Origens")
    for row in resp["flows"]:
        sources = ", ".join(json.loads(row["top_src_ips"] or "[]")[:3])
        table.add_row(row["dst_prefix"], proto_name(row["protocol"]), str(row["dst_port"]),
                      fmt_bps(row["bps"]), sources)
    console.print(table)


def _fmt_mitigation_action(action: str | None) -> str:
    if action == "rtbh":
        return "RTBH"
    if action and action.startswith("rate-limit:"):
        return f"limitado a {int(action.split(':', 1)[1]) // 1_000_000} Mbps"
    return "discard"


# pedido do usuário: "ativo" sozinho não diz se está REALMENTE acontecendo
# agora — um ataque fica "ativo" enquanto o atacante mandar tráfego (correto),
# mas nada avisava quando isso já tinha parado há muito tempo e o registro só
# ainda não fechou sozinho (ver close_stale_attacks, que fecha só depois de
# horas sem reconfirmação). ts_last_seen é atualizado a cada ciclo em que o
# ataque continua confirmado; janela "fresca" de 90s cobre ~3 ciclos de
# agregação (30s padrão), com folga pra jitter.
_ACTIVITY_FRESH_WINDOW_S = 90


def _fmt_activity_freshness(ts_last_seen: int | None, row_open: bool) -> str:
    if not row_open or not ts_last_seen:
        return "-"
    age_s = int(time.time()) - ts_last_seen
    if age_s < _ACTIVITY_FRESH_WINDOW_S:
        return "[green]🟢 em andamento[/green]"
    return f"[yellow]🟡 sem atividade há {fmt_duration(age_s)}[/yellow]"


# pedido do usuário: se o ataque já não está mais acontecendo de verdade
# (🟡 sem atividade — ver _fmt_activity_freshness acima), a Mitigação não deve
# mais gritar "⚠ sem proteção" (é alarme de "ainda te atacando sem bloqueio",
# não de "já te atacou uma vez sem bloqueio"). Mesmo critério do 🟢 acima.
def _is_genuinely_active(ts_end: int | None, ts_last_seen: int | None) -> bool:
    if ts_end or not ts_last_seen:
        return False
    return (int(time.time()) - ts_last_seen) < _ACTIVITY_FRESH_WINDOW_S


def _fmt_attack_mitigation_cell(mitigation: dict | None, row_open: bool = False) -> str:
    if not mitigation:
        return "[dim]sem mitigação[/dim]"
    label = _fmt_mitigation_action(mitigation.get("action"))
    if mitigation.get("active"):
        return f"[green]🛡 ativa ({label})[/green]"
    # ataque GENUINAMENTE ativo (ver _is_genuinely_active) com mitigação já
    # encerrada = cliente SEM proteção agora, não é só histórico
    if row_open:
        return f"[red]⚠ sem proteção ({label})[/red]"
    return f"[dim]encerrada ({label})[/dim]"


def cmd_attacks(args: argparse.Namespace, sock_path: str) -> None:
    if args.id is not None:
        cmd_attack_detail(args.id, sock_path)
        return

    resp = send_command(sock_path, {"cmd": "attacks", "history": args.history, "window": args.window})
    die_on_error(resp)
    title = f"Histórico de Ataques ({args.window})" if args.history else "Ataques Ativos"
    table = Table(title=title)
    table.add_column("ID")
    table.add_column("Alvo")
    table.add_column("Tipo")
    table.add_column("Severidade")
    table.add_column("Pico")
    table.add_column("Atividade")
    table.add_column("Mitigação")
    table.add_column("IA")
    for row in resp["attacks"]:
        row_open = not row.get("ts_end")
        genuinely_active = _is_genuinely_active(row.get("ts_end"), row.get("ts_last_seen"))
        table.add_row(
            str(row["id"]), row["dst_prefix"], row["attack_type"], row["severity"],
            fmt_bps(row["bps_peak"] or 0), _fmt_activity_freshness(row.get("ts_last_seen"), row_open),
            _fmt_attack_mitigation_cell(row.get("mitigation"), genuinely_active),
            "sim" if row.get("ai_analysis") else "-",
        )
    if not resp["attacks"]:
        console.print(f"[green]{title}: nenhum registro.[/green]")
    else:
        console.print(table)
        console.print("[dim]use 'flowguard-cli attacks --id <ID>' para ver o detalhamento e a análise de IA[/dim]")


def cmd_attack_detail(attack_id: int, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "attack_detail", "attack_id": attack_id})
    die_on_error(resp)
    attack, detail = resp["attack"], resp["detail"]
    summary = detail.get("summary", {})

    header = (
        f"[bold]{attack['attack_type']}[/bold] em {attack['dst_prefix']} "
        f"({attack.get('customer') or '?'})\n"
        f"Severidade: {attack['severity']}  |  Pico: {fmt_bps(attack['bps_peak'] or 0)}, "
        f"{attack['pps_peak'] or 0:,} pps\n"
        f"Status: {'encerrado' if attack['ts_end'] else '[red]ativo[/red]'}"
        f"{'  |  Atividade: ' + _fmt_activity_freshness(attack.get('ts_last_seen'), not attack['ts_end']) if not attack['ts_end'] else ''}"
        f"{'  |  Alvo (host): ' + attack['target_host'] if attack.get('target_host') else ''}\n"
        f"Mitigação: {_fmt_attack_mitigation_cell(attack.get('mitigation'), _is_genuinely_active(attack.get('ts_end'), attack.get('ts_last_seen')))}\n"
        f"Duração: {fmt_duration(summary.get('duration_s', 0))}  |  "
        f"Total: {fmt_bytes(summary.get('total_bytes', 0))}, "
        f"{summary.get('total_packets', 0):,} pacotes, "
        f"{summary.get('total_flows', 0):,} flows"
    )
    console.print(Panel(header, title=f"Ataque #{attack_id}"))

    ports_table = Table(title="Portas/protocolos dominantes")
    ports_table.add_column("Protocolo")
    ports_table.add_column("Porta")
    ports_table.add_column("Tráfego")
    ports_table.add_column("Bytes totais")
    ports_table.add_column("Pacotes totais")
    ports_table.add_column("Tam. médio pkt")
    ports_table.add_column("Flows")
    for p in detail["by_port"]:
        ports_table.add_row(
            str(p["protocol"]), str(p["dst_port"]), fmt_bps(p["bps"]),
            fmt_bytes(p.get("total_bytes", 0)), f"{p.get('total_packets', 0):,}",
            f"{p.get('avg_pkt_size', 0)} B", f"{p.get('flow_count', 0):,}",
        )
    console.print(ports_table)

    sources_table = Table(title="Principais IPs de origem")
    sources_table.add_column("IP")
    sources_table.add_column("Ocorrências")
    for s in detail["top_sources"]:
        sources_table.add_row(s["ip"], str(s["occurrences"]))
    console.print(sources_table)

    if attack.get("ai_analysis"):
        console.print(Panel(attack["ai_analysis"], title="Análise de IA", border_style="cyan"))
    else:
        console.print("[dim]sem análise de IA para este ataque (desativada, severidade abaixo do "
                       "limiar configurado, ou rate limit atingido no momento da detecção).[/dim]")


def _fmt_rule_mechanism(action: str) -> str:
    return "RTBH" if action == "rtbh" else "FlowSpec"


def _fmt_rule_trigger(trigger_type: str | None) -> str:
    return "automático" if trigger_type == "auto" else "manual"


def _resolve_device_name(peer: str, bgp_cfg: dict) -> str:
    key = "peer_device_main" if peer == "main" else f"peer_device_{peer}"
    device_name = bgp_cfg.get(key)
    return device_name or ("NE8000BGP" if peer == "main" else peer)


def cmd_rules(args: argparse.Namespace, sock_path: str) -> None:
    if getattr(args, "history", False):
        _cmd_rules_history(args)
        return
    resp = send_command(sock_path, {"cmd": "rules"})
    die_on_error(resp)
    table = Table(title="Regras FlowSpec Ativas")
    table.add_column("ID")
    table.add_column("Origem")
    table.add_column("Destino")
    table.add_column("Ação")
    table.add_column("Mecanismo")
    table.add_column("Equipamento")
    table.add_column("Gatilho")
    table.add_column("Expira em")
    now = time.time()
    for row in resp["rules"]:
        ttl = max(0, int(row["expires_at"] - now))
        table.add_row(
            str(row["id"]), row.get("src_prefix") or "-", row.get("dst_prefix") or "-", row["action"],
            _fmt_rule_mechanism(row["action"]), row.get("device_name") or "-",
            _fmt_rule_trigger(row.get("trigger_type")), f"{ttl}s",
        )
    if not resp["rules"]:
        console.print("[green]Nenhuma regra FlowSpec ativa.[/green]")
    else:
        console.print(table)


def _cmd_rules_history(args: argparse.Namespace) -> None:
    """Lê TODAS as regras FlowSpec/RTBH já criadas (ativas ou não) direto do
    SQLite em modo read-only — não passa pelo socket/daemon (mesmo padrão
    standalone do routercfg), então funciona mesmo se o daemon estiver fora
    do ar e não precisa de nenhuma mudança no processo já rodando."""
    import sqlite3

    from collector import storage

    with open(args.config, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    db_path = cfg["database"]["path"]
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        rules = storage.list_flowspec_rules(conn, active_only=False)
    finally:
        conn.close()

    bgp_cfg = cfg.get("bgp", {})
    table = Table(title=f"Histórico completo de regras FlowSpec/RTBH ({len(rules)})")
    table.add_column("ID")
    table.add_column("Criada em")
    table.add_column("App")
    table.add_column("Origem")
    table.add_column("Destino")
    table.add_column("Ação")
    table.add_column("Mecanismo")
    table.add_column("Equipamento")
    table.add_column("Gatilho")
    table.add_column("Rótulo")
    table.add_column("Status")
    for row in rules:
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(row["created_at"]))
        status = "[green]ativa[/green]" if row["active"] else "[dim]expirada/removida[/dim]"
        app = "ClientGuard" if row.get("origin") == "clientguard" else "FlowGuard"
        peer = row.get("peer") or "main"
        table.add_row(str(row["id"]), when, app, row.get("src_prefix") or "-", row.get("dst_prefix") or "-",
                      row["action"], _fmt_rule_mechanism(row["action"]), _resolve_device_name(peer, bgp_cfg),
                      _fmt_rule_trigger(row.get("trigger_type")), row.get("label") or "-", status)
    if not rules:
        console.print("[yellow]Nenhuma regra FlowSpec/RTBH foi criada ainda.[/yellow]")
    else:
        console.print(table)


def cmd_monitor_list(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "monitor_list"})
    die_on_error(resp)
    table = Table(title="Prefixos Monitorados")
    table.add_column("Prefixo")
    table.add_column("Cliente")
    table.add_column("Tráfego", justify="right")
    table.add_column("Pacotes/s", justify="right")
    table.add_column("Flows", justify="right")
    table.add_column("Capacidade", justify="right")
    for row in resp["monitor"]:
        capacity_mbps = row["capacity_mbps"]
        if capacity_mbps:
            pct = (row["bps"] / 1e6) / capacity_mbps * 100
            capacity_str = f"{pct:.0f}% de {capacity_mbps} Mbps"
        else:
            capacity_str = "-"
        table.add_row(
            row["prefix"], row["customer"] or "-", fmt_bps(row["bps"]),
            f"{row['pps']:,}".replace(",", "."), str(row["flows"]), capacity_str,
        )
    if not resp["monitor"]:
        console.print("[yellow]Nenhum prefixo monitorado (protected_prefixes.yaml vazio).[/yellow]")
    else:
        console.print(table)


def cmd_ban(args: argparse.Namespace, sock_path: str) -> None:
    payload = {"cmd": "ban", "target": args.target}
    if args.ttl_minutes is not None:
        payload["ttl_s"] = int(args.ttl_minutes * 60)
    resp = send_command(sock_path, payload)
    _print_simple(resp)


def cmd_unban(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "unban", "target": args.target})
    _print_simple(resp)


def cmd_flowspec_add(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "flowspec_add", "rule": args.rule})
    _print_simple(resp)


def cmd_flowspec_del(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "flowspec_del", "rule_id": args.rule_id})
    _print_simple(resp)


def cmd_dismiss(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "dismiss_attack", "attack_id": args.id})
    _print_simple(resp, ok_message=f"ataque {args.id} marcado como dispensado")


def cmd_dismiss_all(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "dismiss_all_attacks"})
    die_on_error(resp)
    console.print(f"[green]{resp['cleared']} ataque(s) ativo(s) dispensado(s).[/green]")


def cmd_toggles_list(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "toggles"})
    die_on_error(resp)
    table = Table(title="Tipos de ataque detectados pelo FlowGuard")
    table.add_column("Tipo")
    table.add_column("Estado")
    for key, value in resp["toggles"].items():
        table.add_row(key, "[green]habilitado[/green]" if value else "[red]desabilitado[/red]")
    console.print(table)


def cmd_toggles_set(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "set_toggle", "key": args.key, "value": args.value == "on"})
    _print_simple(resp, ok_message=f"{args.key} = {args.value}")


_AUTO_MODE_LABELS = {"off": "desligado", "suggestion": "sim (perfil)", "rtbh": "sim (RTBH direto)"}


def cmd_mitigation_list(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "mitigation_profiles"})
    die_on_error(resp)
    table = Table(title="Perfis de mitigação sugerida por tipo de ataque")
    table.add_column("Tipo")
    table.add_column("Estratégia")
    table.add_column("Limiar de pacote")
    table.add_column("Limite de banda")
    table.add_column("Automático")
    rtbh_ttl_s = resp["profiles"].get(configio.RTBH_TTL_KEY, configio.DEFAULT_RTBH_TTL_S)
    for attack_type, profile in resp["profiles"].items():
        if attack_type == configio.RTBH_TTL_KEY:
            continue
        auto_mode = profile.get("auto_mode", "off")
        table.add_row(
            attack_type, profile.get("kind", "-"),
            f"{profile['pkt_len_min']}b" if "pkt_len_min" in profile else "-",
            f"{profile.get('rate_limit_mbps', '-')} Mbps",
            _AUTO_MODE_LABELS.get(auto_mode, auto_mode),
        )
    console.print(table)
    console.print("[dim]kind: rtbh (blackhole total) | discard (FlowSpec, só o tráfego do ataque) | "
                   "rate_limit (FlowSpec, só limita banda)[/dim]")
    console.print("[dim]Automático só tem efeito nos prefixos com auto_mitigate: true "
                   "(flowguard-cli monitor add --auto-mitigate)[/dim]")
    console.print(f"[dim]Duração padrão do RTBH (botão \"Mitigar\"/auto_mode=rtbh): "
                   f"{rtbh_ttl_s}s (~{rtbh_ttl_s / 60:.0f} min) — flowguard-cli mitigation rtbh-ttl <minutos> "
                   f"pra mudar, ou --ttl-minutes em 'ban'/'mitigar' pra um valor pontual[/dim]")


def cmd_mitigation_set(args: argparse.Namespace, sock_path: str) -> None:
    fields: dict = {}
    if args.kind is not None:
        fields["kind"] = args.kind
    if args.pkt_len_min is not None:
        fields["pkt_len_min"] = args.pkt_len_min
    if args.rate_limit_mbps is not None:
        fields["rate_limit_mbps"] = args.rate_limit_mbps
    if args.auto_mode is not None:
        fields["auto_mode"] = args.auto_mode
    if not fields:
        console.print("[red]informe pelo menos um de --kind/--pkt-len-min/--rate-limit-mbps/--auto-mode[/red]")
        return
    resp = send_command(sock_path, {"cmd": "set_mitigation_profiles", "profiles": {args.attack_type: fields}})
    _print_simple(resp, ok_message=f"{args.attack_type}: {fields}")


def cmd_mitigation_rtbh_ttl(args: argparse.Namespace, sock_path: str) -> None:
    if args.minutes is None:
        resp = send_command(sock_path, {"cmd": "mitigation_profiles"})
        die_on_error(resp)
        ttl_s = resp["profiles"].get(configio.RTBH_TTL_KEY, configio.DEFAULT_RTBH_TTL_S)
        console.print(f"Duração padrão do RTBH: {ttl_s}s (~{ttl_s / 60:.0f} min)")
        return
    ttl_s = int(args.minutes * 60)
    resp = send_command(sock_path, {
        "cmd": "set_mitigation_profiles", "profiles": {configio.RTBH_TTL_KEY: ttl_s},
    })
    _print_simple(resp, ok_message=f"duração padrão do RTBH = {ttl_s}s (~{args.minutes:.0f} min)")


def cmd_scan_list(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "scan_detection_cfg"})
    die_on_error(resp)
    cfg = resp["scan_detection"]
    table = Table(title="Detecção de port scan (fora -> prefixo protegido)")
    table.add_column("Chave")
    table.add_column("Valor")
    for key, value in cfg.items():
        table.add_row(key, str(value))
    console.print(table)
    console.print("[dim]auto_block também precisa de mitigation_profiles.port_scan_horizontal/vertical."
                   "auto_mode != off (flowguard-cli mitigation set)[/dim]")


def cmd_scan_set(args: argparse.Namespace, sock_path: str) -> None:
    fields: dict = {}
    for name, key in (
        ("enabled", "enabled"), ("horizontal_enabled", "horizontal_enabled"),
        ("vertical_enabled", "vertical_enabled"), ("auto_block", "auto_block"),
    ):
        value = getattr(args, name)
        if value is not None:
            fields[key] = value == "on"
    for name, key in (
        ("horizontal_hosts", "horizontal_hosts"), ("vertical_ports", "vertical_ports"),
        ("horizontal_max_avg_bytes", "horizontal_max_avg_bytes"),
        ("vertical_max_avg_bytes", "vertical_max_avg_bytes"),
        ("max_tracked_src_ips_per_cycle", "max_tracked_src_ips_per_cycle"),
    ):
        value = getattr(args, name)
        if value is not None:
            fields[key] = value
    if args.horizontal_max_avg_bytes_off:
        fields["horizontal_max_avg_bytes"] = None
    if args.vertical_max_avg_bytes_off:
        fields["vertical_max_avg_bytes"] = None
    if not fields:
        console.print("[red]informe pelo menos uma opção (--enabled/--horizontal-hosts/--vertical-ports/...)[/red]")
        return
    resp = send_command(sock_path, {"cmd": "scan_detection_cfg_set", "changes": fields})
    _print_simple(resp, ok_message=f"scan_detection: {fields}")


def cmd_scan_offenders(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "scan_offenders", "history": args.history})
    die_on_error(resp)
    table = Table(title="Scanners detectados" + (" (histórico)" if args.history else " (ativos)"))
    table.add_column("Prefixo")
    table.add_column("Src IP")
    table.add_column("Tipo")
    table.add_column("Contagem")
    table.add_column("Bloqueado")
    table.add_column("Início")
    for row in resp["offenders"]:
        table.add_row(
            row["dst_prefix"], row["src_ip"], row["scan_type"], str(row["dst_count"]),
            "sim" if row["mitigated"] else "não",
            time.strftime("%d/%m %H:%M", time.localtime(row["ts_start"])),
        )
    console.print(table)


def cmd_coordinated_list(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "coordinated_destination_cfg"})
    die_on_error(resp)
    cfg = resp["coordinated_destination"]
    table = Table(title="Detecção de destino coordenado (N src externos -> 1 host/porta protegido)")
    table.add_column("Chave")
    table.add_column("Valor")
    for key, value in cfg.items():
        table.add_row(key, str(value))
    console.print(table)
    console.print("[dim]detecção/alerta apenas nesta versão — sem mitigação automática "
                   "(mitigation_profiles.coordinated_destination não existe ainda)[/dim]")


def cmd_coordinated_set(args: argparse.Namespace, sock_path: str) -> None:
    fields: dict = {}
    for name, key in (("enabled", "enabled"), ("auto_block", "auto_block")):
        value = getattr(args, name)
        if value is not None:
            fields[key] = value == "on"
    for name, key in (
        ("min_distinct_sources", "min_distinct_sources"),
        ("max_tracked_keys_per_cycle", "max_tracked_keys_per_cycle"),
    ):
        value = getattr(args, name)
        if value is not None:
            fields[key] = value
    if not fields:
        console.print("[red]informe pelo menos uma opção (--enabled/--min-distinct-sources/...)[/red]")
        return
    resp = send_command(sock_path, {"cmd": "coordinated_destination_cfg_set", "changes": fields})
    _print_simple(resp, ok_message=f"coordinated_destination: {fields}")


def cmd_coordinated_offenders(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "coordinated_destination_offenders", "history": args.history})
    die_on_error(resp)
    table = Table(title="Destinos coordenados detectados" + (" (histórico)" if args.history else " (ativos)"))
    table.add_column("Prefixo")
    table.add_column("Dst IP")
    table.add_column("Porta")
    table.add_column("Protocolo")
    table.add_column("Fontes")
    table.add_column("Bloqueado")
    table.add_column("Início")
    for row in resp["offenders"]:
        table.add_row(
            row["dst_prefix"], row["dst_ip"], str(row["dst_port"]), str(row["protocol"]),
            str(row["src_count"]), "sim" if row["mitigated"] else "não",
            time.strftime("%d/%m %H:%M", time.localtime(row["ts_start"])),
        )
    console.print(table)


_AUTO_ONOFF = ["on", "off"]


def cmd_escalation_list(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "escalation_cfg"})
    die_on_error(resp)
    cfg = resp["escalation"]
    table = Table(title="Bloqueio progressivo por reincidência (scan)")
    table.add_column("Chave")
    table.add_column("Valor")
    for key, value in cfg.items():
        table.add_row(key, str(value))
    console.print(table)


def cmd_escalation_set(args: argparse.Namespace, sock_path: str) -> None:
    fields: dict = {}
    if args.enabled is not None:
        fields["enabled"] = args.enabled == "on"
    for name in ("tracking_window_s", "base_ttl_s", "max_ttl_s", "max_steps"):
        value = getattr(args, name)
        if value is not None:
            fields[name] = value
    if args.factor is not None:
        fields["factor"] = args.factor
    if not fields:
        console.print("[red]informe pelo menos uma opção (--enabled/--base-ttl-s/--factor/...)[/red]")
        return
    resp = send_command(sock_path, {"cmd": "escalation_cfg_set", "changes": fields})
    _print_simple(resp, ok_message=f"escalation: {fields}")


def cmd_learn_templates(args: argparse.Namespace, sock_path: str) -> None:
    payload = {"cmd": "learn_templates", "apply": args.apply}
    if args.sigma is not None:
        payload["sigma"] = args.sigma
    if args.min_samples is not None:
        payload["min_samples"] = args.min_samples
    if args.min_threshold_mbps is not None:
        payload["min_threshold_bps"] = int(args.min_threshold_mbps * 1e6)
    resp = send_command(sock_path, payload)
    die_on_error(resp)
    title = "Templates aplicados" if resp["applied"] else "Proposta (dry-run — use --apply pra gravar)"
    table = Table(title=title)
    table.add_column("Prefixo")
    table.add_column("Amostras")
    table.add_column("Média")
    table.add_column("Limiar antigo")
    table.add_column("Limiar novo")
    table.add_column("Template novo")
    for r in resp["results"]:
        if not r["ready"]:
            table.add_row(r["prefix"], str(r["samples"]), "-", "-", "-", "[dim]amostras insuficientes[/dim]")
            continue
        table.add_row(
            r["prefix"], str(r["samples"]), fmt_bps(r["bps_mean"]),
            fmt_bps(r["old_effective_threshold"]), fmt_bps(r["new_threshold"]), r["new_template"],
        )
    console.print(table)
    if not resp["applied"]:
        console.print("[dim]Nada foi gravado — rode de novo com --apply pra criar os templates e "
                       "reatribuir os prefixos.[/dim]")


def cmd_whitelist_add(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "whitelist_add", "prefix": args.prefix})
    _print_simple(resp)


def cmd_whitelist_del(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "whitelist_del", "prefix": args.prefix})
    _print_simple(resp)


def cmd_monitor_add(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {
        "cmd": "monitor_add", "prefix": args.prefix, "customer": args.customer,
        "capacity_mbps": args.capacity_mbps, "auto_mitigate": args.auto_mitigate,
        "notify_wa": args.notify_wa,
    })
    _print_simple(resp)


def cmd_monitor_del(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "monitor_del", "prefix": args.prefix})
    _print_simple(resp)


def cmd_reload(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "reload"})
    _print_simple(resp, ok_message="config recarregado (SIGHUP)")


def cmd_stop(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "stop"})
    _print_simple(resp, ok_message="sinal de parada enviado ao daemon")


def _print_simple(resp: dict, ok_message: str = "ok") -> None:
    if resp.get("ok"):
        console.print(f"[green]{ok_message}[/green]")
    else:
        console.print(f"[red]Erro:[/red] {resp.get('error', 'desconhecido')}")
        sys.exit(1)


# --- modo interativo -------------------------------------------------------

def build_dashboard(sock_path: str) -> Group:
    resp = send_command(sock_path, {"cmd": "dashboard", "top_limit": 8})

    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    if not resp.get("ok"):
        header = Panel(f"[red]Daemon indisponível: {resp.get('error')}[/red]", title="FlowGuard Monitor")
        return Group(header)

    status = resp["status"]
    top = resp["top"]
    attacks = resp["attacks"]
    monitor = resp["monitor"]
    bgp = resp.get("bgp", {})
    if not status.get("ok"):
        header = Panel(f"[red]Daemon indisponível: {status.get('error')}[/red]", title="FlowGuard Monitor")
        return Group(header)

    statusbar = (
        f"Tráfego: [bold]{fmt_bps(status['bps'])}[/bold]  |  "
        f"Pacotes/s: [bold]{status['pps']:,}[/bold]  |  "
        f"Flows: [bold]{status['flows']}[/bold]  |  "
        f"Ataques: [bold red]{status['active_attacks']}[/bold red] ATIVOS  |  "
        f"Regras: [bold]{status['active_rules']}[/bold]  |  "
        f"BGP: {fmt_bgp_state(bgp)}  |  Daemon: [green]OK[/green]"
    ).replace(",", ".")

    header = Panel(statusbar, title=f"FlowGuard Monitor  |  {now_str}  |  Ctrl+C para sair")

    top_table = Table(title="Top Prefixos (inbound)")
    top_table.add_column("Prefixo")
    top_table.add_column("Tráfego", justify="right")
    for row in top.get("top_prefixes", []):
        top_table.add_row(row["dst_prefix"], fmt_bps(row["bps"]))

    monitor_table = Table(title="Prefixos Monitorados")
    monitor_table.add_column("Prefixo")
    monitor_table.add_column("Cliente")
    monitor_table.add_column("Tráfego", justify="right")
    monitor_table.add_column("Pacotes/s", justify="right")
    monitor_table.add_column("Flows", justify="right")
    monitor_table.add_column("Capacidade", justify="right")
    for row in monitor.get("monitor", []):
        capacity_mbps = row["capacity_mbps"]
        if capacity_mbps:
            pct = (row["bps"] / 1e6) / capacity_mbps * 100
            capacity_str = f"{pct:.0f}% de {capacity_mbps} Mbps"
        else:
            capacity_str = "-"
        monitor_table.add_row(
            row["prefix"], row["customer"] or "-", fmt_bps(row["bps"]),
            f"{row['pps']:,}".replace(",", "."), str(row["flows"]), capacity_str,
        )
    if not monitor.get("monitor"):
        monitor_table.add_row("-", "-", "-", "-", "-", "[yellow]nenhum prefixo monitorado[/yellow]")

    attacks_table = Table(title="Ataques Ativos")
    attacks_table.add_column("Alvo")
    attacks_table.add_column("Tipo")
    attacks_table.add_column("Severidade")
    for row in attacks.get("attacks", []):
        attacks_table.add_row(row["dst_prefix"], row["attack_type"], row["severity"])
    if not attacks.get("attacks"):
        attacks_table.add_row("-", "-", "[green]nenhum[/green]")

    return Group(header, monitor_table, top_table, attacks_table)


def cmd_warmode_list(args: argparse.Namespace, sock_path: str) -> None:
    devices = list_devices()
    if not devices:
        console.print("[yellow]Nenhum equipamento configurado em warmode.yaml "
                       "(copie warmode.yaml.example e preencha).[/yellow]")
        return
    table = Table(title="Modo Guerra — Equipamentos Configurados")
    table.add_column("Nome")
    table.add_column("Host")
    table.add_column("Tipo")
    table.add_column("Comandos")
    table.add_column("Comandos de reversão")
    for d in devices:
        n = d["n_commands"]
        cmds_str = str(n) if n else "[red]0 (nada vai rodar aqui)[/red]"
        n_revert = d["n_revert_commands"]
        revert_str = str(n_revert) if n_revert else "[yellow]0 (sem reversão)[/yellow]"
        table.add_row(d["name"], d["host"] or "-", d["device_type"] or "-", cmds_str, revert_str)
    console.print(table)


def _parse_set_args(pairs: list[str] | None) -> dict:
    values = {}
    for item in pairs or []:
        if "=" not in item:
            raise SystemExit(f"formato inválido para --set: '{item}' (use campo=valor)")
        k, v = item.split("=", 1)
        values[k] = v
    return values


def cmd_routercfg_list(args: argparse.Namespace, sock_path: str) -> None:
    from routercfg.templates import list_templates_public
    templates = list_templates_public()
    if not templates:
        console.print("[yellow]Nenhum template em router_templates.yaml.[/yellow]")
        return
    table = Table(title="Config. Roteador — Templates Disponíveis")
    table.add_column("ID")
    table.add_column("Label")
    table.add_column("Categoria")
    table.add_column("Campos")
    for t in templates:
        fields_str = ", ".join(f["name"] for f in t["fields"])
        table.add_row(t["id"], t["label"], t["category"], fields_str)
    console.print(table)


def cmd_routercfg_preview(args: argparse.Namespace, sock_path: str) -> None:
    from routercfg.apply import preview
    from routercfg.templates import ValidationError
    values = _parse_set_args(args.set)
    try:
        result = preview(args.template_id, values)
    except ValidationError as exc:
        console.print(f"[red]Erro de validação:[/red] {exc}")
        raise SystemExit(1)
    console.print(Panel("\n".join(result["commands"]), title=f"Comandos — {result['label']}"))
    console.print(Panel("\n".join(result["undo_commands"]), title="Comandos de reversão", border_style="yellow"))


def cmd_routercfg_apply(args: argparse.Namespace, sock_path: str) -> None:
    from routercfg.apply import apply_template, preview
    from routercfg.templates import ValidationError
    values = _parse_set_args(args.set)
    try:
        result = preview(args.template_id, values)
    except ValidationError as exc:
        console.print(f"[red]Erro de validação:[/red] {exc}")
        raise SystemExit(1)
    console.print(Panel(
        "\n".join(result["commands"]),
        title=f"[bold]Isto vai ser enviado ao roteador agora[/bold] — {result['label']}",
        border_style="red",
    ))
    if not args.yes and not Confirm.ask("Confirma a aplicação?", default=False):
        console.print("Cancelado.")
        return
    try:
        job = apply_template(args.template_id, values, trigger="cli", confirm_window_s=args.window)
    except ValidationError as exc:
        console.print(f"[red]Erro:[/red] {exc}")
        raise SystemExit(1)
    console.print(Panel(
        f"Job {job['id']}\nAplicado em {result['label']}.\n"
        f"Confirme com 'flowguard-cli routercfg confirm {job['id']}' em até {job['confirm_window_s'] // 60}min "
        "ou a mudança será revertida automaticamente.",
        title="[green]Aplicado[/green]", border_style="green",
    ))


def cmd_routercfg_confirm(args: argparse.Namespace, sock_path: str) -> None:
    from routercfg.apply import confirm_job
    from routercfg.templates import ValidationError
    try:
        confirm_job(args.job_id)
        console.print("[green]Confirmado.[/green]")
    except ValidationError as exc:
        console.print(f"[red]Erro:[/red] {exc}")
        raise SystemExit(1)


def cmd_routercfg_revert(args: argparse.Namespace, sock_path: str) -> None:
    from routercfg.apply import revert_job
    from routercfg.templates import ValidationError
    try:
        job = revert_job(args.job_id, trigger="manual")
        console.print(f"[green]Revertido via {job['revert_result']['method']}.[/green]")
    except ValidationError as exc:
        console.print(f"[red]Erro:[/red] {exc}")
        raise SystemExit(1)


def cmd_routercfg_discover(args: argparse.Namespace, sock_path: str) -> None:
    from routercfg.discovery import discover_all
    from routercfg.templates import ValidationError
    try:
        result = discover_all()
    except ValidationError as exc:
        console.print(f"[red]Erro:[/red] {exc}")
        raise SystemExit(1)
    except Exception as exc:
        console.print(f"[red]Falha ao consultar o roteador via SSH:[/red] {exc}")
        raise SystemExit(1)
    console.print(f"AS local: [bold]{result['local_as'] or '?'}[/bold]")
    peers_table = Table(title="Peers BGP")
    peers_table.add_column("IP")
    peers_table.add_column("AS remoto")
    peers_table.add_column("Grupo")
    peers_table.add_column("Descrição")
    peers_table.add_column("Estado")
    for p in result["peers"]:
        estado = "[green]up[/green]" if p["state"] == "up" else "[red]down (ignore)[/red]"
        peers_table.add_row(p["peer_ip"], p["remote_as"] or "-", p["group"] or "-", p["description"] or "-", estado)
    console.print(peers_table)
    nets_table = Table(title="Prefixos anunciados (network statements)")
    nets_table.add_column("CIDR")
    for n in result["networks"]:
        nets_table.add_row(n["cidr"])
    console.print(nets_table)
    if_table = Table(title="Interfaces")
    if_table.add_column("Nome")
    if_table.add_column("IP")
    if_table.add_column("Físico")
    if_table.add_column("Protocolo")
    for i in result["interfaces"]:
        phy = "[green]up[/green]" if i["physical"] == "up" else ("[yellow]admin-down[/yellow]" if i["admin_down"] else "[red]down[/red]")
        if_table.add_row(i["name"], i["ip"] or "-", phy, i["protocol"])
    console.print(if_table)
    vlan_table = Table(title="VLANs")
    vlan_table.add_column("VID")
    vlan_table.add_column("Nome")
    vlan_table.add_column("Status")
    vlan_table.add_column("Portas")
    for v in result["vlans"]:
        vlan_table.add_row(v["vlan_id"], v["name"] or "-", v["status"], v["ports"] or "-")
    console.print(vlan_table)


def cmd_routercfg_routes(args: argparse.Namespace, sock_path: str) -> None:
    from routercfg.discovery import discover_peer_routes
    from routercfg.templates import ValidationError
    direction = "received" if args.received else "advertised"
    try:
        result = discover_peer_routes(args.peer_ip, direction=direction)
    except ValidationError as exc:
        console.print(f"[red]Erro:[/red] {exc}")
        raise SystemExit(1)
    except Exception as exc:
        console.print(f"[red]Falha ao consultar o roteador via SSH:[/red] {exc}")
        raise SystemExit(1)
    table = Table(title=f"Rotas {direction} — peer {args.peer_ip} ({len(result['prefixes'])} prefixo(s))")
    table.add_column("Prefixo")
    for p in result["prefixes"]:
        table.add_row(p)
    console.print(table)


def cmd_routercfg_operators(args: argparse.Namespace, sock_path: str) -> None:
    from routercfg.discovery import discover_operator_routes
    from routercfg.templates import ValidationError
    direction = "received" if args.received else "advertised"
    try:
        result = discover_operator_routes(direction=direction)
    except ValidationError as exc:
        console.print(f"[red]Erro:[/red] {exc}")
        raise SystemExit(1)
    except Exception as exc:
        console.print(f"[red]Falha ao consultar o roteador via SSH:[/red] {exc}")
        raise SystemExit(1)
    console.print(f"AS local: [bold]{result['local_as'] or '?'}[/bold] — rotas {direction}")
    for op in result["operators"]:
        table = Table(title=f"{op['peer_ip']} (AS{op['remote_as']}) {op.get('description') or ''} — {len(op['prefixes'])} prefixo(s)")
        table.add_column("Prefixo")
        for p in op["prefixes"]:
            table.add_row(p)
        if not op["prefixes"]:
            table.add_row("[dim](nenhum)[/dim]")
        console.print(table)


def cmd_routercfg_history(args: argparse.Namespace, sock_path: str) -> None:
    from routercfg.apply import list_history
    jobs = list_history(limit=args.limit)
    if not jobs:
        console.print("[yellow]Nenhuma mudança registrada ainda.[/yellow]")
        return
    table = Table(title="Config. Roteador — Histórico")
    table.add_column("Job")
    table.add_column("Template")
    table.add_column("Status")
    table.add_column("Quando")
    for j in jobs:
        table.add_row(j["id"][:8], j["label"], j["status"], time.strftime("%Y-%m-%d %H:%M", time.localtime(j["created_at"])))
    console.print(table)


def cmd_warmode_run(args: argparse.Namespace, sock_path: str) -> None:
    devices = list_devices()
    if not devices:
        console.print("[yellow]Nenhum equipamento configurado em warmode.yaml.[/yellow]")
        return
    console.print(Panel(
        "\n".join(f"- {d['name']} ({d['host']}): {d['n_commands']} comando(s)" for d in devices),
        title="[bold red]MODO GUERRA[/bold red] — isto vai rodar comandos reais nestes equipamentos agora",
        border_style="red",
    ))
    if not args.yes and not Confirm.ask("Confirma a execução?", default=False):
        console.print("Cancelado.")
        return
    console.print("Executando em paralelo...")
    results = run_war_mode(trigger="cli")
    for r in results:
        if r["ok"]:
            console.print(Panel(r["output"] or "(sem saída)", title=f"[green]OK[/green] {r['device']} ({r['elapsed_s']}s)"))
        else:
            console.print(Panel(r.get("error", "erro desconhecido"), title=f"[red]FALHOU[/red] {r['device']}", border_style="red"))


def cmd_warmode_revert(args: argparse.Namespace, sock_path: str) -> None:
    devices = list_devices()
    if not devices:
        console.print("[yellow]Nenhum equipamento configurado em warmode.yaml.[/yellow]")
        return
    console.print(Panel(
        "\n".join(f"- {d['name']} ({d['host']}): {d['n_revert_commands']} comando(s) de reversão" for d in devices),
        title="[bold]Sair do Modo Guerra[/bold] — isto vai rodar os comandos de reversão nestes equipamentos agora",
        border_style="yellow",
    ))
    if not args.yes and not Confirm.ask("Confirma a reversão?", default=False):
        console.print("Cancelado.")
        return
    console.print("Executando em paralelo...")
    results = run_war_mode_revert(trigger="cli")
    for r in results:
        if r["ok"]:
            console.print(Panel(r["output"] or "(sem saída)", title=f"[green]OK[/green] {r['device']} ({r['elapsed_s']}s)"))
        else:
            console.print(Panel(r.get("error", "erro desconhecido"), title=f"[red]FALHOU[/red] {r['device']}", border_style="red"))


def run_interactive(sock_path: str, interval: float) -> None:
    try:
        with Live(build_dashboard(sock_path), console=console, screen=True, auto_refresh=False) as live:
            while True:
                time.sleep(interval)
                live.update(build_dashboard(sock_path), refresh=True)
    except KeyboardInterrupt:
        pass


# --- main --------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="flowguard-cli — cliente de terminal do FlowGuard")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--socket", default=None, help="sobrescreve o caminho do socket")
    parser.add_argument("--interval", type=float, default=1.0,
                         help="intervalo de atualização do monitor interativo, em segundos (padrão: 1.0)")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("status").set_defaults(func=cmd_status)
    sub.add_parser("top").set_defaults(func=cmd_top)
    sub.add_parser("flows").set_defaults(func=cmd_flows)

    p_attacks = sub.add_parser("attacks")
    p_attacks.add_argument("--history", action="store_true")
    p_attacks.add_argument("--window", choices=["1h", "6h", "24h", "7d"], default="24h",
                            help="janela do histórico (só com --history, padrão: 24h)")
    p_attacks.add_argument("--id", type=int, default=None,
                            help="mostra detalhamento (com análise de IA, se disponível) de um ataque específico")
    p_attacks.set_defaults(func=cmd_attacks)

    p_rules = sub.add_parser("rules")
    p_rules.add_argument("--history", action="store_true", help="mostra TODAS as regras já criadas (ativas ou não), lendo o SQLite direto")
    p_rules.set_defaults(func=cmd_rules)

    p_ban = sub.add_parser("ban")
    p_ban.add_argument("target")
    p_ban.add_argument("--ttl-minutes", type=float, dest="ttl_minutes",
                        help="duração do bloqueio RTBH em minutos (padrão: mitigation_profiles.yaml "
                             "rtbh_default_ttl_s, ver 'mitigation list')")
    p_ban.set_defaults(func=cmd_ban)

    p_unban = sub.add_parser("unban")
    p_unban.add_argument("target")
    p_unban.set_defaults(func=cmd_unban)

    p_flowspec = sub.add_parser("flowspec")
    flowspec_sub = p_flowspec.add_subparsers(dest="flowspec_action", required=True)
    p_fs_add = flowspec_sub.add_parser("add")
    p_fs_add.add_argument("rule")
    p_fs_add.set_defaults(func=cmd_flowspec_add)
    p_fs_del = flowspec_sub.add_parser("del")
    p_fs_del.add_argument("rule_id")
    p_fs_del.set_defaults(func=cmd_flowspec_del)

    p_dismiss = sub.add_parser("dismiss", help="marca um ataque ativo como dispensado (some da lista/contagem de ativos)")
    p_dismiss.add_argument("id", type=int)
    p_dismiss.set_defaults(func=cmd_dismiss)

    sub.add_parser("dismiss-all", help="marca TODOS os ataques ativos como dispensados de uma vez"
                    ).set_defaults(func=cmd_dismiss_all)

    p_toggles = sub.add_parser("toggles", help="liga/desliga cada tipo de ataque detectado")
    toggles_sub = p_toggles.add_subparsers(dest="toggles_action", required=True)
    toggles_sub.add_parser("list").set_defaults(func=cmd_toggles_list)
    p_toggles_set = toggles_sub.add_parser("set")
    p_toggles_set.add_argument("key", choices=sorted(configio.DEFAULT_FEATURE_TOGGLES))
    p_toggles_set.add_argument("value", choices=["on", "off"])
    p_toggles_set.set_defaults(func=cmd_toggles_set)

    p_mitigation = sub.add_parser("mitigation", help="estratégia/intensidade de mitigação sugerida por tipo de ataque")
    mitigation_sub = p_mitigation.add_subparsers(dest="mitigation_action", required=True)
    mitigation_sub.add_parser("list").set_defaults(func=cmd_mitigation_list)
    p_mitigation_set = mitigation_sub.add_parser("set")
    p_mitigation_set.add_argument("attack_type", choices=sorted(configio.DEFAULT_MITIGATION_PROFILES))
    p_mitigation_set.add_argument("--kind", choices=configio.MITIGATION_KINDS,
                                   help="rtbh (blackhole total) | discard (FlowSpec, só o tráfego do ataque) | "
                                        "rate_limit (FlowSpec, só limita banda)")
    p_mitigation_set.add_argument("--pkt-len-min", type=int, dest="pkt_len_min",
                                   help="limiar de tamanho de pacote em bytes (só dns_amp/ntp_amp)")
    p_mitigation_set.add_argument("--rate-limit-mbps", type=float, dest="rate_limit_mbps",
                                   help="limite de banda em Mbps (usado quando kind=rate_limit)")
    p_mitigation_set.add_argument("--auto-mode", choices=configio.MITIGATION_AUTO_MODES, dest="auto_mode",
                                   help="off (nunca dispara sozinho) | suggestion (aplica o kind acima "
                                        "sozinho) | rtbh (bloqueia o prefixo sozinho) — só tem efeito nos "
                                        "prefixos com auto_mitigate: true")
    p_mitigation_set.set_defaults(func=cmd_mitigation_set)
    p_mitigation_rtbh_ttl = mitigation_sub.add_parser(
        "rtbh-ttl", help="duração padrão do bloqueio RTBH (botão \"Mitigar\"/auto_mode=rtbh)")
    p_mitigation_rtbh_ttl.add_argument("minutes", type=float, nargs="?",
                                        help="nova duração em minutos (omitir só mostra o valor atual)")
    p_mitigation_rtbh_ttl.set_defaults(func=cmd_mitigation_rtbh_ttl)

    p_scan = sub.add_parser("scan", help="detecção de port scan de fora pra dentro")
    scan_sub = p_scan.add_subparsers(dest="scan_action", required=True)
    scan_sub.add_parser("list").set_defaults(func=cmd_scan_list)
    p_scan_set = scan_sub.add_parser("set")
    p_scan_set.add_argument("--enabled", choices=_AUTO_ONOFF)
    p_scan_set.add_argument("--horizontal-enabled", dest="horizontal_enabled", choices=_AUTO_ONOFF)
    p_scan_set.add_argument("--vertical-enabled", dest="vertical_enabled", choices=_AUTO_ONOFF)
    p_scan_set.add_argument("--horizontal-hosts", dest="horizontal_hosts", type=int,
                             help="N hosts distintos (mesma porta) pra contar como scan horizontal")
    p_scan_set.add_argument("--vertical-ports", dest="vertical_ports", type=int,
                             help="N portas distintas (mesmo host) pra contar como scan vertical")
    p_scan_set.add_argument("--horizontal-max-avg-bytes", dest="horizontal_max_avg_bytes", type=int,
                             help="acima disso (bytes médios por host) é tráfego real, não sonda — "
                                  "0 ou omitir 'null' não desativa; use --horizontal-max-avg-bytes-off")
    p_scan_set.add_argument("--horizontal-max-avg-bytes-off", dest="horizontal_max_avg_bytes_off",
                             action="store_true", help="desativa o filtro de bytes médios do horizontal")
    p_scan_set.add_argument("--vertical-max-avg-bytes", dest="vertical_max_avg_bytes", type=int,
                             help="acima disso (bytes médios por porta) é tráfego real (ex: streaming/CDN), "
                                  "não sonda de reconhecimento")
    p_scan_set.add_argument("--vertical-max-avg-bytes-off", dest="vertical_max_avg_bytes_off",
                             action="store_true", help="desativa o filtro de bytes médios do vertical")
    p_scan_set.add_argument("--max-tracked-src-ips-per-cycle", dest="max_tracked_src_ips_per_cycle", type=int)
    p_scan_set.add_argument("--auto-block", dest="auto_block", choices=_AUTO_ONOFF,
                             help="liga o bloqueio automático (também precisa de "
                                  "mitigation_profiles.port_scan_*.auto_mode != off)")
    p_scan_set.set_defaults(func=cmd_scan_set)
    p_scan_offenders = scan_sub.add_parser("offenders", help="scanners detectados")
    p_scan_offenders.add_argument("--history", action="store_true", help="inclui offenders já encerrados")
    p_scan_offenders.set_defaults(func=cmd_scan_offenders)

    p_coord = sub.add_parser("coordinated", help="destino coordenado (N src externos -> 1 host/porta protegido)")
    coord_sub = p_coord.add_subparsers(dest="coordinated_action", required=True)
    coord_sub.add_parser("list").set_defaults(func=cmd_coordinated_list)
    p_coord_set = coord_sub.add_parser("set")
    p_coord_set.add_argument("--enabled", choices=_AUTO_ONOFF)
    p_coord_set.add_argument("--min-distinct-sources", dest="min_distinct_sources", type=int,
                              help="N src_ips externos distintos convergindo no mesmo host/porta pra disparar")
    p_coord_set.add_argument("--max-tracked-keys-per-cycle", dest="max_tracked_keys_per_cycle", type=int)
    p_coord_set.add_argument("--auto-block", dest="auto_block", choices=_AUTO_ONOFF,
                              help="sem efeito nesta versão — sem mitigation_profiles.coordinated_destination ainda")
    p_coord_set.set_defaults(func=cmd_coordinated_set)
    p_coord_offenders = coord_sub.add_parser("offenders", help="destinos coordenados detectados")
    p_coord_offenders.add_argument("--history", action="store_true", help="inclui offenders já encerrados")
    p_coord_offenders.set_defaults(func=cmd_coordinated_offenders)

    p_escalation = sub.add_parser("escalation", help="bloqueio progressivo por reincidência (scan)")
    escalation_sub = p_escalation.add_subparsers(dest="escalation_action", required=True)
    escalation_sub.add_parser("list").set_defaults(func=cmd_escalation_list)
    p_escalation_set = escalation_sub.add_parser("set")
    p_escalation_set.add_argument("--enabled", choices=_AUTO_ONOFF)
    p_escalation_set.add_argument("--tracking-window-s", dest="tracking_window_s", type=int)
    p_escalation_set.add_argument("--base-ttl-s", dest="base_ttl_s", type=int)
    p_escalation_set.add_argument("--factor", type=float)
    p_escalation_set.add_argument("--max-ttl-s", dest="max_ttl_s", type=int)
    p_escalation_set.add_argument("--max-steps", dest="max_steps", type=int)
    p_escalation_set.set_defaults(func=cmd_escalation_set)

    p_learn = sub.add_parser("learn-templates",
                              help="deriva limiar de ddos_bps_threshold do baseline real e gera templates")
    p_learn.add_argument("--sigma", type=float, help="default: detection.baseline_sigma já configurado")
    p_learn.add_argument("--min-samples", dest="min_samples", type=int,
                          help="default: detection.baseline_min_samples já configurado")
    p_learn.add_argument("--min-threshold-mbps", dest="min_threshold_mbps", type=float,
                          help="piso do limiar sugerido, em Mbps (default: 500)")
    p_learn.add_argument("--apply", action="store_true",
                          help="aplica de verdade (cria templates + reatribui prefixos) — sem isso só mostra a proposta")
    p_learn.set_defaults(func=cmd_learn_templates)

    p_whitelist = sub.add_parser("whitelist")
    whitelist_sub = p_whitelist.add_subparsers(dest="whitelist_action", required=True)
    p_wl_add = whitelist_sub.add_parser("add")
    p_wl_add.add_argument("prefix")
    p_wl_add.set_defaults(func=cmd_whitelist_add)
    p_wl_del = whitelist_sub.add_parser("del")
    p_wl_del.add_argument("prefix")
    p_wl_del.set_defaults(func=cmd_whitelist_del)

    p_monitor = sub.add_parser("monitor", help="hosts/redes monitorados (protected_prefixes.yaml)")
    p_monitor.set_defaults(func=cmd_monitor_list)
    monitor_sub = p_monitor.add_subparsers(dest="monitor_action")
    p_mon_add = monitor_sub.add_parser("add")
    p_mon_add.add_argument("prefix")
    p_mon_add.add_argument("--customer", default="")
    p_mon_add.add_argument("--capacity-mbps", type=int, default=0)
    p_mon_add.add_argument("--auto-mitigate", action="store_true")
    p_mon_add.add_argument("--notify-wa", action="store_true")
    p_mon_add.set_defaults(func=cmd_monitor_add)
    p_mon_del = monitor_sub.add_parser("del")
    p_mon_del.add_argument("prefix")
    p_mon_del.set_defaults(func=cmd_monitor_del)

    p_warmode = sub.add_parser("warmode", help="botão de emergência — roda comandos SSH em vários equipamentos (warmode.yaml)")
    p_warmode.set_defaults(func=cmd_warmode_list)
    warmode_sub = p_warmode.add_subparsers(dest="warmode_action")
    warmode_sub.add_parser("list").set_defaults(func=cmd_warmode_list)
    p_warmode_run = warmode_sub.add_parser("run")
    p_warmode_run.add_argument("--yes", action="store_true", help="pula a confirmação interativa")
    p_warmode_run.set_defaults(func=cmd_warmode_run)
    p_warmode_revert = warmode_sub.add_parser("revert", help="Sair do Modo Guerra — roda os comandos de reversão")
    p_warmode_revert.add_argument("--yes", action="store_true", help="pula a confirmação interativa")
    p_warmode_revert.set_defaults(func=cmd_warmode_revert)

    p_routercfg = sub.add_parser("routercfg", help="edita configuração do roteador de borda via templates validados (SSH)")
    p_routercfg.set_defaults(func=cmd_routercfg_list)
    routercfg_sub = p_routercfg.add_subparsers(dest="routercfg_action")
    routercfg_sub.add_parser("list").set_defaults(func=cmd_routercfg_list)

    p_rc_preview = routercfg_sub.add_parser("preview")
    p_rc_preview.add_argument("template_id")
    p_rc_preview.add_argument("--set", action="append", help="campo=valor (repita por campo)")
    p_rc_preview.set_defaults(func=cmd_routercfg_preview)

    p_rc_apply = routercfg_sub.add_parser("apply")
    p_rc_apply.add_argument("template_id")
    p_rc_apply.add_argument("--set", action="append", help="campo=valor (repita por campo)")
    p_rc_apply.add_argument("--yes", action="store_true", help="pula a confirmação interativa")
    p_rc_apply.add_argument("--window", type=int, default=300, help="janela de confirmação em segundos (padrão 300)")
    p_rc_apply.set_defaults(func=cmd_routercfg_apply)

    p_rc_confirm = routercfg_sub.add_parser("confirm")
    p_rc_confirm.add_argument("job_id")
    p_rc_confirm.set_defaults(func=cmd_routercfg_confirm)

    p_rc_revert = routercfg_sub.add_parser("revert")
    p_rc_revert.add_argument("job_id")
    p_rc_revert.set_defaults(func=cmd_routercfg_revert)

    p_rc_history = routercfg_sub.add_parser("history")
    p_rc_history.add_argument("--limit", type=int, default=20)
    p_rc_history.set_defaults(func=cmd_routercfg_history)

    p_rc_discover = routercfg_sub.add_parser("discover", help="lê a config real do roteador (BGP, interfaces, VLANs)")
    p_rc_discover.set_defaults(func=cmd_routercfg_discover)

    p_rc_routes = routercfg_sub.add_parser("routes", help="rotas anunciadas/recebidas de um peer BGP específico")
    p_rc_routes.add_argument("peer_ip")
    p_rc_routes.add_argument("--received", action="store_true", help="mostra rotas recebidas em vez de anunciadas")
    p_rc_routes.set_defaults(func=cmd_routercfg_routes)

    p_rc_operators = routercfg_sub.add_parser("operators", help="IPs anunciados/recebidos de TODAS as operadoras (peers com AS remoto != AS local)")
    p_rc_operators.add_argument("--received", action="store_true", help="mostra rotas recebidas em vez de anunciadas")
    p_rc_operators.set_defaults(func=cmd_routercfg_operators)

    sub.add_parser("reload").set_defaults(func=cmd_reload)
    sub.add_parser("stop").set_defaults(func=cmd_stop)

    args = parser.parse_args()
    sock_path = args.socket or resolve_socket_path(args.config)

    if args.command is None:
        run_interactive(sock_path, args.interval)
        return

    args.func(args, sock_path)


if __name__ == "__main__":
    main()
