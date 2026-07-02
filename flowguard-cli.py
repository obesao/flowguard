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
from warmode.executor import list_devices, run_war_mode

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
        table.add_row("BGP (ExaBGP)", peer_line)
    else:
        table.add_row("BGP (ExaBGP)", f"[dim]indisponível: {bgp.get('error')}[/dim]")
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
    table.add_column("Mitigado")
    table.add_column("IA")
    for row in resp["attacks"]:
        table.add_row(
            str(row["id"]), row["dst_prefix"], row["attack_type"], row["severity"],
            fmt_bps(row["bps_peak"] or 0), "sim" if row["mitigated"] else "não",
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
        f"{'  |  Alvo (host): ' + attack['target_host'] if attack.get('target_host') else ''}\n"
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


def cmd_rules(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "rules"})
    die_on_error(resp)
    table = Table(title="Regras FlowSpec Ativas")
    table.add_column("ID")
    table.add_column("Origem")
    table.add_column("Destino")
    table.add_column("Ação")
    table.add_column("Expira em")
    now = time.time()
    for row in resp["rules"]:
        ttl = max(0, int(row["expires_at"] - now))
        table.add_row(str(row["id"]), row.get("src_prefix") or "-", row.get("dst_prefix") or "-", row["action"], f"{ttl}s")
    if not resp["rules"]:
        console.print("[green]Nenhuma regra FlowSpec ativa.[/green]")
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
    resp = send_command(sock_path, {"cmd": "ban", "target": args.target})
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


def cmd_mitigation_list(args: argparse.Namespace, sock_path: str) -> None:
    resp = send_command(sock_path, {"cmd": "mitigation_profiles"})
    die_on_error(resp)
    table = Table(title="Perfis de mitigação sugerida por tipo de ataque")
    table.add_column("Tipo")
    table.add_column("Estratégia")
    table.add_column("Limiar de pacote")
    table.add_column("Limite de banda")
    for attack_type, profile in resp["profiles"].items():
        table.add_row(
            attack_type, profile.get("kind", "-"),
            f"{profile['pkt_len_min']}b" if "pkt_len_min" in profile else "-",
            f"{profile.get('rate_limit_mbps', '-')} Mbps",
        )
    console.print(table)
    console.print("[dim]kind: rtbh (blackhole total) | discard (FlowSpec, só o tráfego do ataque) | "
                   "rate_limit (FlowSpec, só limita banda)[/dim]")


def cmd_mitigation_set(args: argparse.Namespace, sock_path: str) -> None:
    fields: dict = {}
    if args.kind is not None:
        fields["kind"] = args.kind
    if args.pkt_len_min is not None:
        fields["pkt_len_min"] = args.pkt_len_min
    if args.rate_limit_mbps is not None:
        fields["rate_limit_mbps"] = args.rate_limit_mbps
    if not fields:
        console.print("[red]informe pelo menos um de --kind/--pkt-len-min/--rate-limit-mbps[/red]")
        return
    resp = send_command(sock_path, {"cmd": "set_mitigation_profiles", "profiles": {args.attack_type: fields}})
    _print_simple(resp, ok_message=f"{args.attack_type}: {fields}")


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
    for d in devices:
        n = d["n_commands"]
        cmds_str = str(n) if n else "[red]0 (nada vai rodar aqui)[/red]"
        table.add_row(d["name"], d["host"] or "-", d["device_type"] or "-", cmds_str)
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

    sub.add_parser("rules").set_defaults(func=cmd_rules)

    p_ban = sub.add_parser("ban")
    p_ban.add_argument("target")
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
    p_mitigation_set.set_defaults(func=cmd_mitigation_set)

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
