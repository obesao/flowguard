"""Servidor de controle via Unix socket — protocolo JSON por linha, consumido pelo flowguard-cli."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from pathlib import Path

from bgp import flowspec
from collector import configio, storage

LOG = logging.getLogger("flowguard.socket")

WHITELIST_HEADER = (
    "# whitelist.yaml — endereços/prefixos que o FlowGuard NUNCA deve bloquear ou\n"
    "# mitigar (RTBH/FlowSpec), mesmo que cruzem os limiares de detecção.\n"
    "# Editável diretamente ou via: flowguard-cli whitelist add|del <prefixo>"
)
PROTECTED_PREFIXES_HEADER = (
    "# protected_prefixes.yaml — hosts/redes monitorados pelo FlowGuard.\n"
    "# Editável diretamente ou via: flowguard-cli monitor add|del <prefixo>"
)


class SocketServer:
    """Atende um comando por conexão: lê uma linha JSON, responde uma linha JSON, fecha."""

    def __init__(self, daemon):
        self.daemon = daemon
        self._server: asyncio.base_events.Server | None = None
        self._path: str | None = None

    async def start(self) -> None:
        path = self.daemon.config["daemon"]["socket"]
        self._path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        self._server = await asyncio.start_unix_server(self._handle_client, path=path)
        os.chmod(path, 0o600)
        LOG.info("socket de controle ativo em %s", path)
        try:
            async with self._server:
                await self._server.serve_forever()
        except asyncio.CancelledError:
            pass  # close() cancela serve_forever() — encerramento esperado
        finally:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    def close(self) -> None:
        if self._server is not None:
            self._server.close()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line = await reader.readline()
            if not line:
                return
            try:
                request = json.loads(line.decode("utf-8"))
            except json.JSONDecodeError:
                response = {"ok": False, "error": "JSON inválido"}
            else:
                response = await self._dispatch(request)
            writer.write((json.dumps(response) + "\n").encode("utf-8"))
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass  # cliente (ex.: flowguard-cli) desconectou antes de receber a resposta
        except Exception:
            LOG.exception("erro ao atender cliente do socket")
        finally:
            writer.close()

    async def _dispatch(self, request: dict) -> dict:
        cmd = request.get("cmd", "")
        handler = getattr(self, f"_cmd_{cmd}", None)
        if handler is None:
            return {"ok": False, "error": f"comando desconhecido: {cmd}"}
        try:
            return await handler(request)
        except Exception as exc:
            LOG.exception("erro ao executar comando %s", cmd)
            return {"ok": False, "error": str(exc)}

    # --- comandos -----------------------------------------------------

    async def _cmd_dashboard(self, request: dict) -> dict:
        """Agrega status+top+attacks+monitor+bgp numa única ida ao socket — usado pelo modo
        interativo do CLI, que antes pagava 4 round-trips sequenciais por frame."""
        status, top, attacks, monitor, bgp = await asyncio.gather(
            self._cmd_status({}),
            self._cmd_top({"limit": request.get("top_limit", 8)}),
            self._cmd_attacks({}),
            self._cmd_monitor_list({}),
            self._cmd_bgp_status({}),
        )
        return {"ok": True, "status": status, "top": top, "attacks": attacks, "monitor": monitor, "bgp": bgp}

    async def _cmd_bgp_status(self, request: dict) -> dict:
        status = await self.daemon.bgp_manager.status()
        return {"ok": True, **status}

    async def _cmd_status(self, request: dict) -> dict:
        interval = self.daemon.config["database"]["aggregate_interval_s"]
        stats = await self.daemon.run_read_db(storage.daemon_stats, window_s=interval)
        return {
            "ok": True,
            "pid": os.getpid(),
            "uptime_s": time.time() - self.daemon.started_at,
            **stats,
        }

    async def _cmd_top(self, request: dict) -> dict:
        interval = self.daemon.config["database"]["aggregate_interval_s"]
        limit = int(request.get("limit", 20))
        top = await self.daemon.run_read_db(storage.top_prefixes, window_s=interval, limit=limit)
        return {"ok": True, "top_prefixes": top}

    async def _cmd_flows(self, request: dict) -> dict:
        interval = self.daemon.config["database"]["aggregate_interval_s"]
        limit = int(request.get("limit", 20))
        flows = await self.daemon.run_read_db(storage.top_flows, window_s=interval, limit=limit)
        return {"ok": True, "flows": flows}

    async def _cmd_attacks(self, request: dict) -> dict:
        history = bool(request.get("history", False))
        window_s, _ = storage.pick_window(request.get("window", "24h"))
        attacks = await self.daemon.run_read_db(
            storage.list_attacks, active_only=not history, since_s=window_s,
        )
        return {"ok": True, "attacks": attacks}

    async def _cmd_attack_detail(self, request: dict) -> dict:
        attack_id = request.get("attack_id")
        if not attack_id:
            return {"ok": False, "error": "attack_id obrigatório"}
        attack = await self.daemon.run_read_db(storage.get_attack, int(attack_id))
        if not attack:
            return {"ok": False, "error": f"ataque #{attack_id} não encontrado"}
        interval_s = self.daemon.config["database"]["aggregate_interval_s"]
        detail = await self.daemon.run_read_db(
            storage.attack_detail, attack["dst_prefix"], attack["ts_start"], attack["ts_end"], 20, interval_s,
        )
        timeseries = await self.daemon.run_read_db(
            storage.attack_timeseries, attack["dst_prefix"], attack["ts_start"], attack["ts_end"],
        )
        return {"ok": True, "attack": attack, "detail": detail, "timeseries": timeseries}

    async def _cmd_rules(self, request: dict) -> dict:
        rules = await self.daemon.run_read_db(storage.list_flowspec_rules)
        return {"ok": True, "rules": rules}

    async def _cmd_monitor_list(self, request: dict) -> dict:
        protected = self.daemon.config.get("protected_prefixes", [])
        prefixes = [entry["prefix"] for entry in protected if entry.get("prefix")]
        interval = self.daemon.config["database"]["aggregate_interval_s"]
        live = await self.daemon.run_read_db(storage.stats_for_prefixes, prefixes, interval)
        items = []
        for entry in protected:
            prefix = entry.get("prefix")
            s = live.get(prefix, {})
            items.append({
                "prefix": prefix,
                "customer": entry.get("customer", ""),
                "capacity_mbps": entry.get("capacity_mbps", 0),
                "bps": s.get("bps") or 0,
                "pps": s.get("pps") or 0,
                "flows": s.get("flow_count") or 0,
            })
        return {"ok": True, "monitor": items}

    async def _cmd_ban(self, request: dict) -> dict:
        target = request.get("target")
        if not target:
            return {"ok": False, "error": "target obrigatório"}
        return await self.daemon.bgp_manager.ban(target, attack_id=request.get("attack_id"), ttl_s=request.get("ttl_s"))

    async def _cmd_unban(self, request: dict) -> dict:
        target = request.get("target")
        if not target:
            return {"ok": False, "error": "target obrigatório"}
        return await self.daemon.bgp_manager.unban(target)

    async def _cmd_flowspec_add(self, request: dict) -> dict:
        raw_rule = request.get("rule")
        if not raw_rule:
            return {"ok": False, "error": "rule obrigatório"}
        if isinstance(raw_rule, str):
            try:
                rule = flowspec.parse_rule_string(raw_rule)
            except ValueError as exc:
                return {"ok": False, "error": str(exc)}
        elif isinstance(raw_rule, dict):
            rule = raw_rule
        else:
            return {"ok": False, "error": "rule deve ser string ou objeto"}
        return await self.daemon.bgp_manager.flowspec_add(rule, attack_id=request.get("attack_id"), ttl_s=request.get("ttl_s"))

    async def _cmd_flowspec_del(self, request: dict) -> dict:
        rule_id = request.get("rule_id")
        if not rule_id:
            return {"ok": False, "error": "rule_id obrigatório"}
        try:
            rule_id = int(rule_id)
        except (TypeError, ValueError):
            return {"ok": False, "error": "rule_id inválido"}
        return await self.daemon.bgp_manager.flowspec_del(rule_id)

    async def _cmd_dismiss_attack(self, request: dict) -> dict:
        attack_id = request.get("attack_id")
        if not attack_id:
            return {"ok": False, "error": "attack_id obrigatório"}
        found = await self.daemon.run_db(storage.dismiss_attack, self.daemon.conn, int(attack_id))
        if not found:
            return {"ok": False, "error": "ataque não encontrado ou já não está ativo"}
        return {"ok": True}

    async def _cmd_dismiss_all_attacks(self, request: dict) -> dict:
        cleared = await self.daemon.run_db(storage.dismiss_all_active_attacks, self.daemon.conn)
        return {"ok": True, "cleared": cleared}

    # --- toggles: liga/desliga cada tipo de ataque via portal/CLI ---------

    async def _cmd_toggles(self, request: dict) -> dict:
        return {"ok": True, "toggles": self.daemon.config.get("detection_toggles", {})}

    async def _cmd_set_toggle(self, request: dict) -> dict:
        key = request.get("key")
        if key not in configio.DEFAULT_FEATURE_TOGGLES:
            return {"ok": False, "error": f"toggle desconhecido: {key}"}
        path = self.daemon.config["_detection_toggles_file"]
        updated = configio.save_feature_toggle(path, key, bool(request.get("value")))
        self.daemon.reload_config()
        return {"ok": True, "toggles": updated}

    async def _cmd_whitelist_add(self, request: dict) -> dict:
        prefix = request.get("prefix")
        if not prefix:
            return {"ok": False, "error": "prefixo obrigatório"}
        path = self.daemon.config["_whitelist_file"]
        items = configio.load_yaml_list(path)
        if prefix in items:
            return {"ok": False, "error": "prefixo já está na whitelist"}
        items.append(prefix)
        configio.save_yaml_list(path, items, header_comment=WHITELIST_HEADER)
        self.daemon.reload_config()
        return {"ok": True}

    async def _cmd_whitelist_del(self, request: dict) -> dict:
        prefix = request.get("prefix")
        if not prefix:
            return {"ok": False, "error": "prefixo obrigatório"}
        path = self.daemon.config["_whitelist_file"]
        items = configio.load_yaml_list(path)
        if prefix not in items:
            return {"ok": False, "error": "prefixo não está na whitelist"}
        items.remove(prefix)
        configio.save_yaml_list(path, items, header_comment=WHITELIST_HEADER)
        self.daemon.reload_config()
        return {"ok": True}

    @staticmethod
    def _build_monitor_entry(prefix: str, request: dict) -> dict:
        entry = {
            "prefix": prefix,
            "customer": request.get("customer", ""),
            "capacity_mbps": request.get("capacity_mbps", 0),
            "auto_mitigate": bool(request.get("auto_mitigate", False)),
            "notify_wa": bool(request.get("notify_wa", False)),
        }
        thresholds = {}
        for key in ("ddos_bps_threshold", "ddos_pps_threshold"):
            value = (request.get("thresholds") or {}).get(key)
            if value:
                thresholds[key] = int(value)
        if thresholds:
            entry["thresholds"] = thresholds
        return entry

    async def _cmd_monitor_add(self, request: dict) -> dict:
        prefix = request.get("prefix")
        if not prefix:
            return {"ok": False, "error": "prefixo obrigatório"}
        path = self.daemon.config["_protected_prefixes_file"]
        items = configio.load_yaml_list(path)
        if any(entry.get("prefix") == prefix for entry in items):
            return {"ok": False, "error": "prefixo já está monitorado"}
        items.append(self._build_monitor_entry(prefix, request))
        configio.save_yaml_list(path, items, header_comment=PROTECTED_PREFIXES_HEADER)
        self.daemon.reload_config()
        return {"ok": True}

    async def _cmd_monitor_set(self, request: dict) -> dict:
        """Cria ou atualiza (upsert) um prefixo monitorado — usado pelo editor de
        configuração do portal, onde 'salvar' deve funcionar tanto para um prefixo
        novo quanto para ajustar limiares de um já existente."""
        prefix = request.get("prefix")
        if not prefix:
            return {"ok": False, "error": "prefixo obrigatório"}
        path = self.daemon.config["_protected_prefixes_file"]
        items = configio.load_yaml_list(path)
        entry = self._build_monitor_entry(prefix, request)
        for i, existing in enumerate(items):
            if existing.get("prefix") == prefix:
                items[i] = entry
                break
        else:
            items.append(entry)
        configio.save_yaml_list(path, items, header_comment=PROTECTED_PREFIXES_HEADER)
        self.daemon.reload_config()
        return {"ok": True}

    async def _cmd_monitor_del(self, request: dict) -> dict:
        prefix = request.get("prefix")
        if not prefix:
            return {"ok": False, "error": "prefixo obrigatório"}
        path = self.daemon.config["_protected_prefixes_file"]
        items = configio.load_yaml_list(path)
        filtered = [entry for entry in items if entry.get("prefix") != prefix]
        if len(filtered) == len(items):
            return {"ok": False, "error": "prefixo não está monitorado"}
        configio.save_yaml_list(path, filtered, header_comment=PROTECTED_PREFIXES_HEADER)
        self.daemon.reload_config()
        return {"ok": True}

    async def _cmd_reload(self, request: dict) -> dict:
        self.daemon.reload_config()
        return {"ok": True}

    async def _cmd_stop(self, request: dict) -> dict:
        asyncio.get_running_loop().call_later(0.2, self.daemon.stop)
        return {"ok": True, "message": "encerrando..."}
