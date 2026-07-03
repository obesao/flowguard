"""BgpManager — aplica/retira mitigação BGP (RTBH e FlowSpec), falando com
bgp/speaker.py pelo socket dedicado a ele, e mantém o estado das regras em
flowspec_rules (sobrevive a restart do daemon e permite expirar por TTL).

`ban`/`unban` (RTBH) e `flowspec_add`/`flowspec_del` são sempre iniciados pelo
operador (CLI ou portal) — a engine de detecção (analyzer/engine.py) só notifica,
não chama nada aqui diretamente. Auto-mitigação completa (mitigation.auto_mode)
fica para uma fase futura.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time

from collector import control, storage

LOG = logging.getLogger("flowguard.bgp")


class BgpManager:
    def __init__(self, daemon):
        self.daemon = daemon

    def _bgp_cfg(self) -> dict:
        return self.daemon.config.get("bgp", {})

    def _mitigation_cfg(self) -> dict:
        return self.daemon.config.get("mitigation", {})

    async def _send(self, payload: dict) -> dict:
        sock_path = self._bgp_cfg().get("exabgp_socket", "/var/run/exabgp.sock")
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, control.send_command, sock_path, payload, 4.0)

    async def status(self) -> dict:
        """Estado da sessão BGP com o NE8000, visto pelo flowguard-speaker (populado via
        notificações "neighbor-changes" do ExaBGP — ver bgp/speaker.py). peer_state é
        sempre "up" ou "down": "down" cobre sessão caída, ainda conectando (TCP up mas
        BGP não estabelecido) e "nunca recebemos evento nenhum" (speaker acabou de
        subir, ou exabgp.conf sem `neighbor-changes;` no bloco api)."""
        peer_ip = self._bgp_cfg().get("peer_ip")
        resp = await self._send({"action": "status"})
        if not resp.get("ok"):
            return {"peer_state": "down", "peer_ip": peer_ip, "detail": resp.get("error", "erro desconhecido")}
        info = resp.get("neighbors", {}).get(peer_ip)
        if not info:
            return {"peer_state": "down", "peer_ip": peer_ip, "detail": "nenhum evento de estado recebido do ExaBGP ainda"}
        return {
            "peer_state": "up" if info.get("state") == "up" else "down",
            "peer_ip": peer_ip,
            "raw_state": info.get("state"),
            "reason": info.get("reason", ""),
            "updated_at": info.get("updated_at"),
        }

    async def _check_rule_budget(self) -> str | None:
        max_rules = self._mitigation_cfg().get("max_rules", 50)
        active = await self.daemon.run_read_db(storage.list_flowspec_rules, active_only=True)
        if len(active) >= max_rules:
            return f"limite de regras FlowSpec/RTBH atingido ({max_rules}) — remova regras antigas antes de adicionar novas"
        return None

    async def ban(self, target: str, attack_id: int | None = None, ttl_s: int | None = None,
                  origin: str = "flowguard") -> dict:
        try:
            prefix = str(ipaddress.ip_network(target, strict=False))
        except ValueError:
            return {"ok": False, "error": f"endereço/prefixo inválido: {target}"}

        bgp_cfg = self._bgp_cfg()
        community = bgp_cfg.get("rtbh_community")
        nexthop = bgp_cfg.get("nexthop_blackhole")
        if not community or not nexthop:
            return {"ok": False, "error": "bgp.rtbh_community/nexthop_blackhole não configurados em config.yaml"}

        budget_error = await self._check_rule_budget()
        if budget_error:
            return {"ok": False, "error": budget_error}

        resp = await self._send({
            "action": "announce", "kind": "rtbh",
            "rule": {"dst_prefix": prefix, "community": community, "nexthop": nexthop},
        })
        if not resp.get("ok"):
            return resp

        now = int(time.time())
        ttl_s = ttl_s or self._mitigation_cfg().get("default_ttl_s", 3600)
        rule_id = await self.daemon.run_db(storage.insert_flowspec_rule, self.daemon.conn, {
            "created_at": now, "expires_at": now + ttl_s, "attack_id": attack_id,
            "dst_prefix": prefix, "action": "rtbh", "label": f"ban {prefix}", "origin": origin,
        })
        LOG.warning("RTBH anunciado: %s (regra id=%s, ttl=%ds)", prefix, rule_id, ttl_s)
        return {"ok": True, "rule_id": rule_id}

    async def unban(self, target: str) -> dict:
        try:
            prefix = str(ipaddress.ip_network(target, strict=False))
        except ValueError:
            return {"ok": False, "error": f"endereço/prefixo inválido: {target}"}

        resp = await self._send({"action": "withdraw", "kind": "rtbh", "rule": {"dst_prefix": prefix}})
        if resp.get("ok"):
            await self.daemon.run_db(storage.deactivate_flowspec_rules_by_prefix, self.daemon.conn, prefix, "rtbh")
            LOG.info("RTBH retirado: %s", prefix)
        return resp

    async def flowspec_add(self, rule: dict, attack_id: int | None = None, ttl_s: int | None = None,
                            origin: str = "flowguard") -> dict:
        budget_error = await self._check_rule_budget()
        if budget_error:
            return {"ok": False, "error": budget_error}

        resp = await self._send({"action": "announce", "kind": "flowspec", "rule": rule})
        if not resp.get("ok"):
            return resp

        now = int(time.time())
        ttl_s = ttl_s or self._mitigation_cfg().get("default_ttl_s", 3600)
        row = {
            "created_at": now, "expires_at": now + ttl_s, "attack_id": attack_id,
            "dst_prefix": rule.get("dst_prefix"), "src_prefix": rule.get("src_prefix"),
            "protocol": rule.get("protocol"), "dst_port": rule.get("dst_port"),
            "src_port": rule.get("src_port"), "tcp_flags": rule.get("tcp_flags"),
            "pkt_len": rule.get("pkt_len"), "action": rule["action"],
            "label": rule.get("label", ""), "origin": origin,
        }
        rule_id = await self.daemon.run_db(storage.insert_flowspec_rule, self.daemon.conn, row)
        LOG.warning("FlowSpec anunciado: %s (regra id=%s, ttl=%ds)", rule, rule_id, ttl_s)
        return {"ok": True, "rule_id": rule_id}

    async def flowspec_del(self, rule_id: int) -> dict:
        row = await self.daemon.run_read_db(storage.get_flowspec_rule, rule_id)
        if not row:
            return {"ok": False, "error": "regra não encontrada"}
        if not row["active"]:
            return {"ok": False, "error": "regra já está inativa"}

        kind = "rtbh" if row["action"] == "rtbh" else "flowspec"
        resp = await self._send({"action": "withdraw", "kind": kind, "rule": dict(row)})
        if resp.get("ok"):
            await self.daemon.run_db(storage.deactivate_flowspec_rule, self.daemon.conn, rule_id)
            LOG.info("regra retirada manualmente: id=%s %s", rule_id, row.get("dst_prefix"))
        return resp

    async def expire_cycle(self) -> None:
        now = int(time.time())
        rows = await self.daemon.run_read_db(storage.list_expired_flowspec_rules, now)
        for row in rows:
            kind = "rtbh" if row["action"] == "rtbh" else "flowspec"
            resp = await self._send({"action": "withdraw", "kind": kind, "rule": dict(row)})
            if resp.get("ok"):
                await self.daemon.run_db(storage.deactivate_flowspec_rule, self.daemon.conn, row["id"])
                LOG.info("regra expirada e retirada: id=%s %s (%s)", row["id"], row.get("dst_prefix"), row["action"])
            else:
                LOG.error("falha ao retirar regra expirada id=%s: %s", row["id"], resp.get("error"))

    async def withdraw_all(self) -> dict:
        """Retira todas as regras ativas — usado no shutdown gracioso do daemon e pelo
        botão "Apagar todas as regras" do portal (cmd flowspec_del_all). Desativa no
        banco só as que confirmaram a retirada de verdade — uma falha de withdraw não
        pode apagar o rastro local de uma regra que continua anunciada no roteador
        (mesma classe de bug encontrada e corrigida no ClientGuard: status local
        dessincronizado do estado real da regra na borda)."""
        try:
            rows = await self.daemon.run_read_db(storage.list_flowspec_rules, active_only=True)
        except Exception:
            LOG.exception("falha ao listar regras ativas para retirada")
            return {"ok": False, "error": "falha ao listar regras ativas"}
        removed, failed = 0, 0
        for row in rows:
            kind = "rtbh" if row["action"] == "rtbh" else "flowspec"
            try:
                resp = await self._send({"action": "withdraw", "kind": kind, "rule": dict(row)})
            except Exception:
                LOG.exception("falha ao retirar regra id=%s", row["id"])
                resp = {"ok": False}
            if resp.get("ok"):
                await self.daemon.run_db(storage.deactivate_flowspec_rule, self.daemon.conn, row["id"])
                removed += 1
            else:
                failed += 1
                LOG.error("falha ao retirar regra id=%s: %s", row["id"], resp.get("error"))
        if removed:
            LOG.info("%d regra(s) FlowSpec/RTBH retirada(s)", removed)
        return {"ok": failed == 0, "removed": removed, "failed": failed}
