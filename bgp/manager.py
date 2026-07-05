"""BgpManager — aplica/retira mitigação BGP (RTBH e FlowSpec), falando com
bgp/speaker.py pelo socket dedicado a ele, e mantém o estado das regras em
flowspec_rules (sobrevive a restart do daemon e permite expirar por TTL).

`ban`/`unban` (RTBH) e `flowspec_add`/`flowspec_del` continuam podendo ser
iniciados pelo operador (CLI ou portal). A engine de detecção (analyzer/engine.py)
também pode chamar `auto_mitigate` diretamente na abertura de um ataque, quando o
tipo de ataque tem `mitigation_profiles.<tipo>.auto_mode != "off"` E o prefixo tem
`auto_mitigate: true` (protected_prefixes.yaml) — as duas travas precisam estar
ligadas, nenhuma sozinha dispara nada.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time

from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from bgp import flowspec
from collector import configio, control, storage
from routercfg import verify
from routercfg.templates import ValidationError

LOG = logging.getLogger("flowguard.bgp")


class BgpManager:
    def __init__(self, daemon):
        self.daemon = daemon

    def _bgp_cfg(self) -> dict:
        return self.daemon.config.get("bgp", {})

    def _mitigation_cfg(self) -> dict:
        return self.daemon.config.get("mitigation", {})

    def _rtbh_default_ttl_s(self) -> int:
        """Duração padrão do RTBH, configurável (mitigation_profiles.yaml,
        RTBH_TTL_KEY) — separada de mitigation.default_ttl_s (config.yaml), que
        continua valendo só pras regras FlowSpec (discard/rate_limit)."""
        profiles = self.daemon.config.get("mitigation_profiles", {})
        return profiles.get(configio.RTBH_TTL_KEY, configio.DEFAULT_RTBH_TTL_S)

    def _peer_ip(self, peer: str) -> str | None:
        """Resolve o nome lógico de peer ('main', 'pppoe', ...) pro IP configurado em
        config.yaml (bgp.peer_ip pro 'main', bgp.peer_ip_<nome> pros demais) — permite
        múltiplas sessões BGP simultâneas no mesmo exabgp.conf (ver neighbor em
        bgp/flowspec.build_command). 'main' é sempre bgp.peer_ip, pra não quebrar
        nenhuma regra/config já existente de antes de existir mais de um peer."""
        bgp_cfg = self._bgp_cfg()
        if peer == "main":
            return bgp_cfg.get("peer_ip")
        return bgp_cfg.get(f"peer_ip_{peer}")

    def _device_for_peer(self, peer: str) -> str | None:
        """Resolve o nome lógico de peer pro nome do equipamento em warmode.yaml,
        usado só pra verificação via SSH (verify_rule) — a sessão BGP em si nunca
        depende disso. 'main' pode devolver None (routercfg.apply._device_for(None)
        já usa 'NE8000BGP' como default) — só peers adicionais exigem mapeamento
        explícito em bgp.peer_device_<nome>, senão a verificação falha com erro
        claro em vez de silenciosamente apontar pro equipamento errado."""
        if peer == "main":
            return self._bgp_cfg().get("peer_device_main")
        return self._bgp_cfg().get(f"peer_device_{peer}")

    async def verify_rule(self, rule_id: int) -> dict:
        """Confere via SSH (routercfg.verify) se uma regra de flowspec_rules está
        DE FATO no roteador — funciona pra regra ativa, expirada ou revertida (é
        exatamente esse último caso — "banco diz revertida, será que o roteador
        concorda?" — que motivou a feature; ver bugs reais desta base onde o
        estado local e o estado real da borda ficaram dessincronizados)."""
        row = await self.daemon.run_read_db(storage.get_flowspec_rule, rule_id)
        if not row:
            return {"ok": False, "error": "regra não encontrada"}

        peer = row["peer"] if "peer" in row.keys() else "main"
        device_name = self._device_for_peer(peer)
        if device_name is None and peer != "main":
            return {"ok": False, "error": f"peer '{peer}' sem equipamento mapeado para "
                                           f"verificação (bgp.peer_device_{peer} em config.yaml)"}

        session = await self.status(peer)

        loop = asyncio.get_running_loop()
        try:
            router_check = await loop.run_in_executor(
                None, verify.verify_rule, dict(row), device_name, self._bgp_cfg(),
            )
        except ValidationError as exc:
            router_check = {"match_status": verify.MATCH_ERROR, "detail": str(exc),
                             "command": None, "raw_output": None}
        except (NetmikoAuthenticationException, NetmikoTimeoutException) as exc:
            router_check = {"match_status": verify.MATCH_ERROR, "detail": f"falha ao conectar no roteador: {exc}",
                             "command": None, "raw_output": None}

        return {
            "ok": True,
            "rule": dict(row),
            "peer": peer,
            "device_name": device_name or "NE8000BGP",
            "bgp_session": session,
            "router_check": router_check,
            "checked_at": int(time.time()),
        }

    async def _send(self, payload: dict) -> dict:
        sock_path = self._bgp_cfg().get("exabgp_socket", "/var/run/exabgp.sock")
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, control.send_command, sock_path, payload, 4.0)

    async def status(self, peer: str = "main") -> dict:
        """Estado de uma sessão BGP, visto pelo flowguard-speaker (populado via
        notificações "neighbor-changes" do ExaBGP — ver bgp/speaker.py). peer_state é
        sempre "up" ou "down": "down" cobre sessão caída, ainda conectando (TCP up mas
        BGP não estabelecido) e "nunca recebemos evento nenhum" (speaker acabou de
        subir, ou exabgp.conf sem `neighbor-changes;` no bloco api). peer: nome lógico
        ('main' = NE8000BGP, ou outro configurado em bgp.peer_ip_<nome>)."""
        peer_ip = self._peer_ip(peer)
        if not peer_ip:
            return {"peer_state": "unconfigured", "peer_ip": None, "detail": f"peer '{peer}' não configurado"}
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
                  origin: str = "flowguard", trigger_type: str = "manual") -> dict:
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

        # RTBH é sempre 'main': é um conceito de blackhole na borda (nexthop
        # discard), não faz sentido em nenhum outro peer que venha a existir.
        resp = await self._send({
            "action": "announce", "kind": "rtbh",
            "rule": {"dst_prefix": prefix, "community": community, "nexthop": nexthop},
            "neighbor": self._peer_ip("main"),
        })
        if not resp.get("ok"):
            return resp

        now = int(time.time())
        ttl_s = ttl_s or self._rtbh_default_ttl_s()
        rule_id = await self.daemon.run_db(storage.insert_flowspec_rule, self.daemon.conn, {
            "created_at": now, "expires_at": now + ttl_s, "attack_id": attack_id,
            "dst_prefix": prefix, "action": "rtbh", "label": f"ban {prefix}", "origin": origin,
            "peer": "main", "trigger_type": trigger_type,
        })
        if attack_id is not None:
            await self.daemon.run_db(storage.mark_attack_mitigated, self.daemon.conn, attack_id)
        self.daemon.fire_and_forget(
            self.daemon.notify_mitigation_applied(rule_id, attack_id, prefix, "rtbh", trigger_type, ttl_s),
            f"alerta de mitigação aplicada (regra {rule_id})",
        )
        LOG.warning("RTBH anunciado: %s (regra id=%s, ttl=%ds)", prefix, rule_id, ttl_s)
        return {"ok": True, "rule_id": rule_id}

    async def unban(self, target: str) -> dict:
        try:
            prefix = str(ipaddress.ip_network(target, strict=False))
        except ValueError:
            return {"ok": False, "error": f"endereço/prefixo inválido: {target}"}

        resp = await self._send({
            "action": "withdraw", "kind": "rtbh", "rule": {"dst_prefix": prefix},
            "neighbor": self._peer_ip("main"),
        })
        if resp.get("ok"):
            # captura attack_id/created_at ANTES de desativar — deactivate_flowspec_rules_by_prefix
            # não devolve quais linhas afetou, e esse contexto alimenta o alerta abaixo
            rules = await self.daemon.run_read_db(storage.list_active_flowspec_rules_by_prefix, prefix, "rtbh")
            await self.daemon.run_db(storage.deactivate_flowspec_rules_by_prefix, self.daemon.conn, prefix, "rtbh")
            LOG.info("RTBH retirado: %s", prefix)
            for rule in rules:
                self.daemon.fire_and_forget(
                    self.daemon.notify_mitigation_reverted(
                        rule["id"], rule.get("attack_id"), prefix, "rtbh", "revertida manualmente", rule["created_at"]
                    ),
                    f"alerta de mitigação revertida (regra {rule['id']})",
                )
        return resp

    async def flowspec_add(self, rule: dict, attack_id: int | None = None, ttl_s: int | None = None,
                            origin: str = "flowguard", peer: str = "main", trigger_type: str = "manual") -> dict:
        neighbor = self._peer_ip(peer)
        if not neighbor:
            return {"ok": False, "error": f"peer BGP '{peer}' não configurado (bgp.peer_ip_{peer} em config.yaml)"}

        budget_error = await self._check_rule_budget()
        if budget_error:
            return {"ok": False, "error": budget_error}

        resp = await self._send({"action": "announce", "kind": "flowspec", "rule": rule, "neighbor": neighbor})
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
            "label": rule.get("label", ""), "origin": origin, "peer": peer, "trigger_type": trigger_type,
        }
        rule_id = await self.daemon.run_db(storage.insert_flowspec_rule, self.daemon.conn, row)
        if attack_id is not None:
            await self.daemon.run_db(storage.mark_attack_mitigated, self.daemon.conn, attack_id)
        self.daemon.fire_and_forget(
            self.daemon.notify_mitigation_applied(rule_id, attack_id, rule.get("dst_prefix"), rule["action"], trigger_type, ttl_s),
            f"alerta de mitigação aplicada (regra {rule_id})",
        )
        LOG.warning("FlowSpec anunciado pro peer '%s': %s (regra id=%s, ttl=%ds)", peer, rule, rule_id, ttl_s)
        return {"ok": True, "rule_id": rule_id}

    async def flowspec_del(self, rule_id: int) -> dict:
        row = await self.daemon.run_read_db(storage.get_flowspec_rule, rule_id)
        if not row:
            return {"ok": False, "error": "regra não encontrada"}
        if not row["active"]:
            return {"ok": False, "error": "regra já está inativa"}

        kind = "rtbh" if row["action"] == "rtbh" else "flowspec"
        neighbor = self._peer_ip(row["peer"] if "peer" in row.keys() else "main")
        resp = await self._send({"action": "withdraw", "kind": kind, "rule": dict(row), "neighbor": neighbor})
        if resp.get("ok"):
            await self.daemon.run_db(storage.deactivate_flowspec_rule, self.daemon.conn, rule_id)
            LOG.info("regra retirada manualmente: id=%s %s", rule_id, row.get("dst_prefix"))
            self.daemon.fire_and_forget(
                self.daemon.notify_mitigation_reverted(
                    rule_id, row.get("attack_id"), row.get("dst_prefix"), row["action"],
                    "revertida manualmente", row["created_at"],
                ),
                f"alerta de mitigação revertida (regra {rule_id})",
            )
        return resp

    async def auto_mitigate(self, attack_id: int, attack_type: str, dst_prefix: str, auto_mode: str) -> dict:
        """Chamada pela engine de detecção (analyzer/engine.py) na abertura de um
        ataque, quando as duas travas de auto-mitigação estão ligadas (ver docstring
        do módulo). auto_mode == "rtbh" espelha o botão manual "Mitigar" (bloqueio
        total do prefixo, ignora o kind configurado); auto_mode == "suggestion"
        espelha o botão "Aplicar Sugestão" (usa mitigation_profiles — pode virar
        rtbh/discard/rate_limit dependendo do tipo). Só é chamada 1x por abertura de
        ataque (engine.py só passa por aqui em to_insert/to_notify, nunca em
        to_update), então não precisa checar aqui se já foi mitigado antes."""
        if auto_mode == "rtbh":
            resp = await self.ban(dst_prefix, attack_id=attack_id, origin="flowguard", trigger_type="auto")
        else:
            profiles = self.daemon.config.get("mitigation_profiles", {})
            suggestion = flowspec.suggest_mitigation(attack_type, dst_prefix, profiles)
            if suggestion["kind"] == "rtbh":
                resp = await self.ban(dst_prefix, attack_id=attack_id, origin="flowguard", trigger_type="auto")
            else:
                resp = await self.flowspec_add(suggestion["rule"], attack_id=attack_id, origin="flowguard",
                                                trigger_type="auto")

        if resp.get("ok"):
            LOG.warning("mitigação automática aplicada: ataque #%s (%s, modo=%s) -> regra id=%s",
                        attack_id, attack_type, auto_mode, resp.get("rule_id"))
        else:
            LOG.error("mitigação automática FALHOU: ataque #%s (%s, modo=%s): %s",
                       attack_id, attack_type, auto_mode, resp.get("error"))
        return resp

    async def expire_cycle(self) -> None:
        now = int(time.time())
        rows = await self.daemon.run_read_db(storage.list_expired_flowspec_rules, now)
        for row in rows:
            kind = "rtbh" if row["action"] == "rtbh" else "flowspec"
            neighbor = self._peer_ip(row["peer"] if "peer" in row.keys() else "main")
            resp = await self._send({"action": "withdraw", "kind": kind, "rule": dict(row), "neighbor": neighbor})
            if resp.get("ok"):
                await self.daemon.run_db(storage.deactivate_flowspec_rule, self.daemon.conn, row["id"])
                LOG.info("regra expirada e retirada: id=%s %s (%s)", row["id"], row.get("dst_prefix"), row["action"])
                self.daemon.fire_and_forget(
                    self.daemon.notify_mitigation_reverted(
                        row["id"], row.get("attack_id"), row.get("dst_prefix"), row["action"],
                        "TTL expirado", row["created_at"],
                    ),
                    f"alerta de mitigação revertida (regra {row['id']})",
                )
            else:
                LOG.error("falha ao retirar regra expirada id=%s: %s", row["id"], resp.get("error"))

    async def withdraw_all(self) -> dict:
        """Retira todas as regras ativas — usado no shutdown gracioso do daemon e pelo
        botão "Apagar todas as regras" do portal (cmd flowspec_del_all). Desativa no
        banco só as que confirmaram a retirada de verdade — uma falha de withdraw não
        pode apagar o rastro local de uma regra que continua anunciada no roteador
        (mesma classe de bug encontrada e corrigida no ClientGuard: status local
        dessincronizado do estado real da regra na borda).

        Deliberadamente NÃO dispara notify_mitigation_reverted por regra: isso roda
        toda vez que o daemon reinicia (deploy normal) e no botão de limpeza em massa
        do portal — mandar 1 WhatsApp por regra ativa nesses casos seria spam, não
        um alerta de segurança de verdade."""
        try:
            rows = await self.daemon.run_read_db(storage.list_flowspec_rules, active_only=True)
        except Exception:
            LOG.exception("falha ao listar regras ativas para retirada")
            return {"ok": False, "error": "falha ao listar regras ativas"}
        removed, failed = 0, 0
        for row in rows:
            kind = "rtbh" if row["action"] == "rtbh" else "flowspec"
            neighbor = self._peer_ip(row["peer"] if "peer" in row.keys() else "main")
            try:
                resp = await self._send({"action": "withdraw", "kind": kind, "rule": dict(row), "neighbor": neighbor})
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
