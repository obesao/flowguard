"""Motor de detecção: DDoS volumétrico + amplificação (DNS/NTP/SSDP/Memcached/CLDAP)
+ anomalia de baseline (EWMA por prefixo).

Roda ao final de cada ciclo de agregação do daemon, recebendo os totais já
calculados em memória (sem round-trip ao SQLite para os dados do ciclo atual).
Escopado apenas aos prefixos em protected_prefixes — os demais dst_prefix
vistos no tráfego (destinos de saída dos clientes, ex: Facebook/Apple) não são
algo que se possa ou deva mitigar via FlowSpec/RTBH.

Todas as leituras/escritas em `attacks` de um ciclo são feitas em 1 SELECT +
1 transação de escrita (não 1 round-trip por prefixo x tipo de ataque) — com
8 prefixos x 6 tipos isso evitava ~96 commits individuais por ciclo, tempo
suficiente para estourar o timeout de clientes do socket de controle.
"""

from __future__ import annotations

import ipaddress
import logging
import math

from bgp import escalation
from collector import storage

LOG = logging.getLogger("flowguard.detect")

# porta de origem (UDP) -> (tipo de ataque, severidade) — ver "Ataques Detectados" no spec
AMP_PORTS = {
    53: ("dns_amp", "critical"),
    123: ("ntp_amp", "critical"),
    1900: ("ssdp_amp", "critical"),
    11211: ("memcached_amp", "critical"),
    389: ("cldap_amp", "high"),
}

# públicas (sem "_") porque flowguard.py também precisa delas pra agregar
# syn_totals — mesmo motivo de AMP_PORTS ser público
PROTO_TCP = 6
TCP_FLAG_SYN = 0x02
TCP_FLAG_ACK = 0x10


# Cache de 1 slot das redes de whitelist já parseadas — achado real de profiling
# de CPU (2026-07-10): evaluate_scan_cycle chama _is_whitelisted 1x por src_ip
# externo rastreado no ciclo (pode ser centenas), e sem isso cada chamada
# reparseava TODA a whitelist (ipaddress.ip_network() por entrada) do zero —
# ~9.5% da CPU do daemon só nisso. Mesmo padrão/motivo de
# collector/prefixes.py::_parsed_networks (whitelist só muda de fato num
# reload_config()).
_wl_cache_key: int | None = None
_wl_cache_list_ref: list | None = None
_wl_cache_networks: list = []


def _parsed_whitelist(whitelist: list[str]):
    global _wl_cache_key, _wl_cache_list_ref, _wl_cache_networks
    if _wl_cache_key == id(whitelist) and _wl_cache_list_ref is whitelist:
        return _wl_cache_networks
    parsed = []
    for entry in whitelist:
        try:
            parsed.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            continue
    _wl_cache_key = id(whitelist)
    _wl_cache_list_ref = whitelist
    _wl_cache_networks = parsed
    return parsed


def _is_whitelisted(prefix: str, whitelist: list[str]) -> bool:
    try:
        net = ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return False
    for wl_net in _parsed_whitelist(whitelist):
        if net == wl_net or net.subnet_of(wl_net):
            return True
    return False


class DetectionEngine:
    def __init__(self, daemon):
        self.daemon = daemon
        # (dst_prefix, attack_type) -> timestamp em que a condição começou a ser observada
        self._pending: dict[tuple, float] = {}
        # (dst_prefix, src_ip, scan_type) -> idem, namespace separado do de cima (chave
        # de formato diferente, e port_scan_offenders é uma tabela própria, não `attacks`)
        self._pending_scan: dict[tuple, float] = {}
        # (dst_prefix, dst_ip, dst_port, protocol) -> idem, namespace próprio (tabela
        # coordinated_destination_offenders, chave pelo DESTINO, não pelo atacante)
        self._pending_coord: dict[tuple, float] = {}

    async def evaluate_cycle(self, now: int, proto_totals: dict, amp_totals: dict, syn_totals: dict | None = None) -> None:
        syn_totals = syn_totals or {}
        cfg = self.daemon.config
        detection_cfg = cfg.get("detection", {})
        protected = cfg.get("protected_prefixes", [])
        whitelist = cfg.get("whitelist", [])
        toggles = cfg.get("detection_toggles", {})
        mitigation_profiles = cfg.get("mitigation_profiles", {})
        detection_templates = cfg.get("detection_templates", {})

        def toggle_on(key: str) -> bool:
            return toggles.get(key, True)
        min_duration = detection_cfg.get("min_attack_duration_s", 10)
        # duração mínima própria pra anomalia de baseline — separada de min_duration
        # porque esse detector reage a desvio estatístico de tráfego normal (ruidoso
        # por natureza), não a um limiar fixo cruzado por um ataque real e óbvio como
        # ddos_volumetrico/amplificação; exigir mais tempo sustentado aqui filtra picos
        # curtos de tráfego legítimo sem atrasar a detecção dos ataques de alta confiança.
        baseline_min_duration = detection_cfg.get("baseline_min_duration_s", min_duration)
        default_bps_threshold = detection_cfg.get("ddos_bps_threshold", 500_000_000)
        default_pps_threshold = detection_cfg.get("ddos_pps_threshold", 100_000)
        # limiar próprio de amplificação, separado do volumétrico (achado: reusava
        # ddos_bps_threshold, 500M — ataques de amplificação real costumam ter volume
        # bem menor que um DDoS volumétrico puro, então esse limiar deixava passar
        # amplificação genuína que nunca chegava perto de 500M).
        default_amp_bps_threshold = detection_cfg.get("amp_bps_threshold", 100_000_000)
        # syn_ratio_threshold já existia no config.yaml de instalações antigas mas nunca
        # tinha sido lido por nenhum código — só religando um limiar órfão, não inventando
        syn_ratio_threshold = detection_cfg.get("syn_ratio_threshold", 0.9)
        syn_min_pps_floor = detection_cfg.get("syn_min_pps_floor", 500)

        baseline_enabled = detection_cfg.get("baseline_enabled", True)
        baseline_min_samples = detection_cfg.get("baseline_min_samples", 120)
        baseline_sigma = detection_cfg.get("baseline_sigma", 4)
        baseline_min_bps = detection_cfg.get("baseline_min_bps", 5_000_000)
        baseline_window_min = detection_cfg.get("baseline_window_minutes", 180)
        interval_s = cfg["database"]["aggregate_interval_s"]
        baseline_alpha = 2 / (max(1, (baseline_window_min * 60) / interval_s) + 1)

        open_attacks = await self.daemon.run_read_db(storage.list_open_attacks_by_key)
        baselines = await self.daemon.run_read_db(storage.list_baselines) if baseline_enabled else {}

        to_insert: list[dict] = []
        to_update: list[tuple] = []
        to_close: list[tuple] = []
        to_notify: list[tuple] = []
        baseline_updates: list[tuple] = []

        for entry in protected:
            prefix = entry.get("prefix")
            if not prefix or _is_whitelisted(prefix, whitelist):
                continue

            # resolução do limiar: thresholds explícito do prefixo > template
            # (protected_prefixes.yaml::template -> detection_templates.yaml, ex.
            # 'cgnat' pra pool com tráfego agregado de muitos clientes combinados) >
            # padrão global de detection.* em config.yaml.
            template_vals = detection_templates.get(entry.get("template"), {}) if entry.get("template") else {}
            overrides = entry.get("thresholds") or {}
            bps_threshold = overrides.get("ddos_bps_threshold", template_vals.get("ddos_bps_threshold", default_bps_threshold))
            pps_threshold = overrides.get("ddos_pps_threshold", template_vals.get("ddos_pps_threshold", default_pps_threshold))
            amp_bps_threshold = overrides.get(
                "amp_bps_threshold", template_vals.get("amp_bps_threshold", default_amp_bps_threshold))

            by_proto = proto_totals.get(prefix, {})
            total_bps = sum(v["bps"] for v in by_proto.values())
            total_pps = sum(v["pps"] for v in by_proto.values())
            volumetric_hit = total_bps > bps_threshold or total_pps > pps_threshold

            # attack_type tem que ser ESTÁVEL entre ciclos — usar o protocolo dominante
            # no nome (ddos_tcp/ddos_udp) faz a chave trocar sempre que dois protocolos
            # de volume parecido alternam de líder, abandonando o registro anterior, que
            # nunca mais seria reavaliado para fechar (ficaria "preso" aberto para sempre).
            if toggle_on("ddos_volumetrico"):
                self._evaluate(now, prefix, "ddos_volumetrico", "critical", volumetric_hit, total_bps, total_pps,
                                min_duration, entry, open_attacks, to_insert, to_update, to_close, to_notify)

            # any_amp_hit é calculado independente do toggle de cada amp_type — ele só
            # existe pra suprimir a anomalia de baseline quando já há amplificação real
            # acontecendo (evita alerta duplicado do mesmo tráfego por dois detectores),
            # então precisa refletir o estado factual do tráfego, não o que está habilitado.
            any_amp_hit = False
            for src_port, (amp_type, severity) in AMP_PORTS.items():
                amp = amp_totals.get((prefix, src_port))
                amp_bps = amp["bps"] if amp else 0
                amp_pps = amp["pps"] if amp else 0
                amp_hit = amp_bps > amp_bps_threshold
                any_amp_hit = any_amp_hit or amp_hit
                if toggle_on(amp_type):
                    self._evaluate(now, prefix, amp_type, severity, amp_hit, amp_bps, amp_pps,
                                    min_duration, entry, open_attacks, to_insert, to_update, to_close, to_notify)

            # SYN flood: proporção de pacotes SYN "puro" (SYN setado, ACK não setado —
            # isola o flood de SYN-ACK de resposta legítima a handshake real) sobre o
            # total de TCP do prefixo. Só avaliada acima de um piso de pps de TCP total
            # (syn_min_pps_floor) — sem isso, um prefixo quase sem tráfego TCP dispararia
            # com 2 SYN em 2 pacotes (proporção 100%) sem ser um ataque de verdade.
            total_tcp = by_proto.get(PROTO_TCP, {})
            total_tcp_pps = total_tcp.get("pps", 0)
            syn = syn_totals.get(prefix, {})
            syn_pps = syn.get("pps", 0)
            syn_hit = total_tcp_pps >= syn_min_pps_floor and syn_pps / total_tcp_pps >= syn_ratio_threshold if total_tcp_pps else False
            if toggle_on("syn_flood"):
                self._evaluate(now, prefix, "syn_flood", "high", syn_hit, syn.get("bps", 0), syn_pps,
                                min_duration, entry, open_attacks, to_insert, to_update, to_close, to_notify)

            # Anomalia de baseline: só entra em jogo quando nenhum limiar estático (acima)
            # disparou — ela existe pra pegar ataques relevantes pra um cliente PEQUENO
            # (que nunca chegaria perto do limiar fixo global), não pra duplicar alerta
            # de um pico que um limiar estático já capturou.
            anomaly_hit = False
            if baseline_enabled and not volumetric_hit and not any_amp_hit and not syn_hit:
                baseline = baselines.get(prefix)
                if baseline and baseline["samples"] >= baseline_min_samples:
                    bps_std = math.sqrt(max(baseline["bps_var"], 0))
                    anomaly_threshold = baseline["bps_mean"] + baseline_sigma * bps_std
                    anomaly_hit = (
                        total_bps > anomaly_threshold
                        and total_bps > baseline_min_bps
                        and total_bps > baseline["bps_mean"] * 1.5
                    )
                    if toggle_on("anomalia_baseline"):
                        self._evaluate(now, prefix, "anomalia_baseline", "high", anomaly_hit, total_bps, total_pps,
                                        baseline_min_duration, entry, open_attacks, to_insert, to_update, to_close, to_notify)

            if baseline_enabled and not (volumetric_hit or any_amp_hit or syn_hit or anomaly_hit):
                baseline_updates.append((prefix, total_bps, total_pps, baseline_alpha, now))

        inserted_ids: list[int] = []
        if to_insert or to_update or to_close:
            inserted_ids = await self.daemon.run_db(
                storage.apply_attack_changes, self.daemon.conn, to_insert, to_update, to_close
            )

        if baseline_updates:
            await self.daemon.run_db(storage.update_baselines, self.daemon.conn, baseline_updates)

        # to_insert e to_notify crescem em lockstep (1 to_notify.append por to_insert.append,
        # ver _evaluate) — dá pra casar attack_id com sua notificação por posição, sem SELECT.
        # Notificações saem via fire_and_forget, NUNCA aguardadas aqui: cada uma envolve
        # rede (análise IA, WhatsApp, webhook) com timeouts de vários segundos, e este
        # método roda dentro do ciclo de agregação — esperar N notificações em série
        # atrasaria o ciclo e transbordaria a fila de flows bem no meio de um ataque.
        for attack_id, (prefix, attack_type, severity, bps, pps, entry, ts_start) in zip(inserted_ids, to_notify):
            LOG.warning(
                "ATAQUE DETECTADO: %s em %s (%s) — %.1f Mbps, %s pps",
                attack_type, prefix, entry.get("customer") or "?", bps / 1e6, f"{pps:,}".replace(",", "."),
            )
            self.daemon.fire_and_forget(
                self.daemon.notify_attack(attack_id, prefix, attack_type, severity, bps, pps, entry, ts_start),
                f"ataque #{attack_id} detectado",
            )

            # Auto-mitigação: só dispara com as DUAS travas ligadas — o tipo de
            # ataque (mitigation_profiles.<tipo>.auto_mode) e o prefixo/cliente
            # (protected_prefixes.<prefixo>.auto_mitigate). Roda só aqui (abertura),
            # nunca em to_update, então nunca reaplica pro mesmo ataque a cada ciclo.
            auto_mode = (mitigation_profiles.get(attack_type) or {}).get("auto_mode", "off")
            if auto_mode != "off" and entry.get("auto_mitigate"):
                self.daemon.fire_and_forget(
                    self.daemon.bgp_manager.auto_mitigate(attack_id, attack_type, prefix, auto_mode),
                    f"mitigação automática do ataque #{attack_id}",
                )

        for attack_id, prefix, attack_type, severity, bps_peak, ts_start, ts_end in to_close_log(to_close, open_attacks):
            # target_host só fica disponível depois de apply_attack_changes calcular e
            # gravar em attacks.target_host (ver storage.attack_top_host) — recarrega
            # a linha em vez de recalcular a agregação de novo aqui.
            attack_row = await self.daemon.run_read_db(storage.get_attack, attack_id)
            target_host = attack_row.get("target_host") if attack_row else None
            LOG.info("ataque encerrado: %s em %s (pico %.1f Mbps)", attack_type, prefix, bps_peak / 1e6)
            self.daemon.fire_and_forget(
                self.daemon.notify_attack_closed(
                    attack_id, prefix, attack_type, severity, bps_peak, ts_start, ts_end, target_host
                ),
                f"ataque #{attack_id} encerrado",
            )

    def _evaluate(self, now, prefix, attack_type, severity, triggered, bps, pps, min_duration, entry,
                  open_attacks, to_insert, to_update, to_close, to_notify) -> None:
        key = (prefix, attack_type)
        existing = open_attacks.get(key)

        if triggered:
            first_seen = self._pending.setdefault(key, now)
            if (now - first_seen) >= min_duration:
                if existing:
                    to_update.append((existing["id"], bps, pps, now))
                else:
                    to_insert.append({
                        "ts_start": now, "dst_prefix": prefix, "customer": entry.get("customer", ""),
                        "attack_type": attack_type, "severity": severity, "bps_peak": bps, "pps_peak": pps,
                    })
                    to_notify.append((prefix, attack_type, severity, bps, pps, entry, now))
        else:
            self._pending.pop(key, None)
            if existing:
                to_close.append((existing["id"], now, existing["dst_prefix"], existing["ts_start"]))


    async def evaluate_scan_cycle(self, now: int, scan_totals: dict, interval: int) -> None:
        """Port scan de fora pra dentro: 1 src_ip externo -> N hosts distintos do
        prefixo (horizontal) ou -> N portas distintas do mesmo host (vertical).
        scan_totals vem já montado por flowguard.py::_aggregate_once, chave
        (dst_prefix, src_ip) -> {"dst_ips": set, "dst_ports": {dst_ip: set(portas)},
        "packets": int}. Ver Parte A do plano desta feature pra motivo da tabela
        própria (port_scan_offenders) em vez de reusar `attacks`."""
        cfg = self.daemon.config
        scan_cfg = cfg.get("scan_detection", {})
        if not scan_cfg.get("enabled", True):
            return
        whitelist = cfg.get("whitelist", [])
        mitigation_profiles = cfg.get("mitigation_profiles", {})
        escalation_cfg = cfg.get("escalation", {})
        min_duration = cfg.get("detection", {}).get("min_attack_duration_s", 10)
        horizontal_hosts = scan_cfg.get("horizontal_hosts", 20)
        vertical_ports = scan_cfg.get("vertical_ports", 50)

        open_offenders = await self.daemon.run_read_db(storage.list_open_scan_offenders_by_key)

        to_insert: list[dict] = []
        to_update: list[tuple] = []
        to_close: list[tuple] = []
        to_notify: list[tuple] = []
        seen_keys: set[tuple] = set()

        for (prefix, src_ip), st in scan_totals.items():
            if _is_whitelisted(f"{src_ip}/32", whitelist):
                continue
            pps = int(st["packets"] / interval) if interval else 0
            # horizontal = MESMA porta em vários hosts distintos — sem isso, qualquer
            # servidor popular (CDN/big-tech) respondendo a vários clientes meus (cada
            # um na sua porta efêmera de retorno) bate o limiar (achado real de
            # produção). n_hosts é o pior caso entre as portas vistas nesse ciclo.
            n_hosts = max((len(ips) for ips in st["dst_ips_by_port"].values()), default=0)
            max_ports = max((len(ports) for ports in st["dst_ports"].values()), default=0)

            if scan_cfg.get("horizontal_enabled", True):
                key = (prefix, src_ip, "horizontal")
                seen_keys.add(key)
                self._evaluate_scan(now, key, n_hosts >= horizontal_hosts, n_hosts, pps,
                                     min_duration, open_offenders, to_insert, to_update, to_close, to_notify)
            if scan_cfg.get("vertical_enabled", True):
                key = (prefix, src_ip, "vertical")
                seen_keys.add(key)
                self._evaluate_scan(now, key, max_ports >= vertical_ports, max_ports, pps,
                                     min_duration, open_offenders, to_insert, to_update, to_close, to_notify)

        # src_ip que não mandou NENHUM pacote pro prefixo neste ciclo não aparece em
        # scan_totals — sem isso, um offender aberto nunca fecharia sozinho quando o
        # atacante simplesmente para (diferente de _evaluate, chamado sempre pra todo
        # (prefixo,tipo) mesmo sem tráfego; aqui só iteramos o que apareceu no ciclo).
        for key, row in open_offenders.items():
            if key in seen_keys:
                continue
            self._pending_scan.pop(key, None)
            to_close.append((row["id"], now))

        inserted_ids: list[int] = []
        if to_insert or to_update or to_close:
            inserted_ids = await self.daemon.run_db(
                storage.apply_scan_offender_changes, self.daemon.conn, to_insert, to_update, to_close
            )

        for offender_id, (prefix, src_ip, scan_type, dst_count, pps) in zip(inserted_ids, to_notify):
            unit = "hosts distintos" if scan_type == "horizontal" else "portas distintas"
            LOG.warning("SCAN DETECTADO: %s de %s contra %s — %d %s, %s pps",
                        scan_type, src_ip, prefix, dst_count, unit, f"{pps:,}".replace(",", "."))

            auto_mode = (mitigation_profiles.get(f"port_scan_{scan_type}") or {}).get("auto_mode", "off")
            if auto_mode != "off" and scan_cfg.get("auto_block", False):
                self.daemon.fire_and_forget(
                    self._auto_block_scanner(offender_id, src_ip, scan_type, escalation_cfg),
                    f"bloqueio automático de scan #{offender_id} ({src_ip})",
                )

    def _evaluate_scan(self, now, key, triggered, dst_count, pps, min_duration,
                        open_offenders, to_insert, to_update, to_close, to_notify) -> None:
        existing = open_offenders.get(key)
        if triggered:
            first_seen = self._pending_scan.setdefault(key, now)
            if (now - first_seen) >= min_duration:
                if existing:
                    to_update.append((existing["id"], dst_count, pps, now))
                else:
                    prefix, src_ip, scan_type = key
                    to_insert.append({"dst_prefix": prefix, "src_ip": src_ip, "scan_type": scan_type,
                                       "ts_start": now, "dst_count": dst_count, "pps_peak": pps})
                    to_notify.append((prefix, src_ip, scan_type, dst_count, pps))
        else:
            self._pending_scan.pop(key, None)
            if existing:
                to_close.append((existing["id"], now))

    async def _auto_block_scanner(self, offender_id: int, src_ip: str, scan_type: str,
                                   escalation_cfg: dict) -> None:
        """flowspec_add direto (não BgpManager.auto_mitigate, que é dst_prefix-shaped
        e mitigaria a VÍTIMA) — scan precisa bloquear o src_ip do ATACANTE."""
        ttl = await self.daemon.run_read_db(escalation.next_ttl_s, src_ip, escalation_cfg)
        resp = await self.daemon.bgp_manager.flowspec_add(
            {"src_prefix": f"{src_ip}/32", "action": "discard", "label": f"FlowGuard auto: port_scan_{scan_type}"},
            attack_id=None, ttl_s=ttl, origin="flowguard", peer="main", trigger_type="auto",
        )
        if resp.get("ok") and resp.get("rule_id") is not None:
            await self.daemon.run_db(storage.mark_scan_offender_mitigated, self.daemon.conn,
                                      offender_id, resp["rule_id"])
        else:
            LOG.error("falha ao bloquear scanner %s (offender #%s): %s", src_ip, offender_id, resp.get("error"))

    async def evaluate_coordinated_destination_cycle(self, now: int, coord_totals: dict, interval: int) -> None:
        """Destino coordenado de fora pra dentro: N src_ip externos distintos convergindo
        pro MESMO host/porta protegido — inverso do scan (lá 1 IP -> N alvos, aqui N IPs
        -> 1 alvo). coord_totals vem já montado por flowguard.py::_aggregate_once, chave
        (dst_prefix, dst_ip, dst_port, protocol) -> {"src_ips": set, "packets": int}.
        Pega ataques distribuídos de baixo volume por fonte, que não batem o limiar de
        ddos_volumetrico (agregado só por bps/pps do prefixo, não por contagem de fontes).
        Mitigação automática deliberadamente FORA desta versão (só detecção/alerta) —
        ver mitigation_profiles.yaml: nenhuma chave coordinated_destination existe ainda,
        então auto_block em coordinated_destination.yaml não tem efeito nenhum hoje
        (mesmo "interruptor morto" documentado pro port scan — aqui é intencional desde
        o início, não um bug latente)."""
        cfg = self.daemon.config
        coord_cfg = cfg.get("coordinated_destination", {})
        if not coord_cfg.get("enabled", True):
            return
        whitelist = cfg.get("whitelist", [])
        min_duration = cfg.get("detection", {}).get("min_attack_duration_s", 10)
        min_sources = coord_cfg.get("min_distinct_sources", 8)
        excluded_ports = set(coord_cfg.get("common_service_ports", []))

        open_offenders = await self.daemon.run_read_db(storage.list_open_coordinated_destination_offenders_by_key)

        to_insert: list[dict] = []
        to_update: list[tuple] = []
        to_close: list[tuple] = []
        to_notify: list[tuple] = []
        seen_keys: set[tuple] = set()

        for (prefix, dst_ip, dst_port, protocol), st in coord_totals.items():
            if dst_port in excluded_ports:
                continue
            if _is_whitelisted(f"{dst_ip}/32", whitelist):
                continue
            n_sources = len(st["src_ips"])
            pps = int(st["packets"] / interval) if interval else 0
            key = (prefix, dst_ip, dst_port, protocol)
            seen_keys.add(key)
            self._evaluate_coord(now, key, n_sources >= min_sources, n_sources, pps,
                                  min_duration, open_offenders, to_insert, to_update, to_close, to_notify)

        # mesmo motivo do scan: destino que não recebeu NENHUM pacote neste ciclo não
        # aparece em coord_totals — sem isso, um offender aberto nunca fecharia sozinho.
        for key, row in open_offenders.items():
            if key in seen_keys:
                continue
            self._pending_coord.pop(key, None)
            to_close.append((row["id"], now))

        if to_insert or to_update or to_close:
            await self.daemon.run_db(
                storage.apply_coordinated_destination_offender_changes, self.daemon.conn,
                to_insert, to_update, to_close,
            )

        for prefix, dst_ip, dst_port, protocol, src_count, pps in to_notify:
            LOG.warning(
                "DESTINO COORDENADO DETECTADO: %s:%d (protocolo %s) dentro de %s — "
                "%d fontes externas distintas, %s pps",
                dst_ip, dst_port, protocol, prefix, src_count, f"{pps:,}".replace(",", "."),
            )

    def _evaluate_coord(self, now, key, triggered, src_count, pps, min_duration,
                         open_offenders, to_insert, to_update, to_close, to_notify) -> None:
        existing = open_offenders.get(key)
        if triggered:
            first_seen = self._pending_coord.setdefault(key, now)
            if (now - first_seen) >= min_duration:
                if existing:
                    to_update.append((existing["id"], src_count, pps, now))
                else:
                    prefix, dst_ip, dst_port, protocol = key
                    to_insert.append({"dst_prefix": prefix, "dst_ip": dst_ip, "dst_port": dst_port,
                                       "protocol": protocol, "ts_start": now, "src_count": src_count,
                                       "pps_peak": pps})
                    to_notify.append((prefix, dst_ip, dst_port, protocol, src_count, pps))
        else:
            self._pending_coord.pop(key, None)
            if existing:
                to_close.append((existing["id"], now))


def to_close_log(to_close: list[tuple], open_attacks: dict[tuple, dict]):
    by_id = {row["id"]: key for key, row in open_attacks.items()}
    for attack_id, ts_end, _dst_prefix, ts_start in to_close:
        key = by_id.get(attack_id)
        if key is None:
            continue
        prefix, attack_type = key
        row = open_attacks[key]
        yield attack_id, prefix, attack_type, row["severity"], row["bps_peak"], ts_start, ts_end
