"""Integração opcional com a API da Anthropic: análise de ataques individuais
(model_events, barato/rápido) e resumo executivo horário (model_report). Nunca
deve derrubar detecção/mitigação — qualquer falha aqui só significa "sem texto
de IA desta vez", loga e segue. A key vem de um .env fora do repo (ai.env_file
no config.yaml), nunca do config.yaml ou do git.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

LOG = logging.getLogger("flowguard.ai")

try:
    import anthropic
except ImportError:
    anthropic = None

SEVERITY_RANK = {"info": 0, "medium": 1, "high": 2, "critical": 3}


def _load_env_file(path: str) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path:
        return values
    p = Path(path)
    if not p.exists():
        return values
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


class RateLimiter:
    """Janela deslizante de 60s — evita estourar rate_limit_rpm sem travar o
    event loop com sleep e sem depender de lib externa."""

    def __init__(self, rpm: int):
        self.rpm = rpm
        self._calls: list[float] = []

    def allow(self) -> bool:
        now = time.monotonic()
        cutoff = now - 60
        self._calls = [t for t in self._calls if t > cutoff]
        if len(self._calls) >= self.rpm:
            return False
        self._calls.append(now)
        return True


class AIClient:
    def __init__(self, cfg: dict):
        cfg = cfg or {}
        self.model_events = cfg.get("model_events", "claude-haiku-4-5-20251001")
        self.model_report = cfg.get("model_report", "claude-sonnet-4-6")
        self.min_severity = cfg.get("min_severity", "high")
        self.hourly_report = bool(cfg.get("hourly_report", False))
        self._limiter = RateLimiter(int(cfg.get("rate_limit_rpm", 5)))
        self._client = None
        self.enabled = bool(cfg.get("enabled")) and anthropic is not None

        if not self.enabled:
            if bool(cfg.get("enabled")) and anthropic is None:
                LOG.warning("ai.enabled=true mas o pacote 'anthropic' não está instalado — IA desativada")
            return

        env = _load_env_file(cfg.get("env_file", ""))
        api_key = env.get("ANTHROPIC_API_KEY")
        if not api_key:
            LOG.warning("ai.enabled=true mas ANTHROPIC_API_KEY não encontrada em %s — IA desativada",
                        cfg.get("env_file"))
            self.enabled = False
            return

        self._client = anthropic.AsyncAnthropic(api_key=api_key)
        LOG.info("IA ativada (eventos=%s, relatório=%s, hourly_report=%s)",
                  self.model_events, self.model_report, self.hourly_report)

    def severity_qualifies(self, severity: str) -> bool:
        return SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK.get(self.min_severity, 2)

    async def analyze_attack(self, attack_type: str, severity: str, dst_prefix: str, customer: str,
                              bps: int, pps: int, detail: dict) -> str | None:
        if not self.enabled:
            return None
        if not self._limiter.allow():
            LOG.warning("rate limit de IA (%s rpm) atingido — pulando análise deste ataque", self._limiter.rpm)
            return None

        by_port = ", ".join(
            f"proto={p['protocol']} porta={p['dst_port']} ({p['bps'] / 1e6:.1f} Mbps)"
            for p in detail.get("by_port", [])[:5]
        ) or "sem detalhamento por porta disponível"
        top_sources = ", ".join(s["ip"] for s in detail.get("top_sources", [])[:10]) or "não identificadas"

        prompt = (
            "Ataque de rede detectado por um sistema anti-DDoS.\n"
            f"Tipo: {attack_type}\n"
            f"Severidade: {severity}\n"
            f"Alvo: {dst_prefix} (cliente: {customer or 'desconhecido'})\n"
            f"Pico observado: {bps / 1e6:.1f} Mbps, {pps:,} pps\n"
            f"Portas/protocolos dominantes: {by_port}\n"
            f"Principais IPs de origem observados: {top_sources}\n\n"
            "Em português, escreva uma análise factual de até 4 frases, direta, cobrindo: "
            "provável natureza do ataque, se os dados sugerem spoofing/amplificação ou tráfego "
            "de origem real, e uma recomendação de ação objetiva. Não invente dados que não "
            "foram fornecidos acima. Responda em texto simples (sem markdown, sem título, sem "
            "listas), só o parágrafo da análise."
        )
        try:
            resp = await self._client.messages.create(
                model=self.model_events, max_tokens=300,
                messages=[{"role": "user", "content": prompt}],
            )
            return resp.content[0].text.strip()
        except Exception:
            LOG.exception("falha ao chamar IA (model_events) para análise de ataque")
            return None

    async def hourly_summary(self, attacks: list[dict]) -> str | None:
        if not self.enabled or not self.hourly_report or not attacks:
            return None
        if not self._limiter.allow():
            LOG.warning("rate limit de IA (%s rpm) atingido — pulando relatório horário", self._limiter.rpm)
            return None

        lines = []
        for a in attacks:
            status = "ainda ativo" if not a.get("ts_end") else "encerrado"
            lines.append(
                f"- {a['attack_type']} em {a['dst_prefix']} ({a.get('customer') or '?'}), "
                f"severidade {a['severity']}, pico {(a.get('bps_peak') or 0) / 1e6:.1f} Mbps [{status}]"
            )
        prompt = (
            "Resumo horário de um sistema anti-DDoS. Ataques registrados na última hora:\n"
            + "\n".join(lines)
            + "\n\nEm português, escreva um resumo executivo de até 6 frases: padrão geral "
              "(tipos/alvos recorrentes), se há indício de campanha coordenada contra um mesmo "
              "cliente/prefixo, e o que merece atenção da operação de rede. Não invente dados "
              "que não foram fornecidos acima. Responda em texto simples (sem markdown, sem "
              "título, sem listas), só o parágrafo do resumo."
        )
        try:
            resp = await self._client.messages.create(
                model=self.model_report, max_tokens=500,
                messages=[{"role": "user", "content": prompt}],
            )
            return resp.content[0].text.strip()
        except Exception:
            LOG.exception("falha ao chamar IA (model_report) para relatório horário")
            return None
