"""Envio de alertas via WhatsApp usando a CallMeBot API (gratuita, sem conta business —
https://www.callmebot.com/blog/free-api-whatsapp-messages/). GET simples, timeout curto,
silencioso em caso de falha, sem retry — mesmo padrão dos webhooks já usados no projeto."""

from __future__ import annotations

import logging
import urllib.parse
import urllib.request
from urllib.error import URLError

LOG = logging.getLogger("flowguard.notifier")

CALLMEBOT_URL = "https://api.callmebot.com/whatsapp.php"


def send_whatsapp(phone: str, apikey: str, message: str, timeout: float = 10.0) -> bool:
    """Envia `message` para `phone` (DDI + número, só dígitos, ex. "5599999999999")
    via CallMeBot. Requer ativação prévia do bot naquele número e a apikey gerada
    nesse processo (ver README) — sem isso a CallMeBot rejeita silenciosamente."""
    if not phone or not apikey or not message:
        return False
    params = urllib.parse.urlencode({"phone": phone, "text": message, "apikey": apikey})
    url = f"{CALLMEBOT_URL}?{params}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            resp.read()
        return True
    except (URLError, OSError, ValueError):
        LOG.exception("falha ao enviar alerta WhatsApp via CallMeBot")
        return False
