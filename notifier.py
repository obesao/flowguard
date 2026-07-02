"""Envio de alertas via WhatsApp usando a Evolution API self-hosted (ver
/root/evolution-api/, docker-compose com Postgres+Redis). Destino (grupo ou
número) é compartilhado com o ClientGuard — só existe UMA sessão WhatsApp real,
configurável pelo portal ("Alertas via WhatsApp" na aba Configuração)."""

from __future__ import annotations

import logging
import sys

LOG = logging.getLogger("flowguard.notifier")

if "/root/evolution-api" not in sys.path:
    sys.path.insert(0, "/root/evolution-api")


def send_whatsapp(message: str) -> bool:
    """Manda `message` pro destino configurado no portal (grupo/número salvo em
    /root/evolution-api/notify.yaml) — silencioso em caso de falha, sem retry,
    mesmo padrão dos outros notifiers do projeto."""
    try:
        import client as evo
    except ImportError:
        LOG.error("client.py da Evolution API não encontrado em /root/evolution-api")
        return False
    dest = evo.load_dest().get("dest")
    if not dest:
        return False
    return evo.send_text(dest, message)
