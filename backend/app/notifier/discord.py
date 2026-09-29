"""Envoi des alertes critiques vers un webhook Discord.

Squelette : l'appel HTTP reel sera branche avec le poller.
"""

import logging

from app.config import settings
from app.models import Alert

logger = logging.getLogger(__name__)


def is_configured() -> bool:
    """Vrai si l'envoi Discord est active et parametre."""
    return bool(settings.discord_enabled and settings.discord_webhook_url)


def build_payload(alert: Alert) -> dict:
    """Construit le corps JSON du webhook Discord."""
    return {
        "username": "Wazuh Supervision",
        "embeds": [
            {
                "title": f"Alerte critique - niveau {alert.level}",
                "description": alert.description,
                "color": 15158332,
                "fields": [
                    {"name": "Regle", "value": str(alert.rule_id), "inline": True},
                    {"name": "Agent", "value": str(alert.agent_name), "inline": True},
                    {"name": "Date", "value": str(alert.timestamp), "inline": False},
                ],
            }
        ],
    }


async def send_alert(alert: Alert) -> bool:
    """Poste une alerte critique sur Discord.

    TODO: implementer l'appel httpx vers le webhook.
    """
    if not is_configured():
        logger.debug("Discord desactive ou non configure, envoi ignore")
        return False
    raise NotImplementedError("send_alert sera implemente avec le poller")
