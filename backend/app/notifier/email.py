"""Envoi des alertes critiques par e-mail (SMTP).

Squelette : la connexion SMTP reelle sera branchee avec le poller.
"""

import logging

from app.config import settings
from app.models import Alert

logger = logging.getLogger(__name__)


def is_configured() -> bool:
    """Vrai si l'envoi d'e-mail est active et parametre."""
    return bool(
        settings.email_enabled
        and settings.smtp_host
        and settings.email_from
        and settings.email_to
    )


def build_message(alert: Alert) -> tuple[str, str]:
    """Construit (sujet, corps) du message pour une alerte."""
    subject = f"[Wazuh] Alerte critique niveau {alert.level} - {alert.description}"
    body = (
        f"Alerte : {alert.description}\n"
        f"Niveau : {alert.level}\n"
        f"Regle  : {alert.rule_id}\n"
        f"Agent  : {alert.agent_name} ({alert.agent_id})\n"
        f"Date   : {alert.timestamp}\n"
    )
    return subject, body


async def send_alert(alert: Alert) -> bool:
    """Envoie une alerte critique par e-mail.

    TODO: implementer l'envoi SMTP (smtplib dans un thread executor).
    """
    if not is_configured():
        logger.debug("E-mail desactive ou non configure, envoi ignore")
        return False
    raise NotImplementedError("send_alert sera implemente avec le poller")
