"""Nettoyage des alertes avant envoi au modele.

Un `full_log` Wazuh peut contenir des secrets (mots de passe en clair,
tokens, cles d'API). Rien de tout cela ne doit sortir du backend.
"""

import logging
import re
from typing import Optional

from app import i18n
from app.ai.schemas import AlertContext
from app.models import Alert

logger = logging.getLogger(__name__)

REDACTED = "[REDACTED]"

# Longueur maximale du journal transmis : au-dela, le contexte n'apporte
# plus rien et le cout augmente.
MAX_LOG_LENGTH = 2000

# Motifs de secrets courants. L'ordre importe peu : tous sont appliques.
SECRET_PATTERNS: list[re.Pattern] = [
    # cle=valeur  /  cle: valeur  /  "cle": "valeur"
    re.compile(
        r'(?i)\b(pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|'
        r'access[_-]?key|secret[_-]?key|private[_-]?key|credential[s]?|'
        r'authorization|auth[_-]?token|session[_-]?id|cookie)\b'
        r'(\s*["\']?\s*[:=]\s*["\']?)([^\s"\',;&]+)'
    ),
    # En-tetes HTTP Authorization
    re.compile(r"(?i)\b(bearer|basic)\s+([A-Za-z0-9._\-+/=]{8,})"),
    # Cles d'API OpenAI et assimilees
    re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}"),
    # Blocs de cles privees
    re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        re.DOTALL,
    ),
    # Jetons JWT
    re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
]


def _mask_key_value(match: re.Match) -> str:
    """Conserve le nom du champ, masque la valeur."""
    return f"{match.group(1)}{match.group(2)}{REDACTED}"


def redact_secrets(text: Optional[str]) -> Optional[str]:
    """Remplace les secrets reconnus par [REDACTED].

    Le nom du champ est conserve : savoir qu'un mot de passe apparait dans
    le journal fait partie de l'analyse, sa valeur non.
    """
    if not text:
        return text

    # L'ordre compte : "Authorization: Bearer <token>" doit d'abord etre
    # traite par le motif de schema, sinon le motif cle=valeur ne masque
    # que le mot "Bearer" et laisse le token en clair.
    cleaned = SECRET_PATTERNS[1].sub(lambda m: f"{m.group(1)} {REDACTED}", text)
    cleaned = SECRET_PATTERNS[0].sub(_mask_key_value, cleaned)

    for pattern in SECRET_PATTERNS[2:]:
        cleaned = pattern.sub(REDACTED, cleaned)

    # Les deux passes peuvent se superposer sur un meme secret.
    return re.sub(rf"(?:{re.escape(REDACTED)}\s*)+", REDACTED, cleaned)


def truncate(text: Optional[str], limit: int = MAX_LOG_LENGTH) -> Optional[str]:
    """Tronque un texte trop long, en le signalant."""
    if not text or len(text) <= limit:
        return text
    return text[:limit] + " ... [tronque]"


def sanitize_alert_for_ai(
    alert: Alert,
    similar_alerts: int = 0,
    agent_os: Optional[str] = None,
) -> AlertContext:
    """Construit le contexte transmis au modele a partir d'une alerte.

    Seuls les champs utiles sont retenus, et `full_log` est expurge de tout
    secret avant de quitter le backend.
    """
    context = AlertContext(
        alert_id=alert.id,
        timestamp=alert.timestamp,
        rule_id=alert.rule.id,
        rule_level=alert.rule.level,
        rule_description=redact_secrets(alert.rule.description),
        # Formulation francaise de reference : le modele s'appuie dessus
        # pour repondre en francais sans reinventer le vocabulaire.
        rule_description_fr=i18n.localize_security_text(
            redact_secrets(alert.rule.description)
        ),
        rule_groups=alert.rule.groups,
        agent_id=alert.agent.id,
        agent_name=alert.agent.name,
        agent_ip=alert.agent.ip,
        location=alert.location,
        full_log=truncate(redact_secrets(alert.full_log)),
        similar_alerts_24h=similar_alerts,
        agent_os=agent_os,
    )

    if context.full_log and REDACTED in context.full_log:
        logger.info("Secret masque dans l'alerte %s avant envoi au modele", alert.id)

    return context
