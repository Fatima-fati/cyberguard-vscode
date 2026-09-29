"""Evaluation du risque : score deterministe + fusion avec l'avis du modele.

Le modele apporte le raisonnement, le backend apporte la reproductibilite.
Le score final ne depend donc pas uniquement de l'humeur du modele, et
reste explicable facteur par facteur.
"""

import logging
import re
from typing import Optional

from app import i18n
from app.ai.schemas import (
    AIModelAnalysis,
    AlertContext,
    RiskFactor,
    band_for_score,
    severity_for_score,
)
from app.config import settings

logger = logging.getLogger(__name__)

# Poids du score deterministe face au score du modele.
BASELINE_WEIGHT = 0.4
AI_WEIGHT = 0.6

# Contribution de chaque type d'evenement au score de base.
EVENT_TYPE_WEIGHTS: dict[str, int] = {
    "malware": 30,
    "privilege_escalation": 28,
    "brute_force": 22,
    "network_attack": 20,
    "suspicious_process": 18,
    "file_integrity_violation": 15,
    "vulnerability": 12,
    "authentication_failure": 10,
    "policy_violation": 8,
    "configuration_weakness": 6,
    "system_event": 0,
    "unknown": 5,
}

# Contribution du verdict du modele au score de base. Sans cela, une
# vulnerabilite jugee critique par l'analyste IA restait tiree vers le bas
# par un score deterministe qui ne connaissait que le niveau Wazuh.
SEVERITY_WEIGHTS: dict[str, int] = {
    "LOW": 0,
    "MEDIUM": 10,
    "HIGH": 20,
    "CRITICAL": 30,
}

# Indices de compte privilegie dans le journal ou la description.
PRIVILEGED_PATTERN = re.compile(
    r"(?i)\b(root|administrator|admin|sudo|SYSTEM|NT AUTHORITY|domain admin)\b"
)

# Plages privees : tout le reste est considere comme expose.
PRIVATE_NETWORK_PATTERN = re.compile(
    r"^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|0\.)"
)
IP_PATTERN = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _rule_level_score(level: int) -> int:
    """Le niveau Wazuh (0-15) ramene sur 0-45 : contexte, pas conclusion."""
    return min(45, max(0, level) * 3)


def _repetition_score(count: int) -> int:
    """Une alerte qui se repete est plus preoccupante qu'un evenement isole."""
    if count >= 50:
        return 15
    if count >= 20:
        return 10
    if count >= 5:
        return 5
    return 0


def _has_public_ip(text: Optional[str]) -> bool:
    """Vrai si le texte contient une IP hors plages privees."""
    if not text:
        return False
    return any(
        not PRIVATE_NETWORK_PATTERN.match(address)
        for address in IP_PATTERN.findall(text)
    )


def compute_baseline(
    context: AlertContext,
    analysis: Optional[AIModelAnalysis] = None,
) -> tuple[int, list[RiskFactor]]:
    """Score deterministe (0-100) et facteurs qui l'expliquent.

    Ne suppose jamais une information absente : chaque facteur n'est compte
    que si la donnee correspondante est reellement presente.
    """
    factors: list[RiskFactor] = []
    score = 0

    level_points = _rule_level_score(context.rule_level)
    score += level_points
    factors.append(
        RiskFactor(
            name="Niveau Wazuh",
            detail=f"règle de niveau {context.rule_level}/15",
            weight=level_points,
        )
    )

    classification = analysis.classification if analysis else "unknown"
    type_points = EVENT_TYPE_WEIGHTS.get(classification, EVENT_TYPE_WEIGHTS["unknown"])
    score += type_points
    factors.append(
        RiskFactor(
            name="Type d'événement",
            detail=i18n.classification_label(classification),
            weight=type_points,
        )
    )

    if analysis is not None:
        severity_points = SEVERITY_WEIGHTS.get(analysis.severity, 0)
        if severity_points:
            score += severity_points
            factors.append(
                RiskFactor(
                    name="Évaluation de l'analyste IA",
                    detail=(
                        "le modèle qualifie l'incident de gravité "
                        f"{i18n.severity_label(analysis.severity)}"
                    ),
                    weight=severity_points,
                )
            )

    repetition_points = _repetition_score(context.similar_alerts_24h)
    if repetition_points:
        score += repetition_points
        factors.append(
            RiskFactor(
                name="Répétition",
                detail=(
                    f"{context.similar_alerts_24h} alertes similaires sur "
                    f"{settings.ai_repetition_window_hours} h"
                ),
                weight=repetition_points,
            )
        )

    haystack = " ".join(
        part for part in (context.rule_description, context.full_log) if part
    )

    if PRIVILEGED_PATTERN.search(haystack):
        score += 10
        factors.append(
            RiskFactor(
                name="Compte privilégié",
                detail="un compte à privilèges apparaît dans l'événement",
                weight=10,
            )
        )

    if _has_public_ip(context.full_log):
        score += 8
        factors.append(
            RiskFactor(
                name="Exposition réseau",
                detail="une adresse IP publique apparaît dans le journal",
                weight=8,
            )
        )

    if not context.full_log:
        factors.append(
            RiskFactor(
                name="Contexte limité",
                detail="journal brut absent : évaluation moins certaine",
                weight=0,
            )
        )

    return min(100, score), factors


def fuse(
    ai_score: int,
    ai_risk_factors: list[str],
    baseline: int,
    factors: list[RiskFactor],
) -> tuple[int, str, str, list[RiskFactor]]:
    """Fusionne un score de modele et un score deterministe.

    Fonction pure, sans domaine metier : les poids AI_WEIGHT et
    BASELINE_WEIGHT sont definis une seule fois pour tout le projet.
    L'analyse d'alertes Wazuh l'utilise via `combine()` ; l'analyse de code
    (`app.code.risk`) l'utilisera avec son propre score deterministe.

    Retourne (score final, severite, libelle lisible, facteurs).
    """
    final = int(round(AI_WEIGHT * ai_score + BASELINE_WEIGHT * baseline))
    final = max(0, min(100, final))

    # Les facteurs cites par le modele completent l'explication, sans poids.
    for label in ai_risk_factors:
        factors.append(RiskFactor(name="Analyse IA", detail=label, weight=0))

    return final, severity_for_score(final), band_for_score(final), factors


def combine(
    context: AlertContext,
    analysis: AIModelAnalysis,
) -> tuple[int, str, str, list[RiskFactor]]:
    """Fusionne l'avis du modele et le score deterministe d'une alerte.

    Retourne (score final, severite, libelle lisible, facteurs).
    """
    baseline, factors = compute_baseline(context, analysis)
    final, severity, band, factors = fuse(
        analysis.risk_score, analysis.risk_factors, baseline, factors
    )

    if severity != analysis.severity:
        logger.debug(
            "Severite recalculee pour %s : modele=%s, finale=%s (score %s)",
            context.alert_id,
            analysis.severity,
            severity,
            final,
        )

    return final, severity, band, factors
