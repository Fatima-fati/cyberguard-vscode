"""Agent IA : orchestration du workflow d'analyse.

    Alerte Wazuh -> nettoyage -> analyse IA -> evaluation du risque
                 -> recommandations -> cache SQLite -> SSE -> frontend

Deux garde-fous structurants :

1. **Le cache fait foi.** Une alerte deja analysee n'est jamais renvoyee au
   modele (sauf demande explicite avec `force`), ce qui borne le cout.
2. **Rien ne remonte vers le poller.** `analyze_new_alerts()` avale toutes
   les erreurs : une panne OpenAI n'a aucun effet sur la collecte Wazuh.
"""

import asyncio
import logging
from typing import Optional

from app.ai import analyzer, risk_assessment
from app.ai.openai_client import AIError, OpenAIClient, get_openai_client
from app.ai.sanitizer import sanitize_alert_for_ai
from app.ai import notifications as notifications_service
from app.ai.schemas import AIAlertAnalysis, AINotification, AIStats
from app.config import settings
from app.models import Alert, StreamEvent
from app.notifier import stream
from app import store

logger = logging.getLogger(__name__)

# Limite les appels simultanes au modele (cout et quotas).
_semaphore: Optional[asyncio.Semaphore] = None


def _get_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(settings.ai_max_concurrency)
    return _semaphore


def get_semaphore() -> asyncio.Semaphore:
    """Limite de concurrence partagee par TOUTES les analyses du projet.

    Alertes Wazuh et, en phase 3, extraits de code passent par le meme
    semaphore : le plafond AI_MAX_CONCURRENCY protege le cout et le quota
    globalement, pas par type d'analyse.
    """
    return _get_semaphore()


def reset_semaphore() -> None:
    """Reinitialise la limite de concurrence (utile aux tests)."""
    global _semaphore
    _semaphore = None


# --------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------


async def get_cached_analysis(alert_id: str) -> Optional[AIAlertAnalysis]:
    """Analyse deja calculee pour cette alerte, si elle existe."""
    payload = await asyncio.to_thread(store.get_ai_analysis, alert_id)
    if not payload:
        return None

    try:
        analysis = AIAlertAnalysis.model_validate_json(payload)
    except ValueError:
        # Analyse persistee dans un format devenu incompatible : on
        # l'ignore plutot que de casser l'affichage.
        logger.warning("Analyse en cache illisible pour %s, elle sera refaite", alert_id)
        return None

    analysis.cached = True
    return analysis


async def _store_analysis(analysis: AIAlertAnalysis) -> None:
    await asyncio.to_thread(
        store.save_ai_analysis,
        analysis.alert_id,
        analysis.severity,
        analysis.risk_score,
        analysis.model_dump_json(),
        analysis.analyzed_at,
    )


# --------------------------------------------------------------------------
# Analyse d'une alerte
# --------------------------------------------------------------------------


async def analyze_alert(
    alert: Alert,
    force: bool = False,
    client: Optional[OpenAIClient] = None,
) -> AIAlertAnalysis:
    """Analyse une alerte et retourne le resultat complet.

    Leve une sous-classe d'AIError si le modele est indisponible ou repond
    n'importe quoi. L'appelant decide quoi en faire.
    """
    if not force:
        cached = await get_cached_analysis(alert.id)
        if cached is not None:
            logger.debug("Analyse de %s servie depuis le cache", alert.id)
            # La notification correspondante est remise a l'etat
            # "analysee" : sans cela, une analyse servie depuis le cache
            # laisserait la notification bloquee sur "analyse en cours".
            try:
                await notifications_service.sync_cached_analysis(cached)
            except Exception:  # noqa: BLE001 - la lecture ne doit jamais echouer
                logger.exception(
                    "Synchronisation de la notification impossible pour %s", alert.id
                )
            return cached

    similar = await asyncio.to_thread(
        store.count_similar_alerts,
        alert.rule.id,
        alert.agent.id,
        settings.ai_repetition_window_hours,
    )

    context = sanitize_alert_for_ai(alert, similar_alerts=similar)

    async with _get_semaphore():
        model_analysis = await analyzer.analyze_context(
            client or get_openai_client(), context
        )

    score, severity, band, factors = risk_assessment.combine(context, model_analysis)

    analysis = AIAlertAnalysis(
        alert_id=alert.id,
        model=settings.openai_model,
        agent_id=alert.agent.id,
        agent_name=alert.agent.name,
        agent_ip=alert.agent.ip,
        rule_id=alert.rule.id,
        rule_level=alert.rule.level,
        alert_timestamp=alert.timestamp,
        classification=model_analysis.classification,
        threat_type=model_analysis.threat_type,
        severity=severity,
        risk_score=score,
        risk_band=band,
        confidence=model_analysis.confidence,
        ai_risk_score=model_analysis.risk_score,
        baseline_risk_score=risk_assessment.compute_baseline(context, model_analysis)[0],
        risk_factors=factors,
        title=model_analysis.title or model_analysis.threat_type,
        summary=model_analysis.summary,
        explanation=model_analysis.explanation,
        why_dangerous=model_analysis.why_dangerous or model_analysis.explanation,
        potential_impact=model_analysis.potential_impact,
        indicators=model_analysis.indicators,
        recommendations=model_analysis.recommendations,
        remediation_available=model_analysis.remediation_available,
        remediation_type=model_analysis.remediation_type,
        remediation_summary=model_analysis.remediation_summary,
        affected_file=model_analysis.affected_file,
        affected_line=model_analysis.affected_line,
    )

    await _store_analysis(analysis)
    await notify_if_needed(analysis)
    logger.info(
        "Alerte %s analysee : %s, risque %s/100 (%s)",
        alert.id,
        analysis.classification,
        analysis.risk_score,
        analysis.severity,
    )
    return analysis


async def notify_if_needed(analysis: AIAlertAnalysis) -> Optional[AINotification]:
    """Cree une notification pour une analyse HIGH ou CRITICAL.

    Ne leve jamais : un probleme de notification ne doit pas invalider une
    analyse deja produite et payee.
    """
    try:
        notification, created = await notifications_service.create_from_analysis(analysis)
    except Exception:  # noqa: BLE001
        logger.exception("Creation de notification impossible pour %s", analysis.alert_id)
        return None

    if notification is None:
        return None

    # Diffusee dans les deux cas : une notification creee alerte
    # l'utilisateur, une notification enrichie met simplement a jour la
    # ligne deja affichee (le frontend distingue les deux par l'identifiant).
    await notifications_service.publish(notification)

    return notification


# --------------------------------------------------------------------------
# Analyse automatique (appelee par le poller, en tache detachee)
# --------------------------------------------------------------------------


def should_analyze(alert: Alert) -> bool:
    """Faut-il analyser automatiquement cette alerte ?"""
    if not settings.ai_analysis_enabled or not settings.ai_enabled:
        return False
    return alert.rule.level >= settings.ai_analysis_min_level


async def analyze_new_alerts(alerts: list[Alert]) -> list[AIAlertAnalysis]:
    """Analyse les nouvelles alertes eligibles, sans jamais lever.

    Appelee par le poller via `_spawn` : la boucle de surveillance ne
    l'attend pas et ne peut pas etre interrompue par une erreur OpenAI.
    """
    selected = [alert for alert in alerts if should_analyze(alert)]
    if not selected:
        return []

    results: list[AIAlertAnalysis] = []
    for alert in selected:
        try:
            analysis = await analyze_alert(alert)
        except AIError as exc:
            # Panne, quota, timeout, reponse invalide : l'alerte reste en
            # base et pourra etre analysee plus tard depuis l'interface.
            logger.warning(
                "Analyse IA impossible pour %s : %s", alert.id, exc.message
            )
            await _mark_failed(alert.id, exc.message)
            continue
        except Exception as exc:  # noqa: BLE001 - rien ne doit remonter au poller
            logger.exception("Erreur inattendue pendant l'analyse de %s", alert.id)
            await _mark_failed(alert.id, str(exc))
            continue

        results.append(analysis)
        await _publish(analysis)

    return results


async def _mark_failed(alert_id: str, message: str) -> None:
    """Note l'echec sur la notification, sans jamais lever.

    L'utilisateur voit "Echec de l'analyse" et la raison, au lieu d'une
    analyse fantome remplie de valeurs par defaut.
    """
    try:
        notification = await notifications_service.mark_analysis_failed(
            alert_id, message
        )
        if notification is not None:
            await notifications_service.publish(notification)
    except Exception:  # noqa: BLE001
        logger.exception("Impossible de noter l'echec d'analyse de %s", alert_id)


async def _publish(analysis: AIAlertAnalysis) -> None:
    """Pousse l'analyse aux navigateurs connectes. Jamais bloquant."""
    try:
        await stream.publish(
            StreamEvent(type="ai_analysis", data=analysis.model_dump(mode="json")),
            event_id=None,
        )
    except Exception:  # noqa: BLE001
        logger.exception("Diffusion SSE de l'analyse impossible")


# --------------------------------------------------------------------------
# Lecture
# --------------------------------------------------------------------------


async def list_analyses(
    limit: int = 50, severity: Optional[str] = None, min_score: int = 0
) -> list[AIAlertAnalysis]:
    """Analyses persistees, les plus recentes d'abord."""
    payloads = await asyncio.to_thread(
        store.list_ai_analyses, limit, severity, min_score
    )

    analyses: list[AIAlertAnalysis] = []
    for payload in payloads:
        try:
            analyses.append(AIAlertAnalysis.model_validate_json(payload))
        except ValueError:
            continue
    return analyses


async def get_stats() -> AIStats:
    """Vue globale affichee en haut de la page AI Security."""
    counters = await asyncio.to_thread(store.ai_analysis_stats)
    counters.update(await asyncio.to_thread(store.notification_stats))

    return AIStats(
        **counters,
        enabled=settings.ai_enabled,
        auto_analysis=settings.ai_analysis_enabled,
        model=settings.openai_model if settings.ai_enabled else "",
    )
