"""Notifications des alertes importantes.

Deux declencheurs, un seul systeme (meme table, meme format, meme flux SSE) :

1. **Le niveau Wazuh** : des qu'une nouvelle alerte atteint NOTIFY_LEVEL,
   une notification est creee par le poller, sans dependre d'OpenAI.
2. **L'analyse IA** : une analyse conclue HIGH ou CRITICAL notifie aussi, et
   *enrichit* la notification deja creee pour la meme alerte au lieu d'en
   ajouter une seconde.

Ce module ne parle jamais a OpenAI : il decide s'il faut notifier, met en
forme le message, et garantit qu'une meme alerte ne genere qu'une seule
notification.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from app import i18n, store
from app.ai.schemas import (
    NOTIFIABLE_SEVERITIES,
    AIAlertAnalysis,
    AINotification,
    severity_for_level,
)
from app.config import settings
from app.models import Alert, StreamEvent
from app.notifier import stream

logger = logging.getLogger(__name__)

# Libelle de severite affiche en tete de message : reference unique du
# projet (app.i18n), pour que la page Alertes, les notifications et les
# canaux externes disent tous la meme chose.
SEVERITY_MARK = i18n.SEVERITY_LABELS

# Origine d'une notification, telle que persistee dans `source`.
SOURCE_WAZUH = "wazuh"
SOURCE_AI = "ia"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def should_notify(analysis: AIAlertAnalysis) -> bool:
    """Faut-il notifier pour cette analyse ?

    Seules les severites HIGH et CRITICAL declenchent une notification, et
    uniquement si le canal correspondant est active dans la configuration.
    """
    if analysis.severity not in NOTIFIABLE_SEVERITIES:
        return False
    if analysis.severity == "HIGH":
        return settings.ai_high_notification_enabled
    return settings.ai_critical_notification_enabled


def build_message(analysis: AIAlertAnalysis) -> str:
    """Message lisible, repris tel quel par l'interface et les canaux.

    La severite affichee est celle de la notification (`notification_severity`),
    pas seulement celle du modele : sans cela, une ligne marquee CRITIQUE
    ouvrirait un message titre ELEVEE.
    """
    severity = notification_severity(analysis)
    mark = SEVERITY_MARK.get(severity, severity)
    title = analysis.title or analysis.threat_type or "Incident de sécurité"

    lines = [
        f"{mark} : {title}",
        "",
        f"Type      : {i18n.classification_label(analysis.classification)}",
        f"Serveur   : {analysis.agent_name or 'inconnu'}",
    ]

    if analysis.affected_file:
        lines.append(f"Fichier   : {analysis.affected_file}")
    if analysis.affected_line:
        lines.append(f"Ligne     : {analysis.affected_line}")

    lines += [
        f"Risque    : {mark} - {analysis.risk_score}/100",
        f"Confiance : {analysis.confidence_percent}%",
        "",
        "Pourquoi ?",
        analysis.why_dangerous or analysis.explanation or analysis.summary or "-",
    ]

    if analysis.potential_impact:
        lines += ["", "Impact potentiel :"]
        lines += [f"- {item}" for item in analysis.potential_impact]

    if analysis.recommendations:
        lines += ["", "Recommandations :"]
        lines += [f"- {item}" for item in analysis.recommendations]

    lines += [
        "",
        (
            "Correction proposée : " + analysis.remediation_summary
            if analysis.remediation_available and analysis.remediation_summary
            else "Aucune correction automatisable identifiée."
        ),
    ]

    return "\n".join(lines)


def initial_remediation_status(analysis: AIAlertAnalysis) -> str:
    """Etat de depart du cycle de remediation.

    Une correction disponible attend toujours une confirmation explicite :
    rien n'est applique sans decision humaine.
    """
    if not analysis.remediation_available or not settings.ai_remediation_enabled:
        return "not_available"
    if analysis.remediation_type in ("none", "manual_only"):
        return "proposed"
    return "awaiting_confirmation"


def _row_to_notification(row: dict[str, Any]) -> AINotification:
    def parse_list(value: Any) -> list[str]:
        if not value:
            return []
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            return []
        return parsed if isinstance(parsed, list) else []

    # Une notification issue du niveau Wazuh porte comme titre la
    # description de la regle. Les lignes creees avant la couche de
    # presentation l'ont stockee en anglais : on la traduit a la lecture.
    # L'operation est idempotente (un titre deja francais ressort inchange)
    # et la description d'origine reste dans `wazuh_description`.
    title = row["title"] or ""
    if (row.get("source") or SOURCE_AI) == SOURCE_WAZUH:
        title = i18n.localize_security_text(title)

    return AINotification(
        id=row["id"],
        alert_id=row["alert_id"],
        server_id=row["server_id"],
        server_name=row["server_name"],
        agent_id=row.get("agent_id"),
        rule_id=row.get("rule_id"),
        rule_level=row.get("rule_level") or 0,
        alert_timestamp=row.get("alert_timestamp"),
        source=row.get("source") or SOURCE_AI,
        title=title,
        wazuh_description=row.get("wazuh_description") or (
            row["title"] if (row.get("source") or SOURCE_AI) == SOURCE_WAZUH else None
        ),
        severity=row["severity"],
        classification=row["classification"],
        risk_score=row["risk_score"],
        confidence=row["confidence"],
        summary=row["summary"] or "",
        why_dangerous=row["why_dangerous"] or "",
        potential_impact=parse_list(row["potential_impact"]),
        recommendations=parse_list(row["recommendations"]),
        notification_message=row["notification_message"] or "",
        remediation_available=bool(row["remediation_available"]),
        remediation_type=row["remediation_type"],
        remediation_summary=row["remediation_summary"] or "",
        remediation_status=row["remediation_status"],
        affected_file=row["affected_file"],
        affected_line=row["affected_line"],
        status=row["status"],
        analysis_status=row.get("analysis_status") or "pending",
        analysis_error=row.get("analysis_error"),
        analyzed_at=row.get("analyzed_at"),
        occurrences=row["occurrences"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        acknowledged_at=row["acknowledged_at"],
        resolved_at=row["resolved_at"],
        dismissed_at=row["dismissed_at"],
    )


SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _max_severity(first: str, second: str) -> str:
    """La plus grave des deux severites."""
    return first if SEVERITY_ORDER.get(first, 0) >= SEVERITY_ORDER.get(second, 0) else second


def notification_severity(analysis: AIAlertAnalysis) -> str:
    """Severite affichee pour une analyse.

    Le niveau Wazuh sert de plancher : une regle de niveau 12 reste
    CRITICAL a l'ecran meme si le modele est plus indulgent. Sans cela, une
    meme alerte s'afficherait ELEVE dans la page Alertes et MEDIUM dans les
    notifications. L'IA peut en revanche aggraver le diagnostic.
    """
    return _max_severity(analysis.severity, severity_for_level(analysis.rule_level))


def _analysis_fields(analysis: AIAlertAnalysis) -> dict[str, Any]:
    """Champs decrivant une analyse IA, communs a la creation et a l'enrichissement."""
    return {
        "title": analysis.title or analysis.threat_type or "Incident de sécurité",
        "severity": notification_severity(analysis),
        "classification": analysis.classification,
        "risk_score": analysis.risk_score,
        "confidence": analysis.confidence,
        "summary": analysis.summary,
        "why_dangerous": analysis.why_dangerous or analysis.explanation,
        "potential_impact": json.dumps(analysis.potential_impact, ensure_ascii=False),
        "recommendations": json.dumps(analysis.recommendations, ensure_ascii=False),
        "notification_message": build_message(analysis),
        "remediation_available": 1 if analysis.remediation_available else 0,
        "remediation_type": analysis.remediation_type,
        "remediation_summary": analysis.remediation_summary,
        "remediation_status": initial_remediation_status(analysis),
        "affected_file": analysis.affected_file,
        "affected_line": analysis.affected_line,
        "source": SOURCE_AI,
        # Seul chemin qui peut declarer une notification analysee : le
        # modele a repondu et sa reponse a ete validee.
        "analysis_status": "analyzed",
        "analysis_error": None,
        "analyzed_at": analysis.analyzed_at,
    }


def _create_sync(analysis: AIAlertAnalysis) -> tuple[Optional[dict[str, Any]], bool]:
    """Cree la notification si besoin. Retourne (ligne, creee).

    `alert_id` porte la contrainte UNIQUE : une alerte deja notifiee n'est
    jamais dupliquee. Si elle avait ete creee sur le niveau Wazuh, l'analyse
    IA vient la completer (classification, score, recommandations,
    remediation) plutot que d'ouvrir une seconde notification.
    """
    existing = store.get_notification_by_alert(analysis.alert_id)

    if existing is None:
        if not should_notify(analysis):
            return None, False
    else:
        if existing.get("source") == SOURCE_WAZUH:
            store.update_notification_fields(
                existing["id"],
                updated_at=_now_iso(),
                **_analysis_fields(analysis),
            )
            store.write_audit(
                "NOTIFICATION_ENRICHED",
                notification_id=existing["id"],
                alert_id=analysis.alert_id,
                actor="agent-ia",
                target=analysis.agent_name,
            )
            logger.info(
                "Notification %s enrichie par l'analyse IA (%s, %s/100)",
                existing["id"],
                analysis.severity,
                analysis.risk_score,
            )
            return store.get_notification(existing["id"]), False

        store.touch_notification(existing["id"], _now_iso())
        logger.info(
            "Notification deja existante pour %s (occurrence %s)",
            analysis.alert_id,
            existing["occurrences"] + 1,
        )
        return store.get_notification(existing["id"]), False

    payload = {
        "alert_id": analysis.alert_id,
        "server_id": analysis.agent_name and analysis.agent_ip or None,
        "server_name": analysis.agent_name,
        "agent_id": analysis.agent_id,
        "rule_id": analysis.rule_id,
        "rule_level": analysis.rule_level,
        "alert_timestamp": analysis.alert_timestamp,
        "status": "new",
        "occurrences": 1,
        "created_at": _now_iso(),
        **_analysis_fields(analysis),
    }

    notification_id = store.insert_notification(payload)
    store.write_audit(
        "NOTIFICATION_CREATED",
        notification_id=notification_id,
        alert_id=analysis.alert_id,
        actor="agent-ia",
        target=analysis.agent_name,
    )
    logger.info(
        "Notification %s creee pour l'alerte %s (%s, %s/100)",
        notification_id,
        analysis.alert_id,
        analysis.severity,
        analysis.risk_score,
    )
    return store.get_notification(notification_id), True


async def create_from_analysis(
    analysis: AIAlertAnalysis,
) -> tuple[Optional[AINotification], bool]:
    """Cree la notification correspondant a une analyse, si elle le merite.

    Retourne (notification, creee). `creee` vaut False si la notification
    existait deja : le frontend ne doit alors pas re-alerter l'utilisateur,
    mais il recoit tout de meme le contenu mis a jour.

    Le seuil (severite HIGH ou CRITICAL) ne conditionne que la *creation* :
    une notification deja ouverte sur le niveau Wazuh est toujours enrichie
    par l'analyse, quel que soit le verdict du modele.
    """
    row, created = await asyncio.to_thread(_create_sync, analysis)
    if row is None:
        return None, False

    return _row_to_notification(row), created


# --------------------------------------------------------------------------
# Notification directe, a partir du niveau Wazuh (NOTIFY_LEVEL)
# --------------------------------------------------------------------------


def should_notify_alert(alert: Alert) -> bool:
    """Cette alerte merite-t-elle une notification ?

    Un seul critere, celui de la configuration : le niveau de la regle
    Wazuh atteint NOTIFY_LEVEL. Aucune distinction d'agent, de systeme
    d'exploitation ni de regle : ce qui vaut pour un serveur vaut pour tous.
    """
    return alert.rule.level >= settings.notify_level


def build_alert_message(alert: Alert, severity: str) -> str:
    """Message d'une notification issue directement d'une alerte Wazuh.

    L'evenement est presente en francais ; la description Wazuh d'origine
    est conservee en clair sur sa propre ligne, pour le diagnostic.
    """
    mark = SEVERITY_MARK.get(severity, severity)
    event = alert.description_fr or "Alerte de sécurité"

    lines = [
        f"{mark} : {event}",
        "",
        f"Serveur           : {alert.agent.name or 'inconnu'}"
        + (f" ({alert.agent.ip})" if alert.agent.ip else ""),
        f"Agent Wazuh       : {alert.agent.id or 'inconnu'}",
        f"Événement         : {event}",
        f"Date              : {alert.timestamp}",
        f"Règle Wazuh       : {alert.rule.id or '-'}",
        f"Niveau Wazuh      : {alert.rule.level}/15",
        f"Sévérité          : {mark}",
    ]

    if alert.rule.description:
        # Donnee Wazuh originale : jamais perdue, jamais reecrite.
        lines.append(f"Description Wazuh : {alert.rule.description}")
    if alert.rule.groups:
        lines.append(f"Catégories        : {i18n.rule_groups_label(alert.rule.groups)}")
    if alert.location:
        lines.append(f"Source            : {alert.location}")

    lines += [
        "",
        (
            "Analyse IA en attente : lancez-la depuis AI Security pour obtenir "
            "le score de risque, l'explication et les recommandations."
        ),
    ]
    return "\n".join(lines)


def _cooldown_reference() -> Optional[str]:
    """Debut de la fenetre de cooldown, ou None si le cooldown est desactive."""
    if settings.notify_cooldown <= 0:
        return None
    moment = datetime.now(timezone.utc) - timedelta(seconds=settings.notify_cooldown)
    return moment.isoformat()


def _create_from_alert_sync(alert: Alert) -> tuple[Optional[dict[str, Any]], bool]:
    """Cree la notification d'une alerte. Retourne (ligne, creee)."""
    existing = store.get_notification_by_alert(alert.id)
    if existing is not None:
        # Meme alerte Wazuh : jamais deux notifications.
        return existing, False

    severity = severity_for_level(alert.rule.level)

    # Cooldown : une meme regle qui se repete sur un meme serveur ne
    # declenche pas une avalanche. Il ne s'applique jamais a un autre
    # serveur, a une autre regle, ni a une severite qui s'aggrave.
    since = _cooldown_reference()
    if since is not None:
        recent = store.find_recent_notification(alert.agent.id, alert.rule.id, since)
        if recent is not None and not _is_escalation(severity, recent["severity"]):
            store.touch_notification(recent["id"], _now_iso())
            logger.info(
                "Notification %s regroupee (cooldown %ss, agent %s, regle %s)",
                recent["id"],
                settings.notify_cooldown,
                alert.agent.id,
                alert.rule.id,
            )
            return store.get_notification(recent["id"]), False

    payload = {
        "alert_id": alert.id,
        "server_id": alert.agent.ip or alert.agent.id,
        "server_name": alert.agent.name,
        "agent_id": alert.agent.id,
        "rule_id": alert.rule.id,
        "rule_level": alert.rule.level,
        "alert_timestamp": alert.timestamp,
        "source": SOURCE_WAZUH,
        # Titre affiche : description Wazuh traduite. L'originale reste
        # dans le message (ligne "Description Wazuh") et dans l'alerte.
        "title": alert.description_fr or "Alerte de sécurité",
        "severity": severity,
        # Sans analyse IA, la classification reste honnetement inconnue et
        # le risk score a zero : rien n'est invente.
        "classification": "unknown",
        "risk_score": 0,
        "confidence": 0.0,
        "summary": (
            f"{alert.description_fr or 'Alerte de sécurité'} "
            f"(règle {alert.rule.id or '-'}, niveau {alert.rule.level}/15) "
            f"sur {alert.agent.name or 'serveur inconnu'}."
        ),
        "why_dangerous": "",
        "potential_impact": "[]",
        "recommendations": "[]",
        "notification_message": build_alert_message(alert, severity),
        "remediation_available": 0,
        "remediation_type": "none",
        "remediation_summary": "",
        "remediation_status": "not_available",
        "status": "new",
        # Une notification n'est PAS une analyse : tant que l'agent IA n'a
        # rien produit, l'etat reste "en attente d'analyse".
        "analysis_status": "pending",
        "wazuh_description": alert.rule.description,
        "occurrences": 1,
        "created_at": _now_iso(),
    }

    notification_id = store.insert_notification(payload)
    store.write_audit(
        "NOTIFICATION_CREATED",
        notification_id=notification_id,
        alert_id=alert.id,
        actor="wazuh",
        target=alert.agent.name,
    )
    logger.info(
        "Notification %s creee pour l'alerte %s (%s, niveau Wazuh %s, agent %s)",
        notification_id,
        alert.id,
        severity,
        alert.rule.level,
        alert.agent.id,
    )
    return store.get_notification(notification_id), True


def _is_escalation(severity: str, previous: str) -> bool:
    """Vrai si la nouvelle severite est plus grave que la precedente."""
    return SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(previous, 0)


async def create_from_alert(alert: Alert) -> tuple[Optional[AINotification], bool]:
    """Cree la notification d'une alerte Wazuh, si son niveau le justifie.

    Retourne (notification, creee). `creee` vaut False quand l'alerte est
    sous le seuil, deja notifiee, ou regroupee par le cooldown.
    """
    if not should_notify_alert(alert):
        return None, False

    row, created = await asyncio.to_thread(_create_from_alert_sync, alert)
    if row is None:
        return None, False

    return _row_to_notification(row), created


# --------------------------------------------------------------------------
# Diffusion temps reel
# --------------------------------------------------------------------------


async def publish(notification: AINotification) -> None:
    """Pousse la notification aux navigateurs connectes. Jamais bloquant."""
    try:
        await stream.publish(
            StreamEvent(
                type="ai_notification", data=notification.model_dump(mode="json")
            ),
            event_id=None,
        )
    except Exception:  # noqa: BLE001 - une panne SSE n'invalide pas la notification
        logger.exception("Diffusion SSE de la notification impossible")


# --------------------------------------------------------------------------
# Lecture et transitions d'etat
# --------------------------------------------------------------------------


async def list_notifications(**filters: Any) -> list[AINotification]:
    rows = await asyncio.to_thread(store.list_notifications, **filters)
    return [_row_to_notification(row) for row in rows]


async def get(notification_id: int) -> Optional[AINotification]:
    row = await asyncio.to_thread(store.get_notification, notification_id)
    return _row_to_notification(row) if row else None


async def acknowledge(notification_id: int, actor: str = "utilisateur") -> Optional[AINotification]:
    """Marque la notification comme vue."""
    row = await asyncio.to_thread(store.get_notification, notification_id)
    if row is None:
        return None

    now = _now_iso()
    await asyncio.to_thread(
        store.update_notification_fields,
        notification_id,
        status="acknowledged",
        acknowledged_at=now,
        updated_at=now,
    )
    await asyncio.to_thread(
        store.write_audit,
        "NOTIFICATION_ACKNOWLEDGED",
        notification_id,
        row["alert_id"],
        None,
        actor,
    )
    return await get(notification_id)


async def dismiss(notification_id: int, actor: str = "utilisateur") -> Optional[AINotification]:
    """Ecarte la notification sans appliquer de correction."""
    row = await asyncio.to_thread(store.get_notification, notification_id)
    if row is None:
        return None

    now = _now_iso()
    fields: dict[str, Any] = {
        "status": "dismissed",
        "dismissed_at": now,
        "updated_at": now,
    }
    # Une correction en attente devient annulee : elle ne reste pas ouverte.
    if row["remediation_status"] in ("awaiting_confirmation", "proposed", "pending"):
        fields["remediation_status"] = "cancelled"

    await asyncio.to_thread(store.update_notification_fields, notification_id, **fields)
    await asyncio.to_thread(
        store.write_audit,
        "NOTIFICATION_DISMISSED",
        notification_id,
        row["alert_id"],
        None,
        actor,
    )
    return await get(notification_id)


# --------------------------------------------------------------------------
# Etat de l'analyse IA
# --------------------------------------------------------------------------
#
# Ces transitions ne touchent qu'`analysis_status` : le statut de lecture
# (`status`), le cooldown, la remediation et la logique HIGH/CRITICAL sont
# inchanges. Une notification absente n'est jamais creee ici : analyser une
# alerte sous le seuil de notification reste possible sans en ouvrir une.


def _set_analysis_state(alert_id: str, **fields: Any) -> Optional[dict[str, Any]]:
    row = store.get_notification_by_alert(alert_id)
    if row is None:
        return None
    store.update_notification_fields(row["id"], updated_at=_now_iso(), **fields)
    return store.get_notification(row["id"])


async def mark_analysis_started(alert_id: str) -> Optional[AINotification]:
    """L'analyse vient d'etre lancee : l'interface affiche "Analyse en cours"."""
    row = await asyncio.to_thread(
        _set_analysis_state, alert_id, analysis_status="analyzing", analysis_error=None
    )
    return _row_to_notification(row) if row else None


async def mark_analysis_failed(
    alert_id: str, error: str
) -> Optional[AINotification]:
    """L'analyse a echoue : on le dit, sans inventer de resultat.

    Les champs du modele (classification, score, confiance) restent a leur
    valeur d'origine et ne sont jamais presentes comme un resultat.
    """
    row = await asyncio.to_thread(
        _set_analysis_state,
        alert_id,
        analysis_status="failed",
        analysis_error=error[:300],
    )
    if row is None:
        return None

    await asyncio.to_thread(
        store.write_audit,
        "ANALYSIS_FAILED",
        row["id"],
        alert_id,
        None,
        "agent-ia",
        None,
        "error",
        error[:300],
    )
    return _row_to_notification(row)


async def sync_cached_analysis(
    analysis: AIAlertAnalysis,
) -> Optional[AINotification]:
    """Aligne la notification sur une analyse deja calculee (cache).

    Sert au seul cas ou `analyze_alert` repond sans rappeler le modele :
    sans cela, une notification passee a "analyse en cours" y resterait.
    N'incremente jamais `occurrences` : relire une analyse n'est pas une
    nouvelle occurrence de l'alerte.
    """
    row = await asyncio.to_thread(store.get_notification_by_alert, analysis.alert_id)
    if row is None:
        return None

    # Notification encore issue du seul niveau Wazuh : l'analyse en cache
    # ne lui a jamais ete appliquee, on l'enrichit maintenant.
    if (row.get("source") or SOURCE_AI) == SOURCE_WAZUH:
        notification, _ = await create_from_analysis(analysis)
        return notification

    if row.get("analysis_status") == "analyzed":
        return None

    updated = await asyncio.to_thread(
        _set_analysis_state,
        analysis.alert_id,
        analysis_status="analyzed",
        analysis_error=None,
        analyzed_at=analysis.analyzed_at,
    )
    return _row_to_notification(updated) if updated else None
