"""Routes HTTP de l'API Wazuh Supervision."""

import logging
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse
from pydantic import ValidationError

from app import poller, server_provisioning, store
from app.auth import AGENT_AUTH
from app.ai import agent as ai_agent
from app.ai import notifications as ai_notifications
from app.ai import remediation as ai_remediation
from app.ai.openai_client import AIError
from app.ai.remediation import RemediationError
from app.config import settings
from app.ai.schemas import (
    HIGH_LEVEL,
    MEDIUM_LEVEL,
    AIAlertAnalysis,
    AIAnalysisRequest,
    AINotification,
    AIStats,
    AuditEntry,
    RemediationDecision,
    RemediationPreview,
    RemediationRecord,
)
from app.models import (
    ActionResponse,
    Agent,
    Alert,
    HealthResponse,
    MonitoringStatus,
    ServerCheckRequest,
    ServerConnectionStatus,
    ServerInstallInstructions,
    ServerProvisionRequest,
    UiConfig,
)
from app.notifier import stream
from app.server_provisioning import ProvisioningConfigError
from app.wazuh_client import WazuhError, get_wazuh_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api")


def _http_error(exc: WazuhError) -> HTTPException:
    """Traduit une erreur Wazuh en reponse HTTP lisible (sans secret)."""
    logger.warning("Erreur Wazuh: %s (%s)", exc.message, exc.detail)
    return HTTPException(
        status_code=exc.status_code,
        detail={"error": exc.message, "detail": exc.detail},
    )


def _config_error(exc: ProvisioningConfigError) -> HTTPException:
    """Traduit une configuration d'enrolement manquante en reponse HTTP.

    503 et non 422 : la demande de l'utilisateur est valide, c'est le backend
    qui n'est pas configure. Le message dit quoi renseigner dans le .env.
    """
    logger.error("Configuration d'enrolement invalide: %s", exc.message)
    return HTTPException(
        status_code=503,
        detail={"error": exc.message, "detail": exc.detail},
    )


# --- Sante -----------------------------------------------------------------


@router.get("/health", response_model=HealthResponse)
async def health():
    """Verifie que le backend est operationnel (API + base SQLite)."""
    try:
        alerts_stored = store.count_alerts()
        database = "ok"
    except Exception as exc:  # noqa: BLE001 - le health ne doit jamais planter
        logger.warning("Base SQLite indisponible: %s", exc)
        alerts_stored = 0
        database = "error"

    return HealthResponse(
        application=settings.app_name,
        status="ok" if database == "ok" else "degraded",
        monitoring=poller.get_status().running,
        sse_clients=stream.subscriber_count(),
        database=database,
        alerts_stored=alerts_stored,
    )


@router.get("/config", response_model=UiConfig)
async def ui_config():
    """Reglages necessaires au frontend (seuils, intervalle)."""
    return UiConfig(
        app_name=settings.app_name,
        poll_interval=settings.poll_interval,
        critical_level=settings.critical_level,
        high_level=HIGH_LEVEL,
        medium_level=MEDIUM_LEVEL,
        notify_level=settings.notify_level,
        notify_cooldown=settings.notify_cooldown,
        ai_enabled=settings.ai_enabled,
        ai_auto_analysis=settings.ai_analysis_enabled,
    )


# --- Surveillance ----------------------------------------------------------


@router.post("/monitoring/start", response_model=ActionResponse)
async def start_monitoring():
    """Demarre la surveillance de notre application (pas Wazuh lui-meme).

    Idempotent : si la surveillance tourne deja, l'etat courant est renvoye
    sans creer de seconde tache.
    """
    already_running = poller.get_status().running
    status = await poller.start()
    return ActionResponse(
        ok=True,
        message=(
            "Surveillance déjà active" if already_running else "Surveillance démarrée"
        ),
        status=status,
    )


@router.post("/monitoring/stop", response_model=ActionResponse)
async def stop_monitoring():
    """Arrete la surveillance. Idempotent lui aussi."""
    was_running = poller.get_status().running
    status = await poller.stop()
    return ActionResponse(
        ok=True,
        message=(
            "Surveillance arrêtée" if was_running else "Surveillance déjà arrêtée"
        ),
        status=status,
    )


@router.get("/monitoring/status", response_model=MonitoringStatus)
async def monitoring_status():
    """Etat courant de la surveillance."""
    return poller.get_status()


# --- Donnees Wazuh ---------------------------------------------------------


@router.get("/servers", response_model=list[Agent])
async def servers(
    limit: int = Query(default=0, ge=0, le=1000, description="0 = valeur du .env"),
    include_manager: bool = Query(
        default=False,
        description="Inclure l'agent 000 (le Wazuh Manager lui-meme)",
    ),
):
    """Liste simplifiee des agents / serveurs Wazuh.

    L'agent 000 est le manager : il est exclu par defaut, car ce n'est pas
    un serveur ajoute par l'utilisateur. Un serveur enrole via
    "Ajouter un serveur" apparait ici automatiquement, sans liste parallele.
    """
    try:
        agents = await get_wazuh_client().get_agents(limit=limit or None)
    except WazuhError as exc:
        raise _http_error(exc) from exc

    return agents if include_manager else server_provisioning.exclude_manager(agents)


@router.post(
    "/servers/provision/instructions",
    response_model=ServerInstallInstructions,
)
async def provision_instructions(request: ServerProvisionRequest):
    """Genere la procedure d'installation de l'agent sur un serveur.

    L'application n'execute aucune de ces commandes : elle les affiche pour
    que l'utilisateur les lance lui-meme sur sa machine.

    Repond 503 tant que l'enrolement n'est pas configure (WAZUH_MANAGER_ADDRESS
    en tete) : aucune procedure approximative n'est renvoyee.
    """
    try:
        return server_provisioning.build_instructions(request)
    except ProvisioningConfigError as exc:
        raise _config_error(exc) from exc


@router.post("/servers/check", response_model=ServerConnectionStatus)
async def check_server(request: ServerCheckRequest):
    """Verifie aupres du Wazuh Manager si le serveur est bien enrole."""
    try:
        return await server_provisioning.check_server(get_wazuh_client(), request)
    except WazuhError as exc:
        raise _http_error(exc) from exc


@router.get("/alerts", response_model=list[Alert])
async def alerts(
    size: int = Query(default=0, ge=0, le=500, description="0 = valeur du .env"),
    min_level: int = Query(default=0, ge=0, le=16),
):
    """Dernieres alertes de securite (source : Wazuh Indexer)."""
    try:
        return await get_wazuh_client().get_alerts(
            size=size or None, min_level=min_level
        )
    except WazuhError as exc:
        raise _http_error(exc) from exc


@router.get("/alerts/stored", response_model=list[Alert])
async def stored_alerts(
    limit: int = Query(default=50, ge=1, le=500),
    min_level: int = Query(default=0, ge=0, le=16),
    agent_id: Optional[str] = Query(
        default=None, description="Identifiant d'agent Wazuh (vide = tous)"
    ),
):
    """Alertes deja persistees en SQLite (sans appeler Wazuh).

    Sans `agent_id`, les alertes de tous les agents sont renvoyees : aucun
    agent n'est privilegie, quel que soit son systeme d'exploitation.
    """
    return store.list_alerts(limit=limit, min_level=min_level, agent_id=agent_id)


@router.get("/alerts/agents")
async def stored_alert_agents():
    """Agents ayant produit des alertes enregistrees (pour les filtres)."""
    return store.list_alert_agents()


# --- Agent IA --------------------------------------------------------------


def _ai_http_error(exc: AIError) -> HTTPException:
    """Traduit une erreur IA en reponse HTTP lisible (sans secret)."""
    logger.warning("Erreur IA: %s (%s)", exc.message, exc.detail)
    return HTTPException(
        status_code=exc.status_code,
        detail={"error": exc.message, "detail": exc.detail},
    )


@router.post("/ai/analyze", response_model=AIAlertAnalysis)
async def ai_analyze(request: AIAnalysisRequest):
    """Analyse une alerte : classification, risque, explication, conseils.

    Accepte soit `alert_id` (l'alerte est relue en base), soit l'alerte
    complete. Une alerte deja analysee est servie depuis le cache, sans
    nouvel appel au modele, sauf si `force` est vrai.
    """
    alert = None

    if request.alert:
        try:
            alert = Alert.model_validate(request.alert)
        except ValidationError as exc:
            raise HTTPException(
                status_code=422,
                detail={"error": "Alerte invalide", "detail": str(exc.errors()[:2])},
            ) from exc
    elif request.alert_id:
        alert = store.get_alert(request.alert_id)

        if alert is None:
            # L'alerte est affichee mais pas encore persistee (poller a
            # l'arret, ou alerte plus ancienne que la base) : on la relit
            # dans l'Indexer plutot que de refuser l'analyse.
            try:
                alert = await get_wazuh_client().get_alert_by_id(request.alert_id)
            except WazuhError as exc:
                raise _http_error(exc) from exc

            if alert is not None:
                # Enregistree au passage : l'analyse, le cache et la page
                # AI Security parlent ensuite de la meme alerte.
                await run_in_threadpool(store.save_alert, alert)

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "Alerte introuvable", "detail": request.alert_id},
        )

    # L'etat de l'analyse suit son deroulement reel : "en cours" pendant
    # l'appel au modele, "analysee" seulement si le resultat est valide,
    # "echec" sinon. Aucune de ces transitions ne cree de notification.
    await ai_notifications.mark_analysis_started(alert.id)

    try:
        return await ai_agent.analyze_alert(alert, force=request.force)
    except AIError as exc:
        notification = await ai_notifications.mark_analysis_failed(
            alert.id, f"{exc.message} ({exc.detail})" if exc.detail else exc.message
        )
        if notification is not None:
            await ai_notifications.publish(notification)
        raise _ai_http_error(exc) from exc


@router.get("/ai/alerts", response_model=list[AIAlertAnalysis])
async def ai_alerts(
    limit: int = Query(default=50, ge=1, le=500),
    severity: Optional[str] = Query(default=None),
    min_score: int = Query(default=0, ge=0, le=100),
):
    """Alertes deja analysees, les plus recentes d'abord."""
    return await ai_agent.list_analyses(
        limit=limit, severity=severity, min_score=min_score
    )


@router.get("/ai/stats", response_model=AIStats)
async def ai_stats():
    """Vue globale : nombre d'analyses par severite et score moyen."""
    return await ai_agent.get_stats()


# --- Notifications IA ------------------------------------------------------


async def _load_notification(notification_id: int) -> AINotification:
    """Charge une notification ou repond 404."""
    notification = await ai_notifications.get(notification_id)
    if notification is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "Notification introuvable", "detail": str(notification_id)},
        )
    return notification


def _remediation_error(exc: RemediationError) -> HTTPException:
    logger.info("Remediation refusee: %s (%s)", exc.message, exc.detail)
    return HTTPException(
        status_code=exc.status_code,
        detail={"error": exc.message, "detail": exc.detail},
    )


@router.get("/ai/notifications", response_model=list[AINotification])
async def ai_notifications_list(
    limit: int = Query(default=100, ge=1, le=500),
    severity: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    remediation_status: Optional[str] = Query(default=None),
    analysis_status: Optional[str] = Query(
        default=None, description="pending | analyzing | analyzed | failed"
    ),
    server: Optional[str] = Query(default=None),
    classification: Optional[str] = Query(default=None),
    remediation_available: Optional[bool] = Query(default=None),
    since: Optional[str] = Query(default=None, description="Date ISO minimale"),
    search: Optional[str] = Query(default=None),
):
    """Historique des notifications, avec filtres et recherche textuelle."""
    return await ai_notifications.list_notifications(
        limit=limit,
        severity=severity,
        status=status,
        remediation_status=remediation_status,
        analysis_status=analysis_status,
        server=server,
        classification=classification,
        remediation_available=remediation_available,
        since=since,
        search=search,
    )


@router.get("/ai/notifications/{notification_id}", response_model=AINotification)
async def ai_notification_detail(notification_id: int):
    """Detail complet d'une notification."""
    return await _load_notification(notification_id)


@router.post(
    "/ai/notifications/{notification_id}/acknowledge", response_model=AINotification
)
async def ai_notification_acknowledge(notification_id: int):
    """Marque la notification comme vue."""
    await _load_notification(notification_id)
    return await ai_notifications.acknowledge(notification_id)


@router.post("/ai/notifications/{notification_id}/dismiss", response_model=AINotification)
async def ai_notification_dismiss(notification_id: int):
    """Ecarte la notification sans appliquer de correction."""
    await _load_notification(notification_id)
    return await ai_notifications.dismiss(notification_id)


@router.get("/ai/notifications/{notification_id}/audit", response_model=list[AuditEntry])
async def ai_notification_audit(notification_id: int):
    """Journal d'audit de cette notification."""
    await _load_notification(notification_id)
    rows = store.list_audit(limit=100, notification_id=notification_id)
    return [AuditEntry(**row) for row in rows]


# --- Remediation -----------------------------------------------------------


@router.post(
    "/ai/notifications/{notification_id}/remediation/preview",
    response_model=RemediationPreview,
)
async def ai_remediation_preview(notification_id: int):
    """Prepare la correction : lecture seule, aucun fichier n'est modifie."""
    notification = await _load_notification(notification_id)
    try:
        return await ai_remediation.build_preview(notification)
    except AIError as exc:
        raise _ai_http_error(exc) from exc


@router.post(
    "/ai/notifications/{notification_id}/remediation/confirm",
    response_model=RemediationRecord,
)
async def ai_remediation_confirm(notification_id: int, decision: RemediationDecision):
    """Applique la correction, uniquement sur confirmation explicite.

    Sans `confirmed: true`, rien n'est ecrit : la demande est refusee.
    """
    notification = await _load_notification(notification_id)

    if not decision.confirmed:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Confirmation explicite requise",
                "detail": "Envoyez confirmed=true pour appliquer la correction.",
            },
        )

    try:
        return await ai_remediation.confirm(notification, actor=decision.actor)
    except RemediationError as exc:
        raise _remediation_error(exc) from exc
    except AIError as exc:
        raise _ai_http_error(exc) from exc


@router.post(
    "/ai/notifications/{notification_id}/remediation/reject",
    response_model=AINotification,
)
async def ai_remediation_reject(notification_id: int, decision: RemediationDecision):
    """L'utilisateur refuse la correction proposee."""
    notification = await _load_notification(notification_id)
    return await ai_remediation.reject(
        notification, reason=decision.reason, actor=decision.actor
    )


@router.get("/ai/remediations", response_model=list[RemediationRecord])
async def ai_remediations_list(
    limit: int = Query(default=100, ge=1, le=500),
    notification_id: Optional[int] = Query(default=None),
):
    """Historique des operations de remediation."""
    return await ai_remediation.list_records(
        limit=limit, notification_id=notification_id
    )


@router.get("/ai/remediations/{remediation_id}", response_model=RemediationRecord)
async def ai_remediation_detail(remediation_id: int):
    record = await ai_remediation.get_record(remediation_id)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "Remédiation introuvable", "detail": str(remediation_id)},
        )
    return record


@router.post(
    "/ai/remediations/{remediation_id}/rollback", response_model=RemediationRecord
)
async def ai_remediation_rollback(remediation_id: int):
    """Restaure la sauvegarde prise avant l'application."""
    try:
        return await ai_remediation.rollback(remediation_id)
    except RemediationError as exc:
        raise _remediation_error(exc) from exc


@router.get("/ai/audit", response_model=list[AuditEntry])
async def ai_audit(limit: int = Query(default=100, ge=1, le=500)):
    """Journal d'audit complet des actions de remediation."""
    return [AuditEntry(**row) for row in store.list_audit(limit=limit)]


# --- Temps reel ------------------------------------------------------------


@router.get("/stream", dependencies=[AGENT_AUTH])
async def event_stream(
    request: Request,
    last_event_id: Optional[str] = Header(default=None, alias="Last-Event-ID"),
    since_id: Optional[str] = Query(
        default=None, description="Repli si l'en-tete Last-Event-ID est absent"
    ),
    project_uid: Optional[str] = Query(
        default=None,
        max_length=64,
        description=(
            "Portee de l'abonnement. Fourni, le client ne recoit que les "
            "evenements de ce projet — un flux ouvert sur un autre projet "
            "n'en verra aucun."
        ),
    ),
):
    """Flux SSE des nouvelles alertes et des findings enrichis.

    Plusieurs clients peuvent ecouter simultanement. Le client se
    reconnecte seul (`retry:`) et renvoie `Last-Event-ID` : les alertes
    arrivees pendant la coupure sont alors rejouees depuis SQLite.

    Authentification exigee depuis la phase 0 : les evenements
    `code_finding` portent des extraits du code analyse, et un flux ouvert
    sans controle les livrait a tout processus local.
    """
    if stream.broker.is_full:
        raise HTTPException(
            status_code=503,
            detail={"error": "Trop de clients SSE connectés"},
        )

    return StreamingResponse(
        stream.subscribe(
            last_event_id=last_event_id or since_id,
            is_disconnected=request.is_disconnected,
            project_uid=project_uid,
        ),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            # Desactive la mise en tampon des proxys (nginx et consorts).
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/stream/stats")
async def stream_stats():
    """Etat du diffuseur SSE (clients connectes, evenements publies)."""
    return stream.stats()
