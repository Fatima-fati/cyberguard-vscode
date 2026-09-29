"""Etat de l'analyse IA d'une notification.

Regle centrale verifiee ici : une notification n'est "analysee" que si le
modele a reellement produit un resultat valide. Ni sa creation, ni sa
lecture par l'utilisateur ne doivent l'affirmer.
"""

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from app import store
from app.ai import agent as ai_agent
from app.ai import notifications as ai_notifications
from app.ai.openai_client import OpenAIClient
from app.config import settings
from app.main import app

from .conftest import make_alert

# Alerte reelle utilisee comme reference (agent 002, regle 5902, niveau 8).
ALERT_5902 = dict(
    wazuh_id="6vJi9p8BH67rg_OAcINX",
    level=8,
    description="New user added to the system.",
    agent_id="002",
    agent_name="fatima-zahra-VMware-Virtual-Platform",
)

VALID_ANSWER = {
    "classification": "policy_violation",
    "threat_type": "creation de compte non planifiee",
    "severity": "MEDIUM",
    "risk_score": 45,
    "confidence": 0.7,
    "title": "Création d'un nouvel utilisateur sur le système",
    "summary": "Un compte utilisateur a été ajouté sur le serveur.",
    "explanation": "Les journaux montrent l'ajout d'un compte local.",
    "why_dangerous": "Un compte créé hors procédure peut servir de porte dérobée.",
    "potential_impact": ["Accès persistant au serveur"],
    "indicators": ["Ajout d'un compte local"],
    "recommendations": ["Vérifier que la création est légitime"],
    "risk_factors": ["Aucune fenêtre de maintenance connue"],
    "remediation_available": False,
    "remediation_type": "manual_only",
    "remediation_summary": "",
}


@pytest.fixture(autouse=True)
def ai_configured(monkeypatch):
    monkeypatch.setattr(settings, "openai_api_key", "sk-test-cle-factice")
    monkeypatch.setattr(settings, "openai_model", "gpt-4o-mini")
    monkeypatch.setattr(settings, "notify_level", 7)
    monkeypatch.setattr(settings, "ai_analysis_enabled", True)
    monkeypatch.setattr(settings, "ai_analysis_min_level", 7)
    ai_agent.reset_semaphore()
    yield
    ai_agent.reset_semaphore()


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def fake_openai(monkeypatch, handler):
    """Branche un client OpenAI dont le transport est simule."""
    fake = OpenAIClient()
    fake._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(ai_agent, "get_openai_client", lambda: fake)
    return fake


def answer_ok(request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "model": "gpt-4o-mini",
            "usage": {"total_tokens": 400},
            "choices": [
                {"message": {"content": json.dumps(VALID_ANSWER, ensure_ascii=False)}}
            ],
        },
    )


def answer_down(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("service injoignable")


async def create_notification(alert):
    store.save_alert(alert)
    notification, created = await ai_notifications.create_from_alert(alert)
    assert created is True
    return notification


# --------------------------------------------------------------------------
# Cas 1 : notification creee, aucune analyse
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_une_notification_creee_est_en_attente_d_analyse():
    """Reproduit le cas signale : agent 002, regle 5902, niveau 8."""
    notification = await create_notification(make_alert(**ALERT_5902))

    assert notification.analysis_status == "pending"
    assert notification.analysis_status_label == "En attente d'analyse"
    assert notification.analyzed is False
    assert notification.analysis_error is None
    # Le statut de lecture ne dit rien de l'analyse.
    assert notification.status == "new"
    assert notification.status_label == "Nouvelle"
    # Les champs du modele restent a leur valeur d'origine : le frontend
    # sait qu'ils ne sont pas un resultat grace a `analyzed`.
    assert notification.classification == "unknown"
    assert notification.risk_score == 0
    assert notification.confidence == 0.0


@pytest.mark.asyncio
async def test_consulter_une_notification_ne_la_declare_pas_analysee():
    """La cause exacte du bug : acquitter n'est pas analyser."""
    notification = await create_notification(make_alert(**ALERT_5902))

    acknowledged = await ai_notifications.acknowledge(notification.id)

    assert acknowledged.status == "acknowledged"
    assert acknowledged.status_label == "Vue"
    # L'analyse, elle, n'a pas bouge.
    assert acknowledged.analysis_status == "pending"
    assert acknowledged.analysis_status_label == "En attente d'analyse"
    assert acknowledged.analyzed is False


@pytest.mark.asyncio
async def test_la_description_wazuh_est_conservee_et_traduite():
    notification = await create_notification(make_alert(**ALERT_5902))

    assert notification.title == "Un nouvel utilisateur a été ajouté au système."
    assert notification.wazuh_description == "New user added to the system."


# --------------------------------------------------------------------------
# Cas 2 : analyse reussie
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_une_analyse_reussie_marque_la_notification_analysee(monkeypatch):
    alert = make_alert(**ALERT_5902)
    await create_notification(alert)
    fake_openai(monkeypatch, answer_ok)

    await ai_agent.analyze_alert(alert)

    refreshed = await ai_notifications.get(1)
    assert refreshed.analysis_status == "analyzed"
    assert refreshed.analysis_status_label == "Analysée"
    assert refreshed.analyzed is True
    assert refreshed.analysis_error is None
    # Les valeurs viennent reellement du modele.
    assert refreshed.classification == "policy_violation"
    assert refreshed.risk_score > 0
    assert refreshed.confidence == 0.7
    assert refreshed.recommendations == ["Vérifier que la création est légitime"]
    # La donnee Wazuh d'origine n'est pas perdue par l'enrichissement.
    assert refreshed.wazuh_description == "New user added to the system."


@pytest.mark.asyncio
async def test_une_analyse_servie_depuis_le_cache_reste_analysee(monkeypatch):
    alert = make_alert(**ALERT_5902)
    await create_notification(alert)
    fake_openai(monkeypatch, answer_ok)

    await ai_agent.analyze_alert(alert)
    await ai_notifications.mark_analysis_started(alert.id)
    cached = await ai_agent.analyze_alert(alert)

    assert cached.cached is True
    refreshed = await ai_notifications.get(1)
    assert refreshed.analysis_status == "analyzed"


# --------------------------------------------------------------------------
# Cas 3 : analyse en echec
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_une_analyse_en_echec_est_signalee_sans_resultat_invente(monkeypatch):
    alert = make_alert(**ALERT_5902)
    await create_notification(alert)
    fake_openai(monkeypatch, answer_down)

    await ai_agent.analyze_new_alerts([alert])

    refreshed = await ai_notifications.get(1)
    assert refreshed.analysis_status == "failed"
    assert refreshed.analysis_status_label == "Échec de l'analyse"
    assert refreshed.analyzed is False
    assert "injoignable" in refreshed.analysis_error
    # Aucun resultat n'a ete fabrique.
    assert refreshed.classification == "unknown"
    assert refreshed.risk_score == 0


@pytest.mark.asyncio
async def test_l_endpoint_analyze_note_l_echec_et_repond_en_francais(
    client, monkeypatch
):
    alert = make_alert(**ALERT_5902)
    await create_notification(alert)
    fake_openai(monkeypatch, answer_down)

    response = client.post("/api/ai/analyze", json={"alert_id": alert.id})

    assert response.status_code == 503
    assert "injoignable" in response.json()["detail"]["error"]

    refreshed = await ai_notifications.get(1)
    assert refreshed.analysis_status == "failed"
    assert refreshed.analysis_error


# --------------------------------------------------------------------------
# Cas 4 et 5 : remediation
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_remediation_disponible_apres_analyse(monkeypatch):
    def answer_with_remediation(request: httpx.Request) -> httpx.Response:
        payload = dict(
            VALID_ANSWER,
            remediation_available=True,
            remediation_type="code_patch",
            remediation_summary="Supprimer le compte créé hors procédure.",
            affected_file="users.conf",
            affected_line=12,
        )
        return httpx.Response(
            200,
            json={
                "model": "gpt-4o-mini",
                "usage": {"total_tokens": 400},
                "choices": [
                    {"message": {"content": json.dumps(payload, ensure_ascii=False)}}
                ],
            },
        )

    alert = make_alert(**ALERT_5902)
    await create_notification(alert)
    fake_openai(monkeypatch, answer_with_remediation)

    await ai_agent.analyze_alert(alert)

    refreshed = await ai_notifications.get(1)
    assert refreshed.analyzed is True
    assert refreshed.remediation_available is True
    # Une correction n'est jamais appliquee sans confirmation explicite.
    assert refreshed.remediation_status == "awaiting_confirmation"


@pytest.mark.asyncio
async def test_remediation_indisponible_seulement_apres_analyse(monkeypatch):
    alert = make_alert(**ALERT_5902)
    notification = await create_notification(alert)

    # Avant analyse : la disponibilite n'est pas etablie.
    assert notification.analyzed is False
    assert notification.remediation_available is False

    fake_openai(monkeypatch, answer_ok)
    await ai_agent.analyze_alert(alert)

    refreshed = await ai_notifications.get(1)
    # Apres analyse : c'est bien l'IA qui conclut qu'il n'y en a pas.
    assert refreshed.analyzed is True
    assert refreshed.remediation_available is False


# --------------------------------------------------------------------------
# AI_ANALYSIS_ENABLED=false
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sans_analyse_automatique_la_notification_reste_en_attente(monkeypatch):
    """Configuration reelle du projet : AI_ANALYSIS_ENABLED=false."""
    monkeypatch.setattr(settings, "ai_analysis_enabled", False)
    alert = make_alert(**ALERT_5902)
    await create_notification(alert)

    analyses = await ai_agent.analyze_new_alerts([alert])

    assert analyses == []
    refreshed = await ai_notifications.get(1)
    assert refreshed.analysis_status == "pending"
    assert refreshed.analysis_status_label == "En attente d'analyse"


# --------------------------------------------------------------------------
# Exposition par l'API
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_l_api_expose_l_etat_d_analyse(client):
    await create_notification(make_alert(**ALERT_5902))

    body = client.get("/api/ai/notifications").json()

    assert body[0]["analysis_status"] == "pending"
    assert body[0]["analysis_status_label"] == "En attente d'analyse"
    assert body[0]["analyzed"] is False
    assert body[0]["status_label"] == "Nouvelle"
    assert body[0]["wazuh_description"] == "New user added to the system."


@pytest.mark.asyncio
async def test_le_filtre_par_etat_d_analyse_fonctionne(client):
    await create_notification(make_alert(**ALERT_5902))

    assert len(client.get("/api/ai/notifications?analysis_status=pending").json()) == 1
    assert len(client.get("/api/ai/notifications?analysis_status=analyzed").json()) == 0
