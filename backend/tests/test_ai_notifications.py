"""Tests des notifications HIGH/CRITICAL et du workflow de remediation.

Aucun appel reseau : OpenAI est simule avec httpx.MockTransport, et les
corrections s'appliquent sur des fichiers temporaires.
"""

import asyncio
import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app import store
from app.ai import agent as ai_agent
from app.ai import notifications as ai_notifications
from app.ai import remediation as ai_remediation
from app.ai.notifications import build_message, should_notify
from app.ai.openai_client import AIUnavailableError, OpenAIClient
from app.ai.remediation import RemediationError, resolve_target
from app.ai.schemas import AIAlertAnalysis
from app.config import settings
from app.main import app
from app.notifier import stream

from .conftest import make_alert

VULNERABLE_LINE = '        String query = "SELECT * FROM users WHERE id = " + userId;'
FIXED_LINE = '        String query = "SELECT * FROM users WHERE id = ?";'

JAVA_SOURCE = "\n".join(
    [
        "package com.example;",
        "",
        "public class UserController {",
        "",
        "    public User find(String userId) {",
        VULNERABLE_LINE,
        "        return jdbc.query(query);",
        "    }",
        "}",
    ]
)

CRITICAL_ANSWER = {
    "classification": "vulnerability",
    "title": "Injection SQL detectee",
    "threat_type": "SQL Injection",
    "severity": "CRITICAL",
    "risk_score": 95,
    "confidence": 94,
    "summary": "Une entree utilisateur est utilisee directement dans une requete SQL.",
    "explanation": "Les journaux montrent une concatenation directe ; cela suggere une injection possible.",
    "why_dangerous": "Un attaquant pourrait modifier la requete SQL executee par l'application.",
    "potential_impact": [
        "Acces non autorise aux donnees",
        "Modification ou suppression de donnees",
    ],
    "indicators": ["concatenation d'une entree utilisateur"],
    "recommendations": ["Utiliser des requetes parametrees", "Valider les entrees"],
    "risk_factors": ["donnee utilisateur non filtree"],
    "remediation_available": True,
    "remediation_type": "code_patch",
    "remediation_summary": "Remplacer la concatenation par une requete parametree.",
    "affected_file": "UserController.java",
    "affected_line": 6,
}

HIGH_ANSWER = {
    **CRITICAL_ANSWER,
    "classification": "brute_force",
    "title": "Attaque par force brute",
    "threat_type": "Brute force",
    "severity": "HIGH",
    "risk_score": 75,
    "remediation_available": False,
    "remediation_type": "none",
    "remediation_summary": "",
    "affected_file": None,
    "affected_line": None,
}

LOW_ANSWER = {
    **HIGH_ANSWER,
    "classification": "system_event",
    "title": "Demarrage du service",
    "severity": "LOW",
    "risk_score": 5,
}

PATCH_ANSWER = {
    "original_line": VULNERABLE_LINE,
    "replacement_line": FIXED_LINE,
    "explanation": "Requete parametree.",
}


@pytest.fixture(autouse=True)
def ai_configured(monkeypatch):
    monkeypatch.setattr(settings, "openai_api_key", "sk-test-cle-factice")
    monkeypatch.setattr(settings, "openai_model", "gpt-4o-mini")
    monkeypatch.setattr(settings, "ai_analysis_enabled", True)
    monkeypatch.setattr(settings, "ai_high_notification_enabled", True)
    monkeypatch.setattr(settings, "ai_critical_notification_enabled", True)
    monkeypatch.setattr(settings, "ai_remediation_enabled", True)
    monkeypatch.setattr(settings, "ai_remediation_backup", True)
    ai_agent.reset_semaphore()
    yield
    ai_agent.reset_semaphore()


@pytest.fixture
def project(tmp_path, monkeypatch):
    """Un mini projet local, seule zone ou une correction peut s'appliquer."""
    root = tmp_path / "projet"
    root.mkdir()
    source = root / "UserController.java"
    source.write_text(JAVA_SOURCE + "\n", encoding="utf-8")
    monkeypatch.setattr(settings, "ai_remediation_root", str(root))
    return source


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def openai_client(answers) -> OpenAIClient:
    """Client simule : `answers` est une liste servie dans l'ordre."""
    queue = list(answers)

    def handler(request: httpx.Request) -> httpx.Response:
        payload = queue.pop(0) if len(queue) > 1 else queue[0]
        return httpx.Response(
            200,
            json={
                "model": "gpt-4o-mini",
                "usage": {"total_tokens": 400},
                "choices": [{"message": {"content": json.dumps(payload)}}],
            },
        )

    client = OpenAIClient()
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return client


async def analyze(
    alert_id: str,
    answer: dict,
    client=None,
    level: int = 12,
    repetitions: int = 0,
):
    """Analyse une alerte, avec eventuellement un historique d'alertes
    similaires (facteur de repetition du risk assessment)."""
    if repetitions:
        store.save_alerts(
            [make_alert(f"{alert_id}-hist-{index}", level=level) for index in range(repetitions)]
        )

    alert = make_alert(alert_id, level=level)
    store.save_alerts([alert])
    return await ai_agent.analyze_alert(alert, client=client or openai_client([answer]))


# --------------------------------------------------------------------------
# Declenchement des notifications
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_une_analyse_critical_cree_une_notification():
    # Verdict critique du modele + alertes similaires recentes : le score
    # fusionne atteint la bande CRITICAL (90-100).
    analysis = await analyze("a-crit", CRITICAL_ANSWER, repetitions=6)

    assert analysis.severity == "CRITICAL"
    assert analysis.title == "Injection SQL detectee"
    assert analysis.potential_impact

    notifications = await ai_notifications.list_notifications()
    assert len(notifications) == 1

    notification = notifications[0]
    assert notification.alert_id == "a-crit"
    assert notification.severity == "CRITICAL"
    assert notification.classification == "vulnerability"
    assert notification.risk_score == analysis.risk_score
    assert notification.remediation_available is True
    assert notification.remediation_status == "awaiting_confirmation"
    assert notification.affected_file == "UserController.java"
    assert notification.affected_line == 6
    assert notification.status == "new"


@pytest.mark.asyncio
async def test_une_analyse_high_cree_une_notification():
    # Niveau 11 : sous CRITICAL_LEVEL, le plancher du niveau Wazuh
    # (HIGH) et le verdict du modele coincident.
    await analyze("a-high", HIGH_ANSWER, level=11)

    notifications = await ai_notifications.list_notifications()
    assert len(notifications) == 1
    assert notifications[0].severity == "HIGH"
    # Sans correction identifiee, le statut le dit clairement.
    assert notifications[0].remediation_available is False
    assert notifications[0].remediation_status == "not_available"


@pytest.mark.asyncio
async def test_une_analyse_low_ne_notifie_pas():
    analysis = await analyze("a-low", LOW_ANSWER, level=3)

    assert analysis.severity == "LOW"
    assert await ai_notifications.list_notifications() == []


@pytest.mark.asyncio
async def test_une_analyse_medium_ne_notifie_pas():
    medium = {**HIGH_ANSWER, "severity": "MEDIUM", "risk_score": 55}
    analysis = await analyze("a-medium", medium, level=6)

    assert analysis.severity == "MEDIUM"
    assert await ai_notifications.list_notifications() == []


def test_should_notify_respecte_la_configuration(monkeypatch):
    high = AIAlertAnalysis(alert_id="x", severity="HIGH")
    critical = AIAlertAnalysis(alert_id="y", severity="CRITICAL")
    low = AIAlertAnalysis(alert_id="z", severity="LOW")

    assert should_notify(high) is True
    assert should_notify(critical) is True
    assert should_notify(low) is False

    monkeypatch.setattr(settings, "ai_high_notification_enabled", False)
    assert should_notify(high) is False
    assert should_notify(critical) is True


@pytest.mark.asyncio
async def test_pas_de_notification_en_double():
    client = openai_client([CRITICAL_ANSWER])
    alert = make_alert("a-crit", level=12)
    store.save_alerts([alert])

    await ai_agent.analyze_alert(alert, client=client)
    await ai_agent.analyze_alert(alert, client=client, force=True)
    await ai_agent.analyze_alert(alert, client=client, force=True)

    notifications = await ai_notifications.list_notifications()
    assert len(notifications) == 1, "une alerte = une notification"
    assert notifications[0].occurrences == 3
    assert notifications[0].updated_at is not None


def test_le_message_contient_les_informations_cles():
    analysis = AIAlertAnalysis(
        alert_id="a-1",
        severity="CRITICAL",
        risk_score=92,
        confidence=0.94,
        title="Injection SQL detectee",
        classification="vulnerability",
        agent_name="PC-192.168.11.148",
        affected_file="UserController.java",
        affected_line=47,
        why_dangerous="Une entree utilisateur est utilisee sans parametrage.",
        potential_impact=["Acces non autorise aux donnees"],
        recommendations=["Utiliser une requete parametree"],
        remediation_available=True,
        remediation_summary="Requete parametree.",
    )

    message = build_message(analysis)

    assert "CRITIQUE" in message
    assert "Injection SQL detectee" in message
    assert "PC-192.168.11.148" in message
    assert "UserController.java" in message
    assert "47" in message
    assert "92/100" in message
    assert "94%" in message
    assert "Acces non autorise aux donnees" in message
    assert "Utiliser une requete parametree" in message
    assert "Correction proposée" in message


@pytest.mark.asyncio
async def test_la_notification_part_en_sse(monkeypatch):
    published = []

    async def capture(event, event_id=None):
        published.append(event)
        return 1

    monkeypatch.setattr(stream, "publish", capture)

    await analyze("a-crit", CRITICAL_ANSWER, repetitions=6)

    events = [event for event in published if event.type == "ai_notification"]
    assert len(events) == 1
    assert events[0].data["severity"] == "CRITICAL"
    assert events[0].data["alert_id"] == "a-crit"


@pytest.mark.asyncio
async def test_une_notification_deja_vue_ne_repart_pas_en_sse(monkeypatch):
    published = []

    async def capture(event, event_id=None):
        published.append(event)
        return 1

    monkeypatch.setattr(stream, "publish", capture)

    client = openai_client([CRITICAL_ANSWER])
    alert = make_alert("a-crit", level=12)
    store.save_alerts([alert])

    await ai_agent.analyze_alert(alert, client=client)
    await ai_agent.analyze_alert(alert, client=client, force=True)

    events = [event for event in published if event.type == "ai_notification"]
    identifiers = {event.data["id"] for event in events}

    # La seconde analyse rediffuse la meme notification (contenu a jour)
    # et non une seconde : le frontend met a jour la ligne existante au lieu
    # de re-alerter l'utilisateur.
    assert len(identifiers) == 1, "pas de seconde notification pour la meme alerte"
    assert len(store.list_notifications()) == 1


@pytest.mark.asyncio
async def test_une_erreur_de_notification_ne_casse_pas_l_analyse(monkeypatch):
    async def exploding(analysis):
        raise RuntimeError("base indisponible")

    monkeypatch.setattr(ai_notifications, "create_from_analysis", exploding)

    analysis = await analyze("a-crit", CRITICAL_ANSWER, repetitions=6)

    assert analysis.severity == "CRITICAL"
    assert store.get_ai_analysis("a-crit") is not None


# --------------------------------------------------------------------------
# Cycle de vie d'une notification
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_acquittement_et_rejet():
    await analyze("a-crit", CRITICAL_ANSWER)
    notification = (await ai_notifications.list_notifications())[0]

    acknowledged = await ai_notifications.acknowledge(notification.id)
    assert acknowledged.status == "acknowledged"
    assert acknowledged.acknowledged_at is not None

    dismissed = await ai_notifications.dismiss(notification.id)
    assert dismissed.status == "dismissed"
    assert dismissed.dismissed_at is not None
    # La correction en attente ne reste pas ouverte.
    assert dismissed.remediation_status == "cancelled"

    actions = {row["action"] for row in store.list_audit(notification_id=notification.id)}
    assert "NOTIFICATION_ACKNOWLEDGED" in actions
    assert "NOTIFICATION_DISMISSED" in actions


# --------------------------------------------------------------------------
# Remediation : garde-fous
# --------------------------------------------------------------------------


def test_sans_racine_configuree_aucune_ecriture_possible(monkeypatch):
    monkeypatch.setattr(settings, "ai_remediation_root", "")

    target, blockers = resolve_target("UserController.java")

    assert target is None
    assert any("AI_REMEDIATION_ROOT" in blocker for blocker in blockers)


def test_la_traversee_de_repertoire_est_refusee(project):
    target, blockers = resolve_target("../../etc/passwd")

    assert target is None
    assert blockers


def test_un_fichier_absent_est_signale(project):
    target, blockers = resolve_target("Inexistant.java")

    assert target is None
    assert any("introuvable" in blocker for blocker in blockers)


def test_un_fichier_trop_gros_est_refuse(project, monkeypatch):
    monkeypatch.setattr(settings, "ai_remediation_max_file_size", 10)

    target, blockers = resolve_target("UserController.java")

    assert target is None
    assert any("volumineux" in blocker for blocker in blockers)


@pytest.mark.asyncio
async def test_apercu_sans_correction_disponible():
    await analyze("a-high", HIGH_ANSWER)
    notification = (await ai_notifications.list_notifications())[0]

    preview = await ai_remediation.build_preview(notification)

    assert preview.available is False
    assert preview.blockers
    assert preview.diff is None


@pytest.mark.asyncio
async def test_apercu_produit_un_diff_sans_rien_modifier(project):
    await analyze("a-crit", CRITICAL_ANSWER)
    notification = (await ai_notifications.list_notifications())[0]
    before = project.read_text(encoding="utf-8")

    preview = await ai_remediation.build_preview(
        notification, client=openai_client([PATCH_ANSWER])
    )

    assert preview.available is True
    assert preview.status == "awaiting_confirmation"
    assert "SELECT * FROM users" in preview.diff
    assert preview.proposed_excerpt == FIXED_LINE
    assert preview.original_excerpt is not None

    # Lecture seule : le fichier est intact.
    assert project.read_text(encoding="utf-8") == before


@pytest.mark.asyncio
async def test_le_diff_ne_touche_qu_une_ligne(project):
    await analyze("a-crit", CRITICAL_ANSWER)
    notification = (await ai_notifications.list_notifications())[0]

    preview = await ai_remediation.build_preview(
        notification, client=openai_client([PATCH_ANSWER])
    )

    added = [line for line in preview.diff.splitlines() if line.startswith("+") and not line.startswith("+++")]
    removed = [line for line in preview.diff.splitlines() if line.startswith("-") and not line.startswith("---")]

    assert len(added) == 1 and len(removed) == 1


@pytest.mark.asyncio
async def test_un_fichier_modifie_depuis_l_analyse_bloque_la_correction(project):
    await analyze("a-crit", CRITICAL_ANSWER)
    notification = (await ai_notifications.list_notifications())[0]

    # Quelqu'un a modifie le fichier entre-temps.
    project.write_text(JAVA_SOURCE.replace(VULNERABLE_LINE, "        // supprime"), encoding="utf-8")

    preview = await ai_remediation.build_preview(
        notification, client=openai_client([PATCH_ANSWER])
    )

    assert preview.available is False
    assert any("ne correspond plus" in blocker for blocker in preview.blockers)


# --------------------------------------------------------------------------
# Remediation : application, rejet, rollback
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_application_reussie_avec_sauvegarde(project):
    await analyze("a-crit", CRITICAL_ANSWER)
    notification = (await ai_notifications.list_notifications())[0]

    record = await ai_remediation.confirm(
        notification, client=openai_client([PATCH_ANSWER])
    )

    assert record.status == "applied"
    assert record.applied_at is not None
    assert record.backup_path is not None

    content = project.read_text(encoding="utf-8")
    assert FIXED_LINE in content
    assert VULNERABLE_LINE not in content

    # La sauvegarde contient bien l'original.
    assert VULNERABLE_LINE in Path(record.backup_path).read_text(encoding="utf-8")

    updated = await ai_notifications.get(notification.id)
    assert updated.remediation_status == "applied"
    assert updated.status == "resolved"

    actions = [row["action"] for row in store.list_audit(notification_id=notification.id)]
    assert "REMEDIATION_APPROVED" in actions
    assert "REMEDIATION_APPLIED" in actions


@pytest.mark.asyncio
async def test_application_impossible_sans_racine(monkeypatch):
    await analyze("a-crit", CRITICAL_ANSWER)
    notification = (await ai_notifications.list_notifications())[0]
    monkeypatch.setattr(settings, "ai_remediation_root", "")

    with pytest.raises(RemediationError):
        await ai_remediation.confirm(notification, client=openai_client([PATCH_ANSWER]))

    actions = [row["action"] for row in store.list_audit(notification_id=notification.id)]
    assert "REMEDIATION_FAILED" in actions


@pytest.mark.asyncio
async def test_application_echouee_si_openai_indisponible(project):
    await analyze("a-crit", CRITICAL_ANSWER)
    notification = (await ai_notifications.list_notifications())[0]
    before = project.read_text(encoding="utf-8")

    def handler(request):
        raise httpx.ConnectError("refuse", request=request)

    failing = OpenAIClient()
    failing._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    with pytest.raises(RemediationError):
        await ai_remediation.confirm(notification, client=failing)

    assert project.read_text(encoding="utf-8") == before, "le fichier reste intact"


@pytest.mark.asyncio
async def test_rejet_de_la_correction(project):
    await analyze("a-crit", CRITICAL_ANSWER)
    notification = (await ai_notifications.list_notifications())[0]

    updated = await ai_remediation.reject(notification, reason="corrige manuellement")

    assert updated.remediation_status == "rejected"
    assert project.read_text(encoding="utf-8") == JAVA_SOURCE + "\n"

    actions = [row["action"] for row in store.list_audit(notification_id=notification.id)]
    assert "REMEDIATION_REJECTED" in actions


@pytest.mark.asyncio
async def test_une_correction_rejetee_ne_peut_plus_etre_appliquee(project):
    await analyze("a-crit", CRITICAL_ANSWER)
    notification = (await ai_notifications.list_notifications())[0]
    await ai_remediation.reject(notification)

    refreshed = await ai_notifications.get(notification.id)
    with pytest.raises(RemediationError):
        await ai_remediation.confirm(refreshed, client=openai_client([PATCH_ANSWER]))


@pytest.mark.asyncio
async def test_rollback_restaure_le_fichier(project):
    await analyze("a-crit", CRITICAL_ANSWER)
    notification = (await ai_notifications.list_notifications())[0]

    record = await ai_remediation.confirm(
        notification, client=openai_client([PATCH_ANSWER])
    )
    assert FIXED_LINE in project.read_text(encoding="utf-8")

    rolled_back = await ai_remediation.rollback(record.id)

    assert rolled_back.status == "cancelled"
    assert rolled_back.rolled_back_at is not None
    assert VULNERABLE_LINE in project.read_text(encoding="utf-8")

    actions = [row["action"] for row in store.list_audit(notification_id=notification.id)]
    assert "REMEDIATION_ROLLED_BACK" in actions


@pytest.mark.asyncio
async def test_rollback_impossible_si_non_appliquee(project):
    await analyze("a-crit", CRITICAL_ANSWER)
    notification = (await ai_notifications.list_notifications())[0]
    await ai_remediation.reject(notification)

    record = (await ai_remediation.list_records())[0]
    with pytest.raises(RemediationError):
        await ai_remediation.rollback(record.id)


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------


def test_endpoint_confirmation_obligatoire(client, monkeypatch, project):
    fake = openai_client([CRITICAL_ANSWER, PATCH_ANSWER])
    monkeypatch.setattr("app.ai.agent.get_openai_client", lambda: fake)
    monkeypatch.setattr("app.ai.remediation.get_openai_client", lambda: fake)

    store.save_alerts([make_alert("a-crit", level=12)])
    client.post("/api/ai/analyze", json={"alert_id": "a-crit"})

    notification = client.get("/api/ai/notifications").json()[0]
    before = project.read_text(encoding="utf-8")

    # Sans confirmation explicite : refus, et fichier intact.
    response = client.post(
        f"/api/ai/notifications/{notification['id']}/remediation/confirm",
        json={"confirmed": False},
    )

    assert response.status_code == 400
    assert "Confirmation explicite" in response.json()["detail"]["error"]
    assert project.read_text(encoding="utf-8") == before


def test_endpoint_workflow_complet(client, monkeypatch, project):
    fake = openai_client([CRITICAL_ANSWER, PATCH_ANSWER])
    monkeypatch.setattr("app.ai.agent.get_openai_client", lambda: fake)
    monkeypatch.setattr("app.ai.remediation.get_openai_client", lambda: fake)

    store.save_alerts([make_alert("a-crit", level=12)])
    client.post("/api/ai/analyze", json={"alert_id": "a-crit"})

    notification = client.get("/api/ai/notifications").json()[0]
    notification_id = notification["id"]

    # Apercu
    preview = client.post(
        f"/api/ai/notifications/{notification_id}/remediation/preview"
    ).json()
    assert preview["available"] is True
    assert preview["diff"]

    # Confirmation
    record = client.post(
        f"/api/ai/notifications/{notification_id}/remediation/confirm",
        json={"confirmed": True, "actor": "fz"},
    ).json()
    assert record["status"] == "applied"
    assert FIXED_LINE in project.read_text(encoding="utf-8")

    # Rollback
    rolled = client.post(f"/api/ai/remediations/{record['id']}/rollback").json()
    assert rolled["status"] == "cancelled"
    assert VULNERABLE_LINE in project.read_text(encoding="utf-8")

    # Audit
    audit = client.get(f"/api/ai/notifications/{notification_id}/audit").json()
    actions = [entry["action"] for entry in audit]
    assert "REMEDIATION_APPLIED" in actions
    assert "REMEDIATION_ROLLED_BACK" in actions
    assert any(entry["actor"] == "fz" for entry in audit)


def test_endpoint_notification_inconnue(client):
    assert client.get("/api/ai/notifications/9999").status_code == 404
    assert client.post("/api/ai/notifications/9999/acknowledge").status_code == 404
    assert (
        client.post(
            "/api/ai/notifications/9999/remediation/confirm", json={"confirmed": True}
        ).status_code
        == 404
    )


def test_endpoint_remediation_inconnue(client):
    assert client.get("/api/ai/remediations/9999").status_code == 404
    assert client.post("/api/ai/remediations/9999/rollback").status_code == 409


def test_endpoint_filtres_de_l_historique(client, monkeypatch):
    fake = openai_client([CRITICAL_ANSWER])
    monkeypatch.setattr("app.ai.agent.get_openai_client", lambda: fake)

    # Historique d'alertes similaires : le facteur de repetition porte le
    # score fusionne dans la bande CRITICAL.
    store.save_alerts([make_alert(f"a-hist-{index}", level=12) for index in range(6)])
    store.save_alerts([make_alert("a-crit", level=12)])
    client.post("/api/ai/analyze", json={"alert_id": "a-crit"})

    assert len(client.get("/api/ai/notifications?severity=CRITICAL").json()) == 1
    assert client.get("/api/ai/notifications?severity=LOW").json() == []
    assert len(client.get("/api/ai/notifications?remediation_available=true").json()) == 1
    assert len(client.get("/api/ai/notifications?search=Injection").json()) == 1
    assert client.get("/api/ai/notifications?search=inexistant").json() == []
    assert len(client.get("/api/ai/notifications?server=srv-web").json()) == 1
    assert len(client.get("/api/ai/notifications?classification=vulnerability").json()) == 1


def test_les_endpoints_ne_divulguent_aucune_cle(client, monkeypatch, project):
    fake = openai_client([CRITICAL_ANSWER, PATCH_ANSWER])
    monkeypatch.setattr("app.ai.agent.get_openai_client", lambda: fake)
    monkeypatch.setattr("app.ai.remediation.get_openai_client", lambda: fake)

    store.save_alerts([make_alert("a-crit", level=12)])
    client.post("/api/ai/analyze", json={"alert_id": "a-crit"})
    notification_id = client.get("/api/ai/notifications").json()[0]["id"]
    client.post(f"/api/ai/notifications/{notification_id}/remediation/preview")

    for response in (
        client.get("/api/ai/notifications"),
        client.get(f"/api/ai/notifications/{notification_id}"),
        client.get("/api/ai/remediations"),
        client.get("/api/ai/audit"),
        client.get("/api/ai/stats"),
    ):
        assert settings.openai_api_key not in response.text
        assert "sk-" not in response.text
        assert "authorization" not in response.text.lower()


def test_les_stats_incluent_les_notifications(client, monkeypatch):
    fake = openai_client([CRITICAL_ANSWER])
    monkeypatch.setattr("app.ai.agent.get_openai_client", lambda: fake)

    store.save_alerts([make_alert("a-crit", level=12)])
    client.post("/api/ai/analyze", json={"alert_id": "a-crit"})

    stats = client.get("/api/ai/stats").json()
    assert stats["notifications"] == 1
    assert stats["notifications_new"] == 1
    assert stats["remediations_available"] == 1


# --------------------------------------------------------------------------
# Non-regression : la surveillance reste intacte
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_le_poller_survit_a_une_panne_de_notification(
    controller_factory, monkeypatch
):
    from .conftest import FakeWazuhClient

    async def failing(alerts):
        raise AIUnavailableError("OpenAI injoignable")

    monkeypatch.setattr(ai_agent, "analyze_new_alerts", failing)

    alerts = [make_alert("a-1", level=12), make_alert("a-2", level=12)]
    controller = controller_factory(FakeWazuhClient(batches=[alerts]))
    await controller._load_state()

    new_alerts = await controller.scan_once()
    await asyncio.sleep(0.05)

    assert len(new_alerts) == 2
    assert store.count_alerts() == 2
    assert controller.status().errors == 0


# --------------------------------------------------------------------------
# Notification issue du niveau Wazuh (NOTIFY_LEVEL), sans agent IA
# --------------------------------------------------------------------------


def test_le_seuil_de_notification_ne_depend_que_du_niveau(monkeypatch):
    monkeypatch.setattr(settings, "notify_level", 7)

    assert ai_notifications.should_notify_alert(make_alert("n-1", level=7)) is True
    assert ai_notifications.should_notify_alert(make_alert("n-2", level=12)) is True
    assert ai_notifications.should_notify_alert(make_alert("n-3", level=6)) is False


@pytest.mark.asyncio
async def test_une_alerte_elevee_cree_une_notification_sans_openai(monkeypatch):
    """La chaine alerte -> notification ne passe pas par OpenAI."""
    monkeypatch.setattr(settings, "notify_level", 7)
    monkeypatch.setattr(settings, "openai_api_key", "")

    alert = make_alert("linux-1", level=10, agent_id="002", agent_name="srv-linux")

    notification, created = await ai_notifications.create_from_alert(alert)

    assert created is True
    assert notification is not None
    assert notification.severity == "HIGH"
    assert notification.source == "wazuh"
    assert notification.agent_id == "002"
    assert notification.server_name == "srv-linux"
    assert notification.rule_id == "5710"
    assert notification.rule_level == 10
    assert notification.alert_timestamp == alert.timestamp
    # Le message porte tous les elements demandes a l'ecran.
    for fragment in ("Serveur", "Règle Wazuh", "Niveau Wazuh", "Date", "ÉLEVÉE"):
        assert fragment in notification.notification_message
    # La description Wazuh d'origine reste disponible pour le diagnostic.
    assert alert.rule.description in notification.notification_message


@pytest.mark.asyncio
async def test_une_alerte_sous_le_seuil_ne_notifie_pas(monkeypatch):
    monkeypatch.setattr(settings, "notify_level", 10)

    notification, created = await ai_notifications.create_from_alert(
        make_alert("basse-1", level=3)
    )

    assert (notification, created) == (None, False)
    assert store.list_notifications() == []


@pytest.mark.asyncio
async def test_les_agents_windows_et_linux_sont_traites_pareil(monkeypatch):
    """Aucune logique specifique a un agent : meme niveau, meme resultat."""
    monkeypatch.setattr(settings, "notify_level", 7)
    monkeypatch.setattr(settings, "notify_cooldown", 0)

    windows, _ = await ai_notifications.create_from_alert(
        make_alert("w-1", level=12, agent_id="001", agent_name="PC-WINDOWS")
    )
    linux, _ = await ai_notifications.create_from_alert(
        make_alert("l-1", level=12, agent_id="002", agent_name="srv-linux")
    )

    assert windows is not None and linux is not None
    assert windows.severity == linux.severity == "CRITICAL"
    assert {windows.agent_id, linux.agent_id} == {"001", "002"}


@pytest.mark.asyncio
async def test_le_cooldown_regroupe_la_meme_regle_sur_le_meme_serveur(monkeypatch):
    monkeypatch.setattr(settings, "notify_level", 7)
    monkeypatch.setattr(settings, "notify_cooldown", 300)

    first, created_first = await ai_notifications.create_from_alert(
        make_alert("c-1", level=10, agent_id="002")
    )
    second, created_second = await ai_notifications.create_from_alert(
        make_alert("c-2", level=10, agent_id="002")
    )

    assert created_first is True
    assert created_second is False
    assert first is not None and second is not None
    assert second.id == first.id
    assert second.occurrences == 2
    assert len(store.list_notifications()) == 1


@pytest.mark.asyncio
async def test_le_cooldown_ne_bloque_ni_un_autre_serveur_ni_une_autre_regle(monkeypatch):
    monkeypatch.setattr(settings, "notify_level", 7)
    monkeypatch.setattr(settings, "notify_cooldown", 300)

    await ai_notifications.create_from_alert(make_alert("d-1", level=10, agent_id="001"))

    autre_serveur, created_serveur = await ai_notifications.create_from_alert(
        make_alert("d-2", level=10, agent_id="002")
    )
    autre_regle = make_alert("d-3", level=10, agent_id="001")
    autre_regle.rule.id = "31151"
    _, created_regle = await ai_notifications.create_from_alert(autre_regle)

    assert created_serveur is True, "un autre serveur doit toujours notifier"
    assert created_regle is True, "une autre regle doit toujours notifier"
    assert autre_serveur is not None
    assert len(store.list_notifications()) == 3


@pytest.mark.asyncio
async def test_le_cooldown_ne_bloque_pas_une_aggravation(monkeypatch):
    monkeypatch.setattr(settings, "notify_level", 7)
    monkeypatch.setattr(settings, "notify_cooldown", 300)

    await ai_notifications.create_from_alert(make_alert("e-1", level=10, agent_id="002"))
    _, created = await ai_notifications.create_from_alert(
        make_alert("e-2", level=13, agent_id="002")
    )

    assert created is True, "une severite qui s'aggrave doit passer le cooldown"


@pytest.mark.asyncio
async def test_l_analyse_ia_enrichit_la_notification_au_lieu_d_en_creer_une_seconde(
    monkeypatch,
):
    monkeypatch.setattr(settings, "notify_level", 7)

    alert = make_alert("f-1", level=12, agent_id="002", agent_name="srv-linux")
    await ai_notifications.create_from_alert(alert)

    analysis = AIAlertAnalysis(
        alert_id=alert.id,
        agent_id="002",
        agent_name="srv-linux",
        rule_id=alert.rule.id,
        rule_level=alert.rule.level,
        severity="CRITICAL",
        risk_score=92,
        classification="brute_force",
        title="Attaque par force brute",
        summary="Nombreuses tentatives echouees.",
    )
    notification, created = await ai_notifications.create_from_analysis(analysis)

    rows = store.list_notifications()
    assert len(rows) == 1, "l'analyse ne doit jamais dupliquer la notification"
    assert created is False
    assert notification is not None
    assert notification.classification == "brute_force"
    assert notification.risk_score == 92
    assert notification.source == "ia"
    # L'identite Wazuh d'origine est conservee.
    assert notification.rule_level == 12
    assert notification.agent_id == "002"


@pytest.mark.asyncio
async def test_le_poller_cree_la_notification_d_une_alerte_elevee(
    controller_factory, monkeypatch
):
    """Chaine complete : Indexer -> poller -> SQLite -> notification -> SSE."""
    from .conftest import FakeWazuhClient

    monkeypatch.setattr(settings, "notify_level", 7)
    monkeypatch.setattr(settings, "notify_cooldown", 0)

    published: list = []

    async def capture(event, event_id=None):
        published.append(event)

    monkeypatch.setattr(stream, "publish", capture)

    alerts = [
        make_alert("g-1", level=3, agent_id="002"),
        make_alert("g-2", level=10, agent_id="002", agent_name="srv-linux"),
    ]
    controller = controller_factory(FakeWazuhClient(batches=[alerts]))
    await controller._load_state()

    await controller.scan_once()
    await asyncio.sleep(0.05)

    rows = store.list_notifications()
    assert len(rows) == 1, "seule l'alerte au-dessus du seuil est notifiee"
    assert rows[0]["alert_id"] == "g-2"
    assert rows[0]["severity"] == "HIGH"
    assert any(event.type == "ai_notification" for event in published)


def test_le_niveau_wazuh_est_un_plancher_de_severite(monkeypatch):
    """Coherence Alertes / Notifications / AI Security sur un meme rule.level."""
    monkeypatch.setattr(settings, "critical_level", 12)

    from app.ai.notifications import notification_severity

    def analyse(severity, level):
        return AIAlertAnalysis(alert_id="s-1", severity=severity, rule_level=level)

    # Le modele ne peut pas minimiser ce que dit le niveau Wazuh...
    assert notification_severity(analyse("MEDIUM", 10)) == "HIGH"
    assert notification_severity(analyse("LOW", 12)) == "CRITICAL"
    # ... mais il peut aggraver.
    assert notification_severity(analyse("CRITICAL", 3)) == "CRITICAL"
