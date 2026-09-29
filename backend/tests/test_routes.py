"""Tests des endpoints /api/health, /api/servers et /api/alerts.

Le client Wazuh est remplace par un double : aucun appel reseau reel.
"""

import httpx
import pytest
from fastapi.testclient import TestClient

from app import routes
from app.main import app
from app.models import Agent, Alert
from app.wazuh_client import IndexerError, WazuhUnavailableError

AGENT = Agent(id="001", name="srv-web", ip="10.0.0.5", status="active", os="Ubuntu 22.04")

ALERT = Alert.from_hit(
    {
        "_id": "alert-1",
        "_source": {
            "timestamp": "2026-08-12T10:00:00.000Z",
            "agent": {"id": "001", "name": "srv-web"},
            "rule": {"id": 5710, "level": 12, "description": "Tentative SSH"},
            "full_log": "Failed password",
            "location": "/var/log/auth.log",
        },
    }
)


class FakeWazuhClient:
    """Double de WazuhClient : renvoie des donnees ou leve une erreur."""

    def __init__(self, agents=None, alerts=None, error=None):
        self._agents = agents or []
        self._alerts = alerts or []
        self._error = error

    async def get_agents(self, limit=None):
        if self._error:
            raise self._error
        return self._agents

    async def get_alerts(self, size=None, min_level=0):
        if self._error:
            raise self._error
        return self._alerts


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def use_fake(monkeypatch, fake):
    monkeypatch.setattr(routes, "get_wazuh_client", lambda: fake)


def test_health_indique_que_le_backend_est_operationnel(client):
    response = client.get("/api/health")
    assert response.status_code == 200

    body = response.json()
    assert body["status"] == "ok"
    assert body["database"] == "ok"
    assert body["monitoring"] is False


def test_servers_retourne_une_liste_simplifiee(client, monkeypatch):
    use_fake(monkeypatch, FakeWazuhClient(agents=[AGENT]))

    response = client.get("/api/servers")
    assert response.status_code == 200

    body = response.json()
    assert body == [
        {
            "id": "001",
            "name": "srv-web",
            "ip": "10.0.0.5",
            "status": "active",
            # Libelle francais ajoute a cote du statut Wazuh brut.
            "status_label": "ACTIVE",
            "os": "Ubuntu 22.04",
            "version": None,
            "group": [],
            "last_keep_alive": None,
        }
    ]
    # Aucune trace du JSON brut de Wazuh.
    assert "affected_items" not in response.text


def test_alerts_retourne_une_liste_d_alertes(client, monkeypatch):
    use_fake(monkeypatch, FakeWazuhClient(alerts=[ALERT]))

    response = client.get("/api/alerts")
    assert response.status_code == 200

    alert = response.json()[0]
    assert alert["id"] == "alert-1"
    assert alert["timestamp"] == "2026-08-12T10:00:00.000Z"
    assert alert["agent"]["name"] == "srv-web"
    assert alert["rule"]["level"] == 12
    assert alert["location"] == "/var/log/auth.log"


def test_servers_repond_503_si_wazuh_est_injoignable(client, monkeypatch):
    use_fake(
        monkeypatch,
        FakeWazuhClient(error=WazuhUnavailableError("Wazuh Manager API injoignable")),
    )

    response = client.get("/api/servers")
    assert response.status_code == 503
    assert "injoignable" in response.json()["detail"]["error"]


def test_alerts_repond_502_si_l_indexer_est_en_erreur(client, monkeypatch):
    use_fake(monkeypatch, FakeWazuhClient(error=IndexerError("Index introuvable")))

    response = client.get("/api/alerts")
    assert response.status_code == 502
    assert "Index introuvable" in response.json()["detail"]["error"]


def test_les_secrets_ne_fuient_pas_dans_les_reponses(client, monkeypatch):
    from app.config import settings

    use_fake(monkeypatch, FakeWazuhClient(agents=[AGENT], alerts=[ALERT]))

    for path in ("/api/health", "/api/servers", "/api/alerts"):
        text = client.get(path).text
        assert settings.wazuh_api_password not in text
        assert settings.indexer_password not in text


# --------------------------------------------------------------------------
# Endpoints de surveillance
# --------------------------------------------------------------------------


@pytest.fixture
def monitoring(monkeypatch):
    """Branche le controleur de l'application sur un Wazuh simule."""
    from app import poller
    from app.config import settings

    from .conftest import FakeWazuhClient, make_alert

    monkeypatch.setattr(settings, "poll_interval", 0.05)
    client = FakeWazuhClient(batches=[[make_alert("a-1"), make_alert("a-2")]])
    controller = poller.MonitoringController(client=client)
    monkeypatch.setattr(poller, "_controller", controller)
    return controller


def test_start_puis_status_puis_stop(client, monitoring):
    status = client.get("/api/monitoring/status").json()
    assert status["running"] is False

    started = client.post("/api/monitoring/start").json()
    assert started["ok"] is True
    assert started["status"]["running"] is True
    assert started["message"] == "Surveillance démarrée"

    status = client.get("/api/monitoring/status").json()
    assert status["running"] is True
    assert status["poll_interval"] == 0.05
    assert "last_scan" in status and "last_alert" in status

    stopped = client.post("/api/monitoring/stop").json()
    assert stopped["status"]["running"] is False
    assert stopped["message"] == "Surveillance arrêtée"


def test_double_start_via_l_api_retourne_l_etat_courant(client, monitoring):
    first = client.post("/api/monitoring/start").json()
    second = client.post("/api/monitoring/start").json()

    assert first["status"]["running"] is True
    assert second["status"]["running"] is True
    assert second["message"] == "Surveillance déjà active"
    assert second["status"]["started_at"] == first["status"]["started_at"]

    client.post("/api/monitoring/stop")


def test_double_stop_via_l_api_retourne_l_etat_courant(client, monitoring):
    client.post("/api/monitoring/start")

    first = client.post("/api/monitoring/stop").json()
    second = client.post("/api/monitoring/stop").json()

    assert first["status"]["running"] is False
    assert second["status"]["running"] is False
    assert second["message"] == "Surveillance déjà arrêtée"


def test_stop_sans_start_via_l_api(client, monitoring):
    response = client.post("/api/monitoring/stop")

    assert response.status_code == 200
    assert response.json()["status"]["running"] is False


def test_les_alertes_persistees_sont_exposees(client, monitoring):
    import time

    client.post("/api/monitoring/start")
    time.sleep(0.3)
    client.post("/api/monitoring/stop")

    stored = client.get("/api/alerts/stored").json()
    assert len(stored) == 2
    assert {alert["id"] for alert in stored} == {"a-1", "a-2"}

    health = client.get("/api/health").json()
    assert health["alerts_stored"] == 2


# --------------------------------------------------------------------------
# Configuration transmise au frontend
# --------------------------------------------------------------------------


def test_config_expose_les_seuils_au_frontend(client, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "notify_level", 7)
    monkeypatch.setattr(settings, "critical_level", 12)
    monkeypatch.setattr(settings, "notify_cooldown", 300)

    body = client.get("/api/config").json()

    assert body == {
        "app_name": settings.app_name,
        "poll_interval": settings.poll_interval,
        "critical_level": 12,
        "high_level": 10,
        "medium_level": 7,
        "notify_level": 7,
        "notify_cooldown": 300,
        "ai_enabled": settings.ai_enabled,
        "ai_auto_analysis": settings.ai_analysis_enabled,
    }


def test_config_ne_divulgue_aucun_secret(client):
    from app.config import settings

    text = client.get("/api/config").text

    assert settings.wazuh_api_password not in text
    assert settings.indexer_password not in text
    assert "password" not in text.lower()
