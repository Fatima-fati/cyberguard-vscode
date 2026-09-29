"""Fixtures partagees : base SQLite temporaire et doubles du client Wazuh."""

from typing import Optional

import pytest

from app import poller, store
from app.config import settings
from app.models import Alert
from app.wazuh_client import WazuhError


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    """Chaque test travaille sur sa propre base SQLite."""
    database = tmp_path / "test-alerts.db"
    monkeypatch.setattr(settings, "database_path", str(database))
    store.init_db()
    yield database


@pytest.fixture(autouse=True)
def reset_controller():
    """Evite qu'un test laisse un controleur (et sa tache) derriere lui."""
    poller._controller = None
    yield
    poller._controller = None


def make_alert(
    wazuh_id: str,
    timestamp: str = "2026-08-12T10:00:00.000+0000",
    level: int = 5,
    description: str = "Alerte de test",
    agent_id: str = "001",
    agent_name: str = "srv-web",
) -> Alert:
    """Construit une alerte comme le ferait l'Indexer."""
    return Alert.from_hit(
        {
            "_id": wazuh_id,
            "_source": {
                "timestamp": timestamp,
                "agent": {"id": agent_id, "name": agent_name, "ip": "10.0.0.5"},
                "rule": {"id": 5710, "level": level, "description": description},
                "full_log": f"log de {wazuh_id}",
                "location": "/var/log/auth.log",
            },
        }
    )


class FakeWazuhClient:
    """Client Wazuh simule : renvoie des lots d'alertes scriptes.

    - `batches` : une liste d'alertes par appel a get_alerts().
      Le dernier lot est reutilise une fois la liste epuisee.
    - `error` : si fourni, get_alerts() leve cette erreur.
    - `calls` : les parametres recus, pour verifier le curseur.
    """

    def __init__(
        self,
        batches: Optional[list[list[Alert]]] = None,
        error: Optional[WazuhError] = None,
    ):
        self.batches = batches if batches is not None else [[]]
        self.error = error
        self.calls: list[dict] = []

    async def get_alerts(self, size=None, min_level=0, since=None, order="desc"):
        self.calls.append(
            {"size": size, "min_level": min_level, "since": since, "order": order}
        )

        if self.error is not None:
            raise self.error

        index = min(len(self.calls) - 1, len(self.batches) - 1)
        return list(self.batches[index])

    async def get_agents(self, limit=None):
        return []


@pytest.fixture
def controller_factory(monkeypatch):
    """Fabrique un MonitoringController branche sur un client simule."""

    def factory(client: FakeWazuhClient, poll_interval: float = 0.05):
        monkeypatch.setattr(settings, "poll_interval", poll_interval)
        controller = poller.MonitoringController(client=client)
        poller._controller = controller
        return controller

    return factory


# --------------------------------------------------------------------------
# Authentification locale (phase 0)
# --------------------------------------------------------------------------
#
# Les routes sensibles exigent un jeton depuis la phase 0. Les tests
# l'installent plutot que de desactiver le controle : une suite qui tourne
# authentification coupee ne prouverait rien du chemin reellement servi en
# production. `auth_headers()` donne l'en-tete a joindre au client.

TEST_AGENT_TOKEN = "jeton-de-test-non-secret"


@pytest.fixture(autouse=True)
def agent_token(monkeypatch):
    """Installe un jeton connu pour toute la duree d'un test.

    Le jeton de test n'est **pas** lu depuis le fichier de l'utilisateur :
    une suite de tests ne doit jamais dependre d'un secret de la machine,
    ni risquer de l'ecraser.
    """
    from app import auth

    monkeypatch.setattr(settings, "agent_auth_enabled", True)
    monkeypatch.setattr(settings, "agent_auth_token", TEST_AGENT_TOKEN)
    auth.set_token_for_tests(TEST_AGENT_TOKEN)
    yield TEST_AGENT_TOKEN
    auth.set_token_for_tests(None)


def auth_headers(token: str = TEST_AGENT_TOKEN) -> dict[str, str]:
    """En-tete d'authentification a passer a un TestClient."""
    return {"Authorization": f"Bearer {token}"}
