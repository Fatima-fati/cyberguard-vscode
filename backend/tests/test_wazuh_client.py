"""Tests du client Wazuh.

Aucun appel reseau reel : les reponses de la Manager API et de l'Indexer
sont simulees avec httpx.MockTransport.
"""

import base64
import json
import time

import httpx
import pytest

from app.models import Agent, Alert
from app.wazuh_client import (
    IndexerError,
    WazuhAPIError,
    WazuhAuthError,
    WazuhClient,
    WazuhTimeoutError,
    WazuhUnavailableError,
    _decode_jwt_expiration,
)


# --------------------------------------------------------------------------
# Outils
# --------------------------------------------------------------------------


def make_jwt(expires_in: int = 900) -> str:
    """Fabrique un JWT factice porteur d'une claim `exp`."""

    def segment(payload: dict) -> str:
        raw = json.dumps(payload).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    header = segment({"alg": "HS256", "typ": "JWT"})
    body = segment({"exp": int(time.time()) + expires_in, "sub": "wazuh-wui"})
    return f"{header}.{body}.signature"


def build_client(handler) -> WazuhClient:
    """Client Wazuh dont le transport HTTP est simule."""
    client = WazuhClient()
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return client


AGENTS_PAYLOAD = {
    "data": {
        "affected_items": [
            {
                "id": "000",
                "name": "wazuh-manager",
                "ip": "127.0.0.1",
                "status": "active",
                "os": {"name": "Ubuntu", "version": "22.04"},
                "version": "Wazuh v4.9.0",
                "group": ["default"],
                "lastKeepAlive": "2026-08-12T00:00:00Z",
            },
            {"id": "001", "name": "srv-web", "status": "disconnected"},
        ],
        "total_affected_items": 2,
    }
}

ALERTS_PAYLOAD = {
    "hits": {
        "total": {"value": 2},
        "hits": [
            {
                "_id": "alert-1",
                "_source": {
                    "timestamp": "2026-08-12T10:00:00.000Z",
                    "agent": {"id": "001", "name": "srv-web", "ip": "10.0.0.5"},
                    "rule": {
                        "id": 5710,
                        "level": 12,
                        "description": "Tentative de connexion SSH",
                        "groups": ["syslog", "sshd"],
                    },
                    "full_log": "Failed password for root",
                    "location": "/var/log/auth.log",
                },
            },
            {
                "_id": "alert-2",
                "_source": {
                    "timestamp": "2026-08-12T09:00:00.000Z",
                    "rule": {"id": 1002, "level": 3, "description": "Evenement mineur"},
                },
            },
        ],
    }
}


# --------------------------------------------------------------------------
# Decodage du JWT
# --------------------------------------------------------------------------


def test_decode_jwt_expiration_lit_la_claim_exp():
    token = make_jwt(expires_in=600)
    expiration = _decode_jwt_expiration(token)
    assert expiration is not None
    assert 590 < expiration - time.time() < 610


def test_decode_jwt_expiration_tolere_un_token_invalide():
    assert _decode_jwt_expiration("pas-un-jwt") is None


# --------------------------------------------------------------------------
# Authentification et cache du token
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authenticate_retourne_le_token():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/security/user/authenticate"
        assert request.url.params["raw"] == "true"
        assert request.headers["authorization"].startswith("Basic ")
        return httpx.Response(200, text=make_jwt())

    client = build_client(handler)
    token = await client.authenticate()

    assert token.count(".") == 2
    assert client.token_is_valid


@pytest.mark.asyncio
async def test_le_token_est_reutilise_sans_nouvelle_authentification():
    calls = {"auth": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["auth"] += 1
        return httpx.Response(200, text=make_jwt())

    client = build_client(handler)
    first = await client.authenticate()
    second = await client.authenticate()
    third = await client.authenticate()

    assert first == second == third
    assert calls["auth"] == 1, "le token doit etre mis en cache"


@pytest.mark.asyncio
async def test_le_token_est_renouvele_avant_expiration():
    calls = {"auth": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["auth"] += 1
        # Duree de vie plus courte que la marge de securite (60s) :
        # le token est donc considere comme deja perime.
        return httpx.Response(200, text=make_jwt(expires_in=10))

    client = build_client(handler)
    await client.authenticate()
    assert not client.token_is_valid

    await client.authenticate()
    assert calls["auth"] == 2, "un token expirant doit etre renouvele"


@pytest.mark.asyncio
async def test_authenticate_leve_une_erreur_sur_identifiants_refuses():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"title": "Unauthorized"})

    client = build_client(handler)
    with pytest.raises(WazuhAuthError):
        await client.authenticate()


@pytest.mark.asyncio
async def test_authenticate_leve_une_erreur_sur_token_vide():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="   ")

    client = build_client(handler)
    with pytest.raises(WazuhAuthError):
        await client.authenticate()


@pytest.mark.asyncio
async def test_wazuh_injoignable():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connexion refusee", request=request)

    client = build_client(handler)
    with pytest.raises(WazuhUnavailableError):
        await client.authenticate()


@pytest.mark.asyncio
async def test_timeout_authentification():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("trop lent", request=request)

    client = build_client(handler)
    with pytest.raises(WazuhTimeoutError):
        await client.authenticate()


# --------------------------------------------------------------------------
# get_agents
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_agents_retourne_des_modeles_propres():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, text=make_jwt())

        assert request.url.path == "/agents"
        assert request.headers["authorization"].startswith("Bearer ")
        return httpx.Response(200, json=AGENTS_PAYLOAD)

    client = build_client(handler)
    agents = await client.get_agents()

    assert len(agents) == 2
    assert all(isinstance(agent, Agent) for agent in agents)

    manager = agents[0]
    assert manager.id == "000"
    assert manager.name == "wazuh-manager"
    assert manager.os == "Ubuntu 22.04"
    assert manager.status == "active"
    assert manager.group == ["default"]

    # Un agent incomplet ne fait pas echouer la normalisation.
    assert agents[1].ip is None


@pytest.mark.asyncio
async def test_get_agents_reutilise_le_token_entre_deux_appels():
    calls = {"auth": 0, "agents": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            calls["auth"] += 1
            return httpx.Response(200, text=make_jwt())
        calls["agents"] += 1
        return httpx.Response(200, json=AGENTS_PAYLOAD)

    client = build_client(handler)
    await client.get_agents()
    await client.get_agents()

    assert calls["agents"] == 2
    assert calls["auth"] == 1


@pytest.mark.asyncio
async def test_get_agents_renouvelle_le_token_sur_401():
    calls = {"auth": 0, "agents": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            calls["auth"] += 1
            return httpx.Response(200, text=make_jwt())

        calls["agents"] += 1
        if calls["agents"] == 1:
            return httpx.Response(401, json={"title": "Token expired"})
        return httpx.Response(200, json=AGENTS_PAYLOAD)

    client = build_client(handler)
    agents = await client.get_agents()

    assert len(agents) == 2
    assert calls["auth"] == 2, "le token doit etre renouvele apres un 401"
    assert calls["agents"] == 2


@pytest.mark.asyncio
async def test_get_agents_sur_erreur_serveur():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, text=make_jwt())
        return httpx.Response(500, text="internal error")

    client = build_client(handler)
    with pytest.raises(WazuhAPIError):
        await client.get_agents()


@pytest.mark.asyncio
async def test_get_agents_sur_reponse_inattendue():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, text=make_jwt())
        return httpx.Response(200, json={"message": "ok"})

    client = build_client(handler)
    with pytest.raises(WazuhAPIError):
        await client.get_agents()


# --------------------------------------------------------------------------
# get_alerts (Indexer)
# --------------------------------------------------------------------------


def test_build_alerts_query_trie_par_timestamp_descendant():
    query = WazuhClient().build_alerts_query(size=25)
    assert query["size"] == 25
    assert query["sort"] == [{"timestamp": {"order": "desc"}}]
    assert query["query"] == {"match_all": {}}


def test_build_alerts_query_filtre_par_niveau():
    query = WazuhClient().build_alerts_query(size=10, min_level=10)
    assert query["query"] == {"range": {"rule.level": {"gte": 10}}}


@pytest.mark.asyncio
async def test_get_alerts_extrait_les_documents():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["body"] = json.loads(request.content)
        assert request.headers["authorization"].startswith("Basic ")
        return httpx.Response(200, json=ALERTS_PAYLOAD)

    client = build_client(handler)
    alerts = await client.get_alerts(size=2)

    assert captured["path"].endswith("/_search")
    assert captured["body"]["size"] == 2
    assert captured["body"]["sort"] == [{"timestamp": {"order": "desc"}}]

    assert len(alerts) == 2
    assert all(isinstance(alert, Alert) for alert in alerts)

    first = alerts[0]
    assert first.id == "alert-1"
    assert first.timestamp == "2026-08-12T10:00:00.000Z"
    assert first.agent.id == "001"
    assert first.agent.name == "srv-web"
    assert first.rule.id == "5710"
    assert first.rule.level == 12
    assert first.rule.description == "Tentative de connexion SSH"
    assert first.full_log == "Failed password for root"
    assert first.location == "/var/log/auth.log"
    assert first.is_critical(10) is True

    # Document partiel : pas d'agent, pas de full_log.
    second = alerts[1]
    assert second.agent.id is None
    assert second.full_log is None
    assert second.is_critical(10) is False


@pytest.mark.asyncio
async def test_get_alerts_sur_indexer_en_erreur():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="search phase execution exception")

    client = build_client(handler)
    with pytest.raises(IndexerError):
        await client.get_alerts()


@pytest.mark.asyncio
async def test_get_alerts_sur_index_absent():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "index_not_found_exception"})

    client = build_client(handler)
    with pytest.raises(IndexerError):
        await client.get_alerts()


@pytest.mark.asyncio
async def test_get_alerts_sur_identifiants_indexer_refuses():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "unauthorized"})

    client = build_client(handler)
    with pytest.raises(WazuhAuthError):
        await client.get_alerts()


@pytest.mark.asyncio
async def test_get_alerts_sur_indexer_injoignable():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connexion refusee", request=request)

    client = build_client(handler)
    with pytest.raises(WazuhUnavailableError):
        await client.get_alerts()


@pytest.mark.asyncio
async def test_get_alerts_sur_reponse_malformee():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"took": 3})

    client = build_client(handler)
    with pytest.raises(IndexerError):
        await client.get_alerts()


def test_extract_alerts_sur_reponse_vide():
    assert WazuhClient.extract_alerts({"hits": {"hits": []}}) == []
