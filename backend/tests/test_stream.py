"""Tests du diffuseur SSE (app.notifier.stream)."""

import asyncio
import json
from typing import Optional

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app import routes

from app import store
from app.config import settings
from app.models import StreamEvent
from app.notifier import stream
from app.notifier.stream import AlertBroker, alert_payload, comment, format_sse

from .conftest import auth_headers, make_alert


@pytest.fixture(autouse=True)
def clean_broker():
    """Aucun client ne doit survivre d'un test a l'autre."""
    stream.broker._subscribers.clear()
    yield
    stream.broker._subscribers.clear()


async def read(agen, count: int = 1) -> list[str]:
    """Lit `count` messages du generateur SSE."""
    return [await agen.__anext__() for _ in range(count)]


def payload_of(message: str) -> dict:
    """Extrait le JSON du champ `data:` d'un message SSE."""
    data = "".join(
        line[len("data: ") :]
        for line in message.splitlines()
        if line.startswith("data: ")
    )
    return json.loads(data)


# --------------------------------------------------------------------------
# Format du protocole
# --------------------------------------------------------------------------


def test_format_sse_produit_un_evenement_valide():
    message = format_sse("alert", {"id": "a-1"}, event_id="a-1", retry_ms=3000)

    assert message.startswith("id: a-1\nretry: 3000\nevent: alert\ndata: ")
    assert message.endswith("\n\n")
    assert payload_of(message) == {"id": "a-1"}


def test_comment_ne_declenche_pas_d_evenement():
    assert comment("heartbeat") == ": heartbeat\n\n"


def test_alert_payload_est_a_plat():
    alert = make_alert("a-1", level=12, description="Force brute")

    assert alert_payload(alert) == {
        "id": "a-1",
        "timestamp": "2026-08-12T10:00:00.000+0000",
        "agent_id": "001",
        "agent_name": "srv-web",
        "rule_id": "5710",
        "rule_level": 12,
        "rule_description": "Force brute",
        # Version francaise, a cote de la description Wazuh originale.
        "rule_description_fr": "Force brute",
        "rule_groups_label": "",
        "location": "/var/log/auth.log",
        "full_log": "log de a-1",
    }


# --------------------------------------------------------------------------
# Diffusion
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_un_client_recoit_les_nouvelles_alertes():
    broker = AlertBroker()
    agen = broker.subscribe()

    hello = (await read(agen))[0]
    assert "event: connected" in hello

    await broker.publish_alert(make_alert("a-1", level=12))
    message = (await read(agen))[0]

    assert message.startswith("id: a-1\n")
    assert "event: alert" in message
    assert payload_of(message)["rule_level"] == 12
    assert payload_of(message)["agent_name"] == "srv-web"

    await agen.aclose()


@pytest.mark.asyncio
async def test_plusieurs_navigateurs_recoivent_la_meme_alerte():
    broker = AlertBroker()
    clients = [broker.subscribe() for _ in range(3)]
    for agen in clients:
        await read(agen)

    assert broker.subscriber_count == 3

    served = await broker.publish_alert(make_alert("a-1"))
    assert served == 3

    for agen in clients:
        assert payload_of((await read(agen))[0])["id"] == "a-1"

    for agen in clients:
        await agen.aclose()

    assert broker.subscriber_count == 0


@pytest.mark.asyncio
async def test_publier_sans_client_ne_leve_pas():
    broker = AlertBroker()
    assert await broker.publish_alert(make_alert("a-1")) == 0


@pytest.mark.asyncio
async def test_une_charge_utile_invalide_ne_leve_pas():
    broker = AlertBroker()

    class NonSerialisable:
        pass

    # `default=str` couvre la plupart des cas ; un objet recursif echoue.
    recursif: dict = {}
    recursif["self"] = recursif

    assert broker.publish_nowait(StreamEvent(type="alert", data=recursif)) == 0


# --------------------------------------------------------------------------
# Le poller n'attend jamais le frontend
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_un_client_lent_ne_bloque_pas_la_publication(monkeypatch):
    monkeypatch.setattr(settings, "sse_queue_size", 2)
    broker = AlertBroker()
    agen = broker.subscribe()
    await read(agen)  # le client se connecte puis ne lit plus rien

    for index in range(5):
        served = await broker.publish_alert(make_alert(f"a-{index}"))
        assert served == 1, "la publication aboutit toujours"

    subscriber = next(iter(broker._subscribers.values()))
    assert subscriber.queue.qsize() == 2
    assert subscriber.dropped == 3

    # Les evenements conserves sont les plus recents.
    assert payload_of((await read(agen))[0])["id"] == "a-3"
    assert payload_of((await read(agen))[0])["id"] == "a-4"

    await agen.aclose()


# --------------------------------------------------------------------------
# Deconnexion, heartbeat, fuites
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_la_deconnexion_libere_le_client():
    broker = AlertBroker()
    agen = broker.subscribe()
    await read(agen)

    assert broker.subscriber_count == 1

    await agen.aclose()

    assert broker.subscriber_count == 0, "aucune file ne doit rester en memoire"


@pytest.mark.asyncio
async def test_une_annulation_libere_aussi_le_client():
    broker = AlertBroker()
    agen = broker.subscribe()
    await read(agen)

    task = asyncio.create_task(agen.__anext__())
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    await agen.aclose()
    assert broker.subscriber_count == 0


@pytest.mark.asyncio
async def test_heartbeat_periodique(monkeypatch):
    monkeypatch.setattr(settings, "sse_heartbeat_seconds", 0.05)
    broker = AlertBroker()
    agen = broker.subscribe()
    await read(agen)

    assert (await read(agen))[0] == ": heartbeat\n\n"

    await agen.aclose()


@pytest.mark.asyncio
async def test_un_client_parti_est_detecte_au_heartbeat(monkeypatch):
    monkeypatch.setattr(settings, "sse_heartbeat_seconds", 0.05)
    broker = AlertBroker()

    async def is_disconnected():
        return True

    agen = broker.subscribe(is_disconnected=is_disconnected)
    await read(agen)

    with pytest.raises(StopAsyncIteration):
        await agen.__anext__()

    assert broker.subscriber_count == 0


@pytest.mark.asyncio
async def test_close_all_termine_tous_les_flux():
    broker = AlertBroker()
    agen = broker.subscribe()
    await read(agen)

    await broker.close_all()

    closing = (await read(agen))[0]
    assert "event: closing" in closing
    with pytest.raises(StopAsyncIteration):
        await agen.__anext__()


# --------------------------------------------------------------------------
# Reconnexion (Last-Event-ID)
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reconnexion_rejoue_les_alertes_manquees():
    store.save_alerts([make_alert("a-1"), make_alert("a-2"), make_alert("a-3")])

    broker = AlertBroker()
    agen = broker.subscribe(last_event_id="a-1")

    await read(agen)  # event: connected
    rejoues = await read(agen, 2)

    assert [payload_of(message)["id"] for message in rejoues] == ["a-2", "a-3"]

    await agen.aclose()


@pytest.mark.asyncio
async def test_reconnexion_sans_identifiant_ne_rejoue_rien():
    store.save_alerts([make_alert("a-1"), make_alert("a-2")])

    broker = AlertBroker()
    agen = broker.subscribe()
    await read(agen)

    await broker.publish_alert(make_alert("a-3"))
    assert payload_of((await read(agen))[0])["id"] == "a-3"

    await agen.aclose()


@pytest.mark.asyncio
async def test_un_identifiant_inconnu_ne_rejoue_pas_tout_l_historique():
    store.save_alerts([make_alert("a-1"), make_alert("a-2")])

    broker = AlertBroker()
    agen = broker.subscribe(last_event_id="identifiant-inconnu")
    await read(agen)

    await broker.publish_alert(make_alert("a-3"))
    assert payload_of((await read(agen))[0])["id"] == "a-3"

    await agen.aclose()


def test_alerts_after_est_borne():
    store.save_alerts([make_alert(f"a-{index}") for index in range(10)])

    suite = store.alerts_after("a-0", limit=3)

    assert [alert.id for alert in suite] == ["a-1", "a-2", "a-3"]


# --------------------------------------------------------------------------
# Limite de clients
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_le_nombre_de_clients_est_borne(monkeypatch):
    monkeypatch.setattr(settings, "sse_max_clients", 2)
    broker = AlertBroker()

    clients = [broker.subscribe() for _ in range(2)]
    for agen in clients:
        await read(agen)

    assert broker.is_full is True

    for agen in clients:
        await agen.aclose()

    assert broker.is_full is False


# --------------------------------------------------------------------------
# Endpoint HTTP
#
# Note : ni TestClient ni httpx.ASGITransport ne savent consommer une reponse
# en streaming (ils bufferisent le corps entier), donc la route est appelee
# directement. Le flux complet est verifie sur un vrai serveur avec curl.
# --------------------------------------------------------------------------


def make_request(headers: Optional[list[tuple[bytes, bytes]]] = None) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/stream",
            "query_string": b"",
            "headers": headers or [],
        }
    )


@pytest.mark.asyncio
async def test_la_route_renvoie_un_flux_sse():
    response = await routes.event_stream(
        request=make_request(), last_event_id=None, since_id=None
    )

    assert response.media_type == "text/event-stream"
    assert response.headers["cache-control"] == "no-cache, no-transform"
    assert response.headers["x-accel-buffering"] == "no"

    iterator = response.body_iterator
    hello = await anext(iterator)
    assert "event: connected" in hello
    assert "retry: 3000" in hello

    await stream.publish_alert(make_alert("a-1", level=12))
    message = await anext(iterator)
    assert payload_of(message)["rule_level"] == 12

    await iterator.aclose()
    assert stream.broker.subscriber_count == 0


@pytest.mark.asyncio
async def test_la_route_rejoue_apres_reconnexion():
    store.save_alerts([make_alert("a-1"), make_alert("a-2")])

    response = await routes.event_stream(
        request=make_request(), last_event_id="a-1", since_id=None
    )

    iterator = response.body_iterator
    await anext(iterator)  # event: connected
    rejoue = await anext(iterator)

    assert payload_of(rejoue)["id"] == "a-2"

    await iterator.aclose()


@pytest.mark.asyncio
async def test_la_route_refuse_les_clients_en_trop(monkeypatch):
    monkeypatch.setattr(settings, "sse_max_clients", 0)

    with pytest.raises(HTTPException) as erreur:
        await routes.event_stream(
            request=make_request(), last_event_id=None, since_id=None
        )

    assert erreur.value.status_code == 503
    assert "SSE" in erreur.value.detail["error"]


def test_endpoint_stats(monkeypatch):
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app, headers=auth_headers()) as client:
        stats = client.get("/api/stream/stats").json()

    assert set(stats) == {"clients", "published", "dropped"}
