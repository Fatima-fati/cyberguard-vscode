"""Cloisonnement du flux SSE par projet (phase 0, faiblesse F2).

Le probleme corrige : un evenement `code_finding` porte un extrait du code
analyse. Diffuse a tous les abonnes, il livrait le code d'un projet aux
fenetres ouvertes sur un autre.

Ces tests exercent le **vrai** diffuseur, pas un double : c'est la seule
facon de verifier une regle de routage.
"""

import asyncio

import pytest

from app.config import settings
from app.models import Alert, AlertSource, Rule, StreamEvent
from app.notifier.stream import AlertBroker


def finding_event(project: str) -> StreamEvent:
    """Evenement de finding, avec l'extrait de code qu'il porte reellement."""
    return StreamEvent(
        type="code_finding",
        data={
            "finding_uid": f"f-{project}",
            "file_path": "src/app.py",
            # C'est cet extrait qui ne doit jamais traverser vers un autre
            # projet : il vient du fichier du developpeur.
            "location": {"snippet": f"secret_de_{project} = 1"},
        },
    )


async def drain(subscriber) -> list[str]:
    """Vide la file d'un abonne sans attendre."""
    messages: list[str] = []
    while not subscriber.queue.empty():
        messages.append(subscriber.queue.get_nowait())
    return messages


@pytest.fixture
def broker():
    return AlertBroker()


# --------------------------------------------------------------------------
# La garantie centrale
# --------------------------------------------------------------------------


async def test_un_finding_du_projet_a_n_atteint_pas_le_projet_b(broker):
    """La garantie de la phase 0, enoncee telle quelle.

    Deux abonnes, deux projets. Le finding de A ne doit exister que pour A.
    """
    abonne_a = broker._register(project_uid="projet-a")
    abonne_b = broker._register(project_uid="projet-b")

    servis = await broker.publish(finding_event("a"), project_uid="projet-a")

    assert servis == 1

    messages_a = await drain(abonne_a)
    messages_b = await drain(abonne_b)

    assert len(messages_a) == 1
    assert "secret_de_a" in messages_a[0]

    # Rien du tout : ni l'evenement, ni une version amputee.
    assert messages_b == []


async def test_un_abonne_sans_projet_ne_capte_pas_les_findings_d_un_projet(broker):
    """Dissymetrie volontaire, et c'est la le coeur du dispositif.

    Si un abonne sans portee recevait tout, il suffirait d'omettre
    `project_uid` pour ecouter les findings de tous les projets. Le
    cloisonnement serait alors declaratif, donc inexistant.
    """
    curieux = broker._register(project_uid=None)
    legitime = broker._register(project_uid="projet-a")

    await broker.publish(finding_event("a"), project_uid="projet-a")

    assert await drain(curieux) == []
    assert len(await drain(legitime)) == 1


async def test_un_evenement_sans_projet_atteint_tout_le_monde(broker):
    """Les alertes Wazuh n'appartiennent a aucun projet : portee globale.

    Le cloisonnement ne doit pas casser la supervision existante.
    """
    abonne_a = broker._register(project_uid="projet-a")
    abonne_b = broker._register(project_uid="projet-b")
    sans_portee = broker._register(project_uid=None)

    servis = await broker.publish(StreamEvent(type="alert", data={"id": "a-1"}))

    assert servis == 3
    assert len(await drain(abonne_a)) == 1
    assert len(await drain(abonne_b)) == 1
    assert len(await drain(sans_portee)) == 1


async def test_une_alerte_wazuh_reste_diffusee_a_tous(broker):
    """Meme verification, par le chemin reel `publish_alert`."""
    abonne_a = broker._register(project_uid="projet-a")
    abonne_b = broker._register(project_uid="projet-b")

    alerte = Alert(
        id="a-1",
        timestamp="2026-09-01T10:00:00.000+0000",
        agent=AlertSource(id="001", name="srv", ip="10.0.0.1"),
        rule=Rule(id="5710", level=10, description="test"),
    )
    servis = await broker.publish_alert(alerte)

    assert servis == 2
    assert len(await drain(abonne_a)) == 1
    assert len(await drain(abonne_b)) == 1


async def test_plusieurs_abonnes_du_meme_projet_recoivent_tous(broker):
    """Deux fenetres VS Code sur le meme projet : les deux sont servies."""
    premier = broker._register(project_uid="projet-a")
    second = broker._register(project_uid="projet-a")
    autre = broker._register(project_uid="projet-b")

    servis = await broker.publish(finding_event("a"), project_uid="projet-a")

    assert servis == 2
    assert len(await drain(premier)) == 1
    assert len(await drain(second)) == 1
    assert await drain(autre) == []


async def test_un_projet_sans_abonne_ne_fait_rien_echouer(broker):
    """Publier vers un projet que personne n'ecoute est sans consequence."""
    broker._register(project_uid="projet-b")
    assert await broker.publish(finding_event("a"), project_uid="projet-a") == 0


async def test_la_portee_est_annoncee_a_la_connexion(broker):
    """L'abonne voit la portee que le serveur lui a attribuee.

    Sans cette confirmation, un `project_uid` mal transmis ne se
    manifesterait que par une absence d'evenements — le symptome le plus
    difficile a diagnostiquer.
    """
    generator = broker.subscribe(project_uid="projet-a")
    premier = await generator.__anext__()

    assert "event: connected" in premier
    assert "projet-a" in premier

    await generator.aclose()


async def test_un_abonne_ferme_ne_retient_aucune_file(broker):
    """Aucune fuite : le cloisonnement n'a pas casse le desabonnement."""
    generator = broker.subscribe(project_uid="projet-a")
    await generator.__anext__()
    assert broker.subscriber_count == 1

    await generator.aclose()
    # Laisse le `finally` du generateur rendre la main.
    await asyncio.sleep(0)
    assert broker.subscriber_count == 0


async def test_le_cloisonnement_survit_a_une_file_saturee(broker, monkeypatch):
    """Un abonne sature perd ses vieux messages, jamais ceux d'un autre."""
    monkeypatch.setattr(settings, "sse_queue_size", 2)

    lent = broker._register(project_uid="projet-a")
    autre = broker._register(project_uid="projet-b")

    for _ in range(5):
        await broker.publish(finding_event("a"), project_uid="projet-a")

    # La file du lent est bornee, mais elle ne contient que du « a ».
    messages = await drain(lent)
    assert len(messages) <= 2
    assert all("secret_de_a" in message for message in messages)
    assert await drain(autre) == []
