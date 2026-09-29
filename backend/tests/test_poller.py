"""Tests du moteur de surveillance (MonitoringController)."""

import asyncio

import pytest

from app import store
from app.config import settings
from app.notifier import stream
from app.poller import format_timestamp, parse_timestamp, shift_timestamp
from app.wazuh_client import WazuhUnavailableError

from .conftest import FakeWazuhClient, make_alert


# --------------------------------------------------------------------------
# Curseur temporel
# --------------------------------------------------------------------------


def test_shift_timestamp_recule_du_chevauchement():
    assert shift_timestamp("2026-08-12T10:00:30.000+0000", -30) == (
        "2026-08-12T10:00:00.000+0000"
    )


def test_shift_timestamp_tolere_un_curseur_illisible():
    assert shift_timestamp("curseur-casse", -30) == "curseur-casse"


def test_parse_timestamp_accepte_les_formats_wazuh_et_iso():
    assert parse_timestamp("2026-08-12T10:00:00.000+0000") is not None
    assert parse_timestamp("2026-08-12T10:00:00.000Z") is not None
    assert parse_timestamp("") is None


# --------------------------------------------------------------------------
# start / stop
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_start_demarre_la_surveillance(controller_factory):
    controller = controller_factory(FakeWazuhClient())

    status = await controller.start()

    assert status.running is True
    assert status.started_at is not None
    assert status.poll_interval == settings.poll_interval
    assert store.get_state(store.STATE_RUNNING) == "1"

    await controller.stop()


@pytest.mark.asyncio
async def test_stop_arrete_la_surveillance(controller_factory):
    controller = controller_factory(FakeWazuhClient())
    await controller.start()

    status = await controller.stop()

    assert status.running is False
    assert status.stopped_at is not None
    assert controller._task is None
    assert store.get_state(store.STATE_RUNNING) == "0"


@pytest.mark.asyncio
async def test_double_start_ne_cree_pas_deux_taches(controller_factory):
    controller = controller_factory(FakeWazuhClient())

    await controller.start()
    task = controller._task

    await controller.start()
    await controller.start()

    assert controller._task is task, "aucune tache concurrente ne doit etre creee"
    assert controller.status().running is True

    await controller.stop()


@pytest.mark.asyncio
async def test_double_stop_retourne_simplement_l_etat(controller_factory):
    controller = controller_factory(FakeWazuhClient())
    await controller.start()

    first = await controller.stop()
    second = await controller.stop()

    assert first.running is False
    assert second.running is False
    assert controller._task is None


@pytest.mark.asyncio
async def test_stop_sans_start_ne_leve_pas(controller_factory):
    controller = controller_factory(FakeWazuhClient())

    status = await controller.stop()

    assert status.running is False


@pytest.mark.asyncio
async def test_start_puis_stop_puis_restart(controller_factory):
    controller = controller_factory(FakeWazuhClient())

    await controller.start()
    await controller.stop()
    status = await controller.start()

    assert status.running is True
    await controller.stop()


@pytest.mark.asyncio
async def test_la_boucle_scanne_reellement(controller_factory):
    alerts = [make_alert("a-1"), make_alert("a-2")]
    client = FakeWazuhClient(batches=[alerts])
    controller = controller_factory(client, poll_interval=0.02)

    await controller.start()
    await asyncio.sleep(0.15)
    await controller.stop()

    assert len(client.calls) >= 2, "la boucle doit interroger l'Indexer plusieurs fois"
    assert controller.status().scans >= 2
    assert store.count_alerts() == 2, "les alertes ne sont enregistrees qu'une fois"


# --------------------------------------------------------------------------
# Recuperation des nouvelles alertes
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_recupere_et_persiste_les_nouvelles_alertes(controller_factory):
    alerts = [
        make_alert("a-1", timestamp="2026-08-12T10:00:00.000+0000"),
        make_alert("a-2", timestamp="2026-08-12T10:00:05.000+0000"),
    ]
    controller = controller_factory(FakeWazuhClient(batches=[alerts]))
    await controller._load_state()

    new_alerts = await controller.scan_once()

    assert [alert.id for alert in new_alerts] == ["a-1", "a-2"]
    assert store.count_alerts() == 2

    stored = store.list_alerts()
    assert stored[0].id == "a-2"
    assert stored[0].rule.description == "Alerte de test"
    assert stored[0].agent.name == "srv-web"
    assert stored[0].location == "/var/log/auth.log"

    status = controller.status()
    assert status.alerts_new == 2
    assert status.last_alert == "2026-08-12T10:00:05.000+0000"
    assert status.last_scan is not None


@pytest.mark.asyncio
async def test_le_curseur_avance_et_applique_le_chevauchement(controller_factory):
    monkeypatched_overlap = settings.poll_overlap_seconds
    alerts = [make_alert("a-1", timestamp="2026-08-12T10:00:30.000+0000")]
    client = FakeWazuhClient(batches=[alerts, []])
    controller = controller_factory(client)

    # Curseur explicite : sans lui, le repli est "maintenant - lookback" et
    # le test dependrait de l'heure a laquelle il est joue.
    store.set_state(store.STATE_CURSOR, "2026-08-12T10:00:00.000+0000")
    await controller._load_state()

    await controller.scan_once()
    assert controller._cursor == "2026-08-12T10:00:30.000+0000"
    assert store.get_state(store.STATE_CURSOR) is not None

    await controller.scan_once()

    # Le second appel repart du curseur, diminue du chevauchement.
    second_since = client.calls[1]["since"]
    expected = shift_timestamp("2026-08-12T10:00:30.000+0000", -monkeypatched_overlap)
    assert second_since == expected
    assert client.calls[1]["order"] == "asc"


@pytest.mark.asyncio
async def test_le_premier_scan_utilise_une_fenetre_courte(controller_factory):
    client = FakeWazuhClient(batches=[[]])
    controller = controller_factory(client)
    await controller._load_state()

    await controller.scan_once()

    since = client.calls[0]["since"]
    assert since is not None
    assert parse_timestamp(since) is not None


@pytest.mark.asyncio
async def test_le_curseur_est_repris_depuis_sqlite(controller_factory):
    store.set_state(store.STATE_CURSOR, "2026-08-12T09:00:00.000+0000")
    client = FakeWazuhClient(batches=[[]])
    controller = controller_factory(client)

    await controller._load_state()
    await controller.scan_once()

    assert client.calls[0]["since"] == shift_timestamp(
        "2026-08-12T09:00:00.000+0000", -settings.poll_overlap_seconds
    )


# --------------------------------------------------------------------------
# Deduplication
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_une_alerte_deja_vue_n_est_pas_ajoutee_deux_fois(controller_factory):
    alerts = [make_alert("a-1"), make_alert("a-2")]
    # Le chevauchement fait remonter les memes alertes a chaque scan.
    controller = controller_factory(FakeWazuhClient(batches=[alerts, alerts, alerts]))
    await controller._load_state()

    first = await controller.scan_once()
    second = await controller.scan_once()
    third = await controller.scan_once()

    assert len(first) == 2
    assert second == []
    assert third == []
    assert store.count_alerts() == 2
    assert controller.status().alerts_new == 2
    assert controller.status().duplicates_skipped == 4


@pytest.mark.asyncio
async def test_doublons_a_l_interieur_d_un_meme_lot(controller_factory):
    doublon = make_alert("a-1")
    controller = controller_factory(
        FakeWazuhClient(batches=[[doublon, make_alert("a-1"), make_alert("a-2")]])
    )
    await controller._load_state()

    new_alerts = await controller.scan_once()

    assert len(new_alerts) == 2
    assert store.count_alerts() == 2


@pytest.mark.asyncio
async def test_la_deduplication_survit_a_un_redemarrage(controller_factory):
    alerts = [make_alert("a-1"), make_alert("a-2")]
    controller = controller_factory(FakeWazuhClient(batches=[alerts]))
    await controller._load_state()
    await controller.scan_once()

    # Nouveau controleur : le cache memoire est vide, SQLite fait foi.
    second_controller = controller_factory(FakeWazuhClient(batches=[alerts]))
    await second_controller._load_state()
    new_alerts = await second_controller.scan_once()

    assert new_alerts == []
    assert store.count_alerts() == 2


def test_save_alert_refuse_le_doublon_au_niveau_sqlite():
    alert = make_alert("a-1")
    assert store.save_alert(alert) is True
    assert store.save_alert(alert) is False
    assert store.count_alerts() == 1


# --------------------------------------------------------------------------
# Robustesse
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_une_erreur_wazuh_n_arrete_pas_le_poller(controller_factory):
    client = FakeWazuhClient(error=WazuhUnavailableError("Indexer injoignable"))
    controller = controller_factory(client, poll_interval=0.02)

    await controller.start()
    await asyncio.sleep(0.12)

    assert controller.status().running is True, "la boucle doit survivre a l'erreur"
    assert controller.status().errors >= 2
    assert "injoignable" in controller.status().last_error

    await controller.stop()


@pytest.mark.asyncio
async def test_le_poller_repart_apres_une_erreur(controller_factory):
    client = FakeWazuhClient(error=WazuhUnavailableError("Indexer injoignable"))
    controller = controller_factory(client)
    await controller._load_state()

    assert await controller.scan_once() == []
    assert controller.status().errors == 1

    # L'Indexer revient.
    client.error = None
    client.batches = [[make_alert("a-1")]]
    new_alerts = await controller.scan_once()

    assert len(new_alerts) == 1
    assert controller.status().last_error is None


@pytest.mark.asyncio
async def test_une_notification_en_echec_ne_bloque_pas_le_scan(
    controller_factory, monkeypatch
):
    from app.notifier import email

    async def failing_send(alert):
        raise RuntimeError("SMTP indisponible")

    monkeypatch.setattr(email, "is_configured", lambda: True)
    monkeypatch.setattr(email, "send_alert", failing_send)

    critique = make_alert("a-critique", level=12)
    controller = controller_factory(FakeWazuhClient(batches=[[critique]]))
    await controller._load_state()

    new_alerts = await controller.scan_once()
    assert len(new_alerts) == 1

    # Les envois externes sont detaches : on laisse tourner la boucle.
    await asyncio.sleep(0.05)

    assert store.was_notified("a-critique", "email") is True
    assert store.count_notifications("email") == 1


@pytest.mark.asyncio
async def test_les_nouvelles_alertes_partent_en_sse(controller_factory, monkeypatch):
    published = []

    async def capture(alert):
        published.append(alert)
        return 1

    monkeypatch.setattr(stream, "publish_alert", capture)

    controller = controller_factory(FakeWazuhClient(batches=[[make_alert("a-1")]]))
    await controller._load_state()
    await controller.scan_once()

    assert len(published) == 1
    assert published[0].id == "a-1"
    assert published[0].rule.level == 5


@pytest.mark.asyncio
async def test_une_alerte_non_critique_ne_declenche_pas_de_notification(
    controller_factory, monkeypatch
):
    from app.notifier import discord, email

    monkeypatch.setattr(email, "is_configured", lambda: True)
    monkeypatch.setattr(discord, "is_configured", lambda: True)
    monkeypatch.setattr(settings, "critical_level", 10)

    controller = controller_factory(FakeWazuhClient(batches=[[make_alert("a-1", level=3)]]))
    await controller._load_state()
    await controller.scan_once()
    await asyncio.sleep(0.05)

    assert store.count_notifications() == 0


# --------------------------------------------------------------------------
# Curseur bloque : plus d'alertes dans le chevauchement que `alert_fetch_size`
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_le_curseur_se_debloque_quand_le_lot_est_plein(
    controller_factory, monkeypatch
):
    """Regression : la surveillance rejouait indefiniment le meme lot.

    Le chevauchement fait repartir 30 s avant le curseur. Si cette fenetre
    contient plus d'alertes que la taille d'un lot, le lot (trie en ordre
    croissant) se termine sur le curseur lui-meme : sans correction, le
    curseur ne bouge plus jamais et aucune alerte nouvelle n'est vue.
    """
    monkeypatch.setattr(settings, "alert_fetch_size", 3)

    saturated = [
        make_alert("v-1", timestamp="2026-08-12T10:00:28.000+0000"),
        make_alert("v-2", timestamp="2026-08-12T10:00:29.000+0000"),
        make_alert("v-3", timestamp="2026-08-12T10:00:30.000+0000"),
    ]
    client = FakeWazuhClient(batches=[saturated])
    controller = controller_factory(client)

    store.set_state(store.STATE_CURSOR, "2026-08-12T10:00:30.000+0000")
    await controller._load_state()

    # 1er cycle : le lot tient dans le chevauchement, le curseur ne peut pas
    # avancer. La reponse est de rejouer sans chevauchement.
    await controller.scan_once()
    assert client.calls[0]["since"] == "2026-08-12T10:00:00.000+0000"
    assert controller._cursor == "2026-08-12T10:00:30.000+0000"
    assert controller._skip_overlap is True

    # 2e cycle : requete au curseur exact. Le lot reste anterieur au curseur
    # (cas limite), on avance donc d'une milliseconde pour sortir de la boucle.
    await controller.scan_once()
    assert client.calls[1]["since"] == "2026-08-12T10:00:30.000+0000", (
        "le chevauchement doit etre saute quand il sature le lot"
    )
    assert controller._cursor == "2026-08-12T10:00:30.001+0000", (
        "le curseur doit depasser le lot plein, sinon la surveillance boucle"
    )
    assert store.get_state(store.STATE_CURSOR) == "2026-08-12T10:00:30.001+0000"


@pytest.mark.asyncio
async def test_le_curseur_ne_recule_jamais(controller_factory, monkeypatch):
    """Un lot plein entierement anterieur au curseur ne le fait pas reculer."""
    monkeypatch.setattr(settings, "alert_fetch_size", 2)

    client = FakeWazuhClient(
        batches=[
            [
                make_alert("p-1", timestamp="2026-08-12T09:59:00.000+0000"),
                make_alert("p-2", timestamp="2026-08-12T09:59:01.000+0000"),
            ]
        ]
    )
    controller = controller_factory(client)

    store.set_state(store.STATE_CURSOR, "2026-08-12T10:00:30.000+0000")
    await controller._load_state()

    await controller.scan_once()
    await controller.scan_once()

    assert controller._cursor == "2026-08-12T10:00:30.001+0000"


@pytest.mark.asyncio
async def test_un_lot_non_plein_ne_touche_pas_au_curseur(controller_factory):
    """Sans saturation, l'absence de nouveaute laisse le curseur en place."""
    client = FakeWazuhClient(
        batches=[[make_alert("q-1", timestamp="2026-08-12T10:00:00.000+0000")]]
    )
    controller = controller_factory(client)

    store.set_state(store.STATE_CURSOR, "2026-08-12T10:00:30.000+0000")
    await controller._load_state()

    await controller.scan_once()

    assert controller._cursor == "2026-08-12T10:00:30.000+0000"


@pytest.mark.asyncio
async def test_un_lot_plein_qui_depasse_le_curseur_avance_normalement(
    controller_factory, monkeypatch
):
    """Cas courant du rattrapage : le lot plein contient des alertes neuves."""
    monkeypatch.setattr(settings, "alert_fetch_size", 2)

    client = FakeWazuhClient(
        batches=[
            [
                make_alert("r-1", timestamp="2026-08-12T10:00:31.000+0000"),
                make_alert("r-2", timestamp="2026-08-12T10:00:32.000+0000"),
            ]
        ]
    )
    controller = controller_factory(client)

    store.set_state(store.STATE_CURSOR, "2026-08-12T10:00:30.000+0000")
    await controller._load_state()

    new_alerts = await controller.scan_once()

    assert len(new_alerts) == 2
    assert controller._cursor == "2026-08-12T10:00:32.000+0000"
    assert controller._skip_overlap is False
