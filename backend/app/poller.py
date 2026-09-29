"""Moteur de surveillance : boucle asyncio qui interroge l'Indexer Wazuh.

Chaine complete :
    FastAPI -> MonitoringController -> boucle asyncio -> Wazuh Indexer
            -> nouvelles alertes -> SQLite -> SSE -> frontend

Le bouton de l'interface ne demarre pas Wazuh (qui tourne deja dans Docker) :
il demarre ou arrete uniquement cette boucle.
"""

import asyncio
import logging
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Optional

from app import store
from app.ai import agent as ai_agent
from app.ai import notifications as ai_notifications
from app.config import settings
from app.models import Alert, MonitoringStatus, StreamEvent
from app.notifier import discord, email, stream
from app.wazuh_client import WazuhClient, WazuhError, get_wazuh_client

logger = logging.getLogger(__name__)

# Format des timestamps de l'Indexer Wazuh : 2026-08-11T22:49:53.604+0000
WAZUH_TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%f%z"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()


def parse_timestamp(value: Optional[str]) -> Optional[datetime]:
    """Interprete un timestamp Wazuh (tolerant sur le format)."""
    if not value:
        return None

    try:
        return datetime.strptime(value, WAZUH_TS_FORMAT)
    except ValueError:
        pass

    try:
        # Gere aussi les formats ISO-8601 avec 'Z' ou decalage '+00:00'.
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        logger.debug("Timestamp illisible: %r", value)
        return None


def format_timestamp(moment: datetime) -> str:
    """Formate un instant comme l'Indexer Wazuh."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"


def shift_timestamp(value: str, seconds: int) -> str:
    """Decale un timestamp de `seconds` (negatif = vers le passe).

    Utilise pour le chevauchement temporel : on re-interroge legerement
    avant le curseur afin de ne pas rater une alerte indexee en retard.
    """
    moment = parse_timestamp(value)
    if moment is None:
        # Curseur illisible : on le renvoie tel quel plutot que de tout perdre.
        return value
    return format_timestamp(moment + timedelta(seconds=seconds))


def nudge_timestamp(value: str, milliseconds: int = 1) -> str:
    """Avance un timestamp du plus petit pas representable (1 ms).

    Sert a debloquer le curseur quand une fenetre de temps contient plus
    d'alertes que `alert_fetch_size` : sans ce pas, le curseur retomberait
    indefiniment sur le meme lot (voir `_advance_cursor`).
    """
    moment = parse_timestamp(value)
    if moment is None:
        return value
    return format_timestamp(moment + timedelta(milliseconds=milliseconds))


class MonitoringController:
    """Pilote le cycle de vie du poller (start / stop / status).

    Une seule tache asyncio peut exister a la fois : cliquer plusieurs fois
    sur "Demarrer" ne cree pas de taches concurrentes.
    """

    def __init__(self, client: Optional[WazuhClient] = None) -> None:
        self._client = client
        self._task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()
        self._lock = asyncio.Lock()

        # Taches de notification detachees (jamais attendues par la boucle).
        self._background: set[asyncio.Task] = set()

        # Cache de dedoublonnage : identifiants Wazuh recemment traites.
        self._seen: OrderedDict[str, None] = OrderedDict()

        self._cursor: Optional[str] = None
        self._status = MonitoringStatus(poll_interval=settings.poll_interval)

        # Vrai quand le dernier lot remonte etait plein : il reste alors des
        # alertes a rattraper, on enchaine sans attendre l'intervalle.
        self._batch_saturated = False

        # Chevauchement temporel : applique par defaut, saute le temps d'un
        # cycle quand il empeche le curseur d'avancer (voir _advance_cursor).
        self._skip_overlap = False
        self._overlap_applied = False

    # ---------------- Acces au client ----------------

    @property
    def client(self) -> WazuhClient:
        return self._client or get_wazuh_client()

    # ---------------- Etat ----------------

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def status(self) -> MonitoringStatus:
        """Etat courant de la surveillance."""
        self._status.running = self.running
        self._status.poll_interval = settings.poll_interval
        self._status.cursor = self._cursor
        return self._status

    # ---------------- Dedoublonnage ----------------

    def _remember(self, wazuh_id: str) -> None:
        """Memorise un identifiant deja traite (cache borne, FIFO)."""
        self._seen[wazuh_id] = None
        self._seen.move_to_end(wazuh_id)
        while len(self._seen) > settings.dedupe_cache_size:
            self._seen.popitem(last=False)

    def _is_known(self, wazuh_id: str) -> bool:
        return wazuh_id in self._seen

    async def _load_state(self) -> None:
        """Recharge le curseur et le cache de dedoublonnage depuis SQLite."""
        self._cursor = await asyncio.to_thread(store.get_state, store.STATE_CURSOR)

        if self._cursor is None:
            # Repli : la derniere alerte connue en base, sinon une fenetre courte.
            latest = await asyncio.to_thread(store.latest_alert_timestamp)
            self._cursor = latest or format_timestamp(
                _now() - timedelta(seconds=settings.initial_lookback_seconds)
            )
            logger.info("Aucun curseur enregistre, demarrage a %s", self._cursor)

        known = await asyncio.to_thread(
            store.known_alert_ids, settings.dedupe_cache_size
        )
        self._seen.clear()
        for wazuh_id in reversed(known):
            self._remember(wazuh_id)

        self._status.last_scan = await asyncio.to_thread(
            store.get_state, store.STATE_LAST_SCAN
        )
        self._status.last_alert = await asyncio.to_thread(
            store.get_state, store.STATE_LAST_ALERT
        )

    # ---------------- Cycle de vie ----------------

    async def start(self) -> MonitoringStatus:
        """Demarre la surveillance. Sans effet si elle tourne deja."""
        async with self._lock:
            if self.running:
                logger.info("Surveillance deja active, demande ignoree")
                return self.status()

            await self._load_state()

            self._stop_event = asyncio.Event()
            self._status.started_at = _now_iso()
            self._status.stopped_at = None
            self._status.last_error = None
            self._task = asyncio.create_task(self._run(), name="wazuh-poller")

            await asyncio.to_thread(store.set_state, store.STATE_RUNNING, "1")
            logger.info(
                "Surveillance demarree (intervalle %ss, curseur %s)",
                settings.poll_interval,
                self._cursor,
            )

        await self._publish_status("started")
        return self.status()

    async def stop(self) -> MonitoringStatus:
        """Arrete la surveillance. Sans effet si elle est deja arretee."""
        async with self._lock:
            task = self._task
            if task is None or task.done():
                self._task = None
                logger.info("Surveillance deja arretee, demande ignoree")
                return self.status()

            self._stop_event.set()
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=5)
            except asyncio.TimeoutError:
                logger.warning("Arret trop lent, annulation de la tache")
                task.cancel()
            except asyncio.CancelledError:
                pass
            except Exception:  # noqa: BLE001 - l'arret ne doit jamais echouer
                logger.exception("Erreur pendant l'arret du poller")

            self._task = None
            self._status.running = False
            self._status.stopped_at = _now_iso()

            await asyncio.to_thread(store.set_state, store.STATE_RUNNING, "0")
            logger.info("Surveillance arretee")

        await self._publish_status("stopped")
        return self.status()

    async def shutdown(self) -> None:
        """Arret complet (extinction de FastAPI) : boucle + notifications."""
        await self.stop()
        for task in list(self._background):
            task.cancel()
        if self._background:
            await asyncio.gather(*self._background, return_exceptions=True)
        self._background.clear()

    # ---------------- Boucle ----------------

    async def _run(self) -> None:
        """Boucle principale : scanne puis attend, jusqu'a demande d'arret."""
        try:
            while not self._stop_event.is_set():
                await self.scan_once()

                # Retard a rattraper : on enchaine sans attendre l'intervalle,
                # sinon un backlog de plusieurs centaines d'alertes mettrait
                # des minutes a remonter. `asyncio.sleep(0)` rend la main a la
                # boucle pour que l'arret reste immediat.
                if self._batch_saturated:
                    await asyncio.sleep(0)
                    continue

                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(), timeout=settings.poll_interval
                    )
                except asyncio.TimeoutError:
                    continue  # Delai ecoule : nouveau cycle.
        except asyncio.CancelledError:
            logger.info("Boucle de surveillance annulee")
            raise
        finally:
            self._status.running = False

    async def scan_once(self) -> list[Alert]:
        """Un cycle : recupere, dedoublonne, persiste et notifie.

        Ne leve jamais : une erreur est enregistree dans le statut et la
        boucle continue au cycle suivant.
        """
        self._status.scans += 1
        self._status.last_scan = _now_iso()

        try:
            alerts = await self._fetch_new_alerts()
        except WazuhError as exc:
            self._record_error(f"{exc.message} ({exc.detail})" if exc.detail else exc.message)
            return []
        except Exception as exc:  # noqa: BLE001 - la boucle ne doit jamais mourir
            logger.exception("Erreur inattendue pendant le scan")
            self._record_error(str(exc))
            return []

        try:
            new_alerts = await self._process(alerts)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Erreur pendant le traitement des alertes")
            self._record_error(str(exc))
            return []

        self._status.last_error = None
        await asyncio.to_thread(
            store.set_state, store.STATE_LAST_SCAN, self._status.last_scan
        )
        return new_alerts

    def _record_error(self, message: str) -> None:
        self._status.errors += 1
        self._status.last_error = message
        logger.warning("Cycle de surveillance en erreur: %s", message)

    async def _fetch_new_alerts(self) -> list[Alert]:
        """Interroge l'Indexer a partir du curseur, avec chevauchement.

        Le chevauchement est saute pour un cycle quand le cycle precedent a
        montre qu'il saturait le lot a lui seul : la fenetre repart alors du
        curseur exact, ce qui garantit de voir enfin les alertes suivantes.
        """
        since = self._cursor
        self._overlap_applied = False

        if since and not self._skip_overlap:
            since = shift_timestamp(since, -settings.poll_overlap_seconds)
            self._overlap_applied = True

        # Consomme la demande : le chevauchement reprend au cycle suivant.
        self._skip_overlap = False

        # Ordre croissant : le curseur avance meme si la fenetre depasse `size`.
        alerts = await self.client.get_alerts(
            size=settings.alert_fetch_size,
            since=since,
            order="asc",
        )

        # Lot plein = l'Indexer avait peut-etre plus a donner : le prochain
        # cycle est enchaine immediatement (rattrapage).
        self._batch_saturated = len(alerts) >= settings.alert_fetch_size
        return alerts

    async def _process(self, alerts: list[Alert]) -> list[Alert]:
        """Filtre les doublons, persiste, avance le curseur et notifie."""
        if not alerts:
            return []

        self._status.alerts_seen += len(alerts)

        # 1. Dedoublonnage rapide en memoire (_id Elasticsearch/OpenSearch).
        candidates: list[Alert] = []
        for alert in alerts:
            if not alert.id:
                continue
            if self._is_known(alert.id):
                self._status.duplicates_skipped += 1
                continue
            candidates.append(alert)

        # 2. SQLite fait foi : INSERT OR IGNORE sur la contrainte UNIQUE.
        new_alerts = await asyncio.to_thread(store.save_alerts, candidates)
        self._status.duplicates_skipped += len(candidates) - len(new_alerts)

        for alert in candidates:
            self._remember(alert.id)

        # 3. Le curseur avance sur le timestamp le plus recent *vu*, meme si
        #    l'alerte etait un doublon : sinon la fenetre ne progresserait pas.
        await self._advance_cursor(alerts)

        if not new_alerts:
            return []

        self._status.alerts_new += len(new_alerts)
        self._status.last_alert = new_alerts[-1].timestamp
        await asyncio.to_thread(
            store.set_state, store.STATE_LAST_ALERT, self._status.last_alert
        )

        logger.info(
            "%s nouvelle(s) alerte(s) sur %s remontee(s)", len(new_alerts), len(alerts)
        )

        for alert in new_alerts:
            await self._notify(alert)

        # Analyse IA en tache detachee : la boucle ne l'attend jamais et
        # une panne OpenAI n'a aucun effet sur la collecte Wazuh.
        self._spawn(ai_agent.analyze_new_alerts(list(new_alerts)), label="ia")

        return new_alerts

    async def _advance_cursor(self, alerts: list[Alert]) -> None:
        """Positionne le curseur sur le timestamp le plus recent rencontre.

        Cas particulier a ne pas manquer : le chevauchement temporel fait
        re-interroger `poll_overlap_seconds` avant le curseur. Si cette
        fenetre contient a elle seule plus de `alert_fetch_size` alertes, le
        lot (trie en ordre croissant) se termine AVANT le curseur : le
        maximum rencontre n'est jamais superieur au curseur, celui-ci ne
        bouge plus et la surveillance rejoue eternellement le meme lot.

        On avance alors d'une milliseconde au-dela du dernier document
        traite. Rien n'est perdu : les documents de ce lot sont deja
        enregistres, et le dedoublonnage (`wazuh_id` UNIQUE) protege ceux qui
        partagent le meme horodatage.
        """
        newest: Optional[datetime] = parse_timestamp(self._cursor)
        newest_raw = self._cursor

        for alert in alerts:
            moment = parse_timestamp(alert.timestamp)
            if moment is None:
                continue
            if newest is None or moment > newest:
                newest, newest_raw = moment, alert.timestamp

        if not newest_raw:
            return

        if newest_raw == self._cursor:
            # Le curseur ne peut pas progresser normalement. Tant que le lot
            # n'est pas plein, c'est simplement qu'il n'y a rien de neuf.
            if not self._batch_saturated:
                return

            if self._overlap_applied:
                # Le lot tient entierement dans le chevauchement : il ne
                # depasse jamais le curseur. On rejoue immediatement le cycle
                # sans chevauchement, en repartant du curseur exact.
                self._skip_overlap = True
                logger.info(
                    "Chevauchement sature (%s alertes avant le curseur %s), "
                    "cycle suivant sans chevauchement",
                    len(alerts),
                    self._cursor,
                )
                return

            # Le lot etant trie en ordre croissant, son dernier document est
            # le point le plus avance reellement traite. Le curseur ne doit
            # jamais reculer : on part du plus tardif des deux.
            reference = self._cursor
            reference_moment = parse_timestamp(reference)
            for alert in alerts:
                moment = parse_timestamp(alert.timestamp)
                if moment is None:
                    continue
                if reference_moment is None or moment > reference_moment:
                    reference, reference_moment = alert.timestamp, moment

            if not reference:
                return

            newest_raw = nudge_timestamp(reference)
            if newest_raw == self._cursor:
                return

            logger.warning(
                "Curseur bloque sur %s (lot plein de %s alertes), avance a %s",
                self._cursor,
                len(alerts),
                newest_raw,
            )

        self._cursor = newest_raw
        try:
            await asyncio.to_thread(store.set_state, store.STATE_CURSOR, newest_raw)
        except Exception:  # noqa: BLE001 - une erreur d'ecriture ne casse pas le cycle
            logger.exception("Impossible de persister le curseur")

    # ---------------- Notifications ----------------

    async def _notify(self, alert: Alert) -> None:
        """Diffuse une nouvelle alerte. N'interrompt jamais la boucle."""
        # SSE : mise en file non bloquante vers les navigateurs connectes.
        # Le poller n'attend jamais le frontend, et une erreur de diffusion
        # ne doit jamais interrompre la surveillance.
        try:
            await stream.publish_alert(alert)
        except Exception:  # noqa: BLE001
            logger.exception("Echec de la diffusion SSE")

        # Notification des alertes importantes : le seuil est NOTIFY_LEVEL et
        # ne depend pas de l'agent IA, qui peut etre desactive ou en panne.
        # L'analyse IA enrichira ensuite la meme notification.
        await self._create_notification(alert)

        if not alert.is_critical(settings.critical_level):
            return

        # E-mail et Discord partent en tache detachee : un SMTP lent ou un
        # webhook injoignable ne doit pas retarder le cycle suivant.
        self._spawn(self._send_external(email, "email", alert), label="email")
        self._spawn(self._send_external(discord, "discord", alert), label="discord")

    async def _create_notification(self, alert: Alert) -> None:
        """Cree la notification liee a l'alerte, si son niveau l'exige.

        Ne leve jamais : un probleme de notification ne doit pas empecher la
        collecte des alertes suivantes.
        """
        try:
            notification, created = await ai_notifications.create_from_alert(alert)
        except Exception:  # noqa: BLE001
            logger.exception("Creation de notification impossible pour %s", alert.id)
            return

        if notification is not None and created:
            await ai_notifications.publish(notification)

    async def _send_external(self, channel_module, channel: str, alert: Alert) -> None:
        """Envoi sur un canal externe, trace dans notifications_sent."""
        if not channel_module.is_configured():
            return

        # Garde anti-doublon : une alerte n'est notifiee qu'une fois par canal.
        first_time = await asyncio.to_thread(
            store.mark_notification, alert.id, channel, "pending"
        )
        if not first_time:
            return

        try:
            await channel_module.send_alert(alert)
            await asyncio.to_thread(
                store.update_notification, alert.id, channel, "sent", None
            )
        except Exception as exc:  # noqa: BLE001 - jamais fatal pour la boucle
            logger.warning("Notification %s en echec: %s", channel, exc)
            await asyncio.to_thread(
                store.update_notification, alert.id, channel, "failed", str(exc)
            )

    def _spawn(self, coroutine, label: str = "tache") -> None:
        """Lance une coroutine en arriere-plan sans jamais l'attendre."""
        task = asyncio.create_task(coroutine, name=f"poller-{label}")
        self._background.add(task)
        task.add_done_callback(self._background.discard)
        task.add_done_callback(lambda t: self._log_background_error(t, label))

    @staticmethod
    def _log_background_error(task: asyncio.Task, label: str) -> None:
        if task.cancelled():
            return
        exception = task.exception()
        if exception is not None:
            logger.warning("Tache %s en echec: %s", label, exception)

    async def _publish_status(self, event: str) -> None:
        """Informe les clients SSE d'un changement d'etat."""
        try:
            await stream.publish(
                StreamEvent(
                    type="monitoring",
                    data={"event": event, **self.status().model_dump(mode="json")},
                )
            )
        except Exception:  # noqa: BLE001
            logger.exception("Echec de la diffusion du statut")


# --------------------------------------------------------------------------
# Instance partagee + API de module (utilisee par les routes)
# --------------------------------------------------------------------------

_controller: Optional[MonitoringController] = None


def get_controller() -> MonitoringController:
    """Controleur unique de l'application."""
    global _controller
    if _controller is None:
        _controller = MonitoringController()
    return _controller


async def start() -> MonitoringStatus:
    return await get_controller().start()


async def stop() -> MonitoringStatus:
    return await get_controller().stop()


def get_status() -> MonitoringStatus:
    return get_controller().status()


async def shutdown() -> None:
    await get_controller().shutdown()
