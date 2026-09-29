"""Diffusion temps reel vers les navigateurs via Server-Sent Events (SSE).

Abstraction centrale : `AlertBroker`.

    poller  ->  broker.publish_alert(alert)   (non bloquant, ne leve jamais)
    routes  ->  broker.subscribe(...)         (un generateur par navigateur)

Points cles :
- plusieurs navigateurs peuvent etre connectes en meme temps ;
- le poller n'attend jamais le frontend : chaque client a sa propre file
  bornee et un client lent perd ses evenements les plus anciens plutot que
  de ralentir la surveillance ;
- battement de coeur periodique pour garder la connexion ouverte ;
- `id:` + `retry:` permettent au navigateur de se reconnecter tout seul et
  de rattraper les alertes manquees (`Last-Event-ID`) ;
- desabonnement systematique dans un `finally` : aucune file ne fuit.

Cloisonnement par projet (phase 0)
----------------------------------

Un evenement `code_finding` porte un extrait du code analyse. Diffuse a
tous les abonnes, il livrerait le code d'un projet aux fenetres ouvertes
sur un autre. La regle est donc :

    publish(event)                     -> tous les abonnes
                                          (alertes Wazuh : portee globale)

    publish(event, project_uid="abc")  -> uniquement les abonnes
                                          inscrits sur « abc »

Un abonne sans portee ne recoit **pas** les evenements adresses a un
projet. C'est volontairement dissymetrique : c'est ce qui garantit qu'un
abonne ne peut pas capter les findings d'un projet en omettant de se
declarer. L'extension se defend deja cote client (`upsertIfTracked`), mais
une defense cote client protege le client, pas les autres.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Optional

from app import i18n
from app.config import settings
from app.models import Alert, StreamEvent

logger = logging.getLogger(__name__)

# Sentinelle interne : demande a un generateur de se terminer proprement.
_CLOSE = object()


# --------------------------------------------------------------------------
# Formatage du protocole SSE
# --------------------------------------------------------------------------


def format_sse(
    event: str,
    data: Any,
    event_id: Optional[str] = None,
    retry_ms: Optional[int] = None,
) -> str:
    """Serialise un evenement au format texte SSE."""
    lines: list[str] = []
    if event_id:
        lines.append(f"id: {event_id}")
    if retry_ms:
        lines.append(f"retry: {retry_ms}")
    lines.append(f"event: {event}")

    payload = json.dumps(data, default=str, ensure_ascii=False)
    # Une charge utile multiligne doit etre prefixee ligne par ligne.
    for line in payload.splitlines() or [""]:
        lines.append(f"data: {line}")

    return "\n".join(lines) + "\n\n"


def comment(text: str) -> str:
    """Commentaire SSE : ignore par EventSource, garde la connexion en vie."""
    return f": {text}\n\n"


def alert_payload(alert: Alert) -> dict[str, Any]:
    """Charge utile a plat d'une alerte, prete a consommer par le frontend."""
    return {
        "id": alert.id,
        "timestamp": alert.timestamp,
        "agent_id": alert.agent.id,
        "agent_name": alert.agent.name,
        "rule_id": alert.rule.id,
        "rule_level": alert.rule.level,
        # Description Wazuh originale (diagnostic) + version francaise
        # affichee par l'interface : les deux voyagent ensemble.
        "rule_description": alert.rule.description,
        "rule_description_fr": alert.rule.description_fr,
        "rule_groups_label": i18n.rule_groups_label(alert.rule.groups),
        "location": alert.location,
        "full_log": alert.full_log,
    }


# --------------------------------------------------------------------------
# Broker
# --------------------------------------------------------------------------


@dataclass
class Subscriber:
    """Un client connecte : navigateur de supervision, ou extension.

    `project_uid` est la portee de l'abonnement. `None` signifie « portee
    globale » : le client recoit les evenements sans destinataire (les
    alertes Wazuh), mais aucun evenement adresse a un projet.
    """

    id: int
    queue: asyncio.Queue = field(repr=False)
    project_uid: Optional[str] = None
    dropped: int = 0

    def put(self, message: Any) -> None:
        """Depose un message sans jamais bloquer l'appelant.

        File pleine (client lent ou fige) : on abandonne le message le plus
        ancien pour garder les alertes les plus recentes.
        """
        try:
            self.queue.put_nowait(message)
            return
        except asyncio.QueueFull:
            pass

        try:
            self.queue.get_nowait()
            self.dropped += 1
        except asyncio.QueueEmpty:  # pragma: no cover - course tres improbable
            pass

        try:
            self.queue.put_nowait(message)
        except asyncio.QueueFull:  # pragma: no cover
            self.dropped += 1


class AlertBroker:
    """Distribue les evenements a tous les navigateurs connectes."""

    def __init__(self) -> None:
        self._subscribers: dict[int, Subscriber] = {}
        self._next_id = 0
        self._published = 0
        self._closing = False

    # ---------------- Etat ----------------

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    @property
    def is_full(self) -> bool:
        return len(self._subscribers) >= settings.sse_max_clients

    def stats(self) -> dict[str, int]:
        return {
            "clients": len(self._subscribers),
            "published": self._published,
            "dropped": sum(sub.dropped for sub in self._subscribers.values()),
        }

    # ---------------- Publication ----------------

    def publish_nowait(
        self,
        event: StreamEvent,
        event_id: Optional[str] = None,
        project_uid: Optional[str] = None,
    ) -> int:
        """Diffuse un evenement immediatement, sans attendre personne.

        `project_uid` restreint la diffusion aux abonnes de ce projet.
        Sans lui, l'evenement part a tous — le cas des alertes Wazuh, qui
        n'appartiennent a aucun projet.

        Retourne le nombre de clients servis. Ne leve jamais : une erreur de
        diffusion ne doit pas remonter jusqu'au poller.
        """
        try:
            message = format_sse(
                event.type,
                event.data,
                event_id=event_id,
                retry_ms=settings.sse_retry_ms,
            )
        except Exception:  # noqa: BLE001 - charge utile non serialisable
            logger.exception("Evenement SSE non serialisable, abandonne")
            return 0

        targets = [
            subscriber
            for subscriber in self._subscribers.values()
            # Egalite stricte, pas « None accepte tout » : un abonne qui ne
            # declare pas de projet ne doit pas capter ceux des autres.
            if project_uid is None or subscriber.project_uid == project_uid
        ]

        for subscriber in targets:
            subscriber.put(message)

        self._published += 1
        return len(targets)

    async def publish(
        self,
        event: StreamEvent,
        event_id: Optional[str] = None,
        project_uid: Optional[str] = None,
    ) -> int:
        """Version awaitable de `publish_nowait` (aucune attente reelle)."""
        return self.publish_nowait(
            event, event_id=event_id, project_uid=project_uid
        )

    async def publish_alert(self, alert: Alert) -> int:
        """Diffuse une nouvelle alerte. L'`id` SSE est l'identifiant Wazuh."""
        return self.publish_nowait(
            StreamEvent(type="alert", data=alert_payload(alert)),
            event_id=alert.id or None,
        )

    # ---------------- Abonnement ----------------

    def _register(self, project_uid: Optional[str] = None) -> Subscriber:
        self._next_id += 1
        subscriber = Subscriber(
            id=self._next_id,
            queue=asyncio.Queue(maxsize=settings.sse_queue_size),
            project_uid=project_uid,
        )
        self._subscribers[subscriber.id] = subscriber
        logger.info(
            "Client SSE #%s connecte (projet %s, %s au total)",
            subscriber.id,
            project_uid or "aucun",
            len(self._subscribers),
        )
        return subscriber

    def _unregister(self, subscriber: Subscriber) -> None:
        self._subscribers.pop(subscriber.id, None)
        logger.info(
            "Client SSE #%s deconnecte (%s restant(s), %s evenement(s) perdu(s))",
            subscriber.id,
            len(self._subscribers),
            subscriber.dropped,
        )

    async def subscribe(
        self,
        last_event_id: Optional[str] = None,
        is_disconnected=None,
        project_uid: Optional[str] = None,
    ) -> AsyncIterator[str]:
        """Generateur consomme par la StreamingResponse d'une route SSE.

        - `last_event_id` : identifiant de la derniere alerte recue par le
          navigateur ; les alertes plus recentes sont rejouees depuis SQLite.
        - `is_disconnected` : coroutine optionnelle (`request.is_disconnected`)
          consultee a chaque battement pour liberer les clients partis.
        - `project_uid` : portee de l'abonnement. L'extension transmet le
          projet ouvert et ne recoit alors que ses propres findings.
        """
        subscriber = self._register(project_uid=project_uid)
        try:
            yield format_sse(
                "connected",
                {
                    "client_id": subscriber.id,
                    "clients": len(self._subscribers),
                    # L'abonne voit la portee que le serveur lui a
                    # reellement attribuee : un `project_uid` mal transmis
                    # se diagnostique ici, pas par l'absence d'evenements.
                    "project_uid": subscriber.project_uid,
                },
                retry_ms=settings.sse_retry_ms,
            )

            for message in self._replay(last_event_id):
                yield message

            while True:
                try:
                    message = await asyncio.wait_for(
                        subscriber.queue.get(),
                        timeout=settings.sse_heartbeat_seconds,
                    )
                except asyncio.TimeoutError:
                    # Rien a envoyer : battement de coeur (commentaire SSE).
                    if is_disconnected is not None and await is_disconnected():
                        logger.debug("Client SSE #%s parti", subscriber.id)
                        break
                    yield comment("heartbeat")
                    continue

                if message is _CLOSE:
                    yield format_sse("closing", {"reason": "arret du serveur"})
                    break

                yield message
        except asyncio.CancelledError:
            # Le navigateur a ferme l'onglet : sortie silencieuse.
            raise
        finally:
            # Toujours execute : aucune file ne reste derriere.
            self._unregister(subscriber)

    def _replay(self, last_event_id: Optional[str]) -> list[str]:
        """Rejoue les alertes arrivees pendant une coupure de connexion."""
        if not last_event_id:
            return []

        # Import tardif : evite une dependance circulaire store <-> notifier.
        from app import store

        try:
            missed = store.alerts_after(last_event_id, limit=settings.sse_replay_limit)
        except Exception:  # noqa: BLE001 - une reconnexion ne doit jamais echouer
            logger.exception("Rejeu impossible apres reconnexion")
            return []

        if not missed:
            return []

        logger.info(
            "Reconnexion apres %s : %s alerte(s) rejouee(s)", last_event_id, len(missed)
        )
        return [
            format_sse("alert", alert_payload(alert), event_id=alert.id)
            for alert in missed
        ]

    # ---------------- Arret ----------------

    async def close_all(self) -> None:
        """Termine proprement tous les flux (extinction de l'application)."""
        self._closing = True
        for subscriber in list(self._subscribers.values()):
            subscriber.put(_CLOSE)

        # Laisse aux generateurs le temps de rendre la main.
        for _ in range(10):
            if not self._subscribers:
                break
            await asyncio.sleep(0.01)

        self._subscribers.clear()
        self._closing = False


# --------------------------------------------------------------------------
# Instance partagee + API de module
# --------------------------------------------------------------------------

broker = AlertBroker()


async def publish(
    event: StreamEvent,
    event_id: Optional[str] = None,
    project_uid: Optional[str] = None,
) -> int:
    return await broker.publish(event, event_id=event_id, project_uid=project_uid)


async def publish_alert(alert: Alert) -> int:
    return await broker.publish_alert(alert)


def subscribe(
    last_event_id: Optional[str] = None,
    is_disconnected=None,
    project_uid: Optional[str] = None,
) -> AsyncIterator[str]:
    return broker.subscribe(
        last_event_id=last_event_id,
        is_disconnected=is_disconnected,
        project_uid=project_uid,
    )


def subscriber_count() -> int:
    return broker.subscriber_count


def stats() -> dict[str, int]:
    return broker.stats()


async def close_all() -> None:
    await broker.close_all()
