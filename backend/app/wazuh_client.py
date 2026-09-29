"""Client HTTP vers les APIs reseau de Wazuh (Manager API + Indexer).

Aucun conteneur Wazuh n'est modifie : uniquement des appels HTTP.
Les identifiants proviennent exclusivement de backend/.env via app.config
et ne sont jamais ecrits dans les logs.
"""

import asyncio
import base64
import binascii
import json
import logging
import time
from typing import Any, Optional

import httpx

from app.config import settings
from app.models import Agent, Alert

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# Exceptions
# --------------------------------------------------------------------------


class WazuhError(Exception):
    """Erreur generique lors d'un echange avec Wazuh."""

    status_code = 502

    def __init__(self, message: str, detail: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.detail = detail


class WazuhUnavailableError(WazuhError):
    """Wazuh est injoignable (connexion refusee, DNS, TLS)."""

    status_code = 503


class WazuhTimeoutError(WazuhUnavailableError):
    """Wazuh n'a pas repondu dans le delai imparti."""

    status_code = 504


class WazuhAuthError(WazuhError):
    """Identifiants refuses ou token invalide."""

    status_code = 502


class WazuhAPIError(WazuhError):
    """La Manager API a repondu par un code HTTP d'erreur."""

    status_code = 502


class IndexerError(WazuhError):
    """L'Indexer a repondu par une erreur ou un contenu inattendu."""

    status_code = 502


# --------------------------------------------------------------------------
# Utilitaires
# --------------------------------------------------------------------------


def _decode_jwt_expiration(token: str) -> Optional[float]:
    """Lit la claim `exp` d'un JWT sans verifier la signature.

    La signature est verifiee par Wazuh, pas par nous : on cherche seulement
    a savoir quand renouveler le token. Retourne None si illisible.
    """
    try:
        payload_segment = token.split(".")[1]
        padding = "=" * (-len(payload_segment) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_segment + padding))
        exp = payload.get("exp")
        return float(exp) if exp is not None else None
    except (IndexError, ValueError, binascii.Error, TypeError):
        logger.debug("Expiration du JWT illisible, TTL par defaut utilise")
        return None


class WazuhClient:
    """Client asynchrone vers la Manager API et l'Indexer.

    Le JWT est conserve en memoire et reutilise entre les requetes ; il est
    renouvele automatiquement peu avant son expiration. Utiliser
    `get_wazuh_client()` pour partager le cache de token dans l'application.
    """

    def __init__(self) -> None:
        self.base_url = settings.wazuh_api_url.rstrip("/")
        self.username = settings.wazuh_api_user
        self.password = settings.wazuh_api_password

        self.indexer_url = settings.indexer_url.rstrip("/")
        self.indexer_user = settings.indexer_user
        self.indexer_password = settings.indexer_password
        self.indexer_index = settings.indexer_index

        # Certificats auto-signes : verify_ssl=false est supporte.
        self.verify_ssl = settings.verify_ssl

        self._token: Optional[str] = None
        self._token_expires_at: float = 0.0
        self._auth_lock = asyncio.Lock()
        self._client: Optional[httpx.AsyncClient] = None

    # ---------------- Cycle de vie ----------------

    @property
    def timeout(self) -> httpx.Timeout:
        return httpx.Timeout(
            settings.request_timeout_seconds,
            connect=settings.connect_timeout_seconds,
        )

    def _http(self) -> httpx.AsyncClient:
        """Client HTTP partage (connexions reutilisees)."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(verify=self.verify_ssl, timeout=self.timeout)
        return self._client

    async def aclose(self) -> None:
        """Ferme le client HTTP sous-jacent."""
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
        self._client = None

    # ---------------- Authentification ----------------

    @property
    def token_is_valid(self) -> bool:
        """Vrai si un token utilisable est en cache (marge de securite incluse)."""
        return bool(self._token) and time.time() < self._token_expires_at

    def invalidate_token(self) -> None:
        """Force une re-authentification au prochain appel."""
        self._token = None
        self._token_expires_at = 0.0

    async def authenticate(self, force: bool = False) -> str:
        """Retourne un JWT valide, renouvele seulement si necessaire.

        POST /security/user/authenticate?raw=true
        """
        if not force and self.token_is_valid:
            return self._token  # type: ignore[return-value]

        async with self._auth_lock:
            # Un appel concurrent a pu renouveler le token entre-temps.
            if not force and self.token_is_valid:
                return self._token  # type: ignore[return-value]

            url = f"{self.base_url}/security/user/authenticate"
            logger.info("Authentification aupres de la Wazuh API (%s)", self.base_url)

            try:
                response = await self._http().post(
                    url,
                    params={"raw": "true"},
                    auth=(self.username, self.password),
                )
            except httpx.TimeoutException as exc:
                raise WazuhTimeoutError(
                    "Délai dépassé lors de l'authentification auprès de Wazuh",
                    detail=str(exc),
                ) from exc
            except httpx.RequestError as exc:
                raise WazuhUnavailableError(
                    "Wazuh Manager API injoignable",
                    detail=f"{type(exc).__name__}: {exc}",
                ) from exc

            if response.status_code in (401, 403):
                # Le mot de passe n'est jamais journalise.
                logger.warning(
                    "Authentification Wazuh refusee (HTTP %s) pour l'utilisateur %s",
                    response.status_code,
                    self.username,
                )
                raise WazuhAuthError(
                    "Identifiants Wazuh refusés",
                    detail=f"HTTP {response.status_code}",
                )

            if response.status_code >= 400:
                raise WazuhAPIError(
                    "Échec de l'authentification auprès de Wazuh",
                    detail=f"HTTP {response.status_code}",
                )

            token = response.text.strip()
            if not token:
                raise WazuhAuthError("Wazuh a renvoyé un token vide")

            expires_at = _decode_jwt_expiration(token)
            if expires_at is None:
                expires_at = time.time() + settings.token_default_ttl_seconds

            self._token = token
            # Renouvellement anticipe grace a la marge de securite.
            self._token_expires_at = expires_at - settings.token_leeway_seconds

            logger.info(
                "Token Wazuh obtenu, reutilisable pendant %ss",
                max(0, int(self._token_expires_at - time.time())),
            )
            return token

    # ---------------- Manager API ----------------

    async def _request_manager(
        self,
        method: str,
        path: str,
        params: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Appel authentifie a la Manager API, avec re-auth unique sur 401."""
        url = f"{self.base_url}{path}"

        for attempt in (1, 2):
            token = await self.authenticate(force=(attempt == 2))
            headers = {"Authorization": f"Bearer {token}"}

            try:
                response = await self._http().request(
                    method, url, params=params, headers=headers
                )
            except httpx.TimeoutException as exc:
                raise WazuhTimeoutError(
                    f"Délai dépassé sur {method} {path}", detail=str(exc)
                ) from exc
            except httpx.RequestError as exc:
                raise WazuhUnavailableError(
                    "Wazuh Manager API injoignable",
                    detail=f"{type(exc).__name__}: {exc}",
                ) from exc

            # Token expire ou revoque : un seul nouvel essai avec un token neuf.
            if response.status_code == 401 and attempt == 1:
                logger.info("Token Wazuh refuse (401), renouvellement puis nouvel essai")
                self.invalidate_token()
                continue

            if response.status_code in (401, 403):
                raise WazuhAuthError(
                    "Accès refusé par la Wazuh API",
                    detail=f"HTTP {response.status_code}",
                )

            if response.status_code >= 400:
                raise WazuhAPIError(
                    f"La Wazuh API a répondu HTTP {response.status_code}",
                    detail=response.text[:300],
                )

            try:
                return response.json()
            except ValueError as exc:
                raise WazuhAPIError(
                    "Réponse illisible de la Wazuh API", detail=str(exc)
                ) from exc

        raise WazuhAPIError("Échec de l'appel à la Wazuh API")

    async def get_agents(self, limit: Optional[int] = None) -> list[Agent]:
        """GET /agents -> liste d'agents normalisee."""
        payload = await self._request_manager(
            "GET",
            "/agents",
            params={"limit": limit or settings.agents_limit},
        )

        data = payload.get("data") or {}
        items = data.get("affected_items")
        if items is None:
            raise WazuhAPIError(
                "Réponse inattendue de GET /agents (data.affected_items absent)"
            )

        agents = [Agent.from_wazuh(item) for item in items if isinstance(item, dict)]
        logger.debug("%s agents recuperes", len(agents))
        return agents

    async def get_manager_info(self) -> dict[str, Any]:
        """GET / sur la Manager API : utile comme test de connexion."""
        payload = await self._request_manager("GET", "/")
        return payload.get("data") or {}

    # ---------------- Indexer ----------------

    def build_alerts_query(
        self,
        size: Optional[int] = None,
        min_level: int = 0,
        since: Optional[str] = None,
        order: str = "desc",
    ) -> dict[str, Any]:
        """Construit la requete _search.

        - `since` : ne remonte que les alertes dont `timestamp` est >= a cette
          valeur (curseur du poller).
        - `order` : "desc" pour l'affichage, "asc" pour le poller (le curseur
          avance alors regulierement, meme si la fenetre depasse `size`).
        """
        filters: list[dict[str, Any]] = []
        if min_level > 0:
            filters.append({"range": {"rule.level": {"gte": min_level}}})
        if since:
            filters.append({"range": {"timestamp": {"gte": since}}})

        if not filters:
            query: dict[str, Any] = {"match_all": {}}
        elif len(filters) == 1:
            query = filters[0]
        else:
            query = {"bool": {"filter": filters}}

        return {
            "size": size or settings.alert_fetch_size,
            "sort": [{"timestamp": {"order": order}}],
            "query": query,
        }

    async def get_alerts(
        self,
        size: Optional[int] = None,
        min_level: int = 0,
        since: Optional[str] = None,
        order: str = "desc",
    ) -> list[Alert]:
        """POST /<index>/_search -> liste d'alertes normalisee."""
        url = f"{self.indexer_url}/{self.indexer_index}/_search"
        body = self.build_alerts_query(
            size=size, min_level=min_level, since=since, order=order
        )

        try:
            response = await self._http().post(
                url,
                json=body,
                auth=(self.indexer_user, self.indexer_password),
            )
        except httpx.TimeoutException as exc:
            raise WazuhTimeoutError(
                "Délai dépassé lors de l'interrogation de l'Indexer", detail=str(exc)
            ) from exc
        except httpx.RequestError as exc:
            raise WazuhUnavailableError(
                "Wazuh Indexer injoignable",
                detail=f"{type(exc).__name__}: {exc}",
            ) from exc

        if response.status_code in (401, 403):
            logger.warning(
                "Acces a l'Indexer refuse (HTTP %s) pour l'utilisateur %s",
                response.status_code,
                self.indexer_user,
            )
            raise WazuhAuthError(
                "Identifiants Indexer refusés", detail=f"HTTP {response.status_code}"
            )

        if response.status_code == 404:
            raise IndexerError(
                f"Index introuvable : {self.indexer_index}", detail="HTTP 404"
            )

        if response.status_code >= 400:
            raise IndexerError(
                f"L'Indexer a répondu HTTP {response.status_code}",
                detail=response.text[:300],
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise IndexerError("Réponse illisible de l'Indexer", detail=str(exc)) from exc

        return self.extract_alerts(payload)

    async def get_alert_by_id(self, alert_id: str) -> Optional[Alert]:
        """Retrouve une alerte precise dans l'Indexer, par son `_id`.

        Utile quand une alerte visible a l'ecran n'a pas encore ete
        persistee par le poller : l'analyse reste possible, quel que soit
        l'agent qui l'a produite.
        """
        if not alert_id:
            return None

        url = f"{self.indexer_url}/{self.indexer_index}/_search"
        body = {"size": 1, "query": {"ids": {"values": [alert_id]}}}

        try:
            response = await self._http().post(
                url,
                json=body,
                auth=(self.indexer_user, self.indexer_password),
            )
        except httpx.TimeoutException as exc:
            raise WazuhTimeoutError(
                "Délai dépassé lors de l'interrogation de l'Indexer", detail=str(exc)
            ) from exc
        except httpx.RequestError as exc:
            raise WazuhUnavailableError(
                "Wazuh Indexer injoignable",
                detail=f"{type(exc).__name__}: {exc}",
            ) from exc

        if response.status_code >= 400:
            raise IndexerError(
                f"L'Indexer a répondu HTTP {response.status_code}",
                detail=response.text[:300],
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise IndexerError("Réponse illisible de l'Indexer", detail=str(exc)) from exc

        alerts = self.extract_alerts(payload)
        return alerts[0] if alerts else None

    @staticmethod
    def extract_alerts(payload: Any) -> list[Alert]:
        """Extrait proprement les documents d'une reponse _search."""
        if not isinstance(payload, dict):
            raise IndexerError("Réponse inattendue de l'Indexer")

        hits = payload.get("hits")
        if not isinstance(hits, dict):
            raise IndexerError("Réponse inattendue de l'Indexer (champ 'hits' absent)")

        documents = hits.get("hits")
        if documents is None:
            raise IndexerError(
                "Réponse inattendue de l'Indexer (champ 'hits.hits' absent)"
            )

        return [Alert.from_hit(hit) for hit in documents if isinstance(hit, dict)]


# --------------------------------------------------------------------------
# Instance partagee (indispensable pour reutiliser le token entre requetes)
# --------------------------------------------------------------------------

_shared_client: Optional[WazuhClient] = None


def get_wazuh_client() -> WazuhClient:
    """Retourne le client partage par l'application (cache de token commun)."""
    global _shared_client
    if _shared_client is None:
        _shared_client = WazuhClient()
    return _shared_client


async def close_wazuh_client() -> None:
    """Ferme le client partage (appele a l'arret de FastAPI)."""
    global _shared_client
    if _shared_client is not None:
        await _shared_client.aclose()
        _shared_client = None
