"""Client HTTP vers l'API OpenAI.

Meme convention que `app.wazuh_client` : httpx, hierarchie d'exceptions
portant leur code HTTP, aucun secret journalise. La cle API ne quitte
jamais le backend.
"""

import json
import logging
from typing import Any, Optional

import httpx

from app.config import settings

logger = logging.getLogger(__name__)


class AIError(Exception):
    """Erreur generique lors d'un echange avec le modele."""

    status_code = 502

    def __init__(self, message: str, detail: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.detail = detail


class AIDisabledError(AIError):
    """Aucune cle API configuree : l'agent IA est inactif."""

    status_code = 503


class AIUnavailableError(AIError):
    """L'API OpenAI est injoignable."""

    status_code = 503


class AITimeoutError(AIUnavailableError):
    """L'API OpenAI n'a pas repondu dans le delai imparti."""

    status_code = 504


class AIQuotaError(AIError):
    """Quota depasse ou trop de requetes."""

    status_code = 429


class AIAuthError(AIError):
    """Cle API refusee."""

    status_code = 502


class AIResponseError(AIError):
    """Reponse inexploitable (JSON invalide, structure inattendue)."""

    status_code = 502


class OpenAIClient:
    """Appel unique : une conversation, une reponse JSON."""

    def __init__(self) -> None:
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def enabled(self) -> bool:
        return settings.ai_enabled

    def _http(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(settings.openai_timeout_seconds, connect=10.0)
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
        self._client = None

    async def complete_json(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> dict[str, Any]:
        """Envoie la conversation et retourne l'objet JSON produit.

        Leve une sous-classe d'AIError en cas de probleme : aucune exception
        httpx ne remonte telle quelle.
        """
        if not self.enabled:
            raise AIDisabledError(
                "Agent IA désactivé : renseignez OPENAI_API_KEY dans backend/.env"
            )

        url = f"{settings.openai_base_url.rstrip('/')}/chat/completions"
        payload = {
            "model": settings.openai_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            # Force une reponse JSON exploitable par Pydantic.
            "response_format": {"type": "json_object"},
            "temperature": 0.2,
            "max_tokens": settings.openai_max_output_tokens,
        }

        try:
            response = await self._http().post(
                url,
                json=payload,
                headers={
                    # La cle ne figure ni dans les logs ni dans les erreurs.
                    "Authorization": f"Bearer {settings.openai_api_key}",
                    "Content-Type": "application/json",
                },
            )
        except httpx.TimeoutException as exc:
            raise AITimeoutError(
                "Le modèle n'a pas répondu dans le délai imparti", detail=str(exc)
            ) from exc
        except httpx.RequestError as exc:
            raise AIUnavailableError(
                "Service d'analyse IA injoignable",
                detail=f"{type(exc).__name__}: {exc}",
            ) from exc

        if response.status_code in (401, 403):
            logger.warning("Cle OpenAI refusee (HTTP %s)", response.status_code)
            raise AIAuthError(
                "Clé OpenAI refusée", detail=f"HTTP {response.status_code}"
            )

        if response.status_code == 429:
            raise AIQuotaError(
                "Quota OpenAI dépassé ou trop de requêtes", detail="HTTP 429"
            )

        if response.status_code >= 400:
            raise AIError(
                f"Le service d'analyse a répondu HTTP {response.status_code}",
                detail=_safe_detail(response),
            )

        try:
            body = response.json()
            content = body["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise AIResponseError(
                "Réponse du modèle inexploitable", detail=str(exc)
            ) from exc

        try:
            parsed = json.loads(content)
        except (ValueError, TypeError) as exc:
            raise AIResponseError(
                "Le modèle n'a pas renvoyé de JSON valide", detail=str(exc)
            ) from exc

        if not isinstance(parsed, dict):
            raise AIResponseError("Le modèle n'a pas renvoyé un objet JSON")

        usage = body.get("usage") or {}
        logger.info(
            "Analyse IA effectuee (modele %s, %s tokens)",
            body.get("model", settings.openai_model),
            usage.get("total_tokens", "?"),
        )
        return parsed


def _safe_detail(response: httpx.Response) -> str:
    """Message d'erreur de l'API, sans en-tetes ni secret."""
    try:
        error = response.json().get("error") or {}
        message = error.get("message")
        if message:
            return str(message)[:300]
    except ValueError:
        pass
    return response.text[:200]


# --------------------------------------------------------------------------
# Instance partagee
# --------------------------------------------------------------------------

_client: Optional[OpenAIClient] = None


def get_openai_client() -> OpenAIClient:
    global _client
    if _client is None:
        _client = OpenAIClient()
    return _client


async def close_openai_client() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None
