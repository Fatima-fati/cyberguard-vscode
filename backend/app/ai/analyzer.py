"""Analyse d'une alerte Wazuh par le modele.

Responsabilite unique : contexte nettoye -> appel du modele -> reponse
validee par Pydantic. Le calcul du risque est fait ailleurs
(`app.ai.risk_assessment`).
"""

import logging
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from app.ai import prompts
from app.ai.openai_client import AIResponseError, OpenAIClient
from app.ai.schemas import AIModelAnalysis, AlertContext

logger = logging.getLogger(__name__)

# Type de sortie attendu : n'importe quel modele Pydantic.
ModelT = TypeVar("ModelT", bound=BaseModel)


async def run_model(
    client: OpenAIClient,
    system_prompt: str,
    user_prompt: str,
    model_cls: type[ModelT],
    subject: str = "",
) -> ModelT:
    """Interroge le modele et valide sa reponse avec `model_cls`.

    Seul endroit du projet ou une reponse de modele devient un objet
    Python : la validation Pydantic y est obligatoire, et une reponse
    incomplete est une erreur, jamais un resultat partiel silencieux.

    Utilise par l'analyse d'alertes Wazuh et, en phase 3, par l'analyse
    d'extraits de code.
    """
    raw = await client.complete_json(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
    )

    try:
        return model_cls.model_validate(raw)
    except ValidationError as exc:
        # Champs manquants ou types inattendus : la reponse est inutilisable.
        logger.warning(
            "Reponse du modele invalide pour %s : %s",
            subject or model_cls.__name__,
            exc.errors()[:2],
        )
        raise AIResponseError(
            "Le modèle a renvoyé une analyse incomplète",
            detail=str(exc.errors()[:2]),
        ) from exc


async def analyze_context(
    client: OpenAIClient,
    context: AlertContext,
) -> AIModelAnalysis:
    """Fait analyser une alerte deja nettoyee.

    Leve une sous-classe d'AIError : soit une panne du service, soit une
    reponse que Pydantic refuse. Aucune exception inattendue ne sort d'ici.
    """
    analysis = await run_model(
        client,
        prompts.SYSTEM_PROMPT,
        prompts.build_user_prompt(context),
        AIModelAnalysis,
        subject=f"l'alerte {context.alert_id}",
    )

    logger.debug(
        "Alerte %s classee %s (severite %s, score modele %s)",
        context.alert_id,
        analysis.classification,
        analysis.severity,
        analysis.risk_score,
    )
    return analysis
