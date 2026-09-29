"""Interface d'enrichissement IA d'un finding. **Inactive en phase 1.**

Le pipeline s'arrete a la detection deterministe tant que
`CODE_AI_ENRICHMENT_ENABLED` est faux : `enrichment_enabled()` renvoie
alors False et `scanner.py` n'appelle jamais `enrich_finding()`.

Ce module ne contient donc aucune logique d'appel HTTP propre : il
delegue a `app.ai.analyzer.run_model()`, qui detient la validation
Pydantic et la traduction des erreurs, exactement comme pour les alertes
Wazuh.
"""

import logging
from typing import Optional

from app.ai.analyzer import run_model
from app.ai.openai_client import AIDisabledError, OpenAIClient, get_openai_client
from app.ai.sanitizer import redact_secrets, truncate
from app.code import prompts
from app.code.schemas import CodeModelFinding, RuleHit
from app.config import settings

logger = logging.getLogger(__name__)

# Nombre de lignes de contexte transmises autour de la ligne signalee.
CONTEXT_LINES = 8


def enrichment_enabled() -> bool:
    """L'enrichissement IA est-il reellement disponible ?

    Deux conditions, toutes deux necessaires : une cle API configuree
    (`settings.ai_enabled`) et l'activation explicite de l'enrichissement
    du code. En phase 1, la seconde est fausse par defaut.
    """
    return settings.ai_enabled and settings.code_ai_enrichment_enabled


def build_excerpt(content: str, line: int, context: int = CONTEXT_LINES) -> str:
    """Extrait autour de la ligne signalee, expurge de tout secret.

    Seul cet extrait quitterait le backend, jamais le fichier entier.
    `redact_secrets` est celui du projet : la meme protection que pour les
    journaux Wazuh.
    """
    lines = content.splitlines()
    start = max(0, line - 1 - context)
    end = min(len(lines), line + context)

    numbered = [
        f"{number:>5} | {text}"
        for number, text in enumerate(lines[start:end], start=start + 1)
    ]
    return truncate(redact_secrets("\n".join(numbered))) or ""


async def enrich_finding(
    hit: RuleHit,
    content: str,
    file_path: str,
    language: str,
    client: Optional[OpenAIClient] = None,
) -> CodeModelFinding:
    """Fait qualifier un signalement par le modele.

    **Non appelee en phase 1.** Leve `AIDisabledError` si l'enrichissement
    n'est pas active, plutot que de laisser croire a une analyse.

    Leve une sous-classe d'`AIError` en cas de panne ou de reponse
    invalide : l'appelant marque alors le scan `failed` et n'invente
    aucun resultat.
    """
    if not enrichment_enabled():
        raise AIDisabledError(
            "Enrichissement IA du code désactivé : activez "
            "CODE_AI_ENRICHMENT_ENABLED et renseignez OPENAI_API_KEY"
        )

    excerpt = build_excerpt(content, hit.location.line_start)

    return await run_model(
        client or get_openai_client(),
        prompts.SYSTEM_PROMPT,
        prompts.build_user_prompt(
            rule_id=hit.rule_id,
            category=hit.category,
            file_path=file_path,
            language=language,
            line=hit.location.line_start,
            excerpt=excerpt,
        ),
        CodeModelFinding,
        subject=f"{file_path}:{hit.location.line_start} ({hit.rule_id})",
    )
