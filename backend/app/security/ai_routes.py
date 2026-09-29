"""Routes de l'assistant IA de securite (phase 6).

    GET  /api/security/ai/health                          etat de l'assistant
    POST /api/project/{uid}/findings/{id}/ai-analysis      expliquer un finding
    POST /api/project/{uid}/ai/summary                     resumer plusieurs findings
    POST /api/project/{uid}/ai/chat                        poser une question
    POST /api/project/{uid}/findings/{id}/ai-fix           proposer un correctif (phase 7)

Routeur separe de `app.security.routes`, qui porte la detection. Le
decoupage n'est pas cosmetique : ces routes sont les seules du paquet a
pouvoir sortir sur le reseau vers un fournisseur d'IA, et les seules a
pouvoir repondre 503 « indisponible » alors que tout le reste fonctionne.
Les melanger aurait rendu cette difference invisible a la lecture.

Ce que ces routes ne font jamais
--------------------------------

- **creer, supprimer ou requalifier un finding.** Aucune ecriture dans
  `security_findings` n'existe dans ce module ni dans
  `app.ai.security_assistant` ; un test le verifie sur le code source, un
  autre compare la ligne du finding avant et apres une analyse ;
- **changer une gravite.** La gravite renvoyee est recopiee du finding ;
- **appeler Wazuh.** Comme le reste de la securite projet, ces routes
  repondent a l'identique avec le Manager et l'Indexer arretes ;
- **lire un fichier du poste.** Elles ne connaissent que ce qui est deja
  en base, et une preuve en base est expurgee.

Le 503 est une reponse normale
------------------------------

Sans cle API, ou l'assistant desactive, ces routes repondent 503 avec une
raison redigee. Ce n'est pas une panne : le reste de l'extension continue
de detecter, d'afficher et de trier des findings. Un 200 accompagne d'un
texte vide aurait ete la pire des reponses possibles — il se serait lu
« rien a signaler ».
"""

import logging

from fastapi import APIRouter, HTTPException

from app.ai import security_assistant as assistant
from app.ai import security_fix
from app.ai.openai_client import AIError
from app.ai.security_fix_schemas import SecurityFixProposal, SecurityFixRequest
from app.ai.security_schemas import (
    SecurityAiHealth,
    SecurityAiSummaryRequest,
    SecurityChatRequest,
    SecurityChatResponse,
    SecurityFindingAiAnalysis,
    SecurityFindingsAiSummary,
)
from app.auth import AGENT_AUTH
from app.project import context as project_context

logger = logging.getLogger(__name__)

router = APIRouter(tags=["security-ai"], dependencies=[AGENT_AUTH])


def _ai_http_error(exc: AIError) -> HTTPException:
    """Traduit une erreur du fournisseur en reponse HTTP.

    Le code vient de l'exception elle-meme (503 indisponible, 504 delai,
    429 quota, 502 reponse inexploitable) : l'extension peut donc
    distinguer « pas configure » de « en panne » de « a repondu n'importe
    quoi », et afficher trois messages differents.
    """
    logger.warning("Assistant IA de securite : %s (%s)", exc.message, exc.detail)
    return HTTPException(
        status_code=exc.status_code,
        detail={"error": exc.message, "detail": exc.detail},
    )


async def _project_or_404(project_uid: str) -> None:
    if not await project_context.exists(project_uid):
        raise HTTPException(
            status_code=404,
            detail={
                "error": "Projet inconnu",
                "detail": (
                    "Enregistrez le projet avec POST /api/project/discover "
                    "avant de demander une analyse IA."
                ),
            },
        )


# --------------------------------------------------------------------------
# Etat
# --------------------------------------------------------------------------


@router.get("/api/security/ai/health", response_model=SecurityAiHealth)
async def security_ai_health():
    """Ce que l'assistant sait faire, ici et maintenant.

    Consultee par l'extension avant d'afficher le moindre bouton IA :
    proposer « Analyser avec l'IA » pour se faire repondre 503 coute plus
    cher que de ne rien proposer. Protegee comme les autres routes de
    securite — elle decrit la configuration du backend.
    """
    return assistant.health()


# --------------------------------------------------------------------------
# Explication d'un finding
# --------------------------------------------------------------------------


@router.post(
    "/api/project/{project_uid}/findings/{finding_id}/ai-analysis",
    response_model=SecurityFindingAiAnalysis,
)
async def analyze_finding_with_ai(
    project_uid: str, finding_id: str, force: bool = False
):
    """Fait expliquer un finding **existant** par l'IA.

    Le finding doit exister et appartenir a ce projet : le chemin porte les
    deux identifiants, et la lecture verifie les deux. Sans cette
    verification, connaitre l'identifiant d'un finding suffirait a en
    obtenir l'explication depuis un autre projet.

    `force=true` refait l'analyse en ignorant le cache. Le defaut est
    `false` : une explication deja payee est resservie.

    La reponse porte `ai_generated: true` et une mise en garde. La gravite
    qu'elle affiche est celle du moteur, recopiee : cette route ne modifie
    aucun finding.
    """
    await _project_or_404(project_uid)

    finding = await assistant.load_finding(project_uid, finding_id)
    if finding is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "Signalement inconnu",
                "detail": (
                    "Aucun signalement de securite ne porte cet identifiant "
                    "dans ce projet. Relancez un balayage, ou verifiez le "
                    "projet."
                ),
            },
        )

    try:
        return await assistant.explain_finding(project_uid, finding, force=force)
    except AIError as exc:
        raise _ai_http_error(exc) from exc


# --------------------------------------------------------------------------
# Resume de plusieurs findings
# --------------------------------------------------------------------------


@router.post(
    "/api/project/{project_uid}/ai/summary",
    response_model=SecurityFindingsAiSummary,
)
async def summarize_findings_with_ai(
    project_uid: str, request: SecurityAiSummaryRequest
):
    """Resume les findings d'un projet et en donne les relations.

    La reponse annonce toujours sa couverture : `findings_considered`,
    `findings_available` et `truncated`. Un resume portant sur vingt-cinq
    findings d'un projet qui en compte trois cents doit se lire comme tel,
    sinon il se lit comme un bilan.
    """
    await _project_or_404(project_uid)

    try:
        return await assistant.summarize_findings(
            project_uid, finding_ids=request.finding_ids or None
        )
    except AIError as exc:
        raise _ai_http_error(exc) from exc


# --------------------------------------------------------------------------
# Chat de securite
# --------------------------------------------------------------------------


@router.post(
    "/api/project/{project_uid}/ai/chat",
    response_model=SecurityChatResponse,
)
async def security_chat(project_uid: str, request: SecurityChatRequest):
    """Repond a une question sur la securite du projet ouvert.

    Le contexte est celui de **ce** projet : ses findings, ses metadonnees.
    La question et l'historique sont expurges avant de sortir du backend,
    et la question renvoyee est la version expurgee — l'utilisateur voit
    ainsi qu'un secret colle par megarde a ete masque.
    """
    await _project_or_404(project_uid)

    try:
        return await assistant.answer_question(project_uid, request)
    except AIError as exc:
        raise _ai_http_error(exc) from exc


# --------------------------------------------------------------------------
# Remediation assistee (phase 7)
# --------------------------------------------------------------------------


@router.post(
    "/api/project/{project_uid}/findings/{finding_id}/ai-fix",
    response_model=SecurityFixProposal,
)
async def propose_fix_with_ai(
    project_uid: str, finding_id: str, request: SecurityFixRequest
):
    """Propose un correctif borne pour un finding **existant**.

    La route **n'ecrit rien** : ni le fichier — le backend n'y a pas acces
    —, ni le finding. Elle renvoie une description de modification, que
    l'extension montre, fait confirmer, applique, puis verifie en relancant
    les moteurs deterministes.

    Trois issues :

    - 200 `available: true` : une modification bornee, validee ;
    - 200 `available: false` : pas de correctif automatique sur (fichier
      protege, verrou, finding referme, ligne incoherente, ou le modele
      l'a dit) — `refusal` explique, `manual_steps` guide ;
    - 502 : la reponse du modele est illisible, dangereuse ou ambigue.
      Rien n'est propose.
    """
    await _project_or_404(project_uid)

    target = await security_fix.load_target(project_uid, finding_id)
    if target is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "Signalement inconnu",
                "detail": (
                    "Aucun signalement ne porte cet identifiant dans ce projet."
                ),
            },
        )

    try:
        return await security_fix.propose_fix(project_uid, target, request)
    except AIError as exc:
        raise _ai_http_error(exc) from exc
