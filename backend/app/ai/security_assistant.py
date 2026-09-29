"""Assistant IA de securite : orchestration (phase 6).

    finding persiste -> contexte expurge -> modele -> reponse validee
                     -> cache SQLite (table separee) -> extension

Trois affirmations que ce module tient, et ou il les tient
---------------------------------------------------------

**Le moteur deterministe reste la source de verite.** Ce module *lit* la
table `security_findings` et n'y ecrit jamais. Il n'existe ici aucun appel
a `store.sync_security_findings`, `store.delete_security_findings` ni a
quoi que ce soit qui ecrive un finding. Un test le verifie sur le code
source, et un autre compare la ligne du finding avant et apres une analyse.

**L'IA ne modifie pas la gravite.** La reponse renvoyee recopie
`finding.severity` dans `deterministic_severity`. La sortie du modele
(`AiFindingExplanation`) ne porte aucun champ de gravite : il n'y a pas de
valeur a recopier, donc pas de chemin pour la recopier.

**L'indisponibilite de l'IA n'empeche rien.** Aucune fonction de ce module
n'est appelee par un chemin de detection. Les balayages de secrets, les
inventaires de dependances, l'analyse d'API et la lecture des findings
fonctionnent a l'identique avec `OPENAI_API_KEY` vide — les routes de cette
phase repondent alors 503 avec une raison, et rien d'autre ne change.

Cloisonnement
-------------

Chaque fonction publique recoit un `project_uid` et ne lit que par lui :
`store.list_security_findings(project_uid, ...)` et
`store.get_security_ai_analysis(project_uid, finding_id)`. Un finding d'un
autre projet est introuvable, y compris en connaissant son identifiant.
"""

import asyncio
import hashlib
import logging
from typing import Optional

from app import store
from app.ai import agent as ai_agent
from app.ai import security_context, security_prompts
from app.ai.analyzer import run_model
from app.ai.openai_client import AIDisabledError, OpenAIClient, get_openai_client
from app.ai.security_schemas import (
    AI_DISCLAIMER,
    AiChatAnswer,
    AiFindingExplanation,
    AiFindingsSummary,
    SecurityAiHealth,
    SecurityChatRequest,
    SecurityChatResponse,
    SecurityFindingAiAnalysis,
    SecurityFindingsAiSummary,
)
from app.config import settings
from app.project import context as project_context
from app.project.schemas import ProjectSecurityContext
from app.security import secrets as secret_service
from app.security.schemas import SecurityFinding

logger = logging.getLogger(__name__)

# Plafond de findings lus en base pour construire un contexte. Plus large
# que ce qui sera transmis : il faut lire pour pouvoir compter, et les
# volumes annonces au modele doivent porter sur le projet entier, pas sur
# l'echantillon qu'il recoit.
FINDINGS_READ_LIMIT = 500

# Raisons d'indisponibilite, redigees cote backend. L'extension les affiche
# telles quelles : une phrase composee cote client finirait par dire
# « aucun probleme » la ou il faut dire « indisponible ».
REASON_NO_PROVIDER = (
    "Assistant IA indisponible : aucune clé API n'est configurée côté "
    "backend (OPENAI_API_KEY). L'analyse de sécurité continue normalement "
    "sans lui."
)
REASON_DISABLED = (
    "Assistant IA désactivé côté backend (SECURITY_AI_ASSISTANT_ENABLED="
    "false). L'analyse de sécurité continue normalement sans lui."
)
REASON_CHAT_DISABLED = (
    "Chat de sécurité désactivé côté backend (SECURITY_AI_CHAT_ENABLED="
    "false). Les explications de signalements restent disponibles."
)
REASON_AVAILABLE = ""


# --------------------------------------------------------------------------
# Disponibilite
# --------------------------------------------------------------------------


def availability_reason() -> str:
    """Pourquoi l'assistant n'est pas disponible, ou une chaine vide."""
    if not settings.ai_enabled:
        return REASON_NO_PROVIDER
    if not settings.security_ai_assistant_enabled:
        return REASON_DISABLED
    return REASON_AVAILABLE


def health() -> SecurityAiHealth:
    """Etat de l'assistant, tel que l'extension le consulte avant d'agir.

    Les trois causes d'indisponibilite sont exposees separement parce que
    le remede differe : renseigner une cle, activer un reglage, ou activer
    le chat seul.
    """
    available = settings.security_ai_available
    reason = availability_reason()
    if available and not settings.security_ai_chat_enabled:
        # L'assistant marche, le chat non : la raison affichee doit parler
        # du chat, sinon l'utilisateur cherche une panne inexistante.
        reason = REASON_CHAT_DISABLED

    return SecurityAiHealth(
        status="ok",
        available=available,
        chat_available=settings.security_ai_chat_available,
        fix_available=available and settings.security_ai_fix_enabled,
        provider_configured=settings.ai_enabled,
        assistant_enabled=settings.security_ai_assistant_enabled,
        chat_enabled=settings.security_ai_chat_enabled,
        # Vide quand rien ne sera appele : annoncer un modele inutilise
        # serait faux.
        model=settings.openai_model if available else "",
        reason=reason,
        disclaimer=AI_DISCLAIMER,
        max_context_findings=settings.security_ai_max_context_findings,
    )


def _require_assistant() -> None:
    """Refuse proprement quand l'assistant n'est pas utilisable.

    `AIDisabledError` porte un 503 : l'extension distingue ainsi
    « indisponible » de « en panne », et n'affiche jamais une explication
    vide qui se lirait « rien a signaler ».
    """
    if not settings.security_ai_available:
        raise AIDisabledError(availability_reason())


def _require_chat() -> None:
    _require_assistant()
    if not settings.security_ai_chat_enabled:
        raise AIDisabledError(REASON_CHAT_DISABLED)


# --------------------------------------------------------------------------
# Lecture des findings — toujours par projet
# --------------------------------------------------------------------------


async def load_finding(
    project_uid: str, finding_id: str
) -> Optional[SecurityFinding]:
    """Finding de **ce** projet, ou `None`.

    Le filtre par projet est verifie ici et pas seulement en base : la
    fonction de lecture `store.get_security_finding` cherche par
    identifiant seul, et s'y fier laisserait un projet demander
    l'explication d'un finding d'un autre projet en connaissant son
    identifiant.
    """
    row = await asyncio.to_thread(store.get_security_finding, finding_id)
    if row is None or row.get("project_uid") != project_uid:
        return None
    return secret_service.row_to_finding(row)


async def load_project_findings(
    project_uid: str, status: str = "open"
) -> list[SecurityFinding]:
    """Findings ouverts d'un projet, du plus grave au plus localise."""
    rows = await asyncio.to_thread(
        store.list_security_findings,
        project_uid,
        None,
        status,
        None,
        FINDINGS_READ_LIMIT,
    )
    return [secret_service.row_to_finding(row) for row in rows]


async def load_project_context(
    project_uid: str,
) -> Optional[ProjectSecurityContext]:
    """Contexte du projet, ou `None` s'il n'a jamais ete indexe.

    `None` n'est pas une erreur : l'assistant doit alors dire qu'il ignore
    le contexte du projet, et le prompt le lui demande explicitement.
    """
    return await project_context.get_context(project_uid)


# --------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------


def finding_signature(finding: SecurityFinding) -> str:
    """Empreinte du finding tel qu'il est maintenant.

    Sert a invalider une explication devenue fausse : si un nouveau
    balayage requalifie le finding — gravite differente, preuve differente,
    ligne deplacee —, l'explication en cache ne le decrit plus et doit etre
    refaite.

    Ne porte aucune valeur de secret : la preuve qui entre dans le calcul
    est deja expurgee, et seul son condensat est conserve.
    """
    material = "|".join(
        [
            finding.severity,
            finding.confidence,
            finding.category,
            finding.title,
            finding.description,
            finding.evidence,
            finding.remediation,
            str(finding.line_start),
            finding.file or "",
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


async def cached_analysis(
    project_uid: str, finding: SecurityFinding
) -> Optional[SecurityFindingAiAnalysis]:
    """Explication deja calculee **et toujours valable** pour ce finding."""
    row = await asyncio.to_thread(
        store.get_security_ai_analysis, project_uid, finding.id
    )
    if row is None:
        return None

    if row.get("finding_signature") != finding_signature(finding):
        logger.info(
            "Explication IA du finding %s ignoree : le signalement a change "
            "depuis son analyse",
            finding.id,
        )
        return None

    try:
        analysis = SecurityFindingAiAnalysis.model_validate_json(row["payload"])
    except ValueError:
        # Format d'une version anterieure : on refait plutot que d'afficher
        # de travers.
        logger.warning(
            "Explication IA en cache illisible pour %s, elle sera refaite",
            finding.id,
        )
        return None

    analysis.cached = True
    return analysis


async def _store_analysis(
    analysis: SecurityFindingAiAnalysis, signature: str
) -> None:
    await asyncio.to_thread(
        store.save_security_ai_analysis,
        analysis.project_uid,
        analysis.finding_id,
        analysis.model,
        signature,
        analysis.model_dump_json(),
    )


# --------------------------------------------------------------------------
# Explication d'un finding
# --------------------------------------------------------------------------


async def explain_finding(
    project_uid: str,
    finding: SecurityFinding,
    force: bool = False,
    client: Optional[OpenAIClient] = None,
) -> SecurityFindingAiAnalysis:
    """Fait expliquer un finding deja produit par un moteur deterministe.

    Leve une sous-classe d'`AIError` quand le modele est indisponible, en
    panne, ou repond n'importe quoi. L'appelant traduit en code HTTP ;
    aucun resultat partiel n'est fabrique, et **rien n'est ecrit** — ni
    dans le cache, ni a fortiori sur le finding.
    """
    _require_assistant()

    if not force:
        cached = await cached_analysis(project_uid, finding)
        if cached is not None:
            logger.debug(
                "Explication IA de %s servie depuis le cache", finding.id
            )
            return cached

    project = await load_project_context(project_uid)
    all_findings = await load_project_findings(project_uid)
    related = security_context.select_related(
        finding, all_findings, settings.security_ai_max_related_findings
    )

    context = security_context.build_finding_context(
        finding=finding,
        project=project,
        related=related,
        counts=security_context.count_findings(all_findings),
        truncated=len(all_findings) >= FINDINGS_READ_LIMIT,
    )

    # Meme semaphore que les analyses d'alertes et de code : le plafond
    # AI_MAX_CONCURRENCY protege le cout globalement, pas par type
    # d'analyse.
    async with ai_agent.get_semaphore():
        explanation = await run_model(
            client or get_openai_client(),
            security_prompts.EXPLAIN_SYSTEM_PROMPT,
            security_prompts.build_explain_prompt(context),
            AiFindingExplanation,
            subject=f"le finding {finding.id}",
        )

    analysis = _to_analysis(
        project_uid=project_uid,
        finding=finding,
        explanation=explanation,
        project_available=project is not None,
        related_count=len(related),
    )

    await _store_analysis(analysis, finding_signature(finding))
    logger.info(
        "Finding %s explique par l'IA (gravite deterministe %s conservee, "
        "%s finding(s) voisin(s) consideres)",
        finding.id,
        finding.severity,
        len(related),
    )
    return analysis


def _to_analysis(
    project_uid: str,
    finding: SecurityFinding,
    explanation: AiFindingExplanation,
    project_available: bool,
    related_count: int,
) -> SecurityFindingAiAnalysis:
    """Assemble la reponse : le finding d'un cote, le texte de l'IA de l'autre.

    Les champs `deterministic_*` viennent **du finding**, jamais de
    `explanation` — qui n'en porte aucun. Ecrire cette fonction sans
    melanger les deux sources est ce qui rend l'affirmation « l'IA ne
    modifie pas la gravite » verifiable a la lecture.
    """
    return SecurityFindingAiAnalysis(
        finding_id=finding.id,
        project_uid=project_uid,
        model=settings.openai_model,
        cached=False,
        # --- recopie du moteur deterministe ---
        category=finding.category,
        deterministic_severity=finding.severity,
        deterministic_confidence=finding.confidence,
        deterministic_title=finding.title,
        deterministic_remediation=finding.remediation,
        detection_engine=finding.detection_engine,
        file=finding.file,
        line=finding.line_start,
        # --- texte du modele ---
        explanation=explanation.explanation,
        why_it_matters=explanation.why_it_matters,
        project_impact=explanation.project_impact,
        evidence_interpretation=explanation.evidence_interpretation,
        recommendation=explanation.recommendation,
        remediation_steps=explanation.remediation_steps,
        secure_example=explanation.secure_example,
        secure_example_language=explanation.secure_example_language,
        related_concepts=explanation.related_concepts,
        developer_summary=explanation.developer_summary,
        insufficient_context=explanation.insufficient_context,
        missing_information=explanation.missing_information,
        confidence=explanation.confidence,
        # --- couverture ---
        project_context_available=project_available,
        related_findings_considered=related_count,
    )


# --------------------------------------------------------------------------
# Resume de plusieurs findings
# --------------------------------------------------------------------------


async def summarize_findings(
    project_uid: str,
    finding_ids: Optional[list[str]] = None,
    client: Optional[OpenAIClient] = None,
) -> SecurityFindingsAiSummary:
    """Resume plusieurs findings d'un projet et en donne les relations.

    `finding_ids` vide signifie « tous les findings ouverts », bornes par
    `SECURITY_AI_MAX_CONTEXT_FINDINGS`. La troncature est annoncee dans la
    reponse **et** dans le prompt : un modele voyant vingt-cinq findings
    sur trois cents conclurait sur trois cents.
    """
    _require_assistant()

    available = await load_project_findings(project_uid)

    if finding_ids:
        # Les identifiants inconnus — ou appartenant a un autre projet —
        # sont simplement absents de la selection : la liste lue est deja
        # filtree par projet.
        wanted = set(finding_ids)
        selected = [item for item in available if item.id in wanted]
    else:
        selected = available

    limit = settings.security_ai_max_context_findings
    truncated = len(selected) > limit
    selected = selected[:limit]

    counts = security_context.count_findings(available)
    project = await load_project_context(project_uid)
    context = security_context.build_overview_context(
        findings=selected,
        project=project,
        counts=counts,
        truncated=truncated,
    )

    async with ai_agent.get_semaphore():
        summary = await run_model(
            client or get_openai_client(),
            security_prompts.SUMMARY_SYSTEM_PROMPT,
            security_prompts.build_summary_prompt(context),
            AiFindingsSummary,
            subject=f"le resume du projet {project_uid}",
        )

    logger.info(
        "Resume IA produit pour le projet %s : %s finding(s) sur %s%s",
        project_uid,
        len(selected),
        len(available),
        " [tronque]" if truncated else "",
    )

    return SecurityFindingsAiSummary(
        project_uid=project_uid,
        model=settings.openai_model,
        summary=summary.summary,
        themes=summary.themes,
        relationships=summary.relationships,
        priority_order=summary.priority_order,
        insufficient_context=summary.insufficient_context,
        missing_information=summary.missing_information,
        findings_considered=len(selected),
        findings_available=len(available),
        truncated=truncated,
        severity_counts=counts,
        project_context_available=project is not None,
    )


# --------------------------------------------------------------------------
# Chat de securite
# --------------------------------------------------------------------------


async def answer_question(
    project_uid: str,
    request: SecurityChatRequest,
    client: Optional[OpenAIClient] = None,
) -> SecurityChatResponse:
    """Repond a une question sur la securite du projet ouvert.

    Le contexte est construit depuis **ce** projet seulement. La question
    et l'historique sont expurges avant de sortir : une question est du
    texte libre, et un secret colle par megarde ne doit pas quitter la
    machine.

    Aucune mise en cache : deux questions ne se ressemblent pas, et un
    cache de reponses de chat couterait en place ce qu'il ne ferait pas
    gagner en appels.
    """
    _require_chat()

    question = security_context.redact_question(request.question)
    history = security_context.redact_history(
        request.history, settings.security_ai_chat_history_turns
    )

    available = await load_project_findings(project_uid)
    limit = settings.security_ai_max_context_findings

    # Une question posee depuis la fiche d'un signalement met celui-ci en
    # tete du contexte : c'est de lui qu'on parle, et il ne doit pas etre
    # le finding que la borne a coupe.
    selected = available
    if request.finding_id:
        focus = [item for item in available if item.id == request.finding_id]
        others = [item for item in available if item.id != request.finding_id]
        selected = focus + others

    truncated = len(selected) > limit
    selected = selected[:limit]

    project = await load_project_context(project_uid)
    context = security_context.build_overview_context(
        findings=selected,
        project=project,
        counts=security_context.count_findings(available),
        truncated=truncated,
    )

    async with ai_agent.get_semaphore():
        answer = await run_model(
            client or get_openai_client(),
            security_prompts.CHAT_SYSTEM_PROMPT,
            security_prompts.build_chat_prompt(context, question, history),
            AiChatAnswer,
            subject=f"une question sur le projet {project_uid}",
        )

    # Volumes et drapeaux seulement : ni la question, ni la reponse, ni un
    # chemin de fichier ne sont journalises.
    logger.info(
        "Question de securite traitee pour le projet %s : %s finding(s) "
        "dans le contexte%s, contexte juge %s par le modele",
        project_uid,
        len(selected),
        " [tronque]" if truncated else "",
        "insuffisant" if answer.insufficient_context else "suffisant",
    )

    return SecurityChatResponse(
        project_uid=project_uid,
        model=settings.openai_model,
        # La question **expurgee** est renvoyee : l'interface affiche ce
        # qui est reellement parti.
        question=question,
        answer=answer.answer,
        insufficient_context=answer.insufficient_context,
        missing_information=answer.missing_information,
        related_concepts=answer.related_concepts,
        findings_considered=len(selected),
        findings_available=len(available),
        truncated=truncated,
        project_context_available=project is not None,
        history_turns_used=len(history),
    )
