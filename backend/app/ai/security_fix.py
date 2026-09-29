"""Remediation assistee : eligibilite, contexte, validation (phase 7).

    finding persiste + extrait expurge -> eligibilite DETERMINISTE
        -> modele -> validation STRICTE -> proposition -> extension

Ce module ne lit aucun fichier et n'en ecrit aucun. Il ne touche pas non
plus aux findings : il les lit, pour savoir sur quoi porte la demande, et
c'est tout. Un test relit son code source a la recherche d'une ecriture
de finding ou d'une ecriture disque.

Trois barrieres, dans cet ordre
-------------------------------

1. **Eligibilite, avant tout appel au modele.** Finding ouvert, fichier
   identique a celui du finding, fichier non protege (`.env`, cle privee,
   certificat, identifiants), ligne visee coherente avec le finding. Un
   refus ici ne coute rien et ne transmet rien.
2. **Expurgation de l'extrait**, ligne a ligne, indentation conservee —
   meme si l'extension l'a deja fait.
3. **Validation de la reponse.** Schema strict (`extra="forbid"`), puis
   controles de surete : plage bornee contenant la ligne visee, aucune
   valeur masquee recopiee, aucun secret ecrit, aucune construction
   dangereuse introduite, aucune commande destructrice dans les etapes
   manuelles. Au moindre doute : refus, et rien n'est propose.
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

from app import store
from app.ai import agent as ai_agent
from app.ai import security_assistant, security_prompts
from app.ai.analyzer import run_model
from app.ai.openai_client import (
    AIDisabledError,
    AIResponseError,
    OpenAIClient,
    get_openai_client,
)
from app.ai.security_fix_schemas import (
    AiFixSuggestion,
    MAX_LINE_LENGTH,
    SecurityFixProposal,
    SecurityFixRequest,
)
from app.ai.security_schemas import AiFindingDigest
from app.config import settings
from app.paths import clean_relative_path
from app.project.ai_contract import build_ai_project_context
from app.project.discovery import classify_path
from app.security.redaction import (
    contains_redaction_marker,
    contains_secret_literal,
    redact_code_line,
    redact_text,
)

logger = logging.getLogger(__name__)


class AIUnsafeResponseError(AIResponseError):
    """Reponse du modele bien formee mais dangereuse ou ambigue."""


REASON_FIX_DISABLED = (
    "Remédiation assistée désactivée côté backend (SECURITY_AI_FIX_ENABLED="
    "false). La remédiation reste manuelle ; l'analyse de sécurité continue "
    "normalement."
)

# --------------------------------------------------------------------------
# Fichiers jamais modifies
# --------------------------------------------------------------------------

# Au-dela du classement « sensible » de la decouverte (`.env`, cles
# privees, magasins de cles, fichiers d'identifiants) : les certificats.
# Un certificat n'est pas un secret, mais le reecrire n'a jamais de sens
# comme correction de code, et une erreur y casse le deploiement.
_PROTECTED_SUFFIXES: tuple[str, ...] = (
    ".crt",
    ".cer",
    ".der",
    ".csr",
    ".p7b",
    ".p7c",
    ".p8",
    ".gpg",
    ".kdbx",
)

# Fichiers de verrouillage : generes par un gestionnaire de paquets. Les
# modifier a la main produit un arbre incoherent ; la bonne remediation
# est de mettre a jour le manifeste puis de regenerer le verrou.
LOCKFILES: frozenset[str] = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pipfile.lock",
        "composer.lock",
        "gemfile.lock",
        "cargo.lock",
        "go.sum",
        "packages.lock.json",
    }
)


def protection_reason(path: str) -> Optional[str]:
    """Pourquoi ce fichier ne doit jamais etre modifie, ou `None`."""
    classified = classify_path(path)
    if classified.kind == "sensitive":
        return (
            f"{path} est un fichier protégé ({classified.reason}) : il n'est "
            "jamais lu ni modifié automatiquement. Remédiation manuelle requise."
        )
    name = path.rsplit("/", 1)[-1].lower()
    if name.endswith(_PROTECTED_SUFFIXES):
        return (
            f"{path} est un certificat ou un fichier de clés : il n'est jamais "
            "modifié automatiquement. Remédiation manuelle requise."
        )
    return None


# --------------------------------------------------------------------------
# Ce sur quoi porte la demande
# --------------------------------------------------------------------------


@dataclass
class FixTarget:
    """Un finding, vu par la remediation, quelle que soit sa table."""

    kind: str  # "security" | "code"
    finding_id: str
    category: str
    severity: str
    confidence: str
    title: str
    description: str
    file: Optional[str]
    line: int
    evidence: str
    remediation: str
    references: list[str] = field(default_factory=list)
    engine: str = ""
    status: str = "open"


async def load_target(project_uid: str, finding_id: str) -> Optional[FixTarget]:
    """Finding de **ce** projet, securite projet ou analyse de fichier.

    Les deux tables sont interrogees, et le projet verifie dans les deux
    cas : un finding de code appartient a un scan, qui appartient a un
    projet. Un finding d'un autre projet est introuvable, meme en
    connaissant son identifiant.
    """
    finding = await security_assistant.load_finding(project_uid, finding_id)
    if finding is not None:
        return FixTarget(
            kind="security",
            finding_id=finding.id,
            category=finding.category,
            severity=finding.severity,
            confidence=finding.confidence,
            title=finding.title,
            description=finding.description,
            file=finding.file,
            line=finding.line_start,
            evidence=finding.evidence,
            remediation=finding.remediation,
            references=list(finding.references),
            engine=finding.detection_engine,
            status=finding.status,
        )

    row = await asyncio.to_thread(store.get_code_finding, finding_id)
    if row is None:
        return None
    scan = await asyncio.to_thread(store.get_code_scan_by_id, int(row["scan_id"]))
    if scan is None or scan.get("project_uid") != project_uid:
        return None

    return FixTarget(
        kind="code",
        finding_id=row["finding_uid"],
        category=row.get("category") or "CODE",
        severity=row.get("severity") or "MEDIUM",
        confidence="MEDIUM",
        title=row.get("title") or row.get("rule_id") or "",
        description=row.get("explanation") or "",
        file=scan.get("file_path"),
        line=int(row.get("line_start") or 0),
        evidence=row.get("snippet") or "",
        remediation=row.get("fix_summary") or "",
        references=[item for item in (row.get("cwe"), row.get("owasp")) if item],
        engine=row.get("rule_id") or "",
        status=row.get("status") or "open",
    )


def dependency_name(target: FixTarget) -> str:
    """Nom du paquet d'un finding de dependance.

    Le moteur ecrit le titre sous la forme « nom version — avis » : le nom
    est le premier mot. Deterministe, et verifie contre la ligne visee.
    """
    return (target.title or "").split(" ", 1)[0].strip()


# --------------------------------------------------------------------------
# Eligibilite — avant tout appel au modele
# --------------------------------------------------------------------------


def eligibility_refusal(target: FixTarget, request: SecurityFixRequest) -> Optional[str]:
    """Raison de ne PAS proposer de correctif automatique, ou `None`.

    Chaque refus est une phrase affichable : l'extension la montre telle
    quelle, sans bouton « Appliquer ».
    """
    if target.status != "open":
        return "Ce signalement n'est plus ouvert : aucun correctif n'est proposé."

    if not target.file:
        return (
            "Ce signalement ne porte pas sur un fichier précis : "
            "remédiation manuelle requise."
        )

    try:
        finding_file = clean_relative_path(target.file)
    except ValueError:
        return "Chemin du signalement inexploitable : remédiation manuelle requise."

    # Borne au fichier du finding : jamais « un fichier voisin ».
    if request.file_path != finding_file:
        return (
            "Le fichier transmis n'est pas celui du signalement : aucun "
            "correctif n'est proposé hors du fichier concerné."
        )

    protected = protection_reason(finding_file)
    if protected:
        return protected

    name = finding_file.rsplit("/", 1)[-1].lower()

    if target.category == "GIT":
        return "Signalement d'historique Git : remédiation manuelle requise."

    if target.category == "DEPENDENCY":
        if name in LOCKFILES:
            return (
                f"{finding_file} est un fichier de verrouillage généré : mettez "
                "à jour la dépendance dans le manifeste, puis régénérez le "
                "verrou avec votre gestionnaire de paquets."
            )
        package = dependency_name(target)
        declared = request.line(request.target_line)
        if not package or not re.search(
            rf"(?<![A-Za-z0-9_.\-]){re.escape(package)}(?![A-Za-z0-9_\-])",
            declared,
            flags=re.IGNORECASE,
        ):
            return (
                "La ligne transmise ne déclare pas cette dépendance : relancez "
                "l'analyse du projet avant de demander un correctif."
            )
        return None

    # Finding localise : la ligne visee est celle du finding, au numero
    # pres. Une autre ligne signifie que le fichier a bouge depuis le
    # balayage — le correctif porterait sur autre chose.
    if target.line < 1:
        return "Ce signalement n'indique pas de ligne : remédiation manuelle requise."
    if request.target_line != target.line:
        return (
            "Le fichier a changé depuis l'analyse (la ligne du signalement ne "
            "correspond plus) : relancez l'analyse avant de demander un correctif."
        )
    return None


# --------------------------------------------------------------------------
# Contexte envoye au modele
# --------------------------------------------------------------------------


def redacted_excerpt(request: SecurityFixRequest) -> list[str]:
    """Extrait reexpurge, ligne a ligne. Voir `redact_code_line`."""
    return [redact_code_line(line, MAX_LINE_LENGTH) for line in request.excerpt_lines]


def _digest(target: FixTarget) -> AiFindingDigest:
    return AiFindingDigest(
        category=target.category,
        severity=target.severity,
        confidence=target.confidence,
        title=redact_text(target.title, 300),
        description=redact_text(target.description, 600),
        file=target.file,
        line=max(0, target.line),
        evidence=redact_text(target.evidence),
        remediation=redact_text(target.remediation, 600),
        references=list(target.references[:6]),
        detection_engine=target.engine,
    )


def build_fix_context(
    target: FixTarget,
    request: SecurityFixRequest,
    excerpt: list[str],
    project=None,
) -> dict:
    """Tout ce qui part vers le modele, et rien d'autre.

    Ni `project_uid`, ni identifiant de finding, ni chemin absolu, ni
    empreinte de fichier : le modele n'en ferait rien.
    """
    context: dict = {
        "finding": _digest(target).model_dump(mode="json", exclude_none=True),
        "language": request.language,
        "target_line": request.target_line,
        "max_range_lines": settings.security_ai_fix_max_range_lines,
        "max_replacement_lines": settings.security_ai_fix_max_replacement_lines,
        "excerpt": [
            {"line": request.excerpt_start_line + index, "text": text}
            for index, text in enumerate(excerpt)
        ],
    }
    if project is not None:
        context["project"] = build_ai_project_context(project).model_dump(mode="json")
    return context


# --------------------------------------------------------------------------
# Validation de la reponse
# --------------------------------------------------------------------------

# Constructions qu'un correctif de securite n'a pas a introduire. Refusees
# quand elles apparaissent dans le remplacement sans figurer deja dans la
# plage d'origine : corriger un appel existant a `subprocess` reste
# possible, en ajouter un ne l'est pas.
_DANGEROUS_CODE: tuple[re.Pattern, ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\bos\.system\s*\(",
        r"\bos\.popen\s*\(",
        r"\bsubprocess\b",
        r"\bchild_process\b",
        r"(?<![\w.])eval\s*\(",
        r"(?<![\w.])exec\s*\(",
        r"\bRuntime\.getRuntime\s*\(\s*\)\s*\.exec",
        r"\bshell\s*=\s*True\b",
        r"\bshell_exec\s*\(",
        r"\bpassthru\s*\(",
        r"\bInvoke-Expression\b",
        r"\brm\s+-rf\b",
        r"\bDROP\s+(TABLE|DATABASE)\b",
        r"\bTRUNCATE\s+TABLE\b",
        r"\bDELETE\s+FROM\b",
        r"(curl|wget)\b[^|\n]*\|\s*(ba|z)?sh\b",
    )
)

# Commandes refusees dans un texte affiche (etapes manuelles,
# avertissements). Elles ne sont jamais executees — mais un texte d'IA qui
# invite a lancer `curl ... | sh` n'est pas un texte qu'on affiche.
_DANGEROUS_TEXT: tuple[re.Pattern, ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\brm\s+-rf\b",
        r"(curl|wget)\b[^|\n]*\|\s*(ba|z)?sh\b",
        r"\bsudo\b",
        r"\bchmod\s+(-R\s+)?777\b",
        r"\bInvoke-Expression\b|\biex\b",
        r"\bmkfs\b|\bdd\s+if=",
        r"\bDROP\s+(TABLE|DATABASE)\b",
        r"\bgit\s+push\s+--force\b",
        r"\bformat\s+[a-z]:",
    )
)


def _introduces(pattern: re.Pattern, original: list[str], replacement: list[str]) -> bool:
    before = any(pattern.search(line) for line in original)
    after = any(pattern.search(line) for line in replacement)
    return after and not before


def validate_suggestion(
    suggestion: AiFixSuggestion,
    request: SecurityFixRequest,
    excerpt: list[str],
) -> None:
    """Leve `AIUnsafeResponseError` si la proposition n'est pas sure.

    Ne renvoie rien quand tout va bien : il n'existe pas de « proposition
    a moitie valide ». Appelee seulement quand `feasible` est vrai.
    """

    def refuse(reason: str) -> None:
        logger.warning("Correctif IA refuse pour %s : %s", request.file_path, reason)
        raise AIUnsafeResponseError(
            "La proposition de l'IA a été rejetée : " + reason, detail=reason
        )

    for text in [suggestion.explanation, suggestion.reason, *suggestion.warnings,
                 *suggestion.manual_steps]:
        if any(pattern.search(text) for pattern in _DANGEROUS_TEXT):
            refuse("elle contient une commande dangereuse.")

    start, end = suggestion.start_line, suggestion.end_line
    if start is None or end is None:
        refuse("elle n'indique pas la plage de lignes à remplacer.")
    assert start is not None and end is not None

    if start > end:
        refuse("la plage de lignes est inversée.")
    if start < request.excerpt_start_line or end > request.excerpt_end_line:
        refuse("elle sort de l'extrait transmis.")
    if not start <= request.target_line <= end:
        refuse("elle ne porte pas sur la ligne du signalement.")
    if end - start + 1 > settings.security_ai_fix_max_range_lines:
        refuse("elle remplace trop de lignes.")

    replacement = suggestion.replacement_lines
    if len(replacement) > settings.security_ai_fix_max_replacement_lines:
        refuse("le remplacement est trop long.")

    for line in replacement:
        if "\n" in line or "\r" in line:
            refuse("une ligne de remplacement contient un saut de ligne.")
        if len(line) > MAX_LINE_LENGTH:
            refuse("une ligne de remplacement est trop longue.")
        if contains_redaction_marker(line):
            refuse(
                "elle recopie une valeur masquée ; appliquée, elle écrirait le "
                "masque à la place du code."
            )
        if contains_secret_literal(line):
            refuse("elle écrit une valeur de secret en clair.")

    offset = request.excerpt_start_line
    original = excerpt[start - offset : end - offset + 1]

    for pattern in _DANGEROUS_CODE:
        if _introduces(pattern, original, replacement):
            refuse("elle introduit une construction dangereuse (exécution de commande, SQL destructeur).")

    if replacement == original:
        refuse("elle ne modifie rien.")

    if all(not line.strip() for line in replacement) and any(
        line.strip() for line in original
    ):
        refuse("elle supprimerait du code sans le remplacer.")


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------


def _deterministic_steps(target: FixTarget) -> list[str]:
    """Etapes que le correctif ne remplace jamais, quel que soit le modele."""
    if target.category == "SECRET":
        return [
            "Ce secret a été exposé : révoquez-le et générez-en un nouveau. "
            "Retirer la valeur du code ne l'efface pas de l'historique Git."
        ]
    if target.category == "DEPENDENCY":
        return [
            "Après la mise à jour du manifeste, régénérez le fichier de "
            "verrouillage avec votre gestionnaire de paquets, puis relancez les tests."
        ]
    return []


def _proposal(project_uid: str, target: FixTarget, request: SecurityFixRequest,
              **fields) -> SecurityFixProposal:
    return SecurityFixProposal(
        finding_id=target.finding_id,
        project_uid=project_uid,
        kind=target.kind,  # type: ignore[arg-type]
        model=settings.openai_model,
        category=target.category,
        deterministic_severity=target.severity,  # type: ignore[arg-type]
        deterministic_title=target.title,
        file=request.file_path,
        base_content_hash=request.content_hash,
        **fields,
    )


async def propose_fix(
    project_uid: str,
    target: FixTarget,
    request: SecurityFixRequest,
    client: Optional[OpenAIClient] = None,
) -> SecurityFixProposal:
    """Propose un correctif borne, ou dit pourquoi il n'y en a pas.

    Leve `AIDisabledError` (503) quand l'assistant est absent, et une
    sous-classe d'`AIResponseError` (502) quand la reponse est inexploitable
    ou dangereuse. Rien n'est ecrit nulle part, dans aucun cas.
    """
    if not settings.security_ai_available:
        raise AIDisabledError(security_assistant.availability_reason())
    if not settings.security_ai_fix_enabled:
        raise AIDisabledError(REASON_FIX_DISABLED)

    manual = _deterministic_steps(target)

    refusal = eligibility_refusal(target, request)
    if refusal:
        logger.info(
            "Correctif IA non propose pour %s (%s) : refus deterministe",
            target.finding_id,
            target.category,
        )
        return _proposal(
            project_uid, target, request,
            available=False, refusal=refusal, manual_steps=manual,
        )

    excerpt = redacted_excerpt(request)
    project = await security_assistant.load_project_context(project_uid)
    context = build_fix_context(target, request, excerpt, project)

    async with ai_agent.get_semaphore():
        suggestion = await run_model(
            client or get_openai_client(),
            security_prompts.FIX_SYSTEM_PROMPT,
            security_prompts.build_fix_prompt(context),
            AiFixSuggestion,
            subject=f"le correctif du finding {target.finding_id}",
        )

    if not suggestion.feasible:
        return _proposal(
            project_uid, target, request,
            available=False,
            refusal=(
                "L'assistant n'a pas trouvé de modification bornée et sûre : "
                "remédiation manuelle requise."
            ),
            explanation=suggestion.explanation,
            reason=suggestion.reason,
            warnings=suggestion.warnings,
            manual_steps=manual + suggestion.manual_steps,
        )

    validate_suggestion(suggestion, request, excerpt)

    logger.info(
        "Correctif IA propose pour %s : lignes %s-%s de %s (%s ligne(s) de "
        "remplacement), gravite deterministe %s conservee",
        target.finding_id,
        suggestion.start_line,
        suggestion.end_line,
        request.file_path,
        len(suggestion.replacement_lines),
        target.severity,
    )

    return _proposal(
        project_uid, target, request,
        available=True,
        start_line=suggestion.start_line or 0,
        end_line=suggestion.end_line or 0,
        replacement_lines=list(suggestion.replacement_lines),
        explanation=suggestion.explanation,
        reason=suggestion.reason,
        warnings=suggestion.warnings,
        manual_steps=manual + suggestion.manual_steps,
    )
