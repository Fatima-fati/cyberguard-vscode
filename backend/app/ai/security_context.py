"""Construction du contexte envoye a l'assistant de securite (phase 6).

Le seul endroit du projet ou un finding de securite devient du texte
destine a un modele. Un seul chemin, pour qu'il n'existe qu'une frontiere
a verifier — et un test la verifie en lisant ce que le client HTTP a
reellement envoye, pas ce que ce module croit envoyer.

Ce qui traverse
---------------

    categorie, gravite, confiance      le constat du moteur
    titre, description                 texte redige par le backend
    chemin RELATIF, ligne              pour situer le probleme
    preuve EXPURGEE et bornee          pour l'interpreter
    remediation deterministe           pour l'enrichir, pas la remplacer
    references (CWE, CVE, GHSA)        pour raccrocher a un referentiel
    contexte de projet reduit          `app.project.ai_contract`
    volumes par gravite et categorie   des nombres

Ce qui ne traverse jamais
-------------------------

    le contenu d'un fichier            aucun champ ne peut le porter
    un chemin absolu                   `app.paths` n'en produit pas
    la valeur d'un secret              reexpurgee ici, avant l'envoi
    une cle d'API, un mot de passe     idem, et jamais depuis la config
    `project_uid`, `root_hash`         identifiants internes, inutiles
    les chemins des fichiers sensibles seul leur NOMBRE circule

Pourquoi reexpurger une preuve deja expurgee
--------------------------------------------

Elle l'a ete par l'extension, puis par le validateur de `SecurityFinding`
avant l'ecriture en base. Une troisieme passe ici peut sembler de trop.
Elle ne l'est pas : la base peut avoir ete ecrite par une version
anterieure du backend, modifiee a la main, ou remplie par un autre
processus de la machine — le backend ecoute en local. La seule garantie
qui tienne est celle appliquee du cote qui **envoie**.
"""

import logging
from typing import Optional

from app.ai.security_schemas import (
    AiFindingCounts,
    AiFindingDigest,
    AiSecurityContext,
    MAX_CHAT_TURN_LENGTH,
    MAX_QUESTION_LENGTH,
    SecurityChatTurn,
)
from app.paths import clean_relative_path
from app.project.ai_contract import build_ai_project_context
from app.project.schemas import ProjectSecurityContext
from app.security.redaction import redact_text
from app.security.schemas import SecurityFinding

logger = logging.getLogger(__name__)

# Borne des textes rediges par le backend et joints au prompt. Une
# description de finding tient largement dessous ; au-dela, c'est un
# symptome, pas un contenu utile.
MAX_DESCRIPTION_LENGTH = 600
MAX_REFERENCES = 6


def _safe_relative_path(value: Optional[str]) -> Optional[str]:
    """Chemin relatif, ou rien.

    `clean_relative_path` refuse un chemin absolu et une remontee
    (`../`). Un chemin qu'il refuse n'est pas corrige ici : il est
    abandonne. Envoyer « quelque chose d'approchant » au modele
    reviendrait a deviner, et la reponse citerait un fichier qui n'existe
    pas.
    """
    if not value:
        return None
    try:
        return clean_relative_path(value)
    except ValueError:
        logger.warning(
            "Chemin de finding non relatif ecarte du contexte IA : il ne "
            "sera pas transmis au modele"
        )
        return None


def finding_digest(finding: SecurityFinding) -> AiFindingDigest:
    """Reduit un finding a ce qu'un modele peut recevoir.

    Enumeration explicite champ par champ, jamais `model_dump()` : un
    champ ajoute demain a `SecurityFinding` n'atteint pas le prompt par
    accident. C'est la meme discipline que `build_ai_project_context`, et
    elle existe pour la meme raison — la facilite, un jour, sera de tout
    passer « parce que c'est plus pratique ».
    """
    return AiFindingDigest(
        category=finding.category,
        # Gravite et confiance du moteur, en lecture seule. Le modele les
        # commente ; rien de sa reponse ne revient ici.
        severity=finding.severity,
        confidence=finding.confidence,
        title=redact_text(finding.title, MAX_DESCRIPTION_LENGTH),
        description=redact_text(finding.description, MAX_DESCRIPTION_LENGTH),
        file=_safe_relative_path(finding.file),
        line=max(0, finding.line_start),
        # Troisieme expurgation. Voir l'en-tete du module.
        evidence=redact_text(finding.evidence),
        remediation=redact_text(finding.remediation, MAX_DESCRIPTION_LENGTH),
        references=list(finding.references[:MAX_REFERENCES]),
        detection_engine=finding.detection_engine,
    )


def count_findings(findings: list[SecurityFinding]) -> AiFindingCounts:
    """Volumes par gravite et par categorie. Des nombres, rien d'autre."""
    counts = AiFindingCounts(total=len(findings))
    by_category: dict[str, int] = {}

    for finding in findings:
        severity = (finding.severity or "").upper()
        if severity == "CRITICAL":
            counts.critical += 1
        elif severity == "HIGH":
            counts.high += 1
        elif severity == "MEDIUM":
            counts.medium += 1
        else:
            counts.low += 1
        by_category[finding.category] = by_category.get(finding.category, 0) + 1

    counts.by_category = dict(sorted(by_category.items()))
    return counts


def select_related(
    finding: SecurityFinding,
    candidates: list[SecurityFinding],
    limit: int,
) -> list[SecurityFinding]:
    """Findings voisins de celui-ci, pour la mise en relation.

    Deux criteres, dans cet ordre : **meme fichier** d'abord — c'est la
    relation la plus utile a un developpeur, qui corrigera les deux d'un
    seul passage —, puis **meme categorie** ailleurs dans le projet.

    Le finding lui-meme est exclu, et la liste est bornee : un projet aux
    cinq cents secrets ne doit pas produire un prompt de cinq cents
    entrees.
    """
    if limit <= 0:
        return []

    others = [item for item in candidates if item.id != finding.id]
    same_file = [
        item for item in others if finding.file and item.file == finding.file
    ]
    same_category = [
        item
        for item in others
        if item.category == finding.category and item not in same_file
    ]

    return (same_file + same_category)[:limit]


def build_finding_context(
    finding: SecurityFinding,
    project: Optional[ProjectSecurityContext],
    related: Optional[list[SecurityFinding]] = None,
    counts: Optional[AiFindingCounts] = None,
    truncated: bool = False,
) -> AiSecurityContext:
    """Contexte complet pour l'explication d'un finding precis."""
    return AiSecurityContext(
        project=build_ai_project_context(project) if project is not None else None,
        finding=finding_digest(finding),
        findings=[finding_digest(item) for item in (related or [])],
        counts=counts or AiFindingCounts(),
        truncated=truncated,
        vulnerability_check_conclusive=(
            project.vulnerability_statistics.conclusive if project else False
        ),
        vulnerability_provider_status=(
            project.vulnerability_statistics.provider_status if project else "disabled"
        ),
    )


def build_overview_context(
    findings: list[SecurityFinding],
    project: Optional[ProjectSecurityContext],
    counts: Optional[AiFindingCounts] = None,
    truncated: bool = False,
) -> AiSecurityContext:
    """Contexte d'ensemble : plusieurs findings, aucun en particulier.

    Sert au resume et au chat. `truncated` n'est pas cosmetique : sans
    lui, un modele voyant vingt-cinq findings sur trois cents conclurait
    sur trois cents.
    """
    return AiSecurityContext(
        project=build_ai_project_context(project) if project is not None else None,
        finding=None,
        findings=[finding_digest(item) for item in findings],
        counts=counts or count_findings(findings),
        truncated=truncated,
        vulnerability_check_conclusive=(
            project.vulnerability_statistics.conclusive if project else False
        ),
        vulnerability_provider_status=(
            project.vulnerability_statistics.provider_status if project else "disabled"
        ),
    )


def redact_question(question: str) -> str:
    """Question de l'utilisateur, expurgee avant de sortir du backend.

    Une question est du texte libre : elle peut porter un secret colle par
    megarde (« pourquoi `DB_PASSWORD=hunter2` est-il signale ? »). Elle
    passe donc par la meme expurgation que les preuves, avec une borne
    plus large — une question n'est pas un extrait de fichier.

    La version expurgee est celle qui part **et** celle qui est renvoyee a
    l'interface : l'utilisateur voit ainsi que son secret a ete masque,
    plutot que de croire l'avoir envoye en clair.
    """
    return redact_text(question, MAX_QUESTION_LENGTH)


def redact_history(
    history: list[SecurityChatTurn], limit: int
) -> list[SecurityChatTurn]:
    """Historique borne et expurge, du plus ancien au plus recent.

    La borne est appliquee **ici**, cote serveur : un client d'une autre
    version, ou un appel direct sur la route, ne doit pas pouvoir faire
    grossir le prompt sans fin. Ce sont les tours les plus anciens qui
    sont abandonnes — la fin de la conversation porte la question.
    """
    if limit <= 0:
        return []

    kept = history[-limit:]
    return [
        SecurityChatTurn(
            role=turn.role,
            message=redact_text(turn.message, MAX_CHAT_TURN_LENGTH),
        )
        for turn in kept
        if (turn.message or "").strip()
    ]
