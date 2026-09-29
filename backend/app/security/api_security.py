"""Reception et persistance des analyses de securite d'API.

Ce module ne detecte rien. La detection tourne **sur le poste**, dans
l'extension : reperer une route dans un fichier source est une operation
locale, et envoyer ce fichier a un serveur pour la meme raison n'en
serait pas une. Le backend recoit des constats, les nettoie, les range et
les compte.

Meme architecture que `secrets.py`, dont ce module reprend les
conventions — deliberement : deux familles de findings qui se rangent de
deux facons differentes finiraient par se comporter differemment, et
l'utilisateur ne saurait plus ce qu'il regarde.

Trois garanties tenues ici, et ou elles sont tenues :

- **aucune valeur en clair n'est ecrite** — `ApiFindingSubmission`
  expurge `evidence` dans son validateur, et une ligne de configuration
  d'API est precisement l'endroit ou un jeton se glisse ;
- **aucun contenu de fichier n'est recu** — le modele ne porte qu'un
  extrait de declaration, borne a 400 caracteres ;
- **une decision de l'utilisateur survit a une nouvelle analyse** —
  c'est `store.sync_security_findings` qui s'en charge, via l'empreinte.

Aucun appel Wazuh : ce module repond a l'identique avec Wazuh
completement arrete.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone

from app import store
from app.config import settings
from app.security.schemas import (
    ApiFindingSubmission,
    ApiScanResult,
    ApiScanSubmission,
    ApiStatistics,
    SecurityFinding,
    finding_fingerprint,
    finding_id_for,
)

logger = logging.getLogger(__name__)

CATEGORY = "API"
ENGINE = "api-scanner"

# Types de probleme qui decrivent un endpoint atteignable sans
# authentification. Comptes a part dans les statistiques : c'est le
# chiffre que l'on regarde en premier.
UNAUTHENTICATED_ISSUES = frozenset({"unauthenticated_endpoint"})


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def apply_confidence(severity: str, confidence: str) -> str:
    """Plafonne la gravite affichee par la confiance de la detection.

    Meme regle que pour les secrets, et elle compte davantage encore ici.
    Une analyse par lignes ne voit que le fichier qu'on lui donne : une
    authentification posee par un middleware monte ailleurs lui est
    invisible. Afficher « CRITICAL : endpoint non authentifie » sur la
    foi d'une preuve qui dit seulement « je n'ai pas vu d'authentification
    dans ce fichier » serait une affirmation que la preuve ne soutient
    pas.

    La gravite **reelle** du probleme n'est pas perdue : la confiance
    voyage a cote et l'interface l'affiche.
    """
    level = (severity or "MEDIUM").upper()
    trust = (confidence or "MEDIUM").upper()

    if trust == "LOW":
        return "LOW" if level == "LOW" else "MEDIUM"
    if trust == "MEDIUM" and level == "CRITICAL":
        return "HIGH"
    return level


def fingerprint_of(submission: ApiFindingSubmission) -> str:
    """Empreinte stable d'un probleme d'API.

    Le discriminant est le **type de probleme** et la regle, jamais la
    preuve : deux analyses du meme fichier produisent la meme empreinte,
    et rien dans la base ne permet de remonter a une valeur.

    Consequence voulue : deplacer une route change l'empreinte, donc le
    finding est recree et une decision « faux positif » ne suit pas la
    route d'une ligne a l'autre. C'est le comportement prudent — la
    decision portait sur ce qui etait la, pas sur ce qui y sera.
    """
    return finding_fingerprint(
        CATEGORY,
        ENGINE,
        submission.file_path,
        submission.line,
        f"{submission.rule_id}:{submission.issue_type}",
    )


def to_finding(project_uid: str, submission: ApiFindingSubmission) -> SecurityFinding:
    """Traduit un constat de l'extension en finding de securite.

    Le titre et la remediation viennent du client parce que c'est lui qui
    detient la table de regles ; un repli est prevu pour qu'un client
    d'une version anterieure produise quand meme un message lisible.
    """
    severity = apply_confidence(submission.severity, submission.confidence)
    described = _describe(submission)

    return SecurityFinding(
        id=finding_id_for(project_uid, fingerprint_of(submission)),
        project_uid=project_uid,
        category=CATEGORY,
        severity=severity,  # type: ignore[arg-type]
        confidence=submission.confidence,
        title=submission.title or described,
        description=submission.description or described,
        file=submission.file_path,
        line_start=submission.line,
        line_end=submission.line,
        evidence=submission.evidence,
        remediation=submission.remediation
        or "Verifiez la protection de cette surface d'API.",
        references=list(submission.references),
        detection_engine=ENGINE,
        status="open",
        created_at=_now_iso(),
    )


def _describe(submission: ApiFindingSubmission) -> str:
    """Libelle de repli, construit a partir du constat lui-meme.

    Sert uniquement quand le client n'a envoye ni titre ni description —
    un client plus ancien, ou un constat tronque. Le texte reste exact :
    il ne dit que ce que le constat porte.
    """
    where = submission.endpoint or submission.file_path
    method = f"{submission.http_method} " if submission.http_method else ""
    issue = submission.issue_type.replace("_", " ")
    return f"{issue} : {method}{where}".strip()


async def record(project_uid: str, submission: ApiScanSubmission) -> ApiScanResult:
    """Enregistre une analyse d'API et retourne ce qui en ressort.

    Le plafond est applique **cote serveur** : l'extension a le sien, mais
    le backend ne fait pas confiance a la borne du client. Quand il mord,
    la troncature est annoncee — un decompte plafonne presente comme
    complet serait un mensonge de securite.
    """
    warnings = list(submission.warnings)
    truncated = submission.truncated

    accepted = submission.findings
    limit = settings.api_max_findings
    if len(accepted) > limit:
        accepted = accepted[:limit]
        truncated = True
        warnings.append(
            f"Analyse d'API tronquee a {limit} signalements par le backend "
            f"({len(submission.findings)} soumis)."
        )

    # Deduplication par empreinte : deux regles peuvent reconnaitre le
    # meme probleme sur la meme ligne (un CORS joker est aussi une
    # configuration permissive). Le premier gagne — les regles
    # specifiques sont evaluees avant les regles larges, cote extension
    # comme ici.
    unique: dict[str, tuple[str, SecurityFinding, ApiFindingSubmission]] = {}
    for item in accepted:
        fingerprint = fingerprint_of(item)
        unique.setdefault(
            fingerprint, (fingerprint, to_finding(project_uid, item), item)
        )

    rows = [
        {
            "finding_id": finding.id,
            "fingerprint": fingerprint,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "title": finding.title,
            "description": finding.description,
            "file_path": finding.file,
            "line_start": finding.line_start,
            "line_end": finding.line_end,
            "evidence": finding.evidence,
            "remediation": finding.remediation,
            "reference_links": json.dumps(finding.references, ensure_ascii=False),
            "detection_engine": finding.detection_engine,
            "status": "open",
        }
        for fingerprint, finding, _ in unique.values()
    ]

    outcome = await asyncio.to_thread(
        store.sync_security_findings, project_uid, CATEGORY, rows
    )

    statistics = await statistics_for(project_uid)
    statistics.scanned_files = submission.scanned_files
    statistics.endpoints_detected = submission.endpoints_detected
    statistics.unauthenticated_endpoints = sum(
        1
        for _, _, item in unique.values()
        if item.issue_type in UNAUTHENTICATED_ISSUES
    )
    statistics.truncated = truncated
    statistics.engine = _engine_label(submission)
    statistics.last_scan = _now_iso()

    # Volumes et types : jamais un extrait, jamais un chemin de secret.
    logger.info(
        "Analyse d'API du projet %s : %s fichier(s) analyse(s), %s route(s) "
        "relevee(s), %s signalement(s) retenu(s) (%s nouveau(x), %s mis a "
        "jour, %s disparu(s))%s",
        project_uid,
        submission.scanned_files,
        submission.endpoints_detected,
        len(rows),
        outcome["inserted"],
        outcome["updated"],
        outcome["removed"],
        " [tronque]" if truncated else "",
    )

    return ApiScanResult(
        project_uid=project_uid,
        findings=await stored_findings(project_uid),
        statistics=statistics,
        warnings=warnings,
    )


def _engine_label(submission: ApiScanSubmission) -> str:
    engine = submission.engine or ENGINE
    return f"{engine}@{submission.engine_version}" if submission.engine_version else engine


async def statistics_for(project_uid: str) -> ApiStatistics:
    """Compteurs d'API pour un projet. Aucun chemin, que des nombres."""
    counts = await asyncio.to_thread(
        store.count_security_findings, project_uid, CATEGORY
    )
    files = await asyncio.to_thread(
        store.count_files_with_security_findings, project_uid, CATEGORY
    )

    return ApiStatistics(
        total=sum(counts.values()),
        critical=counts["CRITICAL"],
        high=counts["HIGH"],
        medium=counts["MEDIUM"],
        low=counts["LOW"],
        files_with_findings=files,
    )


async def stored_findings(project_uid: str) -> list[SecurityFinding]:
    """Findings d'API enregistres pour ce projet."""
    from app.security import secrets as secret_service

    rows = await asyncio.to_thread(
        store.list_security_findings, project_uid, CATEGORY, "open"
    )
    # `row_to_finding` est generique : il reconstruit un finding depuis sa
    # ligne, quelle que soit sa categorie. Le reecrire ici produirait deux
    # lectures divergentes de la meme table.
    return [secret_service.row_to_finding(row) for row in rows]
