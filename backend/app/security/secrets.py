"""Reception et persistance des balayages de secrets.

Ce module ne detecte rien. La detection tourne **sur le poste**, dans
l'extension : lire les fichiers d'un projet pour y chercher un secret est
une operation locale, et l'envoi de ces fichiers a un serveur pour la meme
raison n'en serait pas une. Le backend recoit des constats, les nettoie,
les range et les compte.

Trois garanties tenues ici, et ou elles sont tenues :

- **aucune valeur de secret n'est ecrite en base** — `SecurityFinding`
  reexpurge `evidence` dans son validateur, et le journal ne reprend que
  des volumes et des types ;
- **aucun secret n'est journalise** — les lignes de journal de ce module
  portent des decomptes et des chemins, jamais une preuve ;
- **une decision de l'utilisateur survit a un nouveau balayage** — c'est
  `store.sync_security_findings` qui s'en charge, via l'empreinte.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone

from app import store
from app.config import settings
from app.security import secret_catalog
from app.security.schemas import (
    SecretFindingSubmission,
    SecretScanResult,
    SecretScanSubmission,
    SecretStatistics,
    SecurityFinding,
    finding_fingerprint,
    finding_id_for,
)

logger = logging.getLogger(__name__)

CATEGORY = "SECRET"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def apply_confidence(severity: str, confidence: str) -> str:
    """Plafonne la gravite affichee par la confiance de la detection.

    Regle imposee par la specification, et qui merite son explication :
    **une detection de faible confiance ne s'affiche jamais en CRITICAL.**

    Le raisonnement n'est pas cosmetique. Une liste de findings critiques
    ou un sur deux est un faux positif cesse d'etre lue — et le jour ou un
    vrai secret y figure, il passe inapercu. Preferer une gravite moyenne
    sur une detection douteuse protege la credibilite du signal, qui est
    la seule chose qui rend l'outil utile.

    La gravite **reelle** du probleme n'est pas perdue pour autant : la
    confiance voyage a cote et l'interface l'affiche.
    """
    level = (severity or "MEDIUM").upper()
    trust = (confidence or "MEDIUM").upper()

    if trust == "LOW":
        # Au plus MEDIUM : visible, mais pas au sommet de la liste.
        return "LOW" if level == "LOW" else "MEDIUM"
    if trust == "MEDIUM" and level == "CRITICAL":
        # Une detection moyennement sure ne monte pas jusqu'au cran le
        # plus haut, reserve a ce qui est formel.
        return "HIGH"
    return level


def fingerprint_of(submission: SecretFindingSubmission) -> str:
    """Empreinte stable d'un secret detecte.

    Le discriminant est le **type** de secret, jamais sa valeur : deux
    balayages du meme fichier produisent la meme empreinte, et rien dans
    la base ne permet de remonter a la valeur detectee.

    Consequence voulue : deplacer une ligne change l'empreinte, donc le
    finding est recree et une decision « faux positif » ne suit pas le
    secret d'une ligne a l'autre. C'est le comportement prudent — la
    decision portait sur ce qui etait la, pas sur ce qui y sera.
    """
    return finding_fingerprint(
        CATEGORY,
        "secret-scanner",
        submission.file_path,
        submission.line,
        submission.secret_type,
    )


def to_finding(
    project_uid: str, submission: SecretFindingSubmission
) -> SecurityFinding:
    """Traduit un constat de l'extension en finding de securite.

    Le vocabulaire francais vient du catalogue backend
    (`secret_catalog`), pas du client : une extension d'une version
    anterieure produit ainsi un message correct, et le libelle reste
    defini a un seul endroit.
    """
    described = secret_catalog.describe(submission.secret_type)
    severity = apply_confidence(submission.severity, submission.confidence)

    return SecurityFinding(
        id=finding_id_for(project_uid, fingerprint_of(submission)),
        project_uid=project_uid,
        category=CATEGORY,
        severity=severity,  # type: ignore[arg-type]
        confidence=submission.confidence,
        title=submission.title or described.title,
        description=submission.description or described.description,
        file=submission.file_path,
        line_start=submission.line,
        line_end=submission.line,
        evidence=submission.evidence_redacted,
        remediation=submission.remediation or described.remediation,
        references=list(submission.references) or list(described.references),
        detection_engine="secret-scanner",
        status="open",
        created_at=_now_iso(),
    )


async def record(
    project_uid: str, submission: SecretScanSubmission
) -> SecretScanResult:
    """Enregistre un balayage de secrets et retourne ce qui en ressort.

    Le plafond est applique **cote serveur** : l'extension a le sien, mais
    le backend ne fait pas confiance a la borne du client. Quand il mord,
    la troncature est annoncee — un decompte plafonne presente comme
    complet serait un mensonge de securite.
    """
    warnings = list(submission.warnings)
    truncated = submission.truncated

    accepted = submission.findings
    limit = settings.secret_max_findings
    if len(accepted) > limit:
        accepted = accepted[:limit]
        truncated = True
        warnings.append(
            f"Balayage de secrets tronque a {limit} signalements par le "
            f"backend ({len(submission.findings)} soumis)."
        )

    # Deduplication par empreinte : deux motifs peuvent reconnaitre le
    # meme secret sur la meme ligne (une cle OpenAI est aussi une « cle
    # d'API generique »). Le premier gagne — les motifs specifiques sont
    # evalues avant les motifs larges, cote extension comme ici.
    unique: dict[str, tuple[str, SecurityFinding]] = {}
    for item in accepted:
        fingerprint = fingerprint_of(item)
        unique.setdefault(fingerprint, (fingerprint, to_finding(project_uid, item)))

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
        for fingerprint, finding in unique.values()
    ]

    outcome = await asyncio.to_thread(
        store.sync_security_findings, project_uid, CATEGORY, rows
    )

    statistics = await statistics_for(project_uid)
    statistics.scanned_files = submission.scanned_files
    statistics.truncated = truncated
    statistics.engine = _engine_label(submission)
    statistics.last_scan = _now_iso()

    # Volumes, types et chemins : jamais une preuve, jamais une valeur.
    logger.info(
        "Balayage de secrets du projet %s : %s fichier(s) analyse(s), "
        "%s signalement(s) retenu(s) (%s nouveau(x), %s mis a jour, "
        "%s disparu(s))%s",
        project_uid,
        submission.scanned_files,
        len(rows),
        outcome["inserted"],
        outcome["updated"],
        outcome["removed"],
        " [tronque]" if truncated else "",
    )

    return SecretScanResult(
        project_uid=project_uid,
        findings=await stored_findings(project_uid),
        statistics=statistics,
        warnings=warnings,
    )


def _engine_label(submission: SecretScanSubmission) -> str:
    engine = submission.engine or "secret-scanner"
    return f"{engine}@{submission.engine_version}" if submission.engine_version else engine


async def statistics_for(project_uid: str) -> SecretStatistics:
    """Compteurs de secrets pour un projet. Aucune valeur, que des nombres."""
    counts = await asyncio.to_thread(
        store.count_security_findings, project_uid, CATEGORY
    )
    files = await asyncio.to_thread(
        store.count_files_with_security_findings, project_uid, CATEGORY
    )

    return SecretStatistics(
        total=sum(counts.values()),
        critical=counts["CRITICAL"],
        high=counts["HIGH"],
        medium=counts["MEDIUM"],
        low=counts["LOW"],
        files_with_secrets=files,
    )


async def stored_findings(project_uid: str) -> list[SecurityFinding]:
    """Findings de secrets enregistres pour ce projet."""
    rows = await asyncio.to_thread(
        store.list_security_findings, project_uid, CATEGORY, "open"
    )
    return [row_to_finding(row) for row in rows]


def row_to_finding(row: dict) -> SecurityFinding:
    """Reconstruit un finding depuis sa ligne de base."""
    try:
        references = json.loads(row.get("reference_links") or "[]")
    except (TypeError, ValueError):
        references = []

    return SecurityFinding(
        id=row["finding_id"],
        project_uid=row["project_uid"],
        category=row["category"],
        severity=row.get("severity", "MEDIUM"),
        confidence=row.get("confidence", "MEDIUM"),
        title=row.get("title", ""),
        description=row.get("description", ""),
        file=row.get("file_path"),
        line_start=int(row.get("line_start") or 0),
        line_end=int(row.get("line_end") or 0),
        evidence=row.get("evidence", ""),
        remediation=row.get("remediation", ""),
        references=references if isinstance(references, list) else [],
        detection_engine=row.get("detection_engine", ""),
        status=row.get("status", "open"),
        created_at=row.get("created_at") or _now_iso(),
    )


def new_finding_id() -> str:
    """Identifiant de repli, quand aucune empreinte n'est calculable."""
    return uuid.uuid4().hex
