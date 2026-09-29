"""Routes HTTP de l'analyse de code : /api/code/*.

Routeur independant, monte a cote du routeur principal : aucune route
Wazuh ou IA existante n'est modifiee.

Ce que ces routes ne font jamais : executer le code recu, lancer une
commande systeme, ecrire dans le workspace du developpeur, ou appeler
OpenAI (phase 1).

Authentification (phase 0)
--------------------------

Deux routeurs, et la separation est intentionnelle :

- `router` porte `GET /api/code/health`, **public**. C'est la route de
  diagnostic : si elle exigeait un jeton, un probleme d'authentification
  deviendrait indiscernable d'un backend eteint, et le premier symptome
  serait une extension muette sans explication.
- `protected` porte tout le reste, sous `AGENT_AUTH`. Le defaut est donc
  « protege » : une route ajoutee ici demain l'est sans qu'on y pense.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from app import store
from app.auth import AGENT_AUTH
from app.code import fixes, rules, scanner
from app.code.analyzer import enrichment_enabled
from app.code.schemas import (
    CodeFinding,
    CodeFindingDecision,
    CodeFixProposal,
    CodeHealth,
    CodeRuleInfo,
    CodeScanRequest,
    CodeScanResult,
    CodeStats,
    SeverityCounts,
)
from app.code.scanner import CodeAnalysisDisabledError
from app.config import settings
from app import i18n

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/code", tags=["code"])

# Routes sensibles : analyse, findings, correctifs, statistiques. Le jeton
# local est exige a l'entree du routeur, pas route par route — un oubli ne
# peut donc pas ouvrir une porte.
protected = APIRouter(dependencies=[AGENT_AUTH])

# Version du contrat expose a l'extension. L'extension la compare a la
# sienne pour prevenir clairement en cas de decalage.
API_VERSION = "1.0.0"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _disabled_error(exc: CodeAnalysisDisabledError) -> HTTPException:
    return HTTPException(
        status_code=exc.status_code,
        detail={"error": exc.message, "detail": exc.detail},
    )


# --------------------------------------------------------------------------
# Etat du service
# --------------------------------------------------------------------------


@router.get("/health", response_model=CodeHealth)
async def code_health():
    """Etat du cerveau d'analyse, consulte par l'extension au demarrage."""
    try:
        await asyncio.to_thread(store.code_stats)
        database = "ok"
    except Exception as exc:  # noqa: BLE001 - le health ne plante jamais
        logger.warning("Base indisponible pour l'analyse de code: %s", exc)
        database = "error"

    return CodeHealth(
        status="ok" if database == "ok" and settings.code_analysis_enabled else "degraded",
        analysis_enabled=settings.code_analysis_enabled,
        # Faux tant que l'enrichissement n'est pas active : on n'annonce
        # jamais une capacite IA qui ne tournera pas.
        ai_enabled=enrichment_enabled(),
        rules_version=rules.RULES_VERSION,
        rules_count=len(rules.RULES),
        api_version=API_VERSION,
        max_content_bytes=settings.code_max_content_bytes,
        database=database,
        # Annonce, sans reveler le jeton : l'extension sait si elle doit en
        # presenter un, et un 401 ailleurs devient diagnosticable depuis la
        # seule route publique.
        auth_required=settings.agent_auth_enabled,
        project_context_enabled=True,
        # Vrai des lors que l'une des trois capacites de la phase 2 est
        # active : le detail de chacune est donne par
        # GET /api/security/health.
        project_security_enabled=(
            settings.secret_detection_enabled
            or settings.dependency_inventory_enabled
        ),
    )


@protected.get("/rules", response_model=list[CodeRuleInfo])
async def code_rules():
    """Catalogue des regles deterministes disponibles."""
    return [
        CodeRuleInfo(
            rule_id=rule.rule_id,
            category=rule.category,
            category_label=i18n.code_category_label(rule.category),
            cwe=rule.cwe,
            owasp=rule.owasp,
            severity=rule.severity,
            severity_label=i18n.severity_label(rule.severity),
            confidence=rule.confidence,
            languages=list(rule.languages) or ["*"],
            description=rule.description,
        )
        for rule in rules.catalogue()
    ]


# --------------------------------------------------------------------------
# Analyse
# --------------------------------------------------------------------------


@protected.post("/scan", response_model=CodeScanResult)
async def code_scan(request: CodeScanRequest):
    """Analyse un document envoye par l'extension.

    Le contenu est traite comme du texte : jamais execute, jamais ecrit
    sur disque, jamais journalise. Un contenu deja analyse (meme fichier,
    meme empreinte) ressort du cache avec `cached: true`.
    """
    try:
        return await scanner.scan(request)
    except CodeAnalysisDisabledError as exc:
        raise _disabled_error(exc) from exc


@protected.get("/scans/{scan_uid}", response_model=CodeScanResult)
async def code_scan_detail(scan_uid: str):
    """Relit un scan : repli quand le flux temps reel n'est pas disponible."""
    result = await scanner.get_scan(scan_uid)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "Analyse introuvable", "detail": scan_uid},
        )
    return result


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------


@protected.get("/findings", response_model=list[CodeFinding])
async def code_findings(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    file_path: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None, description="LOW|MEDIUM|HIGH|CRITICAL"),
    status: Optional[str] = Query(default=None, description="open|dismissed|fixed"),
    category: Optional[str] = Query(default=None),
    since: Optional[str] = Query(default=None, description="Date ISO minimale"),
    project_uid: Optional[str] = Query(
        default=None,
        max_length=64,
        description=(
            "Restreint l'historique a un projet. Sans ce filtre, la route "
            "renvoie les findings de tous les projets analyses par ce "
            "backend — deux projets partageant src/app.py se melangeraient."
        ),
    ),
    current_only: bool = Query(
        default=False,
        description=(
            "Avec project_uid : seul le dernier scan de chaque fichier. Un "
            "dernier scan sans finding n'apparait pas dans l'historique."
        ),
    ),
):
    """Historique filtre et pagine des findings."""
    rows = await asyncio.to_thread(
        store.list_code_findings,
        min(limit, settings.code_findings_page_size),
        offset,
        file_path,
        severity,
        status,
        category,
        since,
        project_uid,
        current_only,
    )
    return [scanner.row_to_finding(row) for row in rows]


async def _load_finding(finding_uid: str) -> dict:
    row = await asyncio.to_thread(store.get_code_finding, finding_uid)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "Finding introuvable", "detail": finding_uid},
        )
    return row


@protected.post("/findings/{finding_uid}/fix", response_model=CodeFixProposal)
async def code_finding_fix(
    finding_uid: str,
    current_line: Optional[str] = Query(
        default=None,
        description="Ligne telle qu'elle est dans l'editeur (controle de derive)",
    ),
):
    """Propose un correctif. **Ne modifie jamais aucun fichier.**

    Le backend ne connait pas le poste du developpeur et n'y ecrit rien :
    il decrit la modification, l'editeur l'appliquera apres confirmation.
    """
    row = await _load_finding(finding_uid)

    scan_row = await asyncio.to_thread(store.get_code_scan_by_id, row["scan_id"])
    enriched = {
        **row,
        "scan_file_path": (scan_row or {}).get("file_path", ""),
        "_recommendations": json.loads(row["recommendations"] or "[]"),
    }

    proposal = fixes.propose(enriched, current_line=current_line)

    # Trace de la proposition : utile a l'audit, sans aucune ecriture de
    # fichier. `applied_in_editor` reste a 0 : seule l'extension pourra
    # signaler une application effective.
    if proposal.available:
        await asyncio.to_thread(
            store.insert_code_fix,
            {
                "finding_id": row["id"],
                "original_line": proposal.original_line,
                "replacement_line": proposal.replacement_line,
                "explanation": proposal.explanation,
                "diff": proposal.diff,
                "applied_in_editor": 0,
                "created_at": _now_iso(),
            },
        )

    return proposal


@protected.post("/findings/{finding_uid}/decision", response_model=CodeFinding)
async def code_finding_decision(finding_uid: str, decision: CodeFindingDecision):
    """Enregistre la decision du developpeur : ignore ou corrige.

    Le finding n'est jamais supprime : son historique reste consultable.
    """
    row = await _load_finding(finding_uid)

    await asyncio.to_thread(
        store.update_code_finding_fields,
        row["id"],
        status=decision.status,
        decision_reason=decision.reason,
        updated_at=_now_iso(),
    )

    scan_row = await asyncio.to_thread(store.get_code_scan_by_id, row["scan_id"])
    logger.info(
        "Finding %s marqué %s par %s",
        finding_uid,
        decision.status,
        decision.actor,
    )

    updated = await _load_finding(finding_uid)
    return scanner.row_to_finding(
        {**updated, "scan_uid": (scan_row or {}).get("scan_uid", "")},
        (scan_row or {}).get("file_path", ""),
    )


# --------------------------------------------------------------------------
# Statistiques
# --------------------------------------------------------------------------


@protected.get("/stats", response_model=CodeStats)
async def code_stats():
    """Vue globale : volumes, repartition par severite et par categorie."""
    counters = await asyncio.to_thread(store.code_stats)

    return CodeStats(
        scans=counters["scans"],
        files=counters["files"],
        findings=counters["findings"],
        open=counters["open"],
        dismissed=counters["dismissed"],
        fixed=counters["fixed"],
        by_severity=SeverityCounts(
            critical=counters["critical"],
            high=counters["high"],
            medium=counters["medium"],
            low=counters["low"],
        ),
        by_category=counters["by_category"],
        ai_enabled=enrichment_enabled(),
        rules_version=rules.RULES_VERSION,
    )


# --------------------------------------------------------------------------
# Montage
# --------------------------------------------------------------------------
#
# En fin de fichier, quand toutes les routes protegees sont declarees.
# `protected` herite du prefixe /api/code : les chemins publies ne
# changent pas, seule l'exigence du jeton s'ajoute.
router.include_router(protected)
