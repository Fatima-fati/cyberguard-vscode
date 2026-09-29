"""Orchestration d'un scan de code.

    CodeScanRequest
        -> validation (schemas.py : taille, contenu, empreinte)
        -> cache        (file_path + content_hash)
        -> regles       (rules.py, deterministe, sans reseau)
        -> risque       (risk.py, score explicable)
        -> persistance  (store.py, tables code_*)
        -> CodeScanResult

Contraintes tenues ici :

- **Rien n'est execute.** Le contenu recu est traite comme du texte.
- **Rien n'est ecrit chez le developpeur.** Le backend ne touche jamais
  au poste de travail.
- **Le contenu n'est jamais journalise** : seuls le chemin, la taille et
  l'empreinte apparaissent dans les logs.
- **L'enrichissement IA est optionnel et explicite.** Il n'a lieu que si
  le client le demande ET que le backend l'autorise
  (`CODE_AI_ENRICHMENT_ENABLED`). Desactive, aucune requete ne part vers
  OpenAI : le pipeline s'arrete a la detection deterministe.
- **La reponse HTTP n'attend jamais le modele.** L'enrichissement part en
  tache detachee ; l'editeur recoit immediatement les findings des regles,
  puis la version enrichie par SSE (`event: code_finding`).
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from app import store
from app.ai import agent as ai_agent
from app.ai.openai_client import AIDisabledError, AIError
from app.ai.schemas import RiskFactor
from app.code import analyzer, risk, rules
from app.code.analyzer import enrichment_enabled
from app.code.schemas import (
    CodeFinding,
    CodeLocation,
    CodeModelFinding,
    CodeScanRequest,
    CodeScanResult,
    RuleHit,
    SeverityCounts,
)
from app.config import settings
from app.models import StreamEvent
from app.notifier import stream

logger = logging.getLogger(__name__)

# Taches d'enrichissement en cours. Referencees pour qu'asyncio ne les
# ramasse pas avant la fin (meme precaution que `poller._spawn`).
_background: set[asyncio.Task] = set()


class CodeAnalysisDisabledError(Exception):
    """L'analyse de code est desactivee dans la configuration."""

    status_code = 503

    def __init__(self, message: str, detail: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.detail = detail


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _loads(value: Any) -> list:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return []
    return parsed if isinstance(parsed, list) else []


# --------------------------------------------------------------------------
# Conversion base <-> modele
# --------------------------------------------------------------------------


def row_to_finding(row: dict[str, Any], file_path: str = "") -> CodeFinding:
    return CodeFinding(
        finding_uid=row["finding_uid"],
        scan_uid=row.get("scan_uid") or "",
        rule_id=row["rule_id"],
        category=row["category"],
        cwe=row["cwe"],
        owasp=row["owasp"],
        severity=row["severity"],
        risk_score=row["risk_score"],
        confidence=row["confidence"],
        source=row["source"],
        title=row["title"] or "",
        explanation=row["explanation"] or "",
        why_dangerous=row["why_dangerous"] or "",
        potential_impact=_loads(row["potential_impact"]),
        recommendations=_loads(row["recommendations"]),
        risk_factors=[RiskFactor(**item) for item in _loads(row["risk_factors"])],
        location=CodeLocation(
            line_start=row["line_start"],
            line_end=row["line_end"],
            column_start=row["column_start"],
            column_end=row["column_end"],
            snippet=row["snippet"] or "",
        ),
        file_path=file_path or row.get("scan_file_path") or "",
        fix_available=bool(row["fix_available"]),
        fix_summary=row["fix_summary"] or "",
        status=row["status"],
        decision_reason=row["decision_reason"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _counts(findings: list[CodeFinding]) -> SeverityCounts:
    counts = SeverityCounts()
    for finding in findings:
        if finding.status != "open":
            continue
        if finding.severity == "CRITICAL":
            counts.critical += 1
        elif finding.severity == "HIGH":
            counts.high += 1
        elif finding.severity == "MEDIUM":
            counts.medium += 1
        else:
            counts.low += 1
    return counts


def _enrichment_applied(scan_row: dict[str, Any]) -> bool:
    """L'enrichissement IA a-t-il reellement abouti pour ce scan ?

    Deux conditions verifiables : l'analyse est terminee ET un modele est
    enregistre. Un scan `pending`, `analyzing` ou `failed` ne pretend
    jamais avoir ete enrichi.
    """
    return bool(scan_row.get("model")) and scan_row.get("analysis_status") == "analyzed"


def _result_from_scan(
    scan_row: dict[str, Any],
    findings: list[CodeFinding],
    *,
    cached: bool,
    ai_requested: bool,
) -> CodeScanResult:
    return CodeScanResult(
        scan_uid=scan_row["scan_uid"],
        file_path=scan_row["file_path"],
        language=scan_row["language"],
        content_hash=scan_row["content_hash"],
        workspace=scan_row["workspace"],
        line_count=scan_row["line_count"],
        rules_version=scan_row["rules_version"],
        analysis_status=scan_row["analysis_status"],
        analysis_error=scan_row["analysis_error"],
        model=scan_row["model"] or "",
        findings=findings,
        counts=_counts(findings),
        cached=cached,
        ai_enrichment_requested=ai_requested,
        # Deduit de l'etat reel du scan : on ne pretend jamais qu'une
        # analyse IA a eu lieu sans preuve en base.
        ai_enrichment_applied=_enrichment_applied(scan_row),
        created_at=scan_row["created_at"],
        analyzed_at=scan_row["analyzed_at"],
    )


# --------------------------------------------------------------------------
# Lecture
# --------------------------------------------------------------------------


def _load_scan_sync(scan_uid: str) -> Optional[tuple[dict, list[CodeFinding]]]:
    scan_row = store.get_code_scan(scan_uid)
    if scan_row is None:
        return None

    rows = store.list_code_findings_by_scan(scan_row["id"])
    findings = [
        row_to_finding({**row, "scan_uid": scan_uid}, scan_row["file_path"])
        for row in rows
    ]
    return scan_row, findings


async def get_scan(scan_uid: str) -> Optional[CodeScanResult]:
    """Relit un scan deja effectue (repli quand le SSE n'est pas dispo)."""
    loaded = await asyncio.to_thread(_load_scan_sync, scan_uid)
    if loaded is None:
        return None

    scan_row, findings = loaded
    return _result_from_scan(scan_row, findings, cached=True, ai_requested=False)


# --------------------------------------------------------------------------
# Analyse
# --------------------------------------------------------------------------


def _persist_sync(
    request: CodeScanRequest,
    hits: list,
    enrichment_planned: bool = False,
) -> tuple[dict[str, Any], list[CodeFinding]]:
    """Enregistre le scan et ses findings. Retourne (ligne, findings)."""
    scan_uid = uuid.uuid4().hex
    now = _now_iso()

    scan_id = store.insert_code_scan(
        {
            "scan_uid": scan_uid,
            "workspace": request.workspace,
            "project_uid": request.project_uid,
            "file_path": request.file_path,
            "language": request.language,
            "content_hash": request.content_hash,
            "line_count": request.line_count,
            "rules_version": rules.RULES_VERSION,
            # Sans enrichissement, la detection deterministe est la seule
            # analyse prevue : le scan est termine. Avec enrichissement,
            # il reste en attente jusqu'au verdict du modele.
            "analysis_status": "pending" if enrichment_planned else "analyzed",
            "analysis_error": None,
            "model": "",
            "created_at": now,
            "analyzed_at": None if enrichment_planned else now,
        }
    )
    store.mark_code_scan_seen(scan_id, now)

    hits_in_file = len(hits)
    findings: list[CodeFinding] = []

    for hit in hits:
        score, severity, _band, factors, confidence = risk.assess(
            hit, file_path=request.file_path, hits_in_file=hits_in_file
        )
        finding_uid = uuid.uuid4().hex

        store.insert_code_finding(
            {
                "scan_id": scan_id,
                "finding_uid": finding_uid,
                "rule_id": hit.rule_id,
                "category": hit.category,
                "cwe": hit.cwe,
                "owasp": hit.owasp,
                "severity": severity,
                "risk_score": score,
                "confidence": confidence,
                "source": "rule",
                "title": hit.title,
                "explanation": hit.explanation,
                "why_dangerous": hit.why_dangerous,
                "potential_impact": json.dumps(
                    hit.potential_impact, ensure_ascii=False
                ),
                "recommendations": json.dumps(
                    hit.recommendations, ensure_ascii=False
                ),
                "risk_factors": json.dumps(
                    [factor.model_dump() for factor in factors], ensure_ascii=False
                ),
                "line_start": hit.location.line_start,
                "line_end": hit.location.line_end,
                "column_start": hit.location.column_start,
                "column_end": hit.location.column_end,
                "snippet": hit.location.snippet,
                "fix_available": 0,
                "fix_summary": "",
                "status": "open",
                "decision_reason": None,
                "created_at": now,
                "updated_at": None,
            }
        )

        findings.append(
            CodeFinding(
                finding_uid=finding_uid,
                scan_uid=scan_uid,
                rule_id=hit.rule_id,
                category=hit.category,
                cwe=hit.cwe,
                owasp=hit.owasp,
                severity=severity,
                risk_score=score,
                confidence=confidence,
                source="rule",
                title=hit.title,
                explanation=hit.explanation,
                why_dangerous=hit.why_dangerous,
                potential_impact=list(hit.potential_impact),
                recommendations=list(hit.recommendations),
                risk_factors=factors,
                location=hit.location,
                file_path=request.file_path,
                status="open",
                created_at=now,
            )
        )

    scan_row = store.get_code_scan(scan_uid)
    return scan_row, findings


async def scan(request: CodeScanRequest) -> CodeScanResult:
    """Analyse un document et retourne le resultat complet.

    Le cache est consulte en premier : un contenu deja analyse ne relance
    aucune detection et ressort avec `cached: true`.
    """
    if not settings.code_analysis_enabled:
        raise CodeAnalysisDisabledError(
            "L'analyse de code est désactivée",
            detail="Activez CODE_ANALYSIS_ENABLED dans backend/.env",
        )

    # --- Cache : meme fichier, meme contenu -> meme resultat.
    cached_row = await asyncio.to_thread(
        store.get_code_scan_by_hash, request.file_path, request.content_hash
    )

    # Un resultat en cache n'est valable que s'il a ete produit par le
    # catalogue de regles actuel. Une regle corrigee doit reanalyser les
    # fichiers deja vus : sinon le correctif reste sans effet visible,
    # l'utilisateur relance son scan et retrouve indefiniment l'ancien
    # resultat. Le scan perime est supprime, la contrainte d'unicite
    # (file_path, content_hash) n'admettant qu'une entree par contenu.
    if cached_row is not None and cached_row["rules_version"] != rules.RULES_VERSION:
        logger.info(
            "Cache invalide pour %s : catalogue %s -> %s, reanalyse",
            request.file_path,
            cached_row["rules_version"] or "(inconnu)",
            rules.RULES_VERSION,
        )
        await asyncio.to_thread(store.delete_code_scan, int(cached_row["id"]))
        cached_row = None

    if cached_row is not None:
        loaded = await asyncio.to_thread(_load_scan_sync, cached_row["scan_uid"])
        if loaded is not None:
            scan_row, findings = loaded
            # Ce contenu redevient l'etat courant du fichier : un fichier
            # corrige en revenant a une version deja analysee ne doit pas
            # garder pour dernier scan celui du contenu fautif. Seulement
            # pour le projet proprietaire du scan : le cache est partage
            # entre projets, leur etat courant ne l'est pas.
            if (cached_row.get("project_uid") or None) == (request.project_uid or None):
                await asyncio.to_thread(
                    store.mark_code_scan_seen, int(cached_row["id"]), _now_iso()
                )
            logger.info(
                "Scan servi depuis le cache : %s (%s findings)",
                request.file_path,
                len(findings),
            )
            return _result_from_scan(
                scan_row,
                findings,
                cached=True,
                ai_requested=request.ai_enrichment,
            )

    # --- Detection deterministe. Aucun reseau, aucune execution.
    hits = rules.scan_content(
        request.content,
        language=request.language,
        changed_lines=request.changed_lines,
        max_findings=settings.code_max_findings_per_scan,
    )

    # L'enrichissement n'a lieu que si le client le demande ET que le
    # backend l'autorise. Les deux conditions sont verifiees ici, une
    # seule fois, avant toute ecriture.
    enrichment_planned = bool(hits) and request.ai_enrichment and enrichment_enabled()

    scan_row, findings = await asyncio.to_thread(
        _persist_sync, request, hits, enrichment_planned
    )

    # Le contenu n'apparait jamais dans les journaux : chemin, taille et
    # nombre de findings suffisent au diagnostic.
    logger.info(
        "Scan de %s (%s, %s lignes) : %s finding(s), regles %s",
        request.file_path,
        request.language,
        request.line_count,
        len(findings),
        rules.RULES_VERSION,
    )

    if enrichment_planned:
        # Tache detachee : la reponse HTTP part maintenant, le modele
        # travaille ensuite. L'editeur recevra la version enrichie par SSE.
        _spawn(
            _enrich_scan(
                scan_uid=scan_row["scan_uid"],
                scan_id=scan_row["id"],
                file_path=request.file_path,
                language=request.language,
                content=request.content,
                pairs=list(zip(hits, findings)),
                project_uid=request.project_uid,
            ),
            label=request.file_path,
        )
    elif request.ai_enrichment:
        logger.debug(
            "Enrichissement IA demande mais desactive pour %s", request.file_path
        )

    return _result_from_scan(
        scan_row,
        findings,
        cached=False,
        ai_requested=request.ai_enrichment,
    )


# --------------------------------------------------------------------------
# Enrichissement IA
# --------------------------------------------------------------------------
#
# Chaine : finding deterministe -> extrait expurge -> modele -> fusion des
# scores -> persistance -> SSE. Rien de tout cela n'est attendu par la
# requete HTTP, et aucune erreur ne remonte a l'appelant.


def _spawn(coroutine, label: str) -> None:
    """Lance une coroutine en arriere-plan sans jamais l'attendre."""
    task = asyncio.create_task(coroutine, name=f"code-enrich-{label}")
    _background.add(task)
    task.add_done_callback(_background.discard)


async def _publish_finding(
    finding: CodeFinding,
    scan_uid: str,
    file_path: str,
    analysis_status: str,
    project_uid: Optional[str] = None,
) -> None:
    """Pousse un finding enrichi aux clients connectes. Jamais bloquant.

    `project_uid` cible la diffusion : un finding porte un extrait du
    code analyse, il ne doit atteindre que les clients ouverts sur ce
    projet. Sans projet (fichier isole), la portee reste globale.
    """
    try:
        await stream.publish(
            StreamEvent(
                type="code_finding",
                data={
                    **finding.model_dump(mode="json"),
                    "scan_uid": scan_uid,
                    "file_path": file_path,
                    "analysis_status": analysis_status,
                },
            ),
            project_uid=project_uid,
        )
    except Exception:  # noqa: BLE001 - une panne SSE n'invalide pas l'analyse
        logger.exception("Diffusion SSE du finding impossible")


async def _publish_scan_state(
    scan_uid: str,
    file_path: str,
    analysis_status: str,
    error: Optional[str],
    project_uid: Optional[str] = None,
) -> None:
    """Annonce la fin (ou l'echec) de l'enrichissement d'un scan.

    Necessaire meme sans finding enrichi : sans cet evenement, l'editeur
    resterait indefiniment sur « analyse en cours ».
    """
    try:
        await stream.publish(
            StreamEvent(
                type="code_scan",
                data={
                    "scan_uid": scan_uid,
                    "file_path": file_path,
                    "analysis_status": analysis_status,
                    "analysis_error": error,
                },
            ),
            project_uid=project_uid,
        )
    except Exception:  # noqa: BLE001
        logger.exception("Diffusion SSE de l'etat du scan impossible")


def _apply_verdict_sync(
    finding: CodeFinding,
    hit: RuleHit,
    verdict: CodeModelFinding,
    file_path: str,
    hits_in_file: int,
) -> CodeFinding:
    """Fusionne le verdict du modele avec l'evaluation deterministe.

    La categorie, le CWE et l'OWASP restent ceux de la regle : ils sont
    lies au motif detecte, et laisser le modele les redefinir creerait des
    incoherences avec le catalogue expose par /api/code/rules.
    """
    row = store.get_code_finding(finding.finding_uid)
    if row is None:
        return finding

    now = _now_iso()

    # Le modele conclut que la regle s'est trompee : le finding est ecarte,
    # jamais supprime, et la raison est conservee.
    if verdict.false_positive:
        reason = verdict.explanation or "Écarté par l'analyse IA."
        store.update_code_finding_fields(
            row["id"],
            status="dismissed",
            decision_reason=reason[:300],
            source="ia",
            confidence=verdict.confidence,
            updated_at=now,
        )
        finding.status = "dismissed"
        finding.decision_reason = reason[:300]
        finding.source = "ia"
        finding.confidence = verdict.confidence
        finding.updated_at = now
        return finding

    score, severity, _band, factors = risk.assess_with_model(
        hit,
        verdict.risk_score,
        verdict.risk_factors,
        file_path=file_path,
        hits_in_file=hits_in_file,
    )

    store.update_code_finding_fields(
        row["id"],
        severity=severity,
        risk_score=score,
        confidence=verdict.confidence,
        source="ia",
        title=verdict.title or finding.title,
        explanation=verdict.explanation or finding.explanation,
        why_dangerous=verdict.why_dangerous or finding.why_dangerous,
        potential_impact=json.dumps(
            verdict.potential_impact or finding.potential_impact, ensure_ascii=False
        ),
        recommendations=json.dumps(
            verdict.recommendations or finding.recommendations, ensure_ascii=False
        ),
        risk_factors=json.dumps(
            [factor.model_dump() for factor in factors], ensure_ascii=False
        ),
        fix_available=1 if verdict.fix_available else 0,
        fix_summary=verdict.fix_summary,
        updated_at=now,
    )

    finding.severity = severity
    finding.risk_score = score
    finding.confidence = verdict.confidence
    finding.source = "ia"
    finding.title = verdict.title or finding.title
    finding.explanation = verdict.explanation or finding.explanation
    finding.why_dangerous = verdict.why_dangerous or finding.why_dangerous
    finding.potential_impact = verdict.potential_impact or finding.potential_impact
    finding.recommendations = verdict.recommendations or finding.recommendations
    finding.risk_factors = factors
    finding.fix_available = verdict.fix_available
    finding.fix_summary = verdict.fix_summary
    finding.updated_at = now
    return finding


async def _enrich_scan(
    scan_uid: str,
    scan_id: int,
    file_path: str,
    language: str,
    content: str,
    pairs: list[tuple[RuleHit, CodeFinding]],
    project_uid: Optional[str] = None,
) -> None:
    """Fait qualifier chaque finding par le modele, puis publie le resultat.

    Ne leve jamais : une panne du modele laisse les findings deterministes
    en place et marque le scan `failed`. Aucun resultat n'est invente.
    """
    await asyncio.to_thread(
        store.update_code_scan_fields, scan_id, analysis_status="analyzing"
    )
    await _publish_scan_state(
        scan_uid, file_path, "analyzing", None, project_uid=project_uid
    )

    hits_in_file = len(pairs)
    enriched = 0
    failures: list[str] = []
    disabled = False

    for hit, finding in pairs:
        try:
            # Semaphore partage avec l'analyse des alertes Wazuh : le
            # plafond AI_MAX_CONCURRENCY vaut pour tout le projet.
            async with ai_agent.get_semaphore():
                verdict = await analyzer.enrich_finding(
                    hit, content, file_path, language
                )
        except AIDisabledError as exc:
            # Inutile d'insister sur les findings suivants.
            disabled = True
            failures.append(exc.message)
            break
        except AIError as exc:
            failures.append(f"{hit.rule_id} : {exc.message}")
            logger.warning(
                "Enrichissement impossible pour %s (%s) : %s",
                file_path,
                hit.rule_id,
                exc.message,
            )
            continue
        except Exception as exc:  # noqa: BLE001 - rien ne doit remonter
            failures.append(f"{hit.rule_id} : {exc}")
            logger.exception("Erreur inattendue pendant l'enrichissement de %s", file_path)
            continue

        updated = await asyncio.to_thread(
            _apply_verdict_sync, finding, hit, verdict, file_path, hits_in_file
        )
        enriched += 1
        await _publish_finding(
            updated, scan_uid, file_path, "analyzing", project_uid=project_uid
        )

    # Verdict global : analyse aboutie, partielle, ou en echec.
    if enriched == 0 and failures:
        status = "failed"
        error = failures[0] if disabled else " | ".join(failures[:3])
    else:
        status = "analyzed"
        error = (
            f"{len(failures)} finding(s) non enrichi(s) : {failures[0]}"
            if failures
            else None
        )

    await asyncio.to_thread(
        store.update_code_scan_fields,
        scan_id,
        analysis_status=status,
        analysis_error=error,
        model=settings.openai_model if enriched else "",
        analyzed_at=_now_iso(),
    )

    logger.info(
        "Enrichissement de %s termine : %s/%s finding(s), statut %s",
        file_path,
        enriched,
        hits_in_file,
        status,
    )
    await _publish_scan_state(
        scan_uid, file_path, status, error, project_uid=project_uid
    )
