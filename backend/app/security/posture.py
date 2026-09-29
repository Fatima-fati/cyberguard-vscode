"""Posture de securite explicable et controle CI/CD (phase 8).

    findings existants + contexte de projet + statistiques de balayage
        -> posture par domaine (aucun score)
        -> politique CI deterministe -> resultat machine

**Aucun moteur nouveau, aucune table nouvelle.** Ce module lit ce que les
phases 1 a 7 ont deja ecrit : `security_findings`, le dernier scan de code
de chaque fichier, l'instantane du contexte de projet. Il n'ecrit rien.

**Aucune IA.** Ni la posture ni la politique ne consultent un modele : le
controle CI tourne sans cle API, et une panne du fournisseur d'IA n'y
change rien. **Aucun appel Wazuh** non plus — un test le verifie sur le
code source.

Deux regles d'honnetete, tenues partout
--------------------------------------

1. **« Jamais analyse » n'est pas « zero finding ».** Un domaine sans
   analyse a `findings = None` et l'etat `not_analyzed`. Aucun chemin de
   code ne remplace cette absence par un 0.
2. **« Aucun finding » n'est pas « sur ».** La couverture accompagne
   chaque domaine : un balayage tronque, des dependances non verifiees, un
   fournisseur muet, un langage sans regles rendent le domaine `partial`,
   et le disent.
"""

import asyncio
import logging
from typing import Optional

from app import store
from app.config import settings
from app.project import context as project_context
from app.project.discovery import ANALYSIS_SUPPORTED_LANGUAGES
from app.project.schemas import ProjectSecurityContext
from app.security import secrets as secret_service
from app.security.posture_schemas import (
    CI_CONDITIONS,
    CiBlockingFinding,
    CiCheckResult,
    CiConditionResult,
    CiPolicy,
    CiPolicyRequest,
    CiProject,
    CiReason,
    PostureArea,
    PostureCoverage,
    PostureHistory,
    SecurityPosture,
    PostureCounts,
)
from app.security.redaction import redact_text
from app.security.schemas import SecurityFinding

logger = logging.getLogger(__name__)

FINDINGS_READ_LIMIT = 5000
MAX_BLOCKING_FINDINGS = 50

# Categorie de finding -> domaine de la posture. `CONFIGURATION` et `CODE`
# sont declarees depuis la phase 2 ; elles rejoignent le domaine « code ».
_AREA_OF_CATEGORY = {
    "SECRET": "secrets",
    "DEPENDENCY": "dependencies",
    "API": "api",
    "CODE": "code",
    "CONFIGURATION": "code",
    "GIT": "git",
}

_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

GIT_BACKEND_NOTE = (
    "L'analyse des changements Git est locale à l'éditeur : elle n'est pas "
    "transmise au backend. Consultez la section « Changements Git »."
)


# --------------------------------------------------------------------------
# Lecture
# --------------------------------------------------------------------------


class _Finding:
    """Un finding ouvert, quelle que soit sa table, reduit a la posture."""

    __slots__ = ("id", "area", "category", "severity", "title", "file", "line", "created_at")

    def __init__(self, id, area, category, severity, title, file, line, created_at):
        self.id = id
        self.area = area
        self.category = category
        self.severity = (severity or "LOW").upper()
        self.title = title or ""
        self.file = file
        self.line = int(line or 0)
        self.created_at = created_at or ""


def _from_security(finding: SecurityFinding) -> _Finding:
    return _Finding(
        finding.id,
        _AREA_OF_CATEGORY.get(finding.category, "code"),
        finding.category,
        finding.severity,
        finding.title,
        finding.file,
        finding.line_start,
        finding.created_at,
    )


def _from_code(row: dict) -> _Finding:
    return _Finding(
        row["finding_uid"],
        "code",
        row.get("category") or "CODE",
        row.get("severity"),
        row.get("title"),
        row.get("file_path"),
        row.get("line_start"),
        row.get("created_at"),
    )


def _count(findings: list[_Finding]) -> PostureCounts:
    counts = PostureCounts(total=len(findings))
    for finding in findings:
        if finding.severity == "CRITICAL":
            counts.critical += 1
        elif finding.severity == "HIGH":
            counts.high += 1
        elif finding.severity == "MEDIUM":
            counts.medium += 1
        else:
            counts.low += 1
    return counts


class _Snapshot:
    """Tout ce que la posture lit, lu une fois."""

    def __init__(
        self,
        project: dict,
        context: Optional[ProjectSecurityContext],
        findings: list[_Finding],
        code_files_scanned: int,
        code_last_scan: Optional[str],
        supported_source_files: int,
    ):
        self.project = project
        self.context = context
        self.findings = findings
        self.code_files_scanned = code_files_scanned
        self.code_last_scan = code_last_scan
        self.supported_source_files = supported_source_files

    def of_area(self, area: str) -> list[_Finding]:
        return [finding for finding in self.findings if finding.area == area]


async def _snapshot(project_uid: str) -> Optional[_Snapshot]:
    project = await asyncio.to_thread(store.get_project_by_uid, project_uid)
    if project is None:
        return None

    context = await project_context.get_context(project_uid)
    rows = await asyncio.to_thread(
        store.list_security_findings, project_uid, None, "open", None, FINDINGS_READ_LIMIT
    )
    code = await asyncio.to_thread(store.project_code_posture, project_uid)

    supported_present = sorted(
        item.language
        for item in (context.languages if context else [])
        if item.language in ANALYSIS_SUPPORTED_LANGUAGES
    )
    supported_files = await asyncio.to_thread(
        store.count_indexed_files_for_languages, int(project["id"]), supported_present
    )

    findings = [_from_security(secret_service.row_to_finding(row)) for row in rows]
    findings += [_from_code(row) for row in code["findings"]]

    return _Snapshot(
        project=project,
        context=context,
        findings=findings,
        code_files_scanned=code["files_scanned"],
        code_last_scan=code["last_scan"],
        supported_source_files=supported_files,
    )


# --------------------------------------------------------------------------
# Domaines
# --------------------------------------------------------------------------


def _area(
    name: str,
    findings: list[_Finding],
    analyzed: bool,
    enabled: bool,
    partial_reasons: list[str],
    last_scan: Optional[str],
    metrics: dict[str, int],
    notes: Optional[list[str]] = None,
) -> PostureArea:
    """Assemble un domaine. Le seul endroit ou un etat est decide."""
    if not analyzed:
        state = "not_analyzed" if enabled else "unavailable"
        return PostureArea(
            area=name,  # type: ignore[arg-type]
            state=state,  # type: ignore[arg-type]
            coverage=state,  # type: ignore[arg-type]
            findings=None,
            last_scan=None,
            metrics={},
            warnings=(
                ["Jamais analysé : aucun résultat, ce qui n'est pas « aucun problème »."]
                if enabled
                else ["Capacité désactivée côté backend : aucune analyse possible."]
            ),
        )

    counts = _count(findings)
    return PostureArea(
        area=name,  # type: ignore[arg-type]
        state="findings" if counts.total > 0 else "no_findings",
        coverage="partial" if partial_reasons else "complete",
        findings=counts,
        last_scan=last_scan,
        metrics=metrics,
        warnings=partial_reasons + (notes or []),
    )


def _index_note(context: Optional[ProjectSecurityContext]) -> list[str]:
    if context and context.file_statistics.truncated:
        return [
            f"Index du projet tronqué ({context.file_statistics.indexed} fichier(s) "
            f"sur {context.file_statistics.discovered}) : des fichiers n'ont pas été analysés."
        ]
    return []


def _secrets_area(snapshot: _Snapshot) -> PostureArea:
    findings = snapshot.of_area("secrets")
    context = snapshot.context
    stats = context.secret_statistics if context else None
    analyzed = bool(stats and stats.last_scan) or bool(findings)

    partial: list[str] = []
    if stats and stats.truncated:
        partial.append("Balayage de secrets plafonné : le décompte est un minimum.")
    if analyzed and not (stats and stats.last_scan):
        partial.append("Statistiques du balayage indisponibles (projet non indexé).")
    partial += _index_note(context)

    return _area(
        "secrets",
        findings,
        analyzed,
        settings.secret_detection_enabled,
        partial,
        stats.last_scan if stats else None,
        {
            "files_with_secrets": stats.files_with_secrets if stats else 0,
            "scanned_files": stats.scanned_files if stats else 0,
        },
    )


def _dependencies_area(snapshot: _Snapshot) -> PostureArea:
    findings = snapshot.of_area("dependencies")
    context = snapshot.context
    stats = context.dependency_statistics if context else None
    vulnerabilities = context.vulnerability_statistics if context else None
    analyzed = bool(stats and stats.last_inventory) or bool(findings)

    partial: list[str] = []
    if stats:
        if stats.truncated:
            partial.append("Inventaire des dépendances plafonné.")
        if stats.unverified > 0:
            partial.append(
                f"{stats.unverified} dépendance(s) non vérifiée(s) : version non "
                "figée, écosystème non couvert ou fournisseur muet."
            )
    # Un fournisseur muet ne compte que s'il y avait quelque chose a
    # verifier : un projet sans dependance n'a rien a faire verifier.
    if vulnerabilities and stats and stats.total > 0 and not vulnerabilities.conclusive:
        partial.append(
            vulnerabilities.message
            or f"Vérification des vulnérabilités non concluante ({vulnerabilities.provider_status})."
        )
    if analyzed and not (stats and stats.last_inventory):
        partial.append("Statistiques d'inventaire indisponibles (projet non indexé).")

    return _area(
        "dependencies",
        findings,
        analyzed,
        settings.dependency_inventory_enabled,
        partial,
        stats.last_inventory if stats else None,
        {
            "dependencies": stats.total if stats else 0,
            "vulnerable": stats.vulnerable if stats else 0,
            "unverified": stats.unverified if stats else 0,
            "manifests_read": stats.manifests_read if stats else 0,
        },
    )


def _api_area(snapshot: _Snapshot) -> PostureArea:
    findings = snapshot.of_area("api")
    context = snapshot.context
    stats = context.api_statistics if context else None
    analyzed = bool(stats and stats.last_scan) or bool(findings)

    partial: list[str] = []
    if stats and stats.truncated:
        partial.append("Analyse d'API plafonnée : le décompte est un minimum.")
    if analyzed and not (stats and stats.last_scan):
        partial.append("Statistiques d'analyse d'API indisponibles (projet non indexé).")
    partial += _index_note(context)

    notes: list[str] = []
    if stats and stats.last_scan and stats.endpoints_detected == 0:
        notes.append(
            "Aucune route reconnue : l'analyse statique ne voit que les "
            "déclarations écrites littéralement."
        )

    return _area(
        "api",
        findings,
        analyzed,
        settings.api_security_enabled,
        partial,
        stats.last_scan if stats else None,
        {
            "endpoints_detected": stats.endpoints_detected if stats else 0,
            "unauthenticated_endpoints": stats.unauthenticated_endpoints if stats else 0,
        },
        notes,
    )


def _unsupported_languages(context: Optional[ProjectSecurityContext]) -> list[str]:
    if not context:
        return []
    return sorted(item.language for item in context.languages if not item.analysis_supported)


def _code_area(snapshot: _Snapshot) -> PostureArea:
    findings = snapshot.of_area("code")
    analyzed = snapshot.code_files_scanned > 0 or bool(findings)

    partial: list[str] = []
    expected = snapshot.supported_source_files
    if expected and snapshot.code_files_scanned < expected:
        partial.append(
            f"{snapshot.code_files_scanned} fichier(s) source analysé(s) sur "
            f"{expected} dans des langages couverts."
        )
    unsupported = _unsupported_languages(snapshot.context)
    if unsupported:
        partial.append(
            "Langage(s) sans règles d'analyse de code : " + ", ".join(unsupported) + "."
        )

    return _area(
        "code",
        findings,
        analyzed,
        settings.code_analysis_enabled,
        partial,
        snapshot.code_last_scan,
        {
            "files_scanned": snapshot.code_files_scanned,
            "supported_source_files": expected,
        },
    )


def _git_area(snapshot: _Snapshot) -> PostureArea:
    """Domaine Git, vu du backend : il ne le connait pas.

    L'attribution « introduit / preexistant » de la phase 4 est locale a
    l'editeur. Le backend le dit plutot que d'afficher un zero ; l'extension
    complete ce domaine avec son propre bilan Git.
    """
    findings = snapshot.of_area("git")
    if findings:
        return _area("git", findings, True, True, [], None, {}, [GIT_BACKEND_NOTE])
    return PostureArea(
        area="git",
        state="unavailable",
        coverage="unavailable",
        findings=None,
        warnings=[GIT_BACKEND_NOTE],
    )


# --------------------------------------------------------------------------
# Posture
# --------------------------------------------------------------------------

# Domaines qui comptent pour « analyse complete ». Git en est exclu : son
# analyse est locale a l'editeur, et son absence ici n'est pas un defaut de
# couverture du projet.
_COVERAGE_AREAS = ("secrets", "dependencies", "code", "api")


def _posture(snapshot: _Snapshot) -> SecurityPosture:
    context = snapshot.context
    areas = [
        _secrets_area(snapshot),
        _dependencies_area(snapshot),
        _code_area(snapshot),
        _api_area(snapshot),
        _git_area(snapshot),
    ]

    relevant = [area for area in areas if area.area in _COVERAGE_AREAS]
    if all(area.coverage in ("not_analyzed", "unavailable") for area in relevant):
        analysis = "not_analyzed"
    elif all(area.coverage == "complete" for area in relevant) and not (
        context and context.file_statistics.truncated
    ):
        analysis = "complete"
    else:
        analysis = "partial"

    vulnerabilities = context.vulnerability_statistics if context else None
    coverage = PostureCoverage(
        context_available=context is not None,
        files_discovered=context.file_statistics.discovered if context else 0,
        files_indexed=context.file_statistics.indexed if context else 0,
        index_truncated=bool(context and context.file_statistics.truncated),
        sensitive_files=context.file_statistics.sensitive if context else 0,
        unsupported_languages=_unsupported_languages(context),
        vulnerability_provider=vulnerabilities.provider if vulnerabilities else "",
        vulnerability_provider_status=(
            vulnerabilities.provider_status if vulnerabilities else "disabled"
        ),
        vulnerability_check_conclusive=bool(vulnerabilities and vulnerabilities.conclusive),
        vulnerability_message=vulnerabilities.message if vulnerabilities else "",
        last_discovery=context.last_discovery if context else None,
    )

    stamps = sorted(finding.created_at for finding in snapshot.findings if finding.created_at)
    history = PostureHistory(
        oldest_open_finding=stamps[0] if stamps else None,
        newest_open_finding=stamps[-1] if stamps else None,
    )

    return SecurityPosture(
        project_uid=snapshot.project["project_uid"],
        project_name=snapshot.project.get("display_name") or "",
        analysis=analysis,  # type: ignore[arg-type]
        findings=_count(snapshot.findings),
        areas=areas,
        coverage=coverage,
        history=history,
    )


async def build_posture(project_uid: str) -> Optional[SecurityPosture]:
    """Posture du projet, ou `None` s'il est inconnu."""
    snapshot = await _snapshot(project_uid)
    return _posture(snapshot) if snapshot else None


# --------------------------------------------------------------------------
# Politique CI
# --------------------------------------------------------------------------


def _conditions_from(value: str) -> list[str]:
    """Liste de conditions tiree d'un reglage. Les noms inconnus sont ignores."""
    names = [item.strip() for item in (value or "").split(",") if item.strip()]
    return [name for name in names if name in CI_CONDITIONS]


def resolve_policy(request: Optional[CiPolicyRequest] = None) -> CiPolicy:
    """Politique effective : la requete, sinon la configuration.

    Un mode inconnu en configuration retombe sur `warn`, jamais sur
    `block` : une faute de frappe ne doit pas durcir un pipeline a l'insu
    de ceux qui le maintiennent.
    """
    configured = (settings.ci_policy_mode or "").strip().lower()
    mode = request.mode if request and request.mode else (
        configured if configured in ("off", "warn", "block") else "warn"
    )
    fail_on = (
        list(request.fail_on)
        if request and request.fail_on is not None
        else _conditions_from(settings.ci_fail_on)
    )
    warn_on = (
        list(request.warn_on)
        if request and request.warn_on is not None
        else _conditions_from(settings.ci_warn_on)
    )
    # Une condition presente dans les deux listes est bloquante.
    warn_on = [item for item in warn_on if item not in fail_on]
    return CiPolicy(mode=mode, fail_on=fail_on, warn_on=warn_on)  # type: ignore[arg-type]


def _area_of(posture: SecurityPosture, name: str) -> PostureArea:
    return next(area for area in posture.areas if area.area == name)


def _measure(posture: SecurityPosture) -> dict[str, tuple[int, str]]:
    """Valeur de chaque condition, et sa phrase. Deterministe."""
    secrets = _area_of(posture, "secrets")
    dependencies = _area_of(posture, "dependencies")
    incomplete = [
        area.area
        for area in posture.areas
        if area.area in _COVERAGE_AREAS and area.coverage != "complete"
    ]
    provider_mute = (
        dependencies.findings is not None
        and dependencies.metrics.get("dependencies", 0) > 0
        and not posture.coverage.vulnerability_check_conclusive
    )
    unsupported = posture.coverage.unsupported_languages

    return {
        "critical_findings": (
            posture.findings.critical,
            f"{posture.findings.critical} finding(s) CRITICAL ouvert(s).",
        ),
        "high_findings": (
            posture.findings.high,
            f"{posture.findings.high} finding(s) HIGH ouvert(s).",
        ),
        "secrets_present": (
            secrets.findings.total if secrets.findings else 0,
            f"{secrets.findings.total if secrets.findings else 0} secret(s) détecté(s).",
        ),
        "vulnerable_dependencies": (
            dependencies.findings.total if dependencies.findings else 0,
            f"{dependencies.findings.total if dependencies.findings else 0} "
            "vulnérabilité(s) de dépendance.",
        ),
        "analysis_incomplete": (
            1 if posture.analysis != "complete" else 0,
            "Analyse incomplète : " + (", ".join(incomplete) if incomplete else "index tronqué")
            + ". L'absence de finding ne prouve rien sur ce qui n'a pas été analysé.",
        ),
        "vulnerability_provider_unavailable": (
            1 if provider_mute else 0,
            "Fournisseur de vulnérabilités non concluant "
            f"({posture.coverage.vulnerability_provider_status}) : des dépendances "
            "n'ont pas pu être vérifiées.",
        ),
        "unsupported_languages": (
            len(unsupported),
            "Langage(s) sans règles d'analyse : " + ", ".join(unsupported) + "."
            if unsupported
            else "Aucun langage non couvert.",
        ),
    }


def _blocking_findings(snapshot: _Snapshot) -> list[CiBlockingFinding]:
    selected = [f for f in snapshot.findings if f.severity in ("CRITICAL", "HIGH")]
    selected.sort(key=lambda f: (_SEVERITY_RANK.get(f.severity, 9), f.file or "", f.line, f.id))
    return [
        CiBlockingFinding(
            id=finding.id,
            area=finding.area,  # type: ignore[arg-type]
            category=finding.category,
            severity=finding.severity,
            # Le titre est reexpurge : il peut venir du client.
            title=redact_text(finding.title, 200),
            file=finding.file,
            line=finding.line,
        )
        for finding in selected[:MAX_BLOCKING_FINDINGS]
    ]


def evaluate(snapshot: _Snapshot, policy: CiPolicy) -> CiCheckResult:
    """Evaluation deterministe : memes donnees, meme politique, meme verdict."""
    posture = _posture(snapshot)
    measures = _measure(posture)

    conditions: list[CiConditionResult] = []
    reasons: list[CiReason] = []
    for code in CI_CONDITIONS:
        value, message = measures[code]
        triggered = value > 0
        action = "ignore"
        if triggered and policy.mode != "off":
            if code in policy.fail_on:
                action = "block" if policy.mode == "block" else "warn"
            elif code in policy.warn_on:
                action = "warn"
        conditions.append(
            CiConditionResult(
                code=code,  # type: ignore[arg-type]
                triggered=triggered,
                value=value,
                action=action,  # type: ignore[arg-type]
                message=message,
            )
        )
        if action in ("block", "warn"):
            reasons.append(CiReason(code=code, action=action, message=message))  # type: ignore[arg-type]

    if policy.mode == "off":
        status = "off"
    elif any(reason.action == "block" for reason in reasons):
        status = "blocked"
    elif reasons:
        status = "warning"
    else:
        status = "passed"

    fail = status == "blocked"
    return CiCheckResult(
        project=CiProject(
            project_uid=posture.project_uid, project_name=posture.project_name
        ),
        policy=policy,
        status=status,  # type: ignore[arg-type]
        exit_decision="fail" if fail else "pass",
        exit_code=1 if fail else 0,
        analysis=posture.analysis,
        counts=posture.findings,
        counts_by_area={
            area.area: area.findings.total if area.findings else None
            for area in posture.areas
        },
        conditions=conditions,
        reasons=reasons,
        incomplete_areas=[
            area.area
            for area in posture.areas
            if area.area in _COVERAGE_AREAS and area.coverage != "complete"
        ],
        unsupported_languages=posture.coverage.unsupported_languages,
        vulnerability_provider_status=posture.coverage.vulnerability_provider_status,
        vulnerability_check_conclusive=posture.coverage.vulnerability_check_conclusive,
        blocking_findings=_blocking_findings(snapshot),
    )


async def ci_check(
    project_uid: str, request: Optional[CiPolicyRequest] = None
) -> Optional[CiCheckResult]:
    """Controle CI d'un projet, ou `None` s'il est inconnu."""
    snapshot = await _snapshot(project_uid)
    if snapshot is None:
        return None
    result = evaluate(snapshot, resolve_policy(request))
    # Volumes et verdict seulement : aucun titre, aucun chemin.
    logger.info(
        "Controle CI du projet %s : %s (politique %s, %s finding(s), analyse %s)",
        project_uid,
        result.status,
        result.policy.mode,
        result.counts.total,
        result.analysis,
    )
    return result
