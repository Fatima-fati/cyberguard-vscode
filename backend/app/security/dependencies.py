"""Inventaire des dependances et analyse de vulnerabilites.

Chaine, et pourquoi elle est dans cet ordre
-------------------------------------------

    inventaire soumis   -> normalise, borne, enregistre
    paquets interrogeables -> fournisseur de vulnerabilites
    reponse du fournisseur -> findings + statistiques

L'inventaire est enregistre **avant** toute interrogation : un fournisseur
injoignable ne doit pas faire perdre l'inventaire, qui a de la valeur en
lui-meme (« ce projet tire 412 dependances, dont 38 directes »).

La regle qui gouverne tout ce module
------------------------------------

**« Le fournisseur n'a pas repondu » n'est pas « il n'y a pas de
vulnerabilite ».** Trois etats, et un seul autorise a conclure :

    verifiee et saine      le fournisseur a repondu, rien pour ce paquet
    verifiee et vulnerable le fournisseur a repondu, voici quoi
    NON VERIFIEE           version non figee, ecosysteme non couvert,
                           fournisseur muet — on ne sait pas

Une dependance non verifiee n'est jamais comptee comme saine : elle est
comptee dans `unverified`, et le message affiche dit « impossible de
verifier », jamais « dependance sure ».
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from app import i18n, store
from app.config import settings
from app.security.providers import (
    PackageQuery,
    ProviderOutcome,
    VulnerabilityProvider,
    get_provider,
    provider_name,
)
from app.security.providers.base import PackageVulnerability
from app.security.schemas import (
    DependencyInventorySubmission,
    DependencyRecord,
    DependencyScanResult,
    DependencyStatistics,
    EcosystemSummary,
    SecurityFinding,
    VulnerabilityStatistics,
    finding_fingerprint,
    finding_id_for,
)
from app.security.secrets import row_to_finding

logger = logging.getLogger(__name__)

CATEGORY = "DEPENDENCY"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------
# Normalisation
# --------------------------------------------------------------------------


def deduplicate(
    dependencies: list[DependencyRecord],
) -> list[DependencyRecord]:
    """Ecarte les doublons en privilegiant la version la plus exploitable.

    Un meme paquet apparait souvent deux fois : une contrainte dans le
    manifeste (`"express": "^4.18.0"`) et une version exacte dans le
    lockfile (`4.18.2`). Les garder toutes les deux gonflerait le
    decompte et, surtout, ferait apparaitre le paquet comme « non
    verifiable » alors qu'il l'est.

    Priorite : lockfile avant manifeste, version figee avant contrainte,
    declaration directe avant transitive.
    """

    def rank(record: DependencyRecord) -> tuple[int, int, int]:
        return (
            0 if record.source == "lockfile" else 1,
            0 if record.version else 1,
            0 if record.direct else 1,
        )

    best: dict[str, DependencyRecord] = {}
    for record in dependencies:
        key = f"{record.ecosystem}|{record.name.lower()}"
        current = best.get(key)
        if current is None or rank(record) < rank(current):
            best[key] = record
        elif rank(record) == rank(current) and record.direct and not current.direct:
            best[key] = record

    return sorted(best.values(), key=lambda item: (item.ecosystem, item.name.lower()))


def queryable(
    dependencies: list[DependencyRecord], provider: VulnerabilityProvider
) -> list[PackageQuery]:
    """Paquets qu'on peut reellement soumettre au fournisseur.

    Deux conditions, et chacune ecarte une categorie de dependances qui
    seront comptees **non verifiees** plutot que saines :

    - une **version figee** : `^1.2.0` decrit un intervalle, pas un
      artefact. Demander « cet intervalle est-il vulnerable ? » n'a pas de
      reponse utile ;
    - un **ecosysteme couvert** par le fournisseur configure.
    """
    supported = provider.supported_ecosystems
    return [
        PackageQuery(
            name=record.name, ecosystem=record.ecosystem, version=record.version
        )
        for record in dependencies
        if record.version and record.ecosystem in supported
    ]


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------


def to_finding(
    project_uid: str,
    record: DependencyRecord,
    vulnerability: PackageVulnerability,
    provider: str,
) -> tuple[str, SecurityFinding]:
    """Construit le finding d'une dependance vulnerable, et son empreinte.

    Le discriminant de l'empreinte est l'identifiant de la vulnerabilite :
    le meme CVE sur le meme paquet reste le meme finding d'un balayage a
    l'autre, meme si la ligne du manifeste a bouge.
    """
    fixed = vulnerability.fixed_version
    remediation = (
        f"Mettez « {record.name} » à jour vers la version {fixed} ou "
        "ultérieure, puis regénérez le fichier de verrouillage."
        if fixed
        else (
            f"Aucune version corrigée n'est publiée pour « {record.name} ». "
            "Vérifiez l'avis en référence, et envisagez un contournement ou "
            "un remplacement de cette dépendance."
        )
    )

    # La gravite deduite d'un vecteur CVSS plutot que d'un score publie
    # est annoncee comme telle : l'utilisateur doit pouvoir faire la part
    # de ce qui est mesure et de ce qui est estime.
    caveat = {
        "cvss-vector": " Gravité estimée à partir du vecteur CVSS, faute de score publié.",
        "unrated": " Aucune gravité n'est publiée pour cet avis : la gravité affichée est un défaut prudent.",
    }.get(vulnerability.severity_source, "")

    summary = vulnerability.summary or "Aucun résumé publié pour cet avis."
    dependency_kind = "directe" if record.direct else "transitive"

    references = list(vulnerability.references)
    for alias in vulnerability.aliases:
        if alias.startswith(("CVE-", "GHSA-", "OSV-")):
            references.append(alias)

    fingerprint = finding_fingerprint(
        CATEGORY,
        provider,
        record.manifest,
        0,
        f"{record.ecosystem}|{record.name}|{vulnerability.identifier}",
    )

    return fingerprint, SecurityFinding(
        id=finding_id_for(project_uid, fingerprint),
        project_uid=project_uid,
        category=CATEGORY,
        severity=vulnerability.severity,
        # La detection est formelle : ce n'est pas une heuristique, c'est
        # une correspondance exacte entre une version et un avis publie.
        confidence="HIGH",
        title=(
            f"{record.name} {record.version} — {vulnerability.identifier}"
        ),
        description=(
            f"La dépendance {dependency_kind} « {record.name} » en version "
            f"{record.version} est concernée par {vulnerability.identifier}. "
            f"{summary}{caveat}"
        ),
        file=record.manifest,
        line_start=0,
        line_end=0,
        evidence=(
            f"{record.ecosystem} · {record.name}@{record.version} "
            f"déclarée dans {record.manifest}"
        ),
        remediation=remediation,
        references=references,
        detection_engine=provider,
        status="open",
        created_at=_now_iso(),
    )


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------


async def record_inventory(
    project_uid: str,
    project_id: int,
    submission: DependencyInventorySubmission,
    provider: Optional[VulnerabilityProvider] = None,
) -> DependencyScanResult:
    """Enregistre l'inventaire, interroge le fournisseur, produit les findings."""
    warnings = list(submission.warnings)
    truncated = submission.truncated

    dependencies = deduplicate(list(submission.dependencies))

    limit = settings.project_max_dependencies
    if len(dependencies) > limit:
        dependencies = dependencies[:limit]
        truncated = True
        warnings.append(
            f"Inventaire tronque a {limit} dependances par le backend "
            f"({len(submission.dependencies)} soumises)."
        )

    engine = provider or get_provider()

    # Le fournisseur n'est interroge que si le client le demande ET que le
    # backend l'autorise. Le client demande, le serveur decide : c'est lui
    # qui detient la sortie reseau.
    if submission.check_vulnerabilities:
        packages = queryable(dependencies, engine)
        outcome = await engine.check(packages)
    else:
        outcome = ProviderOutcome(
            status="disabled", detail="Verification non demandee par le client"
        )

    findings, rows, affected = _build_findings(
        project_uid, dependencies, outcome, engine.name
    )

    # L'inventaire est ecrit meme quand le fournisseur est muet : il vaut
    # par lui-meme, et le perdre parce que le reseau est coupe serait une
    # regression fonctionnelle.
    await asyncio.to_thread(
        store.replace_project_dependencies,
        project_id,
        _inventory_rows(dependencies, outcome),
    )
    outcome_summary = await asyncio.to_thread(
        store.sync_security_findings, project_uid, CATEGORY, rows
    )

    statistics, ecosystems = await _statistics(project_id, submission, truncated)
    vulnerability_statistics = _vulnerability_statistics(
        findings, affected, outcome, engine.name, dependencies
    )

    if not outcome.conclusive:
        # L'avertissement est affiche, pas seulement journalise : une
        # verification qui n'a pas eu lieu doit se voir.
        warnings.append(i18n.provider_status_message(outcome.status))

    logger.info(
        "Inventaire du projet %s : %s dependance(s) (%s directe(s)), "
        "fournisseur %s -> %s, %s vulnerabilite(s) (%s nouvelle(s), "
        "%s disparue(s)), %s dependance(s) non verifiee(s)%s",
        project_uid,
        statistics.total,
        statistics.direct,
        engine.name,
        outcome.status,
        len(findings),
        outcome_summary["inserted"],
        outcome_summary["removed"],
        statistics.unverified,
        " [tronque]" if truncated else "",
    )

    return DependencyScanResult(
        project_uid=project_uid,
        findings=await stored_findings(project_uid),
        dependency_statistics=statistics,
        vulnerability_statistics=vulnerability_statistics,
        ecosystems=ecosystems,
        warnings=warnings,
    )


def _build_findings(
    project_uid: str,
    dependencies: list[DependencyRecord],
    outcome: ProviderOutcome,
    provider: str,
) -> tuple[list[SecurityFinding], list[dict], set[str]]:
    findings: list[SecurityFinding] = []
    rows: list[dict] = []
    # Paquets distincts concernes : un paquet portant trois avis compte
    # pour un. C'est le nombre que l'utilisateur doit traiter.
    affected: set[str] = set()

    for record in dependencies:
        query = PackageQuery(
            name=record.name, ecosystem=record.ecosystem, version=record.version
        )
        for vulnerability in outcome.for_package(query):
            fingerprint, finding = to_finding(
                project_uid, record, vulnerability, provider
            )
            findings.append(finding)
            affected.add(f"{record.ecosystem}|{record.name}")
            rows.append(
                {
                    "finding_id": finding.id,
                    "fingerprint": fingerprint,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "title": finding.title,
                    "description": finding.description,
                    "file_path": finding.file,
                    "line_start": 0,
                    "line_end": 0,
                    "evidence": finding.evidence,
                    "remediation": finding.remediation,
                    "reference_links": json.dumps(
                        finding.references, ensure_ascii=False
                    ),
                    "detection_engine": finding.detection_engine,
                    "status": "open",
                }
            )

    return findings, rows, affected


def _inventory_rows(
    dependencies: list[DependencyRecord], outcome: ProviderOutcome
) -> list[dict]:
    """Lignes d'inventaire, chacune sachant si elle a ete verifiee.

    `verified` est ecrit depuis `ProviderOutcome.was_checked`, pas deduit
    de l'absence de vulnerabilite : c'est cette distinction qui empeche la
    base de contenir un « rien trouve » indiscernable d'un « personne n'a
    regarde ».
    """
    now = _now_iso()
    rows: list[dict] = []

    for record in dependencies:
        query = PackageQuery(
            name=record.name, ecosystem=record.ecosystem, version=record.version
        )
        checked = outcome.was_checked(query)
        rows.append(
            {
                "name": record.name,
                "ecosystem": record.ecosystem,
                "version": record.version,
                "direct": record.direct,
                "manifest": record.manifest,
                "source": record.source,
                "vulnerable": bool(outcome.for_package(query)),
                "verified": checked,
                "indexed_at": now,
            }
        )

    return rows


async def _statistics(
    project_id: int,
    submission: DependencyInventorySubmission,
    truncated: bool,
) -> tuple[DependencyStatistics, list[EcosystemSummary]]:
    totals = await asyncio.to_thread(store.dependency_totals, project_id)
    per_ecosystem = await asyncio.to_thread(
        store.dependency_ecosystem_counts, project_id
    )

    statistics = DependencyStatistics(
        total=totals["total"],
        direct=totals["direct"],
        transitive=totals["transitive"],
        vulnerable=totals["vulnerable"],
        unverified=totals["unverified"],
        manifests_read=submission.manifests_read,
        truncated=truncated,
        last_inventory=_now_iso(),
    )
    ecosystems = [EcosystemSummary(**entry) for entry in per_ecosystem]
    return statistics, ecosystems


def _vulnerability_statistics(
    findings: list[SecurityFinding],
    affected: set[str],
    outcome: ProviderOutcome,
    provider: str,
    dependencies: list[DependencyRecord],
) -> VulnerabilityStatistics:
    """Compteurs de vulnerabilites, avec l'etat qui les rend interpretables.

    `message` n'est jamais construit ici : il vient de `app.i18n`, ou les
    formulations sont ecrites une fois. C'est ce qui garantit qu'aucun
    chemin de code ne peut ecrire « aucune vulnerabilite » a partir d'un
    fournisseur muet.
    """
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    checked = len(outcome.checked) if outcome.conclusive else 0

    return VulnerabilityStatistics(
        total=len(findings),
        critical=counts["CRITICAL"],
        high=counts["HIGH"],
        medium=counts["MEDIUM"],
        low=counts["LOW"],
        packages_affected=len(affected),
        packages_checked=checked,
        packages_unverified=max(0, len(dependencies) - checked),
        provider=provider or provider_name(),
        provider_status=outcome.status,
        message=i18n.provider_status_message(outcome.status),
        last_check=_now_iso(),
    )


async def statistics_for(
    project_id: int,
) -> tuple[DependencyStatistics, list[EcosystemSummary]]:
    """Statistiques d'inventaire relues depuis la base, sans nouveau relevé."""
    totals = await asyncio.to_thread(store.dependency_totals, project_id)
    per_ecosystem = await asyncio.to_thread(
        store.dependency_ecosystem_counts, project_id
    )
    return (
        DependencyStatistics(
            total=totals["total"],
            direct=totals["direct"],
            transitive=totals["transitive"],
            vulnerable=totals["vulnerable"],
            unverified=totals["unverified"],
        ),
        [EcosystemSummary(**entry) for entry in per_ecosystem],
    )


async def stored_findings(project_uid: str) -> list[SecurityFinding]:
    rows = await asyncio.to_thread(
        store.list_security_findings, project_uid, CATEGORY, "open"
    )
    return [row_to_finding(row) for row in rows]
