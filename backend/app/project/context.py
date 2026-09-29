"""Assemblage, persistance et relecture du contexte de projet.

Ce module est le seul endroit ou un contexte est construit. Les routes ne
font que valider l'entree et appeler ici : une seule definition de ce
qu'est un contexte, donc pas deux versions qui divergent.

Toutes les fonctions publiques sont asynchrones et deleguent SQLite a un
thread (`asyncio.to_thread`), comme le reste du backend : `sqlite3`
bloque, et la boucle asyncio sert aussi le flux temps reel.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from app import store
from app.config import settings
from app.project import discovery
from app.project.schemas import (
    ClassifiedFile,
    ProjectDiscoverRequest,
    ProjectIndexRequest,
    ProjectRegistration,
    ProjectSecurityContext,
    ProjectStatus,
)
from app.security.schemas import (
    ApiStatistics,
    DependencyStatistics,
    EcosystemSummary,
    SecretStatistics,
    VulnerabilityStatistics,
)

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fallback_name(root_hash: str) -> str:
    """Nom affichable quand l'extension n'en a pas fourni.

    Un fragment de l'empreinte, jamais un chemin : il faut bien afficher
    quelque chose, et ce quelque chose ne doit rien reveler du poste.
    """
    return f"projet-{root_hash[:8]}"


# --------------------------------------------------------------------------
# Enregistrement
# --------------------------------------------------------------------------


async def register(request: ProjectDiscoverRequest) -> ProjectRegistration:
    """Enregistre un projet, ou retrouve celui deja connu pour cette racine.

    Reconciliation par `root_hash` : le meme dossier reouvert retrouve son
    `project_uid`, donc ses scans et ses findings, meme si l'extension a
    perdu l'identifiant entre deux sessions.
    """
    existing = await asyncio.to_thread(
        store.get_project_by_root_hash, request.root_hash
    )

    now = _now_iso()
    name = request.project_name or _fallback_name(request.root_hash)

    if existing is not None:
        # Projet connu : on note le passage et on n'ecrase ni son
        # identifiant ni son contexte. Un contexte existant reste
        # consultable pendant qu'une nouvelle decouverte tourne.
        await asyncio.to_thread(store.touch_project, existing["project_uid"], now)
        logger.info(
            "Projet %s reconnu (decouverte precedente : %s)",
            existing["project_uid"],
            existing.get("last_discovery_at") or "aucune",
        )
        return ProjectRegistration(
            project_uid=existing["project_uid"],
            project_name=existing.get("display_name") or name,
            root_hash=request.root_hash,
            status="discovery",
            known=True,
            last_discovery=existing.get("last_discovery_at"),
        )

    project_uid = uuid.uuid4().hex
    await asyncio.to_thread(
        store.upsert_project,
        {
            "project_uid": project_uid,
            "root_hash": request.root_hash,
            "display_name": name,
            "project_types": "[]",
            "primary_language": None,
            "languages": "[]",
            "frameworks": "[]",
            "file_count": 0,
            "indexed_count": 0,
            "truncated": 0,
            "has_git": 0,
            "git_remote_host": None,
            "discovery_version": request.discovery_version
            or settings.project_discovery_version,
            "status": "discovery",
            "created_at": now,
            "last_seen_at": now,
            "last_discovery_at": None,
        },
    )

    logger.info("Nouveau projet enregistre : %s", project_uid)
    return ProjectRegistration(
        project_uid=project_uid,
        project_name=name,
        root_hash=request.root_hash,
        status="discovery",
        known=False,
        last_discovery=None,
    )


# --------------------------------------------------------------------------
# Index et contexte
# --------------------------------------------------------------------------


def _take(entries: list[ClassifiedFile], kinds: set[str]) -> list[ClassifiedFile]:
    """Selection bornee et triee des fichiers d'une ou plusieurs natures.

    Bornee parce qu'un monorepo peut contenir des centaines de manifestes
    et que la vue n'en affichera jamais autant ; triee pour que deux
    appels renvoient la meme liste.
    """
    selected = [entry for entry in entries if entry.kind in kinds]
    selected.sort(key=lambda entry: entry.path)
    return selected[: settings.project_max_listed_files]


async def submit_index(
    project_uid: str, request: ProjectIndexRequest
) -> Optional[ProjectSecurityContext]:
    """Enregistre l'index soumis et recalcule le contexte.

    Retourne `None` si le projet est inconnu : la route traduit cela en
    404 plutot que de creer un projet a la volee, ce qui masquerait une
    erreur de l'appelant.
    """
    project = await asyncio.to_thread(store.get_project_by_uid, project_uid)
    if project is None:
        return None

    warnings = list(request.warnings)

    # Plafond applique ici, cote serveur : l'extension a le sien, mais le
    # backend ne fait pas confiance a la borne du client.
    files = request.files
    truncated = request.truncated
    limit = settings.project_max_indexed_files
    if len(files) > limit:
        files = files[:limit]
        truncated = True
        warnings.append(
            f"Index tronque a {limit} fichiers par le backend "
            f"({len(request.files)} soumis)."
        )

    classified = discovery.classify_index(files)
    languages = discovery.detect_languages(classified)
    frameworks = discovery.detect_frameworks(request.manifests, classified)
    project_types = discovery.detect_project_types(languages, frameworks, classified)
    stats = discovery.statistics(classified, request.discovered_count, truncated)

    now = _now_iso()

    # Les statistiques de securite du contexte precedent sont reprises.
    #
    # Ce n'est pas de la paresse : re-indexer les fichiers ne dit rien de
    # nouveau sur les secrets ni sur les dependances, et les remettre a
    # zero afficherait « 0 secret » a un projet qui en a — le plus
    # trompeur des deux mensonges possibles. Le balayage suivant les
    # remplacera par des valeurs fraiches.
    previous = await get_context(project_uid)

    # L'index est remplace en une transaction, pas fusionne : un fichier
    # supprime du projet doit disparaitre du decompte.
    rows = [
        {
            "path": classified[position].path,
            "language": discovery.language_for_path(classified[position].path),
            "kind": classified[position].kind,
            "size": entry.size,
            "content_hash": entry.content_hash,
            "mtime": entry.mtime,
            "indexed_at": now,
        }
        for position, entry in enumerate(files)
    ]
    await asyncio.to_thread(store.replace_project_files, int(project["id"]), rows)

    context = ProjectSecurityContext(
        project_uid=project_uid,
        project_name=project.get("display_name") or _fallback_name(project["root_hash"]),
        root_hash=project["root_hash"],
        status="ready",
        project_types=project_types,
        primary_language=discovery.primary_language(languages),
        languages=languages,
        frameworks=frameworks,
        file_statistics=stats,
        manifests=_take(classified, {"manifest"}),
        important_files=_take(classified, {"documentation"}),
        configuration_files=_take(classified, {"config", "infra"}),
        security_sensitive_files=_take(classified, {"sensitive"}),
        git_repository_detected=request.git.detected,
        git_remote_host=request.git.remote_host,
        secret_statistics=(
            previous.secret_statistics if previous else SecretStatistics()
        ),
        dependency_statistics=(
            previous.dependency_statistics if previous else DependencyStatistics()
        ),
        dependency_ecosystems=(
            list(previous.dependency_ecosystems) if previous else []
        ),
        vulnerability_statistics=(
            previous.vulnerability_statistics
            if previous
            else VulnerabilityStatistics()
        ),
        warnings=warnings,
        last_discovery=now,
        discovery_version=request.discovery_version
        or settings.project_discovery_version,
    )

    await _persist(project, context, now)

    # Journalisation par identifiant et par volume : aucun chemin de
    # fichier sensible, aucun contenu. `projectId` suffit a relier les
    # traces entre elles.
    logger.info(
        "Contexte du projet %s calcule : %s fichier(s) indexe(s), "
        "%s langage(s), %s framework(s), %s fichier(s) sensible(s)%s",
        project_uid,
        stats.indexed,
        len(languages),
        len(frameworks),
        stats.sensitive,
        " [tronque]" if stats.truncated else "",
    )

    return context


async def _persist(
    project: dict, context: ProjectSecurityContext, now: str
) -> None:
    """Ecrit le resume dans `projects` et l'instantane dans `project_context`."""
    await asyncio.to_thread(
        store.upsert_project,
        {
            "project_uid": context.project_uid,
            "root_hash": context.root_hash,
            "display_name": context.project_name,
            "project_types": json.dumps(context.project_types, ensure_ascii=False),
            "primary_language": context.primary_language,
            "languages": json.dumps(
                [item.model_dump(mode="json") for item in context.languages],
                ensure_ascii=False,
            ),
            "frameworks": json.dumps(
                [item.model_dump(mode="json") for item in context.frameworks],
                ensure_ascii=False,
            ),
            "file_count": context.file_statistics.discovered,
            "indexed_count": context.file_statistics.indexed,
            "truncated": 1 if context.file_statistics.truncated else 0,
            "has_git": 1 if context.git_repository_detected else 0,
            "git_remote_host": context.git_remote_host,
            "discovery_version": context.discovery_version,
            "status": context.status,
            "created_at": project.get("created_at") or now,
            "last_seen_at": now,
            "last_discovery_at": now,
        },
    )

    await asyncio.to_thread(
        store.save_project_context,
        int(project["id"]),
        context.model_dump_json(),
        now,
    )


async def get_context(project_uid: str) -> Optional[ProjectSecurityContext]:
    """Contexte enregistre, tel qu'il a ete renvoye lors de sa production.

    On relit l'instantane plutot que de recalculer : un second calcul
    pourrait differer du premier (plafonds, version de classement) et
    l'utilisateur verrait deux reponses pour une seule decouverte.

    Un instantane illisible — base modifiee a la main, format d'une
    version anterieure — n'est pas rattrape en silence : la route repond
    que le contexte doit etre reconstruit.
    """
    project = await asyncio.to_thread(store.get_project_by_uid, project_uid)
    if project is None:
        return None

    row = await asyncio.to_thread(store.get_project_context, int(project["id"]))
    if row is None:
        return None

    try:
        return ProjectSecurityContext.model_validate_json(row["payload"])
    except ValueError as exc:
        logger.warning(
            "Contexte du projet %s illisible, reconstruction necessaire: %s",
            project_uid,
            exc,
        )
        return None


async def exists(project_uid: str) -> bool:
    """Le projet est-il enregistre ? Independant de l'existence d'un contexte."""
    return await asyncio.to_thread(store.get_project_by_uid, project_uid) is not None


async def set_status(project_uid: str, status: ProjectStatus) -> None:
    """Change l'etat affiche d'un projet, sans toucher a son contexte."""
    project = await asyncio.to_thread(store.get_project_by_uid, project_uid)
    if project is None:
        return
    await asyncio.to_thread(
        store.upsert_project,
        {
            "project_uid": project["project_uid"],
            "root_hash": project["root_hash"],
            "status": status,
            "last_seen_at": _now_iso(),
        },
    )


# --------------------------------------------------------------------------
# Statistiques de securite (phase 2)
# --------------------------------------------------------------------------


async def apply_security_statistics(
    project_uid: str,
    secret_statistics: Optional[SecretStatistics] = None,
    api_statistics: Optional[ApiStatistics] = None,
    dependency_statistics: Optional[DependencyStatistics] = None,
    dependency_ecosystems: Optional[list[EcosystemSummary]] = None,
    vulnerability_statistics: Optional[VulnerabilityStatistics] = None,
) -> Optional[ProjectSecurityContext]:
    """Reporte les resultats d'un balayage dans le contexte enregistre.

    Pourquoi ecrire dans l'instantane plutot que recalculer a la lecture :
    l'etat du fournisseur de vulnerabilites n'est pas reconstituable
    depuis la base. « Zero vulnerabilite parce que la base a repondu » et
    « zero vulnerabilite parce que personne n'a repondu » donneraient les
    memes lignes en table. Conserver `provider_status` tel qu'il etait au
    moment du balayage est la seule facon de ne pas perdre cette
    distinction — qui est precisement celle qui compte.

    Les parametres absents laissent leur champ inchange : un balayage de
    secrets ne doit pas effacer ce qu'on sait des dependances.

    Retourne `None` quand aucun contexte n'existe encore — projet
    enregistre mais jamais indexe. Ce n'est pas une erreur : le balayage
    a bien eu lieu, ses findings sont enregistres, et le contexte les
    reprendra a la prochaine decouverte.
    """
    project = await asyncio.to_thread(store.get_project_by_uid, project_uid)
    if project is None:
        return None

    context = await get_context(project_uid)
    if context is None:
        logger.info(
            "Statistiques de securite du projet %s non reportees : aucun "
            "contexte enregistre (index jamais soumis)",
            project_uid,
        )
        return None

    if secret_statistics is not None:
        context.secret_statistics = secret_statistics
    if api_statistics is not None:
        context.api_statistics = api_statistics
    if dependency_statistics is not None:
        context.dependency_statistics = dependency_statistics
    if dependency_ecosystems is not None:
        context.dependency_ecosystems = list(dependency_ecosystems)
    if vulnerability_statistics is not None:
        context.vulnerability_statistics = vulnerability_statistics

    await asyncio.to_thread(
        store.save_project_context,
        int(project["id"]),
        context.model_dump_json(),
        _now_iso(),
    )

    # Volumes seulement : aucun chemin, aucune preuve, aucune valeur.
    logger.info(
        "Contexte du projet %s enrichi — %s secret(s), %s dependance(s) "
        "dont %s vulnerable(s) et %s non verifiee(s) [fournisseur : %s]",
        project_uid,
        context.secret_statistics.total,
        context.dependency_statistics.total,
        context.dependency_statistics.vulnerable,
        context.dependency_statistics.unverified,
        context.vulnerability_statistics.provider_status,
    )

    return context
