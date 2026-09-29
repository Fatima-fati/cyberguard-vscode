"""Routes HTTP de la securite projet : /api/project/{uid}/* et /api/security/*.

    GET  /api/security/health                    capacites du moteur
    POST /api/project/{uid}/secrets              balayage de secrets
    POST /api/project/{uid}/api-security         analyse de securite d'API
    POST /api/project/{uid}/dependencies         inventaire + vulnerabilites
    GET  /api/project/{uid}/findings             findings unifies
    GET  /api/project/{uid}/posture              posture explicable (phase 8)
    POST /api/project/{uid}/ci-check             controle CI/CD (phase 8)

Routeur separe de `app.project.routes`, qui porte la decouverte : les deux
partagent le prefixe mais pas le cycle de vie. Un projet peut etre
decouvert sans jamais etre balaye, et l'inverse n'arrive pas.

Ce que ces routes ne font jamais
--------------------------------

- **appeler Wazuh.** Ni le Manager, ni l'Indexer, ni l'API : ces routes
  repondent a l'identique avec Wazuh completement arrete ;
- **lire un fichier du poste.** Le backend recoit des constats produits
  sur la machine du developpeur ;
- **stocker la valeur d'un secret.** `SecurityFinding` reexpurge toute
  preuve dans son validateur, avant meme l'ecriture.

`/api/security/health` est **protegee**, contrairement a
`/api/code/health` : celle-ci existe pour diagnostiquer un probleme
d'authentification, et doit donc repondre sans jeton ; celle-la decrit la
configuration du moteur et n'a aucune raison d'etre publique.
"""

import asyncio
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from app import store
from app.auth import AGENT_AUTH
from app.config import settings
from app.project import context as project_context
from app.security import api_security as api_service
from app.security import dependencies as dependency_service
from app.security import posture as posture_service
from app.security import secrets as secret_service
from app.security.posture_schemas import CiCheckResult, CiPolicyRequest, SecurityPosture
from app.security.providers import get_provider, provider_name
from app.security.schemas import (
    ApiScanResult,
    ApiScanSubmission,
    DependencyInventorySubmission,
    DependencyScanResult,
    SecretScanResult,
    SecretScanSubmission,
    SecurityEngineHealth,
    SecurityFinding,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["security"], dependencies=[AGENT_AUTH])


def _unknown_project(project_uid: str) -> HTTPException:
    return HTTPException(
        status_code=404,
        detail={
            "error": "Projet inconnu",
            "detail": (
                "Enregistrez le projet avec POST /api/project/discover "
                "avant de soumettre un balayage de securite."
            ),
        },
    )


def _disabled(feature: str, setting: str) -> HTTPException:
    """Refus explicite d'une capacite desactivee.

    503 plutot qu'un 200 avec une liste vide : une liste vide se lirait
    « rien a signaler », ce qui est exactement la confusion que cette
    phase s'interdit.
    """
    return HTTPException(
        status_code=503,
        detail={
            "error": f"{feature} desactive",
            "detail": (
                f"Cette capacite est desactivee cote backend ({setting}=false). "
                "Aucun resultat ne peut etre produit, ce qui n'est pas la "
                "meme chose qu'une absence de probleme."
            ),
        },
    )


async def _project_or_404(project_uid: str) -> dict:
    project = await asyncio.to_thread(store.get_project_by_uid, project_uid)
    if project is None:
        raise _unknown_project(project_uid)
    return project


# --------------------------------------------------------------------------
# Etat du moteur
# --------------------------------------------------------------------------


@router.get("/api/security/health", response_model=SecurityEngineHealth)
async def security_health():
    """Ce que le moteur de securite projet sait faire, ici et maintenant.

    L'extension la consulte avant de balayer : lancer un parcours complet
    du disque pour decouvrir ensuite que la route refuse serait du travail
    perdu, et annoncer une capacite qui ne tournera pas coute plus cher
    que de ne rien annoncer.
    """
    provider = get_provider()
    return SecurityEngineHealth(
        status="ok",
        secret_detection_enabled=settings.secret_detection_enabled,
        dependency_inventory_enabled=settings.dependency_inventory_enabled,
        vulnerability_check_enabled=settings.dependency_vulnerability_enabled,
        api_security_enabled=settings.api_security_enabled,
        # Etat reel, pas intention : la propriete exige a la fois une cle
        # API configuree et l'activation de l'assistant.
        ai_assistant_enabled=settings.security_ai_available,
        vulnerability_provider=provider_name(),
        supported_ecosystems=sorted(provider.supported_ecosystems),
        # Constat, pas promesse : aucun appel Wazuh n'existe dans ce
        # paquet, et un test le verifie sur le code source.
        requires_wazuh=False,
    )


# --------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------


@router.post("/api/project/{project_uid}/secrets", response_model=SecretScanResult)
async def submit_secret_scan(project_uid: str, submission: SecretScanSubmission):
    """Enregistre un balayage de secrets realise sur le poste.

    Ce qui traverse cette frontiere : un chemin relatif, une ligne, un
    type de secret, une confiance, et une preuve **deja expurgee**. Jamais
    la valeur detectee, jamais le contenu du fichier.

    Le backend n'accorde aucune confiance a l'expurgation du client : le
    validateur du modele la refait, et c'est celle-la qui est ecrite.
    """
    if not settings.secret_detection_enabled:
        raise _disabled("Detection de secrets", "SECRET_DETECTION_ENABLED")

    await _project_or_404(project_uid)
    result = await secret_service.record(project_uid, submission)

    # Le contexte affiche par la vue « Project » porte les compteurs : il
    # est mis a jour ici, pour que l'interface n'ait pas a recouper deux
    # reponses pour afficher un seul chiffre.
    await project_context.apply_security_statistics(
        project_uid, secret_statistics=result.statistics
    )
    return result


# --------------------------------------------------------------------------
# Securite d'API (phase 5)
# --------------------------------------------------------------------------


@router.post("/api/project/{project_uid}/api-security", response_model=ApiScanResult)
async def submit_api_scan(project_uid: str, submission: ApiScanSubmission):
    """Enregistre une analyse de securite d'API realisee sur le poste.

    Ce qui traverse cette frontiere : un chemin relatif, une ligne, un
    type de probleme, une confiance, et un extrait de **declaration**
    deja expurge. Jamais le contenu du fichier, jamais le corps d'un
    gestionnaire de route.

    Le backend n'accorde aucune confiance a l'expurgation du client : le
    validateur du modele la refait, et c'est celle-la qui est ecrite. Une
    ligne de configuration d'API est precisement l'endroit ou un jeton se
    glisse.
    """
    if not settings.api_security_enabled:
        raise _disabled("Analyse de securite d'API", "API_SECURITY_ENABLED")

    await _project_or_404(project_uid)
    result = await api_service.record(project_uid, submission)

    # Le contexte affiche par la vue « Project » porte les compteurs : il
    # est mis a jour ici, pour que l'interface n'ait pas a recouper deux
    # reponses pour afficher un seul chiffre.
    await project_context.apply_security_statistics(
        project_uid, api_statistics=result.statistics
    )
    return result


# --------------------------------------------------------------------------
# Dependances
# --------------------------------------------------------------------------


@router.post(
    "/api/project/{project_uid}/dependencies", response_model=DependencyScanResult
)
async def submit_dependency_inventory(
    project_uid: str, submission: DependencyInventorySubmission
):
    """Enregistre l'inventaire des dependances et, si possible, le verifie.

    Deux operations distinctes derriere une seule route, et c'est
    volontaire : l'inventaire est enregistre **avant** toute interrogation
    du fournisseur. Un reseau coupe fait perdre la verification, jamais
    l'inventaire.

    La reponse porte toujours l'etat du fournisseur. Une liste de
    vulnerabilites vide accompagnee d'un etat non concluant se lit
    « impossible de verifier », jamais « aucune vulnerabilite ».
    """
    if not settings.dependency_inventory_enabled:
        raise _disabled("Inventaire des dependances", "DEPENDENCY_INVENTORY_ENABLED")

    project = await _project_or_404(project_uid)
    result = await dependency_service.record_inventory(
        project_uid, int(project["id"]), submission
    )

    await project_context.apply_security_statistics(
        project_uid,
        dependency_statistics=result.dependency_statistics,
        dependency_ecosystems=result.ecosystems,
        vulnerability_statistics=result.vulnerability_statistics,
    )
    return result


# --------------------------------------------------------------------------
# Findings unifies
# --------------------------------------------------------------------------


@router.get("/api/project/{project_uid}/findings", response_model=list[SecurityFinding])
async def list_project_findings(
    project_uid: str,
    category: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default="open"),
    severity: Optional[str] = Query(default=None),
    limit: int = Query(default=500, ge=1, le=2000),
):
    """Findings de securite d'un projet, toutes familles confondues.

    Le filtre par projet est impose par la route elle-meme, pas par un
    parametre facultatif : sans lui, deux projets analyses par le meme
    backend melangeraient leurs findings, et un `src/config.py`
    afficherait les secrets de l'autre.
    """
    await _project_or_404(project_uid)

    rows = await asyncio.to_thread(
        store.list_security_findings,
        project_uid,
        (category or "").upper() or None,
        status,
        (severity or "").upper() or None,
        limit,
    )
    return [secret_service.row_to_finding(row) for row in rows]


# --------------------------------------------------------------------------
# Posture de securite et controle CI/CD (phase 8)
# --------------------------------------------------------------------------


@router.get("/api/project/{project_uid}/posture", response_model=SecurityPosture)
async def project_posture(project_uid: str):
    """Posture de securite explicable, par domaine. **Aucun score.**

    Lue dans les findings et le contexte existants : aucun balayage n'est
    lance, aucune IA n'est consultee, Wazuh n'est pas appele. Un domaine
    jamais analyse porte `findings: null`, jamais un zero.
    """
    await _project_or_404(project_uid)
    posture = await posture_service.build_posture(project_uid)
    if posture is None:
        raise _unknown_project(project_uid)
    return posture


@router.post("/api/project/{project_uid}/ci-check", response_model=CiCheckResult)
async def project_ci_check(project_uid: str, request: Optional[CiPolicyRequest] = None):
    """Controle CI/CD deterministe, resultat machine.

    La politique vient de la requete, sinon de la configuration
    (`CI_POLICY_MODE`, `CI_FAIL_ON`, `CI_WARN_ON`), `warn` par defaut. Un
    blocage est toujours accompagne de `reasons` : un pipeline ne doit
    jamais echouer sans dire pourquoi.

    Le code HTTP est 200 dans tous les cas, y compris « blocked » : le
    verdict est une donnee, `exit_code` dit au pipeline quoi en faire.
    """
    await _project_or_404(project_uid)
    result = await posture_service.ci_check(project_uid, request)
    if result is None:
        raise _unknown_project(project_uid)
    return result
