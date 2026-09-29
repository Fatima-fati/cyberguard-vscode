"""Routes HTTP du contexte de projet : /api/project/*.

Trois routes, une par etape. Le decoupage n'est pas cosmetique :
l'enregistrement tient en trois champs et doit repondre instantanement,
alors que l'index peut porter des milliers d'entrees. Les melanger ferait
d'un simple « bonjour, je suis ce projet » une requete de plusieurs
megaoctets.

    POST /api/project/discover              identite      -> project_uid
    POST /api/project/{project_uid}/index   index         -> contexte
    GET  /api/project/{project_uid}/context relecture     -> contexte

Toutes exigent le jeton local : le contexte decrit l'arborescence d'un
projet et la liste de ses fichiers sensibles. Aucune n'est publique, pas
meme en lecture.

Ce que ces routes ne font jamais : lire un fichier sur le disque du
developpeur, renvoyer le contenu d'un fichier, ou renvoyer la valeur d'un
secret. Elles ne connaissent que ce que l'extension leur a decrit.
"""

import logging

from fastapi import APIRouter, HTTPException

from app.auth import AGENT_AUTH
from app.project import context as project_context
from app.project.schemas import (
    ProjectDiscoverRequest,
    ProjectIndexRequest,
    ProjectRegistration,
    ProjectSecurityContext,
)

logger = logging.getLogger(__name__)

# Le jeton est exige a l'entree du routeur : une route ajoutee ici demain
# est protegee sans qu'on ait a y penser.
router = APIRouter(
    prefix="/api/project",
    tags=["project"],
    dependencies=[AGENT_AUTH],
)


def _unknown_project(project_uid: str) -> HTTPException:
    return HTTPException(
        status_code=404,
        detail={
            "error": "Projet inconnu",
            "detail": (
                "Enregistrez le projet avec POST /api/project/discover "
                "avant de soumettre son index."
            ),
        },
    )


@router.post("/discover", response_model=ProjectRegistration)
async def project_discover(request: ProjectDiscoverRequest):
    """Enregistre un projet et retourne son identifiant stable.

    Idempotent : deux appels pour la meme racine renvoient le meme
    `project_uid`. `known: true` indique que le projet etait deja connu —
    l'extension peut alors afficher le contexte existant pendant qu'une
    nouvelle decouverte tourne, au lieu d'une vue vide.
    """
    return await project_context.register(request)


@router.post("/{project_uid}/index", response_model=ProjectSecurityContext)
async def project_index(project_uid: str, request: ProjectIndexRequest):
    """Soumet l'index du projet et recoit le contexte recalcule.

    L'index remplace le precedent dans son entier : un fichier supprime
    doit disparaitre du contexte, sinon le decompte affiche cesse de
    decrire le projet reel.

    Les entrees ne portent que des metadonnees — chemin relatif, taille,
    empreinte, date. Aucun contenu n'est transmis ni attendu.
    """
    result = await project_context.submit_index(project_uid, request)
    if result is None:
        raise _unknown_project(project_uid)
    return result


@router.get("/{project_uid}/context", response_model=ProjectSecurityContext)
async def project_context_read(project_uid: str):
    """Relit le contexte enregistre.

    Deux 404 differents, parce que la marche a suivre differe : un projet
    inconnu doit d'abord etre enregistre, un projet connu mais sans
    contexte doit soumettre son index. Un message unique laisserait
    l'utilisateur sans savoir quoi faire.
    """
    result = await project_context.get_context(project_uid)
    if result is not None:
        return result

    if not await project_context.exists(project_uid):
        raise _unknown_project(project_uid)

    raise HTTPException(
        status_code=404,
        detail={
            "error": "Contexte indisponible",
            "detail": (
                "Ce projet est enregistre mais son index n'a pas encore ete "
                "soumis. Lancez « Refresh Project Security »."
            ),
        },
    )
