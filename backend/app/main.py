"""Point d'entree FastAPI de Wazuh Supervision."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import auth, poller, store
from app.notifier import stream
from app.config import settings
from app.code.routes import router as code_router
from app.project.routes import router as project_router
from app.security.ai_routes import router as security_ai_router
from app.security.routes import router as security_router
from app.routes import router
from app.ai.openai_client import close_openai_client
from app.wazuh_client import close_wazuh_client

logging.basicConfig(level=logging.INFO)

logger = logging.getLogger(__name__)


def _announce_security_posture() -> None:
    """Dit au demarrage ce qui protege ce backend — et ce qui ne le protege pas.

    Les deux reglages annonces ici decident de qui peut appeler les routes
    sensibles. Les laisser deviner au lecteur des journaux serait leur
    donner l'apparence d'un detail de configuration ; ce sont des
    decisions de securite.
    """
    if settings.agent_auth_enabled:
        logger.info(
            "Authentification locale ACTIVE : les routes sensibles exigent "
            "un jeton (fichier %s)",
            auth.token_path(),
        )
    else:
        logger.warning(
            "Authentification locale DESACTIVEE (AGENT_AUTH_ENABLED=false) : "
            "tout processus local peut appeler les routes sensibles"
        )

    if settings.binds_loopback_only:
        logger.info(
            "Mode developpement local : ecoute prevue sur %s", settings.api_host
        )
    else:
        logger.warning(
            "API_HOST=%s : le backend est prevu joignable depuis le reseau. "
            "Verifiez que l'authentification et CORS sont adaptes a ce "
            "deploiement.",
            settings.api_host,
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Prepare la base au demarrage, arrete la surveillance a la fermeture."""
    store.init_db()
    # Avant de servir : le jeton doit exister, sinon les routes protegees
    # ne repondraient que des 401 sans explication.
    if settings.agent_auth_enabled:
        auth.ensure_token()
    _announce_security_posture()
    yield
    await poller.shutdown()
    await stream.close_all()
    await close_wazuh_client()
    await close_openai_client()


app = FastAPI(
    title=f"{settings.app_name} API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
# Analyse de code (extension VS Code). Routeur independant : il n'altere
# aucune route Wazuh ou IA existante.
app.include_router(code_router)
# Contexte de projet (phase 1). Meme principe : routeur a part, protege
# par le meme jeton local que /api/code/*.
app.include_router(project_router)
# Securite projet (phase 2) : secrets, dependances, vulnerabilites.
# Routeur a part, lui aussi. Aucune de ses routes n'appelle Wazuh : elles
# repondent a l'identique avec le Manager et l'Indexer arretes.
app.include_router(security_router)
# Assistant IA de securite (phase 6). Routeur a part : ce sont les seules
# routes du paquet a pouvoir sortir vers un fournisseur d'IA, et les
# seules a repondre 503 « indisponible » pendant que tout le reste
# fonctionne. L'extension ne depend pas d'elles : sans cle API, la
# detection, l'affichage et le tri des findings sont inchanges.
app.include_router(security_ai_router)


@app.get("/")
async def root():
    return {
        "application": settings.app_name,
        "status": "running",
        "docs": "/docs",
        "api": "/api/health",
    }
