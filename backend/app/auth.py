"""Authentification locale entre l'extension VS Code et le backend.

Le probleme resolu ici est precis, et volontairement etroit : le backend
ecoute sur la machine du developpeur et expose des routes qui declenchent
des analyses, lisent des findings et diffusent des extraits de code. Sans
controle, **tout processus local** peut les appeler. Ce module ferme cette
porte, et rien de plus : ce n'est pas un systeme de comptes utilisateurs.

Modele retenu — un jeton local partage
--------------------------------------

    Extension                          Backend
        |                                  |
        |  lit le fichier de jeton         |  genere le jeton au demarrage
        |  (profil utilisateur)            |  s'il n'existe pas
        |                                  |
        |  Authorization: Bearer <jeton>   |
        |--------------------------------->|  compare_digest
        |                                  |
        |<--- 200 ------------------------ |  valide
        |<--- 401 ------------------------ |  absent, malforme ou faux

Proprietes tenues :

- le jeton n'est **jamais** en dur dans le code, ni dans un fichier du
  depot : il vit dans le profil de l'utilisateur, hors de l'arborescence
  du projet, donc hors de portee d'un `git add` ;
- il n'apparait **jamais** dans un journal, ni dans un message d'erreur :
  les refus disent « jeton absent » ou « jeton invalide », jamais la
  valeur attendue ni celle recue ;
- la comparaison passe par `secrets.compare_digest` : la duree de la
  verification ne renseigne pas sur le prefixe correct ;
- il n'est **jamais** transmis a un service externe : seul le backend
  local le connait.

Sur `AGENT_AUTH_TOKEN` : une valeur fournie par l'environnement l'emporte
sur le fichier. C'est ce qui permet a un deploiement (conteneur, service)
d'injecter un secret gere ailleurs sans ecrire sur disque. Le fichier
reste le chemin normal en developpement local.
"""

import logging
import os
import secrets
import stat
from pathlib import Path
from typing import Optional

from fastapi import Depends, HTTPException, Request

from app.config import settings

logger = logging.getLogger(__name__)

# Longueur en octets de l'alea. 32 octets -> 43 caracteres url-safe, soit
# 256 bits : hors de portee d'une recherche exhaustive locale.
TOKEN_BYTES = 32

# Schema attendu dans l'en-tete Authorization.
_SCHEME = "bearer"

# Jeton actif du processus. Charge une seule fois par `ensure_token()`,
# appele au demarrage de l'application.
_token: Optional[str] = None


class AuthNotReadyError(RuntimeError):
    """Le jeton n'a pas pu etre etabli : l'application ne doit pas servir."""


# --------------------------------------------------------------------------
# Emplacement du jeton
# --------------------------------------------------------------------------


def token_path() -> Path:
    """Fichier qui porte le jeton local.

    Hors du depot, dans le profil de l'utilisateur : un secret qui vit
    dans le projet finit par etre commite ou partage avec le dossier.
    `AGENT_TOKEN_PATH` permet de le deplacer sans toucher au code.
    """
    configured = settings.agent_token_path.strip()
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".wazuh-security" / "agent-token"


def _restrict_permissions(path: Path) -> None:
    """Reduit les droits du fichier a son seul proprietaire.

    Sur les systemes POSIX, `chmod 600`. Sur Windows, les ACL heritees du
    profil utilisateur jouent ce role et `chmod` n'a pas d'equivalent
    fidele : on n'affaiblit rien, mais on ne pretend pas non plus avoir
    durci quelque chose. L'echec n'est jamais fatal — un jeton lisible
    reste preferable a un backend qui refuse de demarrer.
    """
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError as exc:  # noqa: BLE001 - plateforme sans chmod utile
        logger.debug("Droits du fichier de jeton inchanges: %s", exc)


def _read_token_file(path: Path) -> Optional[str]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return None
    value = raw.strip()
    return value or None


def _write_token_file(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")
    _restrict_permissions(path)


# --------------------------------------------------------------------------
# Cycle de vie
# --------------------------------------------------------------------------


def ensure_token() -> str:
    """Etablit le jeton du processus. Idempotent.

    Ordre de resolution, du plus explicite au plus commode :

    1. `AGENT_AUTH_TOKEN` dans l'environnement — un deploiement gere son
       secret lui-meme et n'ecrit rien sur disque ;
    2. le fichier de jeton, s'il existe deja — l'extension a pu le lire
       avant ce demarrage, on ne l'invalide pas pour rien ;
    3. sinon, generation et ecriture.

    La valeur retournee n'est jamais journalisee : seule son origine et sa
    longueur le sont, ce qui suffit au diagnostic.
    """
    global _token

    if _token is not None:
        return _token

    configured = settings.agent_auth_token.strip()
    if configured:
        _token = configured
        logger.info(
            "Jeton d'authentification fourni par l'environnement (%s caracteres)",
            len(configured),
        )
        return _token

    path = token_path()

    existing = _read_token_file(path)
    if existing:
        _token = existing
        logger.info("Jeton d'authentification relu depuis %s", path)
        return _token

    generated = secrets.token_urlsafe(TOKEN_BYTES)
    try:
        _write_token_file(path, generated)
    except OSError as exc:
        # Sans jeton lisible par l'extension, l'authentification
        # condamnerait l'extension au silence : on le dit clairement
        # plutot que de servir des 401 inexplicables.
        raise AuthNotReadyError(
            f"Jeton d'authentification non ecrit dans {path}: {exc}"
        ) from exc

    _token = generated
    logger.info("Nouveau jeton d'authentification ecrit dans %s", path)
    return _token


def current_token() -> Optional[str]:
    """Jeton actif, ou `None` si `ensure_token()` n'a pas encore tourne."""
    return _token


def set_token_for_tests(value: Optional[str]) -> None:
    """Installe un jeton connu. **Reserve aux tests.**

    Presente ici plutot que dans les tests eux-memes pour que l'etat de
    module ait un seul point de mutation, visible a la lecture.
    """
    global _token
    _token = value


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------


def _unauthorized(reason: str) -> HTTPException:
    """401 sans indice exploitable.

    `reason` decrit la *forme* du probleme (« absent », « invalide »),
    jamais la valeur attendue ni celle recue.
    """
    return HTTPException(
        status_code=401,
        detail={
            "error": "Authentification requise",
            "detail": reason,
        },
        headers={"WWW-Authenticate": "Bearer"},
    )


def extract_bearer(header_value: Optional[str]) -> Optional[str]:
    """Isole le jeton d'un en-tete `Authorization`.

    Retourne `None` si l'en-tete est absent, vide, d'un autre schema ou
    malforme. Le nom du schema est compare sans tenir compte de la casse,
    comme le veut la RFC 7235.
    """
    if not header_value:
        return None

    parts = header_value.strip().split(None, 1)
    if len(parts) != 2:
        return None

    scheme, value = parts
    if scheme.lower() != _SCHEME:
        return None

    token = value.strip()
    return token or None


def verify_token(candidate: Optional[str]) -> bool:
    """Le jeton presente est-il celui du processus ?

    `compare_digest` plutot que `==` : la duree de la comparaison ne doit
    pas reveler combien de caracteres sont corrects.
    """
    expected = _token
    if not expected or not candidate:
        return False
    return secrets.compare_digest(candidate, expected)


async def require_agent_token(request: Request) -> None:
    """Dependance FastAPI des routes sensibles.

    Ne retourne rien : son seul effet est de laisser passer ou de lever
    un 401. Aucune identite n'est attachee a la requete — il n'y a qu'un
    seul appelant legitime, l'extension de cet utilisateur.
    """
    if not settings.agent_auth_enabled:
        # Desactivation explicite, annoncee au demarrage (voir main.py).
        # Jamais un defaut : `agent_auth_enabled` vaut True par defaut.
        return

    if _token is None:
        # Le jeton n'a pas pu etre etabli. Refuser est le comportement sur :
        # servir sans controle serait un affaiblissement silencieux.
        logger.error("Jeton d'authentification indisponible : requete refusee")
        raise _unauthorized("service d'authentification indisponible")

    presented = extract_bearer(request.headers.get("Authorization"))
    if presented is None:
        raise _unauthorized("en-tete Authorization absent ou malforme")

    if not verify_token(presented):
        # Le chemin demande est trace, jamais le jeton presente.
        logger.warning("Jeton refuse sur %s", request.url.path)
        raise _unauthorized("jeton invalide")


# Dependance prete a l'emploi pour `APIRouter(dependencies=[...])`.
AGENT_AUTH = Depends(require_agent_token)
