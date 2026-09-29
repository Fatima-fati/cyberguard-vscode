"""Fournisseurs de vulnerabilites.

`get_provider()` est le seul point d'entree : il applique la
configuration et retourne toujours un objet, jamais `None`. Quand la
verification est desactivee ou qu'aucun fournisseur ne correspond au nom
configure, c'est `DisabledVulnerabilityProvider` qui repond — l'appelant
suit donc un chemin unique, et l'etat `disabled` remonte jusqu'a l'ecran
au lieu d'etre confondu avec un resultat vide.
"""

import logging
from typing import Optional

from app.config import settings
from app.security.providers.base import (
    DisabledVulnerabilityProvider,
    PackageQuery,
    PackageVulnerability,
    ProviderOutcome,
    VulnerabilityProvider,
)
from app.security.providers.osv import OsvVulnerabilityProvider

logger = logging.getLogger(__name__)

__all__ = [
    "DisabledVulnerabilityProvider",
    "OsvVulnerabilityProvider",
    "PackageQuery",
    "PackageVulnerability",
    "ProviderOutcome",
    "VulnerabilityProvider",
    "get_provider",
    "provider_name",
]

# Fournisseurs connus, par nom de configuration.
_REGISTRY: dict[str, type[VulnerabilityProvider]] = {
    "osv": OsvVulnerabilityProvider,
}


def provider_name() -> str:
    """Nom du fournisseur configure, meme lorsqu'il est desactive.

    Affiche a l'utilisateur : savoir *quelle* base aurait ete interrogee
    fait partie de l'explication, y compris quand elle ne l'a pas ete.
    """
    return (settings.vulnerability_provider or "osv").strip().lower()


def get_provider(force_enabled: Optional[bool] = None) -> VulnerabilityProvider:
    """Fournisseur a utiliser maintenant, selon la configuration.

    `force_enabled` n'existe que pour les tests : le code applicatif lit la
    configuration, et lui seul.
    """
    enabled = (
        settings.dependency_vulnerability_enabled
        if force_enabled is None
        else force_enabled
    )
    if not enabled:
        return DisabledVulnerabilityProvider()

    name = provider_name()
    implementation = _REGISTRY.get(name)
    if implementation is None:
        # Un nom inconnu ne doit pas se solder par un silence qui se
        # lirait comme « aucune vulnerabilite ».
        logger.warning(
            "Fournisseur de vulnerabilites « %s » inconnu : verification "
            "desactivee. Valeurs acceptees : %s",
            name,
            ", ".join(sorted(_REGISTRY)),
        )
        return DisabledVulnerabilityProvider()

    return implementation()
