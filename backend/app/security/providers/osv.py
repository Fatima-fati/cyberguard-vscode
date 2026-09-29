"""Fournisseur de vulnerabilites adosse a OSV (osv.dev).

Pourquoi OSV
------------

Base publique, structuree, gratuite, sans compte ni cle, couvrant les
ecosystemes que ce projet inventorie (npm, PyPI, Maven, Packagist, Go,
RubyGems, crates.io, NuGet). Aucune vulnerabilite n'est ecrite dans ce
depot : elles viennent d'ici, et le code ne depend que de la forme de la
reponse.

Ce qui sort de la machine
-------------------------

Un nom de paquet, son ecosysteme, sa version. Rien d'autre : ni chemin,
ni identifiant de projet, ni contenu de fichier. C'est exactement ce
qu'un registre public connait deja de ces paquets.

Cette sortie reseau reste neanmoins une **decision** : elle est reglee par
`DEPENDENCY_VULNERABILITY_ENABLED` et peut etre coupee, auquel cas
l'inventaire continue de fonctionner et l'etat affiche devient
« verification desactivee » — jamais « aucune vulnerabilite ».

Deux echanges, et pourquoi
--------------------------

    POST /v1/querybatch   -> quels paquets sont concernes (lot de 1000)
    GET  /v1/vulns/{id}   -> le detail d'une vulnerabilite

`querybatch` ne renvoie que des identifiants : c'est un appel, quel que
soit le nombre de dependances. Le detail n'est demande que pour les
identifiants reellement rencontres, et il est plafonne — un projet qui
tirerait deux mille vulnerabilites ne doit pas produire deux mille
requetes.
"""

import asyncio
import logging
from typing import Any, Optional, Sequence

import httpx

from app.ai.schemas import Severity
from app.config import settings
from app.security.providers.base import (
    PackageQuery,
    PackageVulnerability,
    ProviderOutcome,
    VulnerabilityProvider,
)

logger = logging.getLogger(__name__)

# Ecosysteme interne -> nom OSV. La table est la frontiere : au-dela, le
# vocabulaire du projet ne circule plus.
ECOSYSTEM_TO_OSV: dict[str, str] = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "composer": "Packagist",
    "go": "Go",
    "rubygems": "RubyGems",
    "cargo": "crates.io",
    "nuget": "NuGet",
}

# Taille maximale d'un lot accepte par `querybatch`.
BATCH_SIZE = 500

# Correspondance entre le vocabulaire de gravite des bases publiques et
# l'echelle unique du projet (LOW / MEDIUM / HIGH / CRITICAL).
_SEVERITY_WORDS: dict[str, Severity] = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "moderate": "MEDIUM",
    "medium": "MEDIUM",
    "low": "LOW",
}


def severity_from_cvss_score(score: float) -> Severity:
    """Gravite a partir d'un score CVSS v3, selon les paliers usuels."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _severity_from_vector(vector: str) -> Optional[Severity]:
    """Gravite deduite d'un vecteur CVSS, quand le score brut est absent.

    OSV publie souvent un vecteur (`CVSS:3.1/AV:N/...`) sans le score
    calcule. Recalculer un CVSS complet ici serait disproportionne ; on
    retient les deux composantes qui pesent le plus et on reste prudent —
    la gravite deduite est annoncee comme telle (`severity_source`).
    """
    if "CVSS:" not in vector.upper():
        return None

    parts = dict(
        piece.split(":", 1)
        for piece in vector.upper().split("/")
        if ":" in piece and not piece.startswith("CVSS")
    )
    network = parts.get("AV") == "N"
    no_privileges = parts.get("PR") == "N"
    high_impact = "H" in {parts.get("C"), parts.get("I"), parts.get("A")}

    if network and no_privileges and high_impact:
        return "HIGH"
    if high_impact:
        return "MEDIUM"
    return "LOW"


def _severity_of(vulnerability: dict[str, Any]) -> tuple[Severity, str]:
    """Gravite d'une vulnerabilite OSV, avec l'origine de cette gravite.

    Trois sources, par ordre de fiabilite decroissante. L'origine voyage
    avec la valeur : une gravite deduite d'un vecteur ne doit pas se
    presenter comme un score publie.
    """
    for entry in vulnerability.get("severity") or []:
        raw = str(entry.get("score", ""))
        try:
            return severity_from_cvss_score(float(raw)), "cvss-score"
        except (TypeError, ValueError):
            deduced = _severity_from_vector(raw)
            if deduced is not None:
                return deduced, "cvss-vector"

    specific = vulnerability.get("database_specific") or {}
    word = str(specific.get("severity", "")).strip().lower()
    if word in _SEVERITY_WORDS:
        return _SEVERITY_WORDS[word], "database"

    # Aucune gravite publiee. `MEDIUM` plutot que `LOW` : une
    # vulnerabilite dont on ignore la portee ne doit pas se ranger au bas
    # de la liste, ou personne ne la lira.
    return "MEDIUM", "unrated"


def _fixed_version(vulnerability: dict[str, Any], package_name: str) -> Optional[str]:
    """Premiere version corrigee annoncee pour ce paquet, si elle existe."""
    for affected in vulnerability.get("affected") or []:
        package = affected.get("package") or {}
        if package.get("name") and package["name"] != package_name:
            continue
        for entry in affected.get("ranges") or []:
            for event in entry.get("events") or []:
                if event.get("fixed"):
                    return str(event["fixed"])[:80]
    return None


def _references(vulnerability: dict[str, Any]) -> tuple[str, ...]:
    """References documentaires, limitees a HTTPS et a un petit nombre."""
    urls: list[str] = []
    for reference in vulnerability.get("references") or []:
        url = str(reference.get("url", "")).strip()
        if url.startswith("https://") and url not in urls:
            urls.append(url[:300])
        if len(urls) >= 4:
            break
    return tuple(urls)


class OsvVulnerabilityProvider(VulnerabilityProvider):
    """Implementation OSV de `VulnerabilityProvider`.

    Le transport HTTP est injectable : les tests exercent la chaine reelle
    — serialisation, pagination, gestion des codes d'erreur — sans toucher
    au reseau. Un double qui se contenterait de renvoyer des objets Python
    ne prouverait rien du decodage.
    """

    name = "osv"

    def __init__(
        self,
        base_url: Optional[str] = None,
        timeout_seconds: Optional[float] = None,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        max_packages: Optional[int] = None,
        max_details: Optional[int] = None,
    ) -> None:
        self.base_url = (base_url or settings.osv_api_url).rstrip("/")
        self.timeout_seconds = timeout_seconds or settings.osv_timeout_seconds
        self.transport = transport
        self.max_packages = max_packages or settings.osv_max_packages
        self.max_details = max_details or settings.osv_max_vulnerability_details

    @property
    def supported_ecosystems(self) -> frozenset[str]:
        return frozenset(ECOSYSTEM_TO_OSV)

    async def check(self, packages: Sequence[PackageQuery]) -> ProviderOutcome:
        """Interroge OSV pour un lot de paquets.

        Ne leve jamais pour une panne du service : chaque mode de defaut a
        son etat, et c'est l'etat qui decide de ce que l'interface a le
        droit d'ecrire.
        """
        interrogeable = [
            package
            for package in packages
            if package.ecosystem in ECOSYSTEM_TO_OSV and package.version
        ]
        if not interrogeable:
            # Rien a demander n'est pas une panne : le fournisseur est
            # disponible, il n'a simplement rien a verifier.
            return ProviderOutcome(
                status="available",
                detail="Aucun paquet interrogeable (version non figee ou ecosysteme non couvert)",
            )

        truncated = len(interrogeable) > self.max_packages
        interrogeable = interrogeable[: self.max_packages]

        try:
            async with httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout_seconds,
                transport=self.transport,
                headers={"Accept": "application/json"},
            ) as client:
                identifiers = await self._query_batch(client, interrogeable)
                details = await self._fetch_details(client, identifiers)
        except httpx.TimeoutException as exc:
            logger.warning("OSV hors delai : %s", exc)
            return ProviderOutcome(status="timeout", detail=str(exc)[:200])
        except _RateLimited as exc:
            logger.warning("OSV : quota atteint (%s)", exc.status_code)
            return ProviderOutcome(status="rate_limited", detail=str(exc)[:200])
        except _ProviderHttpError as exc:
            logger.warning("OSV a repondu HTTP %s", exc.status_code)
            return ProviderOutcome(status="error", detail=str(exc)[:200])
        except httpx.HTTPError as exc:
            # Reseau coupe, DNS muet, TLS refuse : injoignable. Surtout
            # pas « aucune vulnerabilite ».
            logger.warning("OSV injoignable : %s", exc)
            return ProviderOutcome(status="unavailable", detail=str(exc)[:200])
        except ValueError as exc:
            # Corps illisible : une page d'erreur HTML servie par un
            # intermediaire, par exemple. Le service a repondu, mais rien
            # n'en est exploitable — et surtout pas « rien a signaler ».
            logger.warning("OSV a repondu un corps illisible : %s", exc)
            return ProviderOutcome(status="error", detail=str(exc)[:200])

        # La description est faite PAR PAQUET, pas une fois par avis : la
        # version corrigee depend du paquet concerne, et un meme avis peut
        # couvrir plusieurs paquets avec des versions de correction
        # differentes.
        by_key = {package.key: package for package in interrogeable}

        vulnerabilities: dict[str, list[PackageVulnerability]] = {}
        for key, ids in identifiers.items():
            package = by_key.get(key)
            if package is None:
                continue
            found = [
                _describe(identifier, details[identifier], package.name)
                for identifier in ids
                if identifier in details
            ]
            if found:
                vulnerabilities[key] = found

        checked = {package.key for package in interrogeable}

        # Un detail manquant signifie qu'une vulnerabilite a ete annoncee
        # sans pouvoir etre decrite : le resultat est partiel, et il le dit.
        incomplete = any(
            identifier not in details
            for ids in identifiers.values()
            for identifier in ids
        )
        status = "partial" if (truncated or incomplete) else "available"

        return ProviderOutcome(
            status=status,
            vulnerabilities=vulnerabilities,
            checked=checked,
            detail=(
                f"{len(checked)} paquet(s) interroge(s), "
                f"{len(details)} vulnerabilite(s) decrite(s)"
                + (" [lot plafonne]" if truncated else "")
            ),
        )

    # ---------------- Interne ----------------

    async def _query_batch(
        self, client: httpx.AsyncClient, packages: Sequence[PackageQuery]
    ) -> dict[str, list[str]]:
        """Identifiants de vulnerabilites par paquet, en un appel par lot."""
        found: dict[str, list[str]] = {}

        for start in range(0, len(packages), BATCH_SIZE):
            chunk = packages[start : start + BATCH_SIZE]
            payload = {
                "queries": [
                    {
                        "version": package.version,
                        "package": {
                            "name": package.name,
                            "ecosystem": ECOSYSTEM_TO_OSV[package.ecosystem],
                        },
                    }
                    for package in chunk
                ]
            }

            response = await client.post("/v1/querybatch", json=payload)
            _raise_for_status(response)

            results = (response.json() or {}).get("results") or []
            for package, result in zip(chunk, results):
                ids = [
                    str(entry.get("id"))
                    for entry in (result or {}).get("vulns") or []
                    if entry.get("id")
                ]
                if ids:
                    found[package.key] = ids

        return found

    async def _fetch_details(
        self, client: httpx.AsyncClient, identifiers: dict[str, list[str]]
    ) -> dict[str, dict[str, Any]]:
        """Documents bruts des vulnerabilites rencontrees, une fois chacune.

        Rend les documents plutot que des `PackageVulnerability` construits,
        parce que la description depend du **paquet** concerne : un meme
        avis peut couvrir plusieurs paquets et annoncer pour chacun une
        version corrigee differente. Construire ici forcerait a choisir un
        paquet arbitrairement.

        Le plafond est assume : au-dela, la liste affichee n'est plus
        lisible de toute facon, et l'etat `partial` dit qu'elle est
        incomplete plutot que de laisser croire qu'elle est exhaustive.
        """
        unique: list[str] = []
        for ids in identifiers.values():
            for identifier in ids:
                if identifier not in unique:
                    unique.append(identifier)

        unique = unique[: self.max_details]
        if not unique:
            return {}

        async def fetch(identifier: str) -> tuple[str, Optional[dict[str, Any]]]:
            try:
                response = await client.get(f"/v1/vulns/{identifier}")
                _raise_for_status(response)
                return identifier, response.json()
            except (httpx.HTTPError, _ProviderHttpError, ValueError):
                # Le detail d'une vulnerabilite peut manquer sans que le
                # lot entier soit perdu : l'etat deviendra `partial`.
                return identifier, None

        documents: dict[str, dict[str, Any]] = {}
        for identifier, document in await asyncio.gather(
            *(fetch(identifier) for identifier in unique)
        ):
            if document:
                documents[identifier] = document

        return documents


def _describe(
    identifier: str, document: dict[str, Any], package_name: str
) -> PackageVulnerability:
    """Decrit un avis **pour un paquet donne**.

    Le nom du paquet n'est pas decoratif : c'est lui qui selectionne la
    bonne entree `affected`, donc la bonne version corrigee. Sans lui, la
    remediation se reduirait a « mettez a jour », ce qui n'aide personne.
    """
    severity, source = _severity_of(document)
    return PackageVulnerability(
        identifier=identifier,
        summary=str(document.get("summary") or "").strip()[:300],
        severity=severity,
        fixed_version=_fixed_version(document, package_name),
        aliases=tuple(str(alias) for alias in (document.get("aliases") or [])[:4]),
        references=_references(document),
        severity_source=source,
    )


# --------------------------------------------------------------------------
# Erreurs internes
# --------------------------------------------------------------------------


class _ProviderHttpError(Exception):
    """Reponse HTTP inexploitable du fournisseur."""

    def __init__(self, status_code: int) -> None:
        super().__init__(f"HTTP {status_code}")
        self.status_code = status_code


class _RateLimited(_ProviderHttpError):
    """Quota atteint. Distingue d'une panne : reessayer plus tard a du sens."""


def _raise_for_status(response: httpx.Response) -> None:
    if response.status_code in (429, 403):
        raise _RateLimited(response.status_code)
    if response.status_code >= 400:
        raise _ProviderHttpError(response.status_code)
