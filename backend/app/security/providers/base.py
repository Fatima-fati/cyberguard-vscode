"""Abstraction du fournisseur de vulnerabilites.

Pourquoi une abstraction plutot qu'un appel direct
--------------------------------------------------

Trois raisons, dans l'ordre de leur poids :

1. **Les vulnerabilites ne sont pas ecrites dans ce depot.** Une liste de
   CVE en dur serait perimee le lendemain de sa redaction et donnerait une
   fausse assurance. Elles viennent d'une base tenue a jour, et le code ne
   doit dependre que de la forme de la reponse, pas de la base.
2. **Un fournisseur muet doit se distinguer d'un projet sain.** L'interface
   `VulnerabilityProvider` impose donc de renvoyer un *etat*, pas seulement
   une liste. Un appelant ne peut pas ignorer l'etat : il n'y a pas de
   forme de retour qui ressemble a « aucune vulnerabilite » quand la
   requete a echoue.
3. **Les tests ne doivent pas dependre du reseau.** Un double implementant
   cette interface suffit a exercer toute la chaine.

Ce module ne fait aucun appel reseau : il ne decrit que la forme du
contrat. L'implementation OSV vit a cote.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Sequence

from app.ai.schemas import Severity
from app.security.schemas import CONCLUSIVE_STATUSES, ProviderStatus


@dataclass(frozen=True)
class PackageQuery:
    """Un paquet a verifier, dans sa forme minimale.

    Ce qui n'y figure pas est aussi important que ce qui y figure : ni
    chemin de fichier, ni identifiant de projet, ni contenu. Ce qui sort
    vers un service externe se limite a un nom de paquet, son ecosysteme et
    sa version — soit exactement ce qu'un registre public connait deja.
    """

    name: str
    ecosystem: str
    version: str

    @property
    def key(self) -> str:
        return f"{self.ecosystem}|{self.name}|{self.version}"


@dataclass(frozen=True)
class PackageVulnerability:
    """Une vulnerabilite connue affectant un paquet a une version donnee."""

    identifier: str
    summary: str = ""
    severity: Severity = "MEDIUM"
    # Version corrigee, quand la base la donne. C'est l'information la plus
    # actionnable du lot : sans elle, la remediation reste « mettez a
    # jour », ce qui n'aide personne.
    fixed_version: Optional[str] = None
    aliases: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    # Precise quand la gravite a ete deduite faute de score publie : la
    # difference doit rester visible jusqu'a l'utilisateur.
    severity_source: str = "provider"


@dataclass
class ProviderOutcome:
    """Reponse d'un fournisseur : des resultats **et** un etat.

    `status` n'est pas decoratif. Il decide de ce que l'appelant a le droit
    d'ecrire :

        available / partial   -> « verifie », un decompte a du sens
        tout le reste         -> « impossible de verifier »

    `checked` liste les paquets pour lesquels la reponse fait autorite. Un
    paquet absent de `checked` n'est pas sain : il est inconnu.
    """

    status: ProviderStatus = "disabled"
    # Vulnerabilites par cle de paquet (`PackageQuery.key`).
    vulnerabilities: dict[str, list[PackageVulnerability]] = field(
        default_factory=dict
    )
    checked: set[str] = field(default_factory=set)
    # Detail technique, destine au journal. Jamais affiche tel quel.
    detail: str = ""

    @property
    def conclusive(self) -> bool:
        return self.status in CONCLUSIVE_STATUSES

    def for_package(self, query: PackageQuery) -> list[PackageVulnerability]:
        return self.vulnerabilities.get(query.key, [])

    def was_checked(self, query: PackageQuery) -> bool:
        """Le fournisseur a-t-il reellement repondu pour ce paquet ?

        Distinct de « ce paquet n'a pas de vulnerabilite » : c'est cette
        distinction qui empeche d'ecrire « dependance saine » a partir d'un
        silence.
        """
        return self.conclusive and query.key in self.checked


class VulnerabilityProvider(ABC):
    """Source de verite sur les vulnerabilites connues d'un paquet."""

    #: Nom affiche a l'utilisateur, et enregistre avec chaque finding.
    name: str = "unknown"

    @property
    @abstractmethod
    def supported_ecosystems(self) -> frozenset[str]:
        """Ecosystemes que ce fournisseur sait interroger.

        Un ecosysteme absent d'ici n'est jamais interroge, et les paquets
        concernes sont comptes « non verifies » plutot que « sains ».
        """

    @abstractmethod
    async def check(self, packages: Sequence[PackageQuery]) -> ProviderOutcome:
        """Verifie un lot de paquets.

        Ne leve jamais pour une panne du service : une base injoignable est
        un **resultat** (`status`), pas une exception qui remonterait
        jusqu'a l'utilisateur sous forme d'erreur 500. Seules les erreurs de
        programmation remontent.
        """


class DisabledVulnerabilityProvider(VulnerabilityProvider):
    """Fournisseur inerte, utilise quand la verification est desactivee.

    Un objet plutot que `None` : l'appelant suit le meme chemin de code
    dans les deux cas, et l'etat `disabled` se propage jusqu'a l'ecran au
    lieu d'etre confondu avec un resultat vide.
    """

    name = "disabled"

    @property
    def supported_ecosystems(self) -> frozenset[str]:
        return frozenset()

    async def check(self, packages: Sequence[PackageQuery]) -> ProviderOutcome:
        return ProviderOutcome(
            status="disabled",
            detail="Verification des vulnerabilites desactivee par configuration",
        )
