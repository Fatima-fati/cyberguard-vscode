"""Contrat HTTP du contexte de projet.

Deux directions, deux formes :

    Extension -> Backend    ProjectDiscoverRequest, ProjectIndexRequest
    Backend -> Extension    ProjectSecurityContext

Ce que ce contrat **interdit structurellement** — non par discipline du
code appelant, mais parce qu'aucun champ ne peut le porter :

- le chemin absolu du workspace : seul `root_hash` circule ;
- le contenu d'un fichier : l'index porte une empreinte et une taille ;
- la valeur d'un secret : un fichier sensible est decrit par son chemin,
  son type et la raison de son classement, jamais par ce qu'il contient ;
- l'URL complete d'un remote Git : seul l'hote, qui ne peut pas porter de
  jeton d'acces.
"""

from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator

from app.paths import MAX_PATH_LENGTH, clean_relative_path
from app.security.schemas import (
    ApiStatistics,
    DependencyStatistics,
    EcosystemSummary,
    SecretStatistics,
    VulnerabilityStatistics,
)

# Nature d'un fichier de l'index. `sensitive` n'est pas une gravite : c'est
# un classement qui dit « ne jamais lire ce fichier », pas « ce fichier est
# vulnerable ».
FileKind = Literal[
    "source",
    "manifest",
    "config",
    "infra",
    "test",
    "sensitive",
    "documentation",
    "other",
]

# Etat du contexte, tel que l'interface l'affiche. Aucun score : la posture
# de securite explicable appartient a une phase ulterieure, et un chiffre
# sans son explication serait trompeur.
ProjectStatus = Literal["discovery", "security_scan", "analysis", "ready", "error"]

MAX_DEPENDENCY_NAMES = 500

# La validation vit dans `app.paths` : le contexte de projet et les
# findings de securite en dependent tous les deux, et une regle de
# securite dupliquee finit par diverger.
_clean_relative_path = clean_relative_path


# --------------------------------------------------------------------------
# Entrees
# --------------------------------------------------------------------------


class ProjectDiscoverRequest(BaseModel):
    """Enregistrement d'un projet. Premiere etape de la decouverte.

    Ne porte que l'identite : l'index arrive ensuite, par une route
    distincte, parce qu'il peut peser plusieurs milliers d'entrees alors
    que l'identite tient en trois champs.
    """

    # SHA-256 du chemin racine normalise, calcule par l'extension.
    root_hash: str
    # Nom affichable. C'est le nom du dossier, pas son chemin.
    project_name: str = ""
    discovery_version: str = ""

    @field_validator("root_hash")
    @classmethod
    def check_root_hash(cls, value: str) -> str:
        digest = (value or "").strip().lower()
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError("root_hash doit etre un SHA-256 hexadecimal (64 caracteres)")
        return digest

    @field_validator("project_name")
    @classmethod
    def check_project_name(cls, value: str) -> str:
        name = (value or "").strip()
        if len(name) > 200:
            raise ValueError("Nom de projet trop long")
        # Un nom de dossier peut ressembler a un chemin sous Windows ; on
        # ne garde que le dernier segment pour ne pas stocker d'arborescence.
        return name.replace("\\", "/").rstrip("/").split("/")[-1]


class IndexedFile(BaseModel):
    """Une entree de l'index. Metadonnee seulement, jamais de contenu."""

    path: str
    # Empreinte du contenu, calculee par l'extension. Sert au cache
    # incrementiel des phases suivantes ; le backend ne la recalcule pas.
    content_hash: Optional[str] = None
    size: int = Field(default=0, ge=0)
    # Date de derniere modification, telle que l'extension l'a lue.
    mtime: Optional[str] = None

    @field_validator("path")
    @classmethod
    def check_path(cls, value: str) -> str:
        return _clean_relative_path(value)


class ManifestEvidence(BaseModel):
    """Preuve extraite d'un manifeste de dependances.

    **Des noms, jamais des versions ni du contenu.** Un manifeste peut
    porter une URL de depot privee avec identifiants (`--index-url
    https://user:mdp@…` dans un requirements.txt) : n'en extraire que les
    noms de paquets ecarte cette fuite par construction. Les versions
    seront necessaires a l'analyse de dependances, qui n'est pas cette
    phase et aura son propre contrat.
    """

    path: str
    # npm | pypi | maven | composer | nuget | go | rubygems | unknown
    ecosystem: str = "unknown"
    dependency_names: list[str] = Field(default_factory=list)

    @field_validator("path")
    @classmethod
    def check_path(cls, value: str) -> str:
        return _clean_relative_path(value)

    @field_validator("dependency_names")
    @classmethod
    def check_names(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for name in value[:MAX_DEPENDENCY_NAMES]:
            candidate = (name or "").strip()
            # Un nom de paquet n'a pas de blanc ni de caractere de
            # controle. Ce filtre ecarte au passage une ligne de manifeste
            # transmise par erreur a la place d'un nom.
            if candidate and len(candidate) <= 214 and not any(
                char.isspace() for char in candidate
            ):
                cleaned.append(candidate)
        return cleaned


class GitMetadata(BaseModel):
    """Metadonnees Git : presence et hote, rien de plus.

    Pas de branche courante, pas de dernier commit, pas d'historique :
    la phase 1 constate l'existence du depot. `git_remote_host` porte
    l'hote seul parce qu'une URL de remote complete peut contenir un
    jeton d'acces.
    """

    detected: bool = False
    remote_host: Optional[str] = None

    @field_validator("remote_host")
    @classmethod
    def check_remote_host(cls, value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        host = value.strip().lower()
        # Ceinture et bretelles : si une URL complete arrive malgre tout,
        # on ne conserve que l'hote plutot que de l'enregistrer telle
        # quelle. Un `@` ou un `/` signale une URL, donc un risque de jeton.
        if "@" in host or "/" in host or ":" in host:
            raise ValueError("Seul l'hote du remote est accepte, jamais l'URL complete")
        return host[:255] or None


class ProjectIndexRequest(BaseModel):
    """Index complet d'un projet, soumis apres l'enregistrement.

    Remplace l'index precedent dans son entier : un fichier supprime du
    projet doit disparaitre du contexte, sinon le decompte affiche devient
    faux.
    """

    files: list[IndexedFile] = Field(default_factory=list)
    manifests: list[ManifestEvidence] = Field(default_factory=list)
    git: GitMetadata = Field(default_factory=GitMetadata)
    # Nombre de fichiers rencontres avant plafonnement. Superieur a
    # `len(files)` quand la decouverte a ete tronquee.
    discovered_count: int = Field(default=0, ge=0)
    truncated: bool = False
    # Ce que la decouverte n'a pas pu faire : fichiers trop gros, dossiers
    # illisibles, liens symboliques ecartes. Remonte tel quel a
    # l'utilisateur — une troncature silencieuse serait un mensonge.
    warnings: list[str] = Field(default_factory=list)
    discovery_version: str = ""

    @field_validator("warnings")
    @classmethod
    def check_warnings(cls, value: list[str]) -> list[str]:
        return [item.strip()[:500] for item in value[:50] if item and item.strip()]


# --------------------------------------------------------------------------
# Sortie
# --------------------------------------------------------------------------


class DetectedLanguage(BaseModel):
    """Un langage **constate**, avec le nombre de fichiers qui l'attestent.

    Jamais un langage « pris en charge » : la liste dit ce que ce projet
    contient, pas ce que le moteur saurait analyser.
    """

    language: str
    file_count: int = Field(default=0, ge=0)
    # Part des fichiers source du projet, en pourcentage entier.
    share: int = Field(default=0, ge=0, le=100)
    # Le moteur d'analyse de code a-t-il des regles pour ce langage ?
    # Affiche tel quel : annoncer une couverture inexistante serait pire
    # que de ne rien annoncer.
    analysis_supported: bool = False


class DetectedFramework(BaseModel):
    """Un framework, sa preuve et son origine.

    `evidence` et `source` ne sont pas decoratifs : sans preuve, un
    framework « detecte » est une affirmation non verifiable, et le projet
    s'interdit ce genre d'affirmation.
    """

    framework: str
    # dependency | config-file | manifest
    evidence: str
    # Fichier qui porte la preuve.
    source: str
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class ClassifiedFile(BaseModel):
    """Fichier retenu dans le contexte, avec la raison de son classement."""

    path: str
    kind: FileKind
    # Type precis : `npm-manifest`, `docker`, `environment-secrets`…
    type: str
    # Pourquoi ce fichier est dans cette liste. Affiche a l'utilisateur.
    reason: str = ""


class FileStatistics(BaseModel):
    """Volumes. `truncated` est aussi important que les nombres."""

    discovered: int = 0
    indexed: int = 0
    source: int = 0
    manifests: int = 0
    configuration: int = 0
    tests: int = 0
    sensitive: int = 0
    truncated: bool = False


class ProjectSecurityContext(BaseModel):
    """Ce que l'agent sait du projet.

    Aucun score de securite : la posture explicable, avec sa couverture,
    appartient a une phase ulterieure. `status` decrit ou en est le
    traitement, pas la qualite du projet.
    """

    project_uid: str
    project_name: str
    root_hash: str
    status: ProjectStatus = "ready"

    project_types: list[str] = Field(default_factory=list)
    primary_language: Optional[str] = None
    languages: list[DetectedLanguage] = Field(default_factory=list)
    frameworks: list[DetectedFramework] = Field(default_factory=list)

    file_statistics: FileStatistics = Field(default_factory=FileStatistics)
    manifests: list[ClassifiedFile] = Field(default_factory=list)
    important_files: list[ClassifiedFile] = Field(default_factory=list)
    configuration_files: list[ClassifiedFile] = Field(default_factory=list)
    # Chemin, type et raison. **Jamais le contenu**, jamais un extrait,
    # jamais un nombre de cles : lire un `.env` pour en compter les
    # entrees serait deja le lire.
    security_sensitive_files: list[ClassifiedFile] = Field(default_factory=list)

    git_repository_detected: bool = False
    git_remote_host: Optional[str] = None

    # --- Securite projet (phase 2) -----------------------------------
    #
    # **Des nombres, jamais des valeurs.** Ces quatre champs disent
    # combien de secrets ont ete reperes et dans combien de fichiers,
    # combien de dependances le projet tire et combien sont vulnerables.
    # Aucun ne peut porter la valeur d'un secret : leurs types ne
    # contiennent que des entiers, des libelles d'ecosysteme et un etat
    # de fournisseur.
    #
    # Le detail — quel fichier, quelle ligne, quelle preuve expurgee —
    # vit dans les findings (`GET /api/project/{uid}/findings`), pas ici :
    # un contexte est un resume, et un resume qui grossit a chaque
    # balayage cesse d'en etre un.
    secret_statistics: SecretStatistics = Field(default_factory=SecretStatistics)
    # Phase 5 : decomptes de securite d'API. Des nombres et des libelles,
    # jamais un chemin de route sensible ni un extrait de configuration.
    api_statistics: ApiStatistics = Field(default_factory=ApiStatistics)
    dependency_statistics: DependencyStatistics = Field(
        default_factory=DependencyStatistics
    )
    dependency_ecosystems: list[EcosystemSummary] = Field(default_factory=list)
    # Porte `provider_status` : c'est lui qui distingue « verifie, rien
    # trouve » de « personne n'a pu regarder ». Sans lui, un zero se
    # lirait comme un feu vert.
    vulnerability_statistics: VulnerabilityStatistics = Field(
        default_factory=VulnerabilityStatistics
    )

    warnings: list[str] = Field(default_factory=list)
    last_discovery: Optional[str] = None
    discovery_version: str = ""


class ProjectRegistration(BaseModel):
    """Reponse de l'enregistrement : l'identifiant, et ou en est le projet."""

    project_uid: str
    project_name: str
    root_hash: str
    status: ProjectStatus
    # Vrai si ce projet etait deja connu : l'extension sait alors qu'un
    # contexte existe peut-etre deja et peut eviter une decouverte.
    known: bool = False
    last_discovery: Optional[str] = None
