"""Contrat de la securite projet : findings unifies, secrets, dependances.

Une seule forme de finding
--------------------------

`SecurityFinding` est le modele commun a toutes les familles de detection.
Un secret ecrit en dur et une dependance vulnerable different par leur
`category` et leur `detection_engine`, pas par leur structure : l'interface
les trie, les compte et les affiche par un seul chemin de code.

`CodeFinding` (analyse de fichier, `app.code.schemas`) reste inchange :
son contrat est deja publie, l'extension s'en sert, et le casser pour une
uniformite d'ecriture aurait coute plus qu'il ne rapporte. Les deux se
rejoignent dans la vue, pas dans le type.

Ce que ce contrat interdit structurellement
-------------------------------------------

- **la valeur d'un secret** : une preuve est expurgee avant d'entrer ici
  (`app.security.redaction`), et le validateur la reexpurge sans demander
  la permission a l'appelant ;
- **le chemin absolu d'un fichier** : seul un chemin relatif a la racine du
  projet circule (`app.paths`) ;
- **le contenu d'un fichier** : aucun champ ne peut le porter.
"""

import hashlib
from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field, computed_field, field_validator

from app import i18n
from app.ai.schemas import Severity
from app.paths import clean_relative_path
from app.security.redaction import redact_evidence

# --------------------------------------------------------------------------
# Referentiels
# --------------------------------------------------------------------------

# Familles de detection. `API` et `GIT` sont declarees des maintenant mais
# ne sont produites par aucun moteur : les nommer fige la place qu'elles
# occuperont, ce qui evite de migrer la base et l'interface quand elles
# arriveront. Une categorie annoncee mais vide est honnete ; une categorie
# inventee apres coup casse les filtres deja ecrits.
SecurityCategory = Literal[
    "SECRET",
    "DEPENDENCY",
    "CODE",
    "CONFIGURATION",
    "API",
    "GIT",
]

# Confiance de la detection, sur trois crans.
#
# Elle ne se confond pas avec la gravite : un mot de passe de production
# est grave meme si le motif est incertain, et un placeholder est sans
# gravite meme si le motif est formel. Les deux voyagent donc cote a cote
# jusqu'a l'ecran.
Confidence = Literal["HIGH", "MEDIUM", "LOW"]

SecurityFindingStatus = Literal["open", "dismissed", "fixed"]

# Ecosystemes de dependances reconnus. `unknown` est prevu : un manifeste
# d'un gestionnaire non pris en charge produit un inventaire, pas une
# erreur — et l'inventaire dit alors qu'il n'a pas pu etre verifie.
DependencyEcosystem = Literal[
    "npm",
    "pypi",
    "maven",
    "composer",
    "go",
    "rubygems",
    "cargo",
    "nuget",
    "unknown",
]

# Provenance d'une ligne d'inventaire. La distinction porte une consequence
# directe : un lockfile donne une version **exacte**, donc interrogeable ;
# un manifeste donne une contrainte, souvent pas.
DependencySource = Literal["manifest", "lockfile"]

MAX_REFERENCES = 8
MAX_TITLE_LENGTH = 200
MAX_DESCRIPTION_LENGTH = 1000


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clean_text(value: Optional[str], limit: int) -> str:
    if not value:
        return ""
    return " ".join(str(value).split())[:limit]


# --------------------------------------------------------------------------
# Finding unifie
# --------------------------------------------------------------------------


class SecurityFinding(BaseModel):
    """Un signalement de securite, quelle que soit sa famille.

    `evidence` est **toujours** expurgee : le validateur la repasse par
    `redact_evidence`, sans faire confiance a l'appelant. Ce n'est pas une
    precaution theorique — le backend ecoute en local, et tout processus de
    la machine peut poster sur ses routes.
    """

    id: str
    project_uid: str
    category: SecurityCategory
    severity: Severity = "MEDIUM"
    confidence: Confidence = "MEDIUM"
    title: str = ""
    description: str = ""
    # Chemin relatif a la racine du projet. `None` pour un finding qui ne
    # porte pas sur un fichier precis.
    file: Optional[str] = None
    line_start: int = Field(default=0, ge=0)
    line_end: int = Field(default=0, ge=0)
    # Preuve expurgee. Jamais la valeur reelle d'un secret.
    evidence: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    # Qui a produit ce finding : « secret-scanner@1.0.0 », « osv »…
    # Affiche tel quel : l'utilisateur doit pouvoir savoir a quoi il a
    # affaire, et contester.
    detection_engine: str = ""
    status: SecurityFindingStatus = "open"
    created_at: str = Field(default_factory=_now_iso)

    @field_validator("evidence")
    @classmethod
    def always_redacted(cls, value: str) -> str:
        return redact_evidence(value)

    @field_validator("title")
    @classmethod
    def clean_title(cls, value: str) -> str:
        return _clean_text(value, MAX_TITLE_LENGTH)

    @field_validator("description", "remediation")
    @classmethod
    def clean_long_text(cls, value: str) -> str:
        return _clean_text(value, MAX_DESCRIPTION_LENGTH)

    @field_validator("references")
    @classmethod
    def clean_references(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for item in value[:MAX_REFERENCES]:
            reference = (item or "").strip()
            # Seules des references documentaires : une URL arbitraire
            # affichee comme « reference » serait une invitation au clic.
            if reference.startswith(("https://", "CWE-", "CVE-", "GHSA-", "OSV-")):
                cleaned.append(reference[:300])
        return cleaned

    # --- Libelles francais (presentation seule) -------------------------

    @computed_field  # type: ignore[prop-decorator]
    @property
    def severity_label(self) -> str:
        return i18n.severity_label(self.severity)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def category_label(self) -> str:
        return i18n.security_category_label(self.category)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def confidence_label(self) -> str:
        return i18n.confidence_label(self.confidence)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def status_label(self) -> str:
        return i18n.code_finding_status_label(self.status)


def finding_fingerprint(
    category: str,
    detection_engine: str,
    file_path: Optional[str],
    line: int,
    discriminator: str,
) -> str:
    """Empreinte stable d'un finding, pour le reconnaitre d'un scan a l'autre.

    Sans elle, un second balayage creerait des doublons et, surtout, ferait
    reapparaitre ce que l'utilisateur a deja ecarte. L'empreinte ne porte
    **aucune valeur de secret** : le discriminant est le type de secret ou
    l'identifiant de vulnerabilite, jamais la valeur detectee.
    """
    material = "|".join(
        [category, detection_engine, file_path or "", str(line), discriminator]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def finding_id_for(project_uid: str, fingerprint: str) -> str:
    """Identifiant public d'un finding : propre a UN projet.

    L'empreinte ne porte pas le projet, et c'est voulu : elle sert a
    reconnaitre le meme probleme d'un balayage a l'autre, *dans* un
    projet (l'index unique est `project_uid, category, fingerprint`).
    L'identifiant, lui, est unique dans toute la base. Le deriver de la
    seule empreinte faisait entrer en collision deux projets portant le
    meme secret au meme endroit — `backend/config.py`, ligne 24 — et le
    second balayage echouait sur la contrainte d'unicite.

    Les lignes deja en base gardent leur identifiant : la reconciliation
    retrouve un finding par son empreinte et ne reecrit jamais
    `finding_id`. Aucun identifiant connu de l'extension ne change.
    """
    material = f"{project_uid}|{fingerprint}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


# --------------------------------------------------------------------------
# Secrets : ce que l'extension soumet
# --------------------------------------------------------------------------


class SecretFindingSubmission(BaseModel):
    """Un secret detecte **sur le poste**, decrit sans sa valeur.

    La detection tourne cote extension, pas ici : le backend ne lit jamais
    le disque du developpeur. Ce qui traverse est un constat — ou, quel
    type, avec quelle confiance — et une preuve deja expurgee, que le
    backend expurge une seconde fois.
    """

    rule_id: str = Field(default="", max_length=120)
    file_path: str
    line: int = Field(default=1, ge=1)
    # Colonne, quand le moteur la connait. `None` plutot que 0 : « je ne
    # sais pas » et « premiere colonne » ne sont pas la meme chose.
    column: Optional[int] = Field(default=None, ge=0)
    secret_type: str = Field(default="unknown", max_length=80)
    severity: Severity = "MEDIUM"
    confidence: Confidence = "MEDIUM"
    evidence_redacted: str = ""
    title: str = ""
    description: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)

    @field_validator("file_path")
    @classmethod
    def check_path(cls, value: str) -> str:
        return clean_relative_path(value)

    @field_validator("evidence_redacted")
    @classmethod
    def enforce_redaction(cls, value: str) -> str:
        """Expurgation imposee a l'entree, pas seulement a l'ecriture.

        Le modele ne peut donc pas porter une valeur en clair, meme le
        temps d'un traitement en memoire ou d'une ligne de journal.
        """
        return redact_evidence(value)


class SecretScanSubmission(BaseModel):
    """Resultat d'un balayage de secrets, tel que l'extension l'envoie."""

    findings: list[SecretFindingSubmission] = Field(default_factory=list)
    # Volumes : ils disent la couverture reelle du balayage.
    scanned_files: int = Field(default=0, ge=0)
    skipped_files: int = Field(default=0, ge=0)
    engine: str = Field(default="secret-scanner", max_length=80)
    engine_version: str = Field(default="", max_length=40)
    # Vrai quand un plafond a ete atteint : une couverture partielle se
    # dit, elle ne s'affiche jamais comme complete.
    truncated: bool = False
    warnings: list[str] = Field(default_factory=list)

    @field_validator("warnings")
    @classmethod
    def clean_warnings(cls, value: list[str]) -> list[str]:
        return [item.strip()[:500] for item in value[:50] if item and item.strip()]


class SecretStatistics(BaseModel):
    """Compte des secrets, jamais leurs valeurs."""

    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    files_with_secrets: int = 0
    scanned_files: int = 0
    # `True` quand le balayage a ete plafonne : le decompte est alors un
    # minorant, et l'interface doit pouvoir le dire.
    truncated: bool = False
    engine: str = ""
    last_scan: Optional[str] = None


class SecretScanResult(BaseModel):
    """Reponse a la soumission d'un balayage de secrets."""

    project_uid: str
    findings: list[SecurityFinding] = Field(default_factory=list)
    statistics: SecretStatistics = Field(default_factory=SecretStatistics)
    warnings: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------
# Securite d'API (phase 5)
# --------------------------------------------------------------------------


class ApiFindingSubmission(BaseModel):
    """Un probleme de securite d'API constate **sur le poste**.

    Meme forme que `SecretFindingSubmission`, et pour la meme raison : la
    detection est locale, et ce qui traverse est un constat — ou, quelle
    regle, avec quelle confiance — jamais le contenu du fichier analyse.

    `evidence` est un extrait **de declaration** : la ligne qui declare la
    route ou pose la configuration. Elle passe par `redact_evidence`
    comme toute preuve : une ligne de configuration peut porter un jeton,
    et le backend n'accorde aucune confiance a l'expurgation du client.
    """

    rule_id: str = Field(default="", max_length=120)
    file_path: str
    line: int = Field(default=1, ge=1)
    issue_type: str = Field(default="unknown", max_length=80)
    # Chemin de la route, quand la declaration le porte litteralement.
    endpoint: str = Field(default="", max_length=200)
    http_method: str = Field(default="", max_length=10)
    framework: str = Field(default="", max_length=40)
    severity: Severity = "MEDIUM"
    confidence: Confidence = "MEDIUM"
    evidence: str = Field(default="", max_length=400)
    title: str = ""
    description: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)

    @field_validator("file_path")
    @classmethod
    def check_path(cls, value: str) -> str:
        return clean_relative_path(value)

    @field_validator("evidence")
    @classmethod
    def enforce_redaction(cls, value: str) -> str:
        """Expurgation imposee a l'entree, comme pour les secrets.

        Une ligne de configuration d'API est precisement l'endroit ou un
        jeton se glisse : `Authorization: Bearer ghp_xxx`. Le modele ne
        peut donc pas porter une valeur en clair, meme le temps d'un
        traitement en memoire ou d'une ligne de journal.
        """
        return redact_evidence(value)


class ApiScanSubmission(BaseModel):
    """Resultat d'une analyse d'API, telle que l'extension l'envoie."""

    findings: list[ApiFindingSubmission] = Field(default_factory=list)
    scanned_files: int = Field(default=0, ge=0)
    # Routes relevees, y compris celles qui ne posent aucun probleme :
    # c'est ce chiffre qui dit la couverture reelle de l'analyse.
    endpoints_detected: int = Field(default=0, ge=0)
    engine: str = Field(default="api-scanner", max_length=80)
    engine_version: str = Field(default="", max_length=40)
    truncated: bool = False
    warnings: list[str] = Field(default_factory=list)

    @field_validator("warnings")
    @classmethod
    def clean_warnings(cls, value: list[str]) -> list[str]:
        return [item.strip()[:500] for item in value[:50] if item and item.strip()]


class ApiStatistics(BaseModel):
    """Compte des problemes d'API. Des nombres, jamais des chemins."""

    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    # Dit la couverture, pas le risque : un projet sans route detectee
    # n'est pas un projet sans API, c'est un projet dont l'agent n'a
    # reconnu aucune declaration.
    endpoints_detected: int = 0
    unauthenticated_endpoints: int = 0
    files_with_findings: int = 0
    scanned_files: int = 0
    truncated: bool = False
    engine: str = ""
    # `None` signifie « jamais analyse », pas « aucun probleme ».
    last_scan: Optional[str] = None


class ApiScanResult(BaseModel):
    """Reponse a la soumission d'une analyse d'API."""

    project_uid: str
    findings: list[SecurityFinding] = Field(default_factory=list)
    statistics: ApiStatistics = Field(default_factory=ApiStatistics)
    warnings: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------
# Dependances : inventaire
# --------------------------------------------------------------------------


class DependencyRecord(BaseModel):
    """Une dependance declaree, telle qu'un manifeste ou un lockfile la donne.

    `version` peut etre vide : un manifeste declare souvent une contrainte
    (`^1.2.0`) plutot qu'une version. Une contrainte n'est pas
    interrogeable — la dependance est alors inventoriee **et** signalee
    comme non verifiable, plutot que presentee comme saine.
    """

    name: str = Field(max_length=300)
    ecosystem: DependencyEcosystem = "unknown"
    version: str = Field(default="", max_length=120)
    # Declaree par le projet lui-meme, ou tiree par une autre dependance.
    direct: bool = True
    # Fichier qui porte la declaration. Chemin relatif.
    manifest: str
    source: DependencySource = "manifest"

    @field_validator("manifest")
    @classmethod
    def check_manifest(cls, value: str) -> str:
        return clean_relative_path(value)

    @field_validator("name")
    @classmethod
    def check_name(cls, value: str) -> str:
        name = (value or "").strip()
        if not name:
            raise ValueError("Le nom de la dependance est obligatoire")
        # Un nom de paquet ne porte ni blanc ni caractere de controle. Ce
        # filtre ecarte au passage une ligne de manifeste transmise par
        # erreur a la place d'un nom — c'est elle qui pourrait porter une
        # URL de depot privee avec identifiants.
        if any(character.isspace() for character in name):
            raise ValueError("Un nom de dependance ne contient pas d'espace")
        if "://" in name:
            raise ValueError("Un nom de dependance n'est pas une URL")
        return name

    @field_validator("version")
    @classmethod
    def check_version(cls, value: str) -> str:
        version = (value or "").strip()
        if any(character.isspace() for character in version):
            return ""
        return version

    @property
    def key(self) -> str:
        return f"{self.ecosystem}|{self.name}|{self.version}"


class DependencyInventorySubmission(BaseModel):
    """Inventaire complet, soumis apres lecture des manifestes et lockfiles.

    L'extension n'installe **jamais** les dependances du projet : elle lit
    les manifestes et les lockfiles, rien d'autre. Executer un gestionnaire
    de paquets pour resoudre un arbre reviendrait a executer du code
    arbitraire depuis un depot que l'on est precisement en train d'auditer.
    """

    dependencies: list[DependencyRecord] = Field(default_factory=list)
    manifests_read: int = Field(default=0, ge=0)
    truncated: bool = False
    warnings: list[str] = Field(default_factory=list)
    inventory_version: str = Field(default="", max_length=40)
    # Demande d'interrogation du fournisseur de vulnerabilites. Honoree
    # seulement si le backend l'a activee : le client demande, le serveur
    # decide — c'est lui qui detient la sortie reseau.
    check_vulnerabilities: bool = True

    @field_validator("warnings")
    @classmethod
    def clean_warnings(cls, value: list[str]) -> list[str]:
        return [item.strip()[:500] for item in value[:50] if item and item.strip()]


class EcosystemSummary(BaseModel):
    """Volumes par ecosysteme, avec ce qui a pu etre verifie."""

    ecosystem: str
    total: int = 0
    direct: int = 0
    vulnerable: int = 0
    # Dependances effectivement soumises au fournisseur et pour lesquelles
    # il a repondu. La difference avec `total` est la zone d'ombre.
    verified: int = 0


class DependencyStatistics(BaseModel):
    total: int = 0
    direct: int = 0
    transitive: int = 0
    vulnerable: int = 0
    # Dependances dont on ne sait rien : version non figee, ecosysteme non
    # pris en charge, fournisseur muet. Jamais comptees comme saines.
    unverified: int = 0
    manifests_read: int = 0
    truncated: bool = False
    last_inventory: Optional[str] = None


# --------------------------------------------------------------------------
# Vulnerabilites
# --------------------------------------------------------------------------

# Etat du fournisseur, tel qu'il sera affiche.
#
# La distinction entre ces valeurs est le coeur de l'honnetete de cette
# phase : « le fournisseur n'a pas repondu » n'est pas « il n'y a pas de
# vulnerabilite ». Deux etats seulement autorisent a conclure.
ProviderStatus = Literal[
    "available",
    "partial",
    "disabled",
    "unavailable",
    "timeout",
    "rate_limited",
    "error",
]

# Etats depuis lesquels on peut affirmer qu'une dependance interrogee est
# sans vulnerabilite connue. Volontairement reduit a deux.
CONCLUSIVE_STATUSES: frozenset[str] = frozenset({"available", "partial"})


class VulnerabilityStatistics(BaseModel):
    """Ce que l'analyse de vulnerabilites a etabli, et ce qu'elle ignore."""

    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    packages_affected: int = 0
    # Paquets pour lesquels le fournisseur a effectivement repondu.
    packages_checked: int = 0
    # Paquets non verifies : version non figee, ecosysteme non pris en
    # charge, ou fournisseur indisponible.
    packages_unverified: int = 0
    provider: str = ""
    provider_status: ProviderStatus = "disabled"
    # Message destine a l'utilisateur, deja redige. Jamais « aucune
    # vulnerabilite » quand le fournisseur n'a pas repondu.
    message: str = ""
    last_check: Optional[str] = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def conclusive(self) -> bool:
        """Peut-on conclure quoi que ce soit de ces chiffres ?

        Expose plutot que deduit cote client : c'est la question que
        l'interface doit poser avant d'ecrire « aucune vulnerabilite », et
        la reponse ne doit pas dependre d'une liste d'etats recopiee de ce
        cote-ci de la frontiere.
        """
        return self.provider_status in CONCLUSIVE_STATUSES

    @computed_field  # type: ignore[prop-decorator]
    @property
    def provider_status_label(self) -> str:
        return i18n.provider_status_label(self.provider_status)


class DependencyScanResult(BaseModel):
    """Reponse a la soumission d'un inventaire de dependances."""

    project_uid: str
    findings: list[SecurityFinding] = Field(default_factory=list)
    dependency_statistics: DependencyStatistics = Field(
        default_factory=DependencyStatistics
    )
    vulnerability_statistics: VulnerabilityStatistics = Field(
        default_factory=VulnerabilityStatistics
    )
    ecosystems: list[EcosystemSummary] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------
# Etat du moteur
# --------------------------------------------------------------------------


class SecurityEngineHealth(BaseModel):
    """Ce que le moteur de securite projet sait faire, ici et maintenant.

    Consultee par l'extension avant de balayer : annoncer une capacite qui
    ne tournera pas coute plus cher que de ne rien annoncer.
    """

    status: str = "ok"
    secret_detection_enabled: bool = True
    dependency_inventory_enabled: bool = True
    vulnerability_check_enabled: bool = False
    # Phase 5. Annoncee comme les autres : l'extension consulte cet etat
    # avant d'analyser, pour ne pas parcourir le disque et se faire
    # repondre 404 par une route que ce backend ne porte pas.
    api_security_enabled: bool = True
    # Phase 6. Annoncee comme les autres, et pour la meme raison :
    # l'extension consulte cet etat avant d'afficher le moindre bouton IA.
    # Faux ne signifie jamais « rien a expliquer » : il signifie
    # « l'assistant n'est pas la », et la detection continue sans lui.
    # `GET /api/security/ai/health` en donne le detail et la raison.
    ai_assistant_enabled: bool = False
    vulnerability_provider: str = ""
    # Ecosystemes que le fournisseur configure sait interroger.
    supported_ecosystems: list[str] = Field(default_factory=list)
    # Rappel explicite, verifie par un test : ces fonctions ne dependent
    # pas de Wazuh et tournent avec Wazuh arrete.
    requires_wazuh: bool = False
