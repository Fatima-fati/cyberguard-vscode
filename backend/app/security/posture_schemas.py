"""Contrat de la posture de securite et du controle CI/CD (phase 8).

**Aucun score.** Ni note, ni pourcentage, ni « indice de securite ». La
posture est une **lecture** de ce que les moteurs deterministes ont deja
etabli — findings, statistiques de balayage, couverture — presentee par
domaine, avec ce qui manque dit en toutes lettres. Un chiffre unique
resumerait precisement ce qu'il faut ne pas resumer : la difference entre
« rien trouve » et « rien regarde ».

Quatre etats, et un seul sens pour chacun :

    not_analyzed   aucune analyse n'a eu lieu : `findings` vaut `None`,
                   JAMAIS 0 ;
    unavailable    la capacite est coupee ou n'existe pas ici ;
    no_findings    analyse faite, rien de signale — ce qui n'est pas
                   « sur » : la couverture dit jusqu'ou l'analyse est allee ;
    findings       analyse faite, au moins un finding ouvert.

L'IA n'intervient nulle part : aucun champ de ce module n'est produit par
un modele, et le controle CI fonctionne sans cle API, sans Wazuh.
"""

from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator

PostureAreaName = Literal["secrets", "dependencies", "code", "api", "git"]
AreaCoverage = Literal["not_analyzed", "complete", "partial", "unavailable"]
AreaState = Literal["not_analyzed", "unavailable", "no_findings", "findings"]
OverallAnalysis = Literal["not_analyzed", "partial", "complete"]

CiMode = Literal["off", "warn", "block"]
CiStatus = Literal["off", "passed", "warning", "blocked"]

# Conditions evaluables par la politique CI. Chacune est un fait
# deterministe, calcule depuis la posture — jamais un avis.
CiCondition = Literal[
    "critical_findings",
    "high_findings",
    "secrets_present",
    "vulnerable_dependencies",
    "analysis_incomplete",
    "vulnerability_provider_unavailable",
    "unsupported_languages",
]
CI_CONDITIONS: tuple[str, ...] = (
    "critical_findings",
    "high_findings",
    "secrets_present",
    "vulnerable_dependencies",
    "analysis_incomplete",
    "vulnerability_provider_unavailable",
    "unsupported_languages",
)

CI_SCHEMA_VERSION = "1.0"

HISTORY_UNAVAILABLE = (
    "Historique insuffisant : les findings résolus ne sont pas conservés d'un "
    "balayage à l'autre. Seul l'état courant est affiché."
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class PostureCounts(BaseModel):
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class PostureArea(BaseModel):
    """Un domaine de securite, tel que les moteurs le connaissent."""

    area: PostureAreaName
    state: AreaState
    coverage: AreaCoverage
    # `None` quand rien n'a ete analyse : un zero se lirait « aucun
    # probleme », et c'est exactement la confusion interdite.
    findings: Optional[PostureCounts] = None
    last_scan: Optional[str] = None
    # Volumes propres au domaine : dependances non verifiees, routes
    # relevees, fichiers analyses. Des nombres, jamais des chemins.
    metrics: dict[str, int] = Field(default_factory=dict)
    # Ce qui rend l'analyse incomplete, redige pour l'ecran.
    warnings: list[str] = Field(default_factory=list)


class PostureCoverage(BaseModel):
    """Jusqu'ou l'analyse est allee."""

    context_available: bool = False
    files_discovered: int = 0
    files_indexed: int = 0
    index_truncated: bool = False
    sensitive_files: int = 0
    # Langages presents dans le projet mais sans regles d'analyse de code.
    unsupported_languages: list[str] = Field(default_factory=list)
    vulnerability_provider: str = ""
    vulnerability_provider_status: str = "disabled"
    vulnerability_check_conclusive: bool = False
    vulnerability_message: str = ""
    last_discovery: Optional[str] = None


class PostureHistory(BaseModel):
    """Ce que l'on peut dire de l'evolution — sans rien inventer."""

    available: bool = False
    message: str = HISTORY_UNAVAILABLE
    # Premiere et derniere detection parmi les findings ouverts : des faits
    # enregistres, pas une tendance extrapolee.
    oldest_open_finding: Optional[str] = None
    newest_open_finding: Optional[str] = None


class SecurityPosture(BaseModel):
    """Posture de securite explicable d'un projet. Aucun score."""

    project_uid: str
    project_name: str = ""
    generated_at: str = Field(default_factory=_now_iso)
    analysis: OverallAnalysis = "not_analyzed"
    findings: PostureCounts = Field(default_factory=PostureCounts)
    areas: list[PostureArea] = Field(default_factory=list)
    coverage: PostureCoverage = Field(default_factory=PostureCoverage)
    history: PostureHistory = Field(default_factory=PostureHistory)
    # Rappels verifies par des tests.
    ai_generated: Literal[False] = False
    requires_ai: Literal[False] = False
    requires_wazuh: Literal[False] = False


# --------------------------------------------------------------------------
# Controle CI/CD
# --------------------------------------------------------------------------


class CiPolicyRequest(BaseModel):
    """Politique demandee. Tout champ absent reprend la configuration.

    `fail_on` : conditions qui BLOQUENT en mode `block` (et avertissent en
    mode `warn`). `warn_on` : conditions qui avertissent seulement, quel que
    soit le mode. Une condition presente dans les deux est traitee comme
    bloquante : la politique la plus stricte demandee l'emporte.
    """

    mode: Optional[CiMode] = None
    fail_on: Optional[list[CiCondition]] = None
    warn_on: Optional[list[CiCondition]] = None


class CiPolicy(BaseModel):
    mode: CiMode = "warn"
    fail_on: list[CiCondition] = Field(default_factory=list)
    warn_on: list[CiCondition] = Field(default_factory=list)


class CiConditionResult(BaseModel):
    """Une condition, sa valeur, et ce que la politique en fait."""

    code: CiCondition
    triggered: bool
    # Valeur mesuree : nombre de findings, de langages... 0 ou 1 pour un
    # constat binaire.
    value: int = 0
    action: Literal["block", "warn", "ignore"] = "ignore"
    message: str = ""


class CiReason(BaseModel):
    code: CiCondition
    action: Literal["block", "warn"]
    message: str


class CiBlockingFinding(BaseModel):
    """Finding CRITICAL ou HIGH cite dans le rapport. Aucune preuve."""

    id: str
    area: PostureAreaName
    category: str
    severity: str
    title: str
    # Chemin relatif valide, ou rien. Jamais un chemin absolu.
    file: Optional[str] = None
    line: int = 0

    @field_validator("file")
    @classmethod
    def relative_only(cls, value: Optional[str]) -> Optional[str]:
        from app.paths import clean_relative_path

        if not value:
            return None
        try:
            return clean_relative_path(value)
        except ValueError:
            return None


class CiProject(BaseModel):
    """Identite sure : l'identifiant attribue par le backend et le nom du
    dossier. Ni chemin, ni empreinte de la racine."""

    project_uid: str
    project_name: str = ""


class CiCheckResult(BaseModel):
    """Resultat machine d'un controle CI/CD. Stable, versionne, sans secret."""

    schema_version: str = CI_SCHEMA_VERSION
    project: CiProject
    generated_at: str = Field(default_factory=_now_iso)
    policy: CiPolicy
    status: CiStatus
    # `pass` ou `fail` : ce que le pipeline doit faire. Un blocage est
    # TOUJOURS accompagne de ses raisons.
    exit_decision: Literal["pass", "fail"]
    exit_code: int
    analysis: OverallAnalysis
    counts: PostureCounts
    counts_by_area: dict[str, Optional[int]] = Field(default_factory=dict)
    conditions: list[CiConditionResult] = Field(default_factory=list)
    reasons: list[CiReason] = Field(default_factory=list)
    incomplete_areas: list[str] = Field(default_factory=list)
    unsupported_languages: list[str] = Field(default_factory=list)
    vulnerability_provider_status: str = "disabled"
    vulnerability_check_conclusive: bool = False
    blocking_findings: list[CiBlockingFinding] = Field(default_factory=list)
    requires_ai: Literal[False] = False
    requires_wazuh: Literal[False] = False
