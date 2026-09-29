"""Modeles de l'analyse de code : entree, findings, resultats.

Les severites, seuils et libelles ne sont pas redefinis ici : ils viennent
de `app.ai.schemas` et `app.i18n`, references uniques du projet. Une
vulnerabilite de code et une alerte Wazuh partagent ainsi la meme echelle
(LOW / MEDIUM / HIGH / CRITICAL) et le meme vocabulaire francais.
"""

import hashlib
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, computed_field, field_validator, model_validator

from app import i18n
from app.ai.schemas import (
    AnalysisStatus,
    ModelVerdict,
    RiskFactor,
    Severity,
    band_for_score,
    clean_string_list,
)
from app.config import settings

# --------------------------------------------------------------------------
# Referentiels
# --------------------------------------------------------------------------

CodeLanguage = Literal[
    "python",
    "javascript",
    "typescript",
    "php",
    "java",
    "go",
    "csharp",
    "ruby",
    "sql",
    "yaml",
    "other",
]

# Categories de vulnerabilite reconnues. "unknown" est volontairement
# prevu : une regle ne doit jamais forcer une categorie inventee.
VULNERABILITY_CATEGORIES: tuple[str, ...] = (
    "sql_injection",
    "command_injection",
    "xss",
    "path_traversal",
    "insecure_deserialization",
    "hardcoded_secret",
    "weak_cryptography",
    "ssrf",
    "xxe",
    "insecure_random",
    "broken_access_control",
    "csrf",
    "open_redirect",
    "unsafe_eval",
    "insecure_configuration",
    "unknown",
)

# Cycle de vie d'un finding. Rien n'est jamais supprime physiquement :
# un faux positif est "dismissed", un probleme corrige est "fixed".
FindingStatus = Literal["open", "dismissed", "fixed"]

# Origine d'un finding : regle deterministe ou analyse IA (phase 3).
FindingSource = Literal["rule", "ia"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def content_hash_of(content: str) -> str:
    """Empreinte du contenu analyse : cle de cache et de deduplication."""
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


# --------------------------------------------------------------------------
# Entree
# --------------------------------------------------------------------------


class CodeScanRequest(BaseModel):
    """Document soumis par l'extension VS Code.

    Le contenu n'est jamais execute, jamais ecrit sur disque, jamais
    journalise en entier. Seule sa taille et son empreinte le sont.
    """

    file_path: str
    language: CodeLanguage = "other"
    content: str
    # Empreinte calculee par l'extension. Elle est **verifiee** : un hash
    # qui ne correspond pas au contenu est un desaccord entre le client et
    # le serveur, jamais quelque chose que l'on accepte en silence.
    content_hash: Optional[str] = None
    workspace: Optional[str] = None
    # Projet auquel le fichier appartient (phase 1). Sert a deux choses :
    # filtrer les findings par projet, et adresser les evenements SSE au
    # seul projet concerne. Absent = fichier ouvert hors de tout dossier.
    project_uid: Optional[str] = Field(default=None, max_length=64)
    # Lignes reellement modifiees, si l'extension les connait. Permet de
    # n'analyser que le delta ; vide = tout le fichier.
    changed_lines: Optional[list[int]] = None
    # Demande d'enrichissement IA. Accepte des la phase 1, mais honore
    # seulement quand l'enrichissement est active (phase 3).
    ai_enrichment: bool = True

    @field_validator("file_path")
    @classmethod
    def check_file_path(cls, value: str) -> str:
        path = (value or "").strip()
        if not path:
            raise ValueError("Le chemin du fichier est obligatoire")
        if len(path) > 1024:
            raise ValueError("Le chemin du fichier est trop long")
        return path

    @field_validator("content")
    @classmethod
    def check_content(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("Le contenu du fichier est vide : rien a analyser")

        size = len(value.encode("utf-8", errors="replace"))
        if size > settings.code_max_content_bytes:
            raise ValueError(
                f"Fichier trop volumineux ({size} octets) : la limite est "
                f"{settings.code_max_content_bytes} octets "
                "(CODE_MAX_CONTENT_BYTES)"
            )
        return value

    @field_validator("changed_lines")
    @classmethod
    def check_changed_lines(cls, value: Optional[list[int]]) -> Optional[list[int]]:
        if value is None:
            return None
        lines = sorted({int(line) for line in value if int(line) > 0})
        return lines or None

    @model_validator(mode="after")
    def check_hash(self) -> "CodeScanRequest":
        """Le hash annonce doit correspondre au contenu recu.

        Sans cette verification, le cache pourrait servir le resultat d'un
        autre contenu : l'utilisateur verrait des findings qui ne
        correspondent pas a son fichier.
        """
        computed = content_hash_of(self.content)

        if self.content_hash is None:
            self.content_hash = computed
            return self

        announced = self.content_hash.strip().lower()
        if announced != computed:
            raise ValueError(
                "L'empreinte annoncee ne correspond pas au contenu recu "
                "(content_hash invalide)"
            )
        self.content_hash = announced
        return self

    @property
    def line_count(self) -> int:
        return self.content.count("\n") + 1


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------


class CodeLocation(BaseModel):
    """Emplacement d'un finding dans le fichier (1-indexe, comme VS Code)."""

    line_start: int = 1
    line_end: int = 1
    column_start: int = 0
    column_end: int = 0
    snippet: str = ""


class RuleHit(BaseModel):
    """Declenchement d'une regle deterministe, avant evaluation du risque.

    Une regle est un **indice**, pas une preuve : le vocabulaire employe
    partout ensuite parle de "detecte par une regle", jamais de
    "vulnerabilite confirmee".
    """

    rule_id: str
    category: str = "unknown"
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    base_severity: Severity = "MEDIUM"
    # Confiance du motif lui-meme (0-1) : une regex tres specifique vaut
    # mieux qu'un motif large.
    rule_confidence: float = 0.5
    title: str = ""
    explanation: str = ""
    why_dangerous: str = ""
    potential_impact: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    location: CodeLocation = Field(default_factory=CodeLocation)


class CodeModelFinding(ModelVerdict):
    """Reponse attendue du modele pour un finding (phase 3).

    Herite de `ModelVerdict` : severite, score et confiance sont bornes
    exactement comme pour une analyse d'alerte Wazuh. Aucun appel n'est
    fait en phase 1 ; ce modele existe pour que l'interface soit deja
    figee et testable.
    """

    category: str = "unknown"
    title: str = ""
    explanation: str = ""
    why_dangerous: str = ""
    potential_impact: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    risk_factors: list[str] = Field(default_factory=list)
    # Le modele peut conclure que la regle s'est trompee.
    false_positive: bool = False
    fix_available: bool = False
    fix_summary: str = ""

    @field_validator("category")
    @classmethod
    def known_category(cls, value: str) -> str:
        normalized = (value or "unknown").strip().lower().replace(" ", "_").replace("-", "_")
        return normalized if normalized in VULNERABILITY_CATEGORIES else "unknown"

    @field_validator(
        "potential_impact", "recommendations", "risk_factors", mode="before"
    )
    @classmethod
    def clean_list(cls, value: Any) -> list[str]:
        return clean_string_list(value)


class CodeFinding(BaseModel):
    """Finding expose a l'extension.

    Les valeurs internes (`category`, `severity`, `status`) sont conservees
    telles quelles pour la logique ; les libelles francais sont ajoutes a
    cote, selon la meme convention que le reste du projet.
    """

    finding_uid: str
    scan_uid: str = ""
    rule_id: str
    category: str = "unknown"
    cwe: Optional[str] = None
    owasp: Optional[str] = None

    severity: Severity = "MEDIUM"
    risk_score: int = 0
    confidence: float = 0.0
    source: FindingSource = "rule"

    title: str = ""
    explanation: str = ""
    why_dangerous: str = ""
    potential_impact: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    risk_factors: list[RiskFactor] = Field(default_factory=list)

    location: CodeLocation = Field(default_factory=CodeLocation)
    file_path: str = ""

    fix_available: bool = False
    fix_summary: str = ""

    status: FindingStatus = "open"
    decision_reason: Optional[str] = None
    created_at: str = ""
    updated_at: Optional[str] = None

    # --- Libelles francais (presentation seule)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def severity_label(self) -> str:
        return i18n.severity_label(self.severity)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def category_label(self) -> str:
        return i18n.code_category_label(self.category)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def status_label(self) -> str:
        return i18n.code_finding_status_label(self.status)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_label(self) -> str:
        return i18n.code_finding_source_label(self.source)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def risk_band(self) -> str:
        return band_for_score(self.risk_score)


# --------------------------------------------------------------------------
# Resultats
# --------------------------------------------------------------------------


class SeverityCounts(BaseModel):
    """Repartition d'un ensemble de findings par severite."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low


class CodeScanResult(BaseModel):
    """Resultat complet d'un scan, renvoye a l'extension."""

    scan_uid: str
    file_path: str
    language: CodeLanguage = "other"
    content_hash: str = ""
    workspace: Optional[str] = None
    line_count: int = 0
    rules_version: str = ""

    # Etat de l'analyse IA, meme machine d'etat que les notifications :
    # une analyse n'est "analyzed" que si elle a reellement abouti.
    analysis_status: AnalysisStatus = "analyzed"
    analysis_error: Optional[str] = None
    model: str = ""

    findings: list[CodeFinding] = Field(default_factory=list)
    counts: SeverityCounts = Field(default_factory=SeverityCounts)

    # Vrai quand le meme contenu avait deja ete analyse : aucune nouvelle
    # detection n'a ete lancee, le resultat vient de la base.
    cached: bool = False
    # Enrichissement IA demande par le client mais non execute (phase 1).
    ai_enrichment_requested: bool = False
    ai_enrichment_applied: bool = False

    created_at: str = Field(default_factory=_now_iso)
    analyzed_at: Optional[str] = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def analysis_status_label(self) -> str:
        return i18n.analysis_status_label(self.analysis_status)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def findings_count(self) -> int:
        return len(self.findings)


class CodeFixProposal(BaseModel):
    """Correctif propose pour un finding.

    **Aucune ecriture.** Le backend ne modifie jamais un fichier du poste
    de developpement : il decrit la modification, l'editeur l'applique
    apres confirmation explicite de l'utilisateur.
    """

    finding_uid: str
    available: bool = False
    original_line: Optional[str] = None
    replacement_line: Optional[str] = None
    explanation: str = ""
    diff: Optional[str] = None
    # Ce qui empeche de proposer un correctif sur, en clair.
    blockers: list[str] = Field(default_factory=list)
    # Ce que l'utilisateur doit faire lui-meme.
    manual_steps: list[str] = Field(default_factory=list)
    line: Optional[int] = None
    file_path: str = ""

    @computed_field  # type: ignore[prop-decorator]
    @property
    def applies_automatically(self) -> bool:
        """Rappel explicite : un correctif disponible reste a confirmer."""
        return False


class CodeFindingDecision(BaseModel):
    """Decision de l'utilisateur sur un finding."""

    status: Literal["dismissed", "fixed"]
    reason: Optional[str] = None
    actor: str = "developpeur"

    @field_validator("reason")
    @classmethod
    def clean_reason(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        reason = value.strip()
        return reason[:300] or None


class CodeRuleInfo(BaseModel):
    """Une regle du catalogue, telle qu'exposee par GET /api/code/rules."""

    rule_id: str
    category: str
    category_label: str = ""
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    severity: Severity = "MEDIUM"
    severity_label: str = ""
    confidence: float = 0.5
    languages: list[str] = Field(default_factory=list)
    description: str = ""


class CodeHealth(BaseModel):
    """Etat du service d'analyse de code, consulte par l'extension."""

    status: str = "ok"
    analysis_enabled: bool = True
    # Enrichissement IA reellement disponible (cle configuree ET active).
    ai_enabled: bool = False
    rules_version: str = ""
    rules_count: int = 0
    api_version: str = ""
    max_content_bytes: int = 0
    database: str = "ok"
    # Les routes sensibles exigent-elles le jeton local ? Annonce ici — la
    # seule route publique — pour qu'un 401 ailleurs soit interpretable :
    # sans cette information, une extension mal configuree et un backend
    # eteint donneraient le meme symptome.
    auth_required: bool = False
    # Le backend sait-il tenir un contexte de projet (phase 1) ? Permet a
    # l'extension de se taire proprement face a un backend plus ancien
    # plutot que d'enchainer des 404.
    project_context_enabled: bool = False
    # Le backend porte-t-il le moteur de securite projet (phase 2) :
    # secrets, dependances, vulnerabilites ? Meme role que le drapeau
    # precedent, et meme raison : l'extension doit pouvoir renoncer AVANT
    # de parcourir tout le disque, pas apres.
    #
    # Ce drapeau ne dit rien de Wazuh, et c'est voulu : ces trois moteurs
    # fonctionnent avec Wazuh completement arrete.
    project_security_enabled: bool = False


class CodeStats(BaseModel):
    """Vue globale de l'analyse de code."""

    scans: int = 0
    files: int = 0
    findings: int = 0
    open: int = 0
    dismissed: int = 0
    fixed: int = 0
    by_severity: SeverityCounts = Field(default_factory=SeverityCounts)
    by_category: dict[str, int] = Field(default_factory=dict)
    ai_enabled: bool = False
    rules_version: str = ""
