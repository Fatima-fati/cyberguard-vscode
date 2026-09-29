"""Modeles de l'agent IA : entree envoyee au modele, sortie validee.

Les alertes brutes restent decrites par `app.models.Alert` ; ce module ne
decrit que ce qui est specifique a l'analyse IA.
"""

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, computed_field, field_validator

from app import i18n

# --------------------------------------------------------------------------
# Referentiels centralises (faciles a modifier)
# --------------------------------------------------------------------------

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Seuils du Risk Score -> severite. Bornes hautes incluses.
RISK_THRESHOLDS: list[tuple[int, Severity]] = [
    (39, "LOW"),  # 0-39
    (69, "MEDIUM"),  # 40-69
    (89, "HIGH"),  # 70-89
    (100, "CRITICAL"),  # 90-100
]

# Libelles lisibles par un humain, utilises par le frontend.
RISK_BANDS: list[tuple[int, str]] = [
    (19, "très faible"),
    (39, "faible"),
    (69, "moyen"),
    (89, "élevé"),
    (100, "critique"),
]

# Severites declenchant une notification issue d'une analyse IA.
NOTIFIABLE_SEVERITIES: tuple[str, ...] = ("HIGH", "CRITICAL")

# Correspondance niveau Wazuh -> severite, partagee par tout le projet
# (voir `severity_for_level`). La borne CRITICAL est configurable via
# CRITICAL_LEVEL ; celles-ci restent alignees sur l'echelle Wazuh :
#   0-6 LOW | 7-9 MEDIUM | 10-11 HIGH | >= CRITICAL_LEVEL CRITICAL
HIGH_LEVEL = 10
MEDIUM_LEVEL = 7

# Types de remediation reconnus.
REMEDIATION_TYPES: tuple[str, ...] = (
    "code_patch",
    "configuration_change",
    "account_action",
    "network_rule",
    "manual_only",
    "none",
)

# Etats du cycle de vie d'une remediation.
RemediationStatus = Literal[
    "not_available",
    "pending",
    "proposed",
    "awaiting_confirmation",
    "approved",
    "rejected",
    "applied",
    "failed",
    "cancelled",
]

NotificationStatus = Literal["new", "acknowledged", "dismissed", "resolved"]

# Etat de l'analyse IA d'une notification, independant du statut de lecture.
#   pending   : aucune analyse lancee (cas par defaut d'une notification
#               creee sur le niveau Wazuh, ou AI_ANALYSIS_ENABLED=false) ;
#   analyzing : appel au modele en cours ;
#   analyzed  : le modele a repondu et le resultat est enregistre ;
#   failed    : l'analyse a ete tentee et a echoue (erreur conservee).
AnalysisStatus = Literal["pending", "analyzing", "analyzed", "failed"]

# Types d'evenements reconnus. "unknown" est volontairement prevu : le
# modele ne doit jamais inventer une classification.
EVENT_TYPES: tuple[str, ...] = (
    "authentication_failure",
    "brute_force",
    "malware",
    "privilege_escalation",
    "suspicious_process",
    "network_attack",
    "configuration_weakness",
    "vulnerability",
    "file_integrity_violation",
    "policy_violation",
    "system_event",
    "unknown",
)


def severity_for_score(score: int) -> Severity:
    """Severite correspondant a un Risk Score."""
    for upper, severity in RISK_THRESHOLDS:
        if score <= upper:
            return severity
    return "CRITICAL"


def severity_for_level(level: int, critical_level: Optional[int] = None) -> Severity:
    """Severite correspondant a un niveau de regle Wazuh (0-15).

    Reference unique du projet : les alertes, les notifications et le
    frontend utilisent tous cette correspondance, pour qu'un `rule.level`
    de 12 ne soit jamais lu comme une severite differente d'un ecran a
    l'autre. La borne CRITICAL vient de la configuration (CRITICAL_LEVEL).
    """
    from app.config import settings  # import tardif : evite un cycle

    critical = settings.critical_level if critical_level is None else critical_level

    if level >= critical:
        return "CRITICAL"
    if level >= HIGH_LEVEL:
        return "HIGH"
    if level >= MEDIUM_LEVEL:
        return "MEDIUM"
    return "LOW"


def band_for_score(score: int) -> str:
    """Libelle lisible correspondant a un Risk Score."""
    for upper, label in RISK_BANDS:
        if score <= upper:
            return label
    return "critique"


# --------------------------------------------------------------------------
# Entree : ce qui est reellement envoye au modele
# --------------------------------------------------------------------------


class AlertContext(BaseModel):
    """Champs utiles d'une alerte, apres nettoyage.

    Seuls ces champs quittent le backend : ni credentials, ni token, ni
    document Wazuh complet.
    """

    alert_id: str
    timestamp: Optional[str] = None
    rule_id: Optional[str] = None
    rule_level: int = 0
    rule_description: Optional[str] = None
    # Traduction francaise de la description, fournie au modele pour qu'il
    # reprenne la meme formulation. L'originale reste transmise telle
    # quelle : elle sert de reference technique.
    rule_description_fr: Optional[str] = None
    rule_groups: list[str] = Field(default_factory=list)
    agent_id: Optional[str] = None
    agent_name: Optional[str] = None
    agent_ip: Optional[str] = None
    decoder_name: Optional[str] = None
    location: Optional[str] = None
    full_log: Optional[str] = None
    # Contexte calcule par le backend, pas par le modele.
    similar_alerts_24h: int = 0
    agent_os: Optional[str] = None


# --------------------------------------------------------------------------
# Sortie du modele (avant enrichissement)
# --------------------------------------------------------------------------


def clean_string_list(value: Any, limit: int = 10) -> list[str]:
    """Normalise une liste de chaines renvoyee par un modele.

    Partagee par toutes les sorties de modele du projet : une valeur
    absente devient une liste vide, une chaine seule devient une liste
    d'un element, et la liste est bornee.
    """
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()][:limit]


def clamp_confidence_value(value: Any) -> float:
    """Confiance normalisee entre 0 et 1.

    Partagee par toutes les sorties de modele du projet, y compris celles
    de l'assistant de securite (phase 6) qui n'heritent **pas** de
    `ModelVerdict` : une confiance exprimee en pourcentage doit etre lue
    de la meme facon partout, et une valeur inexploitable doit valoir 0
    plutot que d'etre prise pour une certitude.
    """
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return 0.0
    # Certains modeles repondent en pourcentage.
    if confidence > 1:
        confidence = confidence / 100
    return max(0.0, min(1.0, round(confidence, 2)))


class ModelVerdict(BaseModel):
    """Socle commun a toute reponse de modele evaluant un risque.

    Ne contient que ce qui est independant du domaine : severite, score et
    confiance, avec les garde-fous correspondants. Les analyses d'alertes
    Wazuh (`AIModelAnalysis`) et d'extraits de code (`app.code.schemas`)
    en heritent, pour que le meme laxisme d'un modele soit corrige de la
    meme facon des deux cotes.
    """

    severity: Severity = "LOW"
    risk_score: int = 0
    confidence: float = 0.0

    @field_validator("risk_score", mode="before")
    @classmethod
    def clamp_score(cls, value: Any) -> int:
        """Tolere "72" ou 72.4, refuse tout le reste.

        Le score pilote l'affichage entier : une valeur inexploitable doit
        invalider l'analyse, pas se transformer silencieusement en 0, ce qui
        afficherait un risque nul pour une alerte peut-etre grave.
        """
        if isinstance(value, bool) or not isinstance(value, (int, float, str)):
            raise ValueError("risk_score doit etre un nombre")
        try:
            score = int(round(float(value)))
        except (TypeError, ValueError) as exc:
            raise ValueError("risk_score doit etre un nombre") from exc
        return max(0, min(100, score))

    @field_validator("confidence", mode="before")
    @classmethod
    def clamp_confidence(cls, value: Any) -> float:
        return clamp_confidence_value(value)

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, value: Any) -> str:
        severity = str(value or "").strip().upper()
        return severity if severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL") else "LOW"


class AIModelAnalysis(ModelVerdict):
    """Reponse brute attendue du modele, validee par Pydantic.

    Tout ecart (champ manquant, score hors bornes, type inattendu) leve une
    ValidationError, traitee comme une erreur d'analyse.

    `severity`, `risk_score` et `confidence` viennent de `ModelVerdict`.
    """

    classification: str = "unknown"
    threat_type: str = "unknown"
    title: str = ""
    summary: str = ""
    explanation: str = ""
    why_dangerous: str = ""
    potential_impact: list[str] = Field(default_factory=list)
    indicators: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    risk_factors: list[str] = Field(default_factory=list)

    # Remediation : proposee par le modele, jamais appliquee par lui.
    remediation_available: bool = False
    remediation_type: str = "none"
    remediation_summary: str = ""
    affected_file: Optional[str] = None
    affected_line: Optional[int] = None

    @field_validator("remediation_type", mode="before")
    @classmethod
    def known_remediation_type(cls, value: Any) -> str:
        normalized = str(value or "none").strip().lower().replace(" ", "_").replace("-", "_")
        return normalized if normalized in REMEDIATION_TYPES else "manual_only"

    @field_validator("affected_line", mode="before")
    @classmethod
    def clean_line(cls, value: Any) -> Optional[int]:
        """Une ligne inconnue reste None : on n'invente pas d'emplacement."""
        if value is None or value == "":
            return None
        try:
            line = int(value)
        except (TypeError, ValueError):
            return None
        return line if line > 0 else None

    @field_validator("affected_file", mode="before")
    @classmethod
    def clean_file(cls, value: Any) -> Optional[str]:
        if not value:
            return None
        name = str(value).strip()
        return name or None

    @field_validator("classification")
    @classmethod
    def known_classification(cls, value: str) -> str:
        normalized = (value or "unknown").strip().lower().replace(" ", "_").replace("-", "_")
        return normalized if normalized in EVENT_TYPES else "unknown"

    @field_validator(
        "indicators",
        "recommendations",
        "risk_factors",
        "potential_impact",
        mode="before",
    )
    @classmethod
    def clean_list(cls, value: Any) -> list[str]:
        return clean_string_list(value)


# --------------------------------------------------------------------------
# Sortie finale, exposee au frontend et persistee
# --------------------------------------------------------------------------


class RiskFactor(BaseModel):
    """Un element ayant pese dans le Risk Score."""

    name: str
    detail: str = ""
    weight: int = 0


class AIAlertAnalysis(BaseModel):
    """Analyse complete d'une alerte : IA + evaluation deterministe."""

    alert_id: str
    analyzed_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    model: str = ""

    # Identite de l'alerte, pour un affichage autonome cote frontend
    agent_id: Optional[str] = None
    agent_name: Optional[str] = None
    agent_ip: Optional[str] = None
    rule_id: Optional[str] = None
    rule_level: int = 0
    alert_timestamp: Optional[str] = None

    classification: str = "unknown"
    threat_type: str = "unknown"
    severity: Severity = "LOW"
    risk_score: int = 0
    risk_band: str = "très faible"
    confidence: float = 0.0

    # Detail du calcul : score du modele et score deterministe
    ai_risk_score: int = 0
    baseline_risk_score: int = 0
    risk_factors: list[RiskFactor] = Field(default_factory=list)

    title: str = ""
    summary: str = ""
    explanation: str = ""
    why_dangerous: str = ""
    potential_impact: list[str] = Field(default_factory=list)
    indicators: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)

    remediation_available: bool = False
    remediation_type: str = "none"
    remediation_summary: str = ""
    affected_file: Optional[str] = None
    affected_line: Optional[int] = None

    cached: bool = False

    # --- Libelles francais (presentation seule, valeurs internes intactes)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def severity_label(self) -> str:
        return i18n.severity_label(self.severity)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def classification_label(self) -> str:
        return i18n.classification_label(self.classification)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def threat_type_label(self) -> str:
        """Menace formulee en francais (les termes standards restent tels quels)."""
        if not self.threat_type or self.threat_type.lower() == "unknown":
            return "Non déterminée"
        return i18n.localize_security_text(self.threat_type)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def remediation_type_label(self) -> str:
        return i18n.remediation_type_label(self.remediation_type)

    @property
    def confidence_percent(self) -> int:
        return int(round(self.confidence * 100))

    @property
    def is_notifiable(self) -> bool:
        return self.severity in NOTIFIABLE_SEVERITIES


class AINotification(BaseModel):
    """Notification generee pour une alerte importante.

    Deux origines possibles, un seul format et une seule table :
    - `wazuh` : le niveau de la regle atteint NOTIFY_LEVEL ;
    - `ia`    : l'analyse IA conclut a une severite HIGH ou CRITICAL.

    Une notification creee sur le niveau Wazuh est enrichie (et non
    dupliquee) lorsque l'analyse IA de la meme alerte arrive ensuite.
    """

    id: int
    alert_id: str
    server_id: Optional[str] = None
    server_name: Optional[str] = None
    title: str = ""
    severity: Severity = "HIGH"
    classification: str = "unknown"
    risk_score: int = 0

    # Identite Wazuh de l'alerte a l'origine de la notification.
    agent_id: Optional[str] = None
    rule_id: Optional[str] = None
    rule_level: int = 0
    alert_timestamp: Optional[str] = None
    source: str = "ia"
    confidence: float = 0.0
    summary: str = ""
    why_dangerous: str = ""
    potential_impact: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    notification_message: str = ""

    remediation_available: bool = False
    remediation_type: str = "none"
    remediation_summary: str = ""
    remediation_status: RemediationStatus = "not_available"
    affected_file: Optional[str] = None
    affected_line: Optional[int] = None

    status: NotificationStatus = "new"
    # Etat de l'analyse IA. `status` ne dit que si l'utilisateur a vu la
    # notification : il ne doit jamais servir a affirmer qu'elle a ete
    # analysee.
    analysis_status: AnalysisStatus = "pending"
    analysis_error: Optional[str] = None
    analyzed_at: Optional[str] = None
    # Description Wazuh d'origine (anglaise), conservee pour le diagnostic.
    wazuh_description: Optional[str] = None
    occurrences: int = 1
    created_at: str = ""
    updated_at: Optional[str] = None
    acknowledged_at: Optional[str] = None
    resolved_at: Optional[str] = None
    dismissed_at: Optional[str] = None

    # --- Libelles francais (presentation seule, valeurs internes intactes)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def severity_label(self) -> str:
        return i18n.severity_label(self.severity)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def classification_label(self) -> str:
        return i18n.classification_label(self.classification)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def status_label(self) -> str:
        return i18n.notification_status_label(self.status)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def analysis_status_label(self) -> str:
        return i18n.analysis_status_label(self.analysis_status)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def analyzed(self) -> bool:
        """Vrai uniquement si une analyse IA a reellement abouti.

        Le frontend s'appuie dessus pour ne pas presenter les valeurs par
        defaut (score 0, confiance 0, classification inconnue) comme un
        resultat d'analyse.
        """
        return self.analysis_status == "analyzed"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def remediation_status_label(self) -> str:
        return i18n.remediation_status_label(self.remediation_status)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def remediation_type_label(self) -> str:
        return i18n.remediation_type_label(self.remediation_type)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_label(self) -> str:
        """Ce qui a declenche la notification (niveau Wazuh ou agent IA)."""
        return i18n.source_label(self.source)


class RemediationPreview(BaseModel):
    """Correction proposee, avant toute ecriture.

    Produire cet apercu ne modifie rien : c'est une lecture du fichier
    cible et un diff. L'ecriture demande une confirmation explicite.
    """

    notification_id: int
    alert_id: str
    available: bool = False
    status: RemediationStatus = "not_available"
    remediation_type: str = "none"
    summary: str = ""
    file: Optional[str] = None
    line: Optional[int] = None
    resolved_path: Optional[str] = None
    original_excerpt: Optional[str] = None
    proposed_excerpt: Optional[str] = None
    diff: Optional[str] = None
    blockers: list[str] = Field(default_factory=list)
    manual_steps: list[str] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def status_label(self) -> str:
        return i18n.remediation_status_label(self.status)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def remediation_type_label(self) -> str:
        return i18n.remediation_type_label(self.remediation_type)


class RemediationRecord(BaseModel):
    """Trace d'une operation de remediation."""

    id: int
    notification_id: int
    alert_id: str
    status: RemediationStatus = "pending"
    remediation_type: str = "none"
    summary: str = ""
    file: Optional[str] = None
    line: Optional[int] = None
    diff: Optional[str] = None
    backup_path: Optional[str] = None
    error: Optional[str] = None
    created_at: str = ""
    applied_at: Optional[str] = None
    rolled_back_at: Optional[str] = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def status_label(self) -> str:
        return i18n.remediation_status_label(self.status)


class AuditEntry(BaseModel):
    """Une action tracee dans le journal d'audit."""

    id: int
    action: str
    notification_id: Optional[int] = None
    alert_id: Optional[str] = None
    remediation_id: Optional[int] = None
    actor: str = "utilisateur"
    target: Optional[str] = None
    result: str = "ok"
    error: Optional[str] = None
    created_at: str = ""

    @computed_field  # type: ignore[prop-decorator]
    @property
    def action_label(self) -> str:
        """Action lisible. `action` garde son identifiant technique."""
        return i18n.audit_action_label(self.action)


class RemediationDecision(BaseModel):
    """Confirmation ou rejet d'une correction par l'utilisateur."""

    confirmed: bool = False
    reason: Optional[str] = None
    actor: str = "utilisateur"


class AIAnalysisRequest(BaseModel):
    """Demande d'analyse : par identifiant, ou avec l'alerte complete."""

    alert_id: Optional[str] = None
    alert: Optional[dict[str, Any]] = None
    force: bool = False


class AIStats(BaseModel):
    """Vue globale affichee en haut de la page AI Security."""

    analyzed: int = 0
    low: int = 0
    medium: int = 0
    high: int = 0
    critical: int = 0
    average_risk_score: float = 0.0
    enabled: bool = False
    auto_analysis: bool = False
    model: str = ""
    notifications: int = 0
    notifications_new: int = 0
    remediations_available: int = 0
