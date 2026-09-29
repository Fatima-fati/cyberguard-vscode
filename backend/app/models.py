"""Modeles Pydantic partages entre le client Wazuh, les routes et le store.

Les modeles sont construits a partir des reponses brutes de Wazuh
(Manager API et Indexer) via leurs methodes `from_wazuh` / `from_source`,
de facon a ne jamais exposer le JSON brut au frontend.
"""

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, computed_field, field_validator

from app import i18n


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get(data: Any, *keys: str, default: Any = None) -> Any:
    """Lecture defensive d'une valeur imbriquee : _get(doc, "agent", "id")."""
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current


class Agent(BaseModel):
    """Un agent / serveur surveille par Wazuh (reponse simplifiee)."""

    id: str
    name: str
    ip: Optional[str] = None
    status: Optional[str] = None
    os: Optional[str] = None
    version: Optional[str] = None
    group: list[str] = Field(default_factory=list)
    last_keep_alive: Optional[str] = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def status_label(self) -> str:
        """Statut affiche a l'ecran. `status` garde la valeur Wazuh."""
        return i18n.agent_status_label(self.status)

    @classmethod
    def from_wazuh(cls, item: dict[str, Any]) -> "Agent":
        """Construit un Agent depuis un element de GET /agents."""
        os_name = _get(item, "os", "name")
        os_version = _get(item, "os", "version")
        os_label = " ".join(part for part in (os_name, os_version) if part) or None

        return cls(
            id=str(item.get("id", "")),
            name=item.get("name") or "inconnu",
            ip=item.get("ip") or item.get("registerIP"),
            status=item.get("status"),
            os=os_label,
            version=item.get("version"),
            group=item.get("group") or [],
            last_keep_alive=item.get("lastKeepAlive"),
        )


class Rule(BaseModel):
    """La regle Wazuh ayant declenche une alerte."""

    id: Optional[str] = None
    level: int = 0
    description: str = ""
    groups: list[str] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def description_fr(self) -> str:
        """Description traduite pour l'interface.

        `description` conserve toujours le texte Wazuh original : il reste
        disponible pour le diagnostic, la correlation et l'analyse IA.
        """
        return i18n.localize_security_text(self.description)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def groups_label(self) -> str:
        """Categories de la regle, en francais quand elles sont connues."""
        return i18n.rule_groups_label(self.groups)

    @classmethod
    def from_source(cls, source: dict[str, Any]) -> "Rule":
        rule = source.get("rule") or {}
        rule_id = rule.get("id")

        return cls(
            id=str(rule_id) if rule_id is not None else None,
            level=int(rule.get("level") or 0),
            description=rule.get("description") or "",
            groups=rule.get("groups") or [],
        )


class AlertSource(BaseModel):
    """L'agent tel qu'il apparait dans le document d'alerte de l'Indexer."""

    id: Optional[str] = None
    name: Optional[str] = None
    ip: Optional[str] = None

    @classmethod
    def from_source(cls, source: dict[str, Any]) -> "AlertSource":
        agent = source.get("agent") or {}
        agent_id = agent.get("id")

        return cls(
            id=str(agent_id) if agent_id is not None else None,
            name=agent.get("name"),
            ip=agent.get("ip"),
        )


class Alert(BaseModel):
    """Une alerte de securite normalisee."""

    id: str
    timestamp: str = Field(default_factory=_now_iso)
    agent: AlertSource = Field(default_factory=AlertSource)
    rule: Rule = Field(default_factory=Rule)
    full_log: Optional[str] = None
    location: Optional[str] = None

    # Raccourcis pratiques pour le frontend et le store.
    @property
    def level(self) -> int:
        return self.rule.level

    @property
    def description(self) -> str:
        return self.rule.description

    @property
    def description_fr(self) -> str:
        """Description destinee a l'utilisateur (francais)."""
        return self.rule.description_fr

    @property
    def agent_id(self) -> Optional[str]:
        return self.agent.id

    @property
    def agent_name(self) -> Optional[str]:
        return self.agent.name

    @property
    def rule_id(self) -> Optional[str]:
        return self.rule.id

    def is_critical(self, threshold: int) -> bool:
        return self.rule.level >= threshold

    @classmethod
    def from_hit(cls, hit: dict[str, Any]) -> "Alert":
        """Construit une Alert depuis un `hit` de l'Indexer."""
        source = hit.get("_source") or {}

        return cls(
            id=str(hit.get("_id") or ""),
            timestamp=source.get("timestamp") or source.get("@timestamp") or _now_iso(),
            agent=AlertSource.from_source(source),
            rule=Rule.from_source(source),
            full_log=source.get("full_log"),
            location=source.get("location"),
        )


# --------------------------------------------------------------------------
# Ajout d'un serveur (provisioning d'un agent)
# --------------------------------------------------------------------------

# Wazuh refuse les noms d'agent contenant des espaces ou des caracteres
# speciaux ; la limite officielle est de 128 caracteres.
AGENT_NAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")


class ServerProvisionRequest(BaseModel):
    """Serveur que l'utilisateur souhaite superviser."""

    name: str
    ip: str
    os: Literal["linux", "windows"]
    description: Optional[str] = None

    @field_validator("name")
    @classmethod
    def check_name(cls, value: str) -> str:
        name = value.strip()
        if not name:
            raise ValueError("Le nom du serveur est obligatoire")
        if len(name) > 128:
            raise ValueError("Le nom du serveur ne doit pas dépasser 128 caractères")
        if not AGENT_NAME_PATTERN.match(name):
            raise ValueError(
                "Le nom ne peut contenir que des lettres, chiffres, '.', '_' et '-'"
            )
        return name

    @field_validator("ip")
    @classmethod
    def check_ip(cls, value: str) -> str:
        address = value.strip()
        if not address:
            raise ValueError("L'adresse IP est obligatoire")
        try:
            ipaddress.ip_address(address)
        except ValueError as exc:
            raise ValueError(f"Adresse IP invalide : {address}") from exc
        return address

    @field_validator("description")
    @classmethod
    def clean_description(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        description = value.strip()
        return description or None


class ProvisionedServer(BaseModel):
    """Identite du serveur, telle que renvoyee au frontend."""

    name: str
    ip: str
    os: Literal["linux", "windows"]
    description: Optional[str] = None


class ServerInstallInstructions(BaseModel):
    """Procedure d'installation a executer par l'utilisateur, sur son serveur.

    Aucune de ces commandes n'est executee par l'application.
    """

    server: ProvisionedServer
    manager_address: str
    enrollment_port: int
    agent_port: int
    agent_version: str
    instructions: list[str] = Field(default_factory=list)
    commands: list[str] = Field(default_factory=list)
    verify_commands: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    # Champs de commodite pour le frontend
    @property
    def server_name(self) -> str:
        return self.server.name

    @property
    def ip(self) -> str:
        return self.server.ip


class ServerCheckRequest(BaseModel):
    """Demande de verification : le serveur est-il enrole dans Wazuh ?"""

    name: str
    ip: Optional[str] = None

    @field_validator("name")
    @classmethod
    def check_name(cls, value: str) -> str:
        name = value.strip()
        if not name:
            raise ValueError("Le nom du serveur est obligatoire")
        return name

    @field_validator("ip")
    @classmethod
    def check_ip(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        address = value.strip()
        if not address:
            return None
        try:
            ipaddress.ip_address(address)
        except ValueError as exc:
            raise ValueError(f"Adresse IP invalide : {address}") from exc
        return address


class ServerConnectionStatus(BaseModel):
    """Resultat d'une verification aupres du Wazuh Manager.

    `status` vaut "connected", "pending" ou "multiple". La source de verite
    reste Wazuh : rien n'est marque connecte sans agent correspondant.
    """

    connected: bool = False
    status: Literal["connected", "pending", "multiple"] = "pending"
    message: str = ""
    agent: Optional[Agent] = None
    matches: list[Agent] = Field(default_factory=list)


class MonitoringStatus(BaseModel):
    """Etat courant du moteur de surveillance."""

    running: bool = False
    # int en production (POLL_INTERVAL=10) ; float autorise pour les tests.
    poll_interval: int | float = 0

    @computed_field  # type: ignore[prop-decorator]
    @property
    def state_label(self) -> str:
        """Etat de la surveillance, tel qu'affiche dans l'entete."""
        return "EN COURS" if self.running else "ARRÊTÉE"

    # Horodatages ISO-8601
    started_at: Optional[str] = None
    stopped_at: Optional[str] = None
    last_scan: Optional[str] = None
    last_alert: Optional[str] = None

    # Curseur temporel utilise pour ne recuperer que les nouvelles alertes
    cursor: Optional[str] = None

    # Compteurs cumules depuis le demarrage du processus
    scans: int = 0
    alerts_seen: int = 0
    alerts_new: int = 0
    duplicates_skipped: int = 0
    errors: int = 0
    last_error: Optional[str] = None


class ActionResponse(BaseModel):
    """Reponse generique d'une action (start / stop)."""

    ok: bool = True
    message: str = ""
    status: Optional[MonitoringStatus] = None


class HealthResponse(BaseModel):
    """Etat de sante du backend."""

    application: str
    status: str = "ok"
    monitoring: bool = False
    sse_clients: int = 0
    database: str = "unknown"
    alerts_stored: int = 0


class UiConfig(BaseModel):
    """Reglages transmis au frontend au chargement de la page."""

    app_name: str
    poll_interval: int | float
    # Seuils de l'echelle Wazuh, partages avec le frontend pour que les
    # pages Alertes, Notifications et AI Security affichent la meme
    # severite pour un meme `rule.level`.
    critical_level: int
    high_level: int = 10
    medium_level: int = 7
    notify_level: int
    notify_cooldown: int
    ai_enabled: bool = False
    ai_auto_analysis: bool = False


class StreamEvent(BaseModel):
    """Evenement pousse aux clients via SSE."""

    type: str = "alert"
    data: dict[str, Any] = Field(default_factory=dict)
