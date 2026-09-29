"""Ajout d'un serveur a superviser : instructions puis verification.

Ce service est volontairement independant du moteur de surveillance
(`app.poller`) : il ne fait que produire du texte et interroger la liste des
agents du Wazuh Manager.

Il n'execute **rien** sur la machine distante : ni SSH, ni PowerShell a
distance, ni installation automatique. L'utilisateur copie les commandes et
les execute lui-meme sur son serveur. La source de verite reste Wazuh : un
serveur n'est declare connecte que si le manager expose un agent
correspondant.

Tout ce qui apparait dans les commandes generees vient de la configuration
(`WAZUH_MANAGER_ADDRESS`, ports, version, depot) : aucune adresse n'est codee
en dur, ni deduite de `WAZUH_API_URL`. Une configuration incomplete leve
`ProvisioningConfigError` plutot que de produire une commande fausse.
"""

import ipaddress
import logging
import re
from typing import Optional
from urllib.parse import urlparse

from app import i18n
from app.config import settings
from app.models import (
    Agent,
    ProvisionedServer,
    ServerCheckRequest,
    ServerConnectionStatus,
    ServerInstallInstructions,
    ServerProvisionRequest,
)
from app.wazuh_client import WazuhClient

logger = logging.getLogger(__name__)

# L'agent 000 est le Wazuh Manager lui-meme : ce n'est jamais un serveur
# ajoute par l'utilisateur.
MANAGER_AGENT_ID = "000"

# Noms d'hote qui ne designent que la machine locale : inutilisables comme
# adresse de manager pour un serveur distant.
LOCAL_HOSTNAMES = frozenset(
    {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}
)

# Une version de paquet Wazuh : 4.14.6, eventuellement suivie de la revision
# du paquet (4.14.6-1).
VERSION_PATTERN = re.compile(r"^\d+(\.\d+)*(-\d+)?$")

# Revision de paquet ajoutee quand WAZUH_AGENT_VERSION ne la precise pas :
# les depots Wazuh publient wazuh-agent_<version>-1_<arch>.
DEFAULT_PACKAGE_REVISION = "1"


class ProvisioningConfigError(Exception):
    """Configuration d'enrolement inexploitable.

    Levee **avant** toute generation : mieux vaut dire a l'administrateur ce
    qu'il doit renseigner dans backend/.env que produire une commande qui
    echouera silencieusement sur le serveur a superviser.
    """

    def __init__(self, message: str, detail: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.detail = detail


# --------------------------------------------------------------------------
# Validation de la configuration d'enrolement
# --------------------------------------------------------------------------


def _is_local_address(address: str) -> bool:
    """Vrai si l'adresse n'est joignable que depuis la machine du manager."""
    if address.lower() in LOCAL_HOSTNAMES:
        return True
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return parsed.is_loopback or parsed.is_unspecified


def _check_port(value: object, env_name: str, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 65535:
        raise ProvisioningConfigError(
            f"Le port {label} du Wazuh Manager est invalide.\n"
            f"Renseignez {env_name} avec un port entre 1 et 65535 dans le "
            "fichier .env du backend.",
            detail=f"{env_name}={value!r}",
        )
    return value


def _check_version() -> str:
    version = (settings.wazuh_agent_version or "").strip()
    if not version:
        raise ProvisioningConfigError(
            "La version du Wazuh Agent n'est pas configurée.\n"
            "Renseignez WAZUH_AGENT_VERSION dans le fichier .env du backend.",
        )
    if not VERSION_PATTERN.match(version):
        raise ProvisioningConfigError(
            "La version du Wazuh Agent est invalide.\n"
            "Renseignez WAZUH_AGENT_VERSION au format 4.14.6 dans le fichier "
            ".env du backend.",
            detail=f"WAZUH_AGENT_VERSION={version}",
        )
    return version


def _check_packages_base_url() -> str:
    base = (settings.wazuh_packages_base_url or "").strip().rstrip("/")
    parsed = urlparse(base)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ProvisioningConfigError(
            "L'URL du dépôt des paquets Wazuh est invalide.\n"
            "Renseignez WAZUH_PACKAGES_BASE_URL (http:// ou https://) dans le "
            "fichier .env du backend.",
            detail=f"WAZUH_PACKAGES_BASE_URL={settings.wazuh_packages_base_url!r}",
        )
    return base


def _check_manager_address(target_ip: Optional[str] = None) -> str:
    """Adresse du manager, verifiee pour le serveur vise.

    Une adresse de bouclage n'est acceptee que si le serveur a superviser est
    lui-meme la machine du manager : sinon l'agent tenterait de s'enroler
    aupres de lui-meme.
    """
    manager = settings.manager_address

    if not manager:
        raise ProvisioningConfigError(
            "L'adresse du Wazuh Manager n'est pas configurée.\n"
            "Configurez WAZUH_MANAGER_ADDRESS dans le fichier .env du backend.",
        )

    if _is_local_address(manager) and not (target_ip and _is_local_address(target_ip)):
        raise ProvisioningConfigError(
            f"L'adresse du Wazuh Manager ('{manager}') ne vaut que depuis la "
            "machine du manager : un serveur distant ne peut pas s'y enroler.\n"
            "Configurez WAZUH_MANAGER_ADDRESS dans le fichier .env du backend "
            "avec une adresse IP ou un nom d'hote joignable depuis vos serveurs.",
            detail=f"WAZUH_MANAGER_ADDRESS={manager}",
        )

    return manager


class EnrollmentConfig:
    """Reglages d'enrolement valides, prets a etre injectes dans le texte."""

    def __init__(self, manager: str, version: str, base_url: str):
        self.manager = manager
        self.version = version
        self.base_url = base_url
        self.enrollment_port = settings.wazuh_enrollment_port
        self.agent_port = settings.wazuh_agent_port

    @property
    def package_version(self) -> str:
        """Version telle qu'elle apparait dans le nom du paquet.

        Les depots Wazuh nomment leurs paquets wazuh-agent_4.14.6-1_amd64.deb :
        la revision est ajoutee si WAZUH_AGENT_VERSION ne la precise pas deja.
        """
        if "-" in self.version:
            return self.version
        return f"{self.version}-{DEFAULT_PACKAGE_REVISION}"


def validate_enrollment_config(target_ip: Optional[str] = None) -> EnrollmentConfig:
    """Verifie la configuration d'enrolement ou leve ProvisioningConfigError.

    Ordre volontaire : l'adresse du manager d'abord, car c'est le reglage
    qu'un administrateur doit renseigner en premier.
    """
    manager = _check_manager_address(target_ip)
    _check_port(
        settings.wazuh_enrollment_port, "WAZUH_ENROLLMENT_PORT", "d'enrolement"
    )
    _check_port(settings.wazuh_agent_port, "WAZUH_AGENT_PORT", "de communication")
    version = _check_version()
    base_url = _check_packages_base_url()

    return EnrollmentConfig(manager=manager, version=version, base_url=base_url)


# --------------------------------------------------------------------------
# Generation des instructions
# --------------------------------------------------------------------------


def _header(request: ServerProvisionRequest, config: EnrollmentConfig) -> list[str]:
    """Rappel, en tete du bloc copie, de la cible et des ports utilises."""
    return [
        f"# Wazuh Manager      : {config.manager}",
        f"# Port enrolement    : {config.enrollment_port}/TCP",
        f"# Port communication : {config.agent_port}/TCP",
        f"# Nom de l'agent     : {request.name}",
        f"# Version de l'agent : {config.version}",
        "",
    ]


def _ports_note(config: EnrollmentConfig) -> str:
    return (
        f"Le serveur doit pouvoir joindre {config.manager} sur les ports "
        f"{config.enrollment_port}/TCP (enrôlement) et "
        f"{config.agent_port}/TCP (communication)."
    )


def _linux_instructions(
    request: ServerProvisionRequest, config: EnrollmentConfig
) -> tuple[list[str], list[str], list[str], list[str]]:
    package = f"wazuh-agent_{config.package_version}_amd64.deb"

    instructions = [
        "Connectez-vous en SSH sur le serveur, avec un compte disposant de sudo.",
        "Téléchargez le paquet Wazuh Agent correspondant à votre distribution.",
        "Installez-le en indiquant l'adresse du manager et le nom du serveur : "
        "l'enrôlement est alors automatique.",
        "Rechargez systemd, activez puis démarrez le service wazuh-agent.",
        "Vérifiez que le service est bien actif.",
        "Revenez ici et cliquez sur \"Vérifier la connexion\".",
    ]

    commands = _header(request, config) + [
        "# 1. Telechargement (Debian / Ubuntu)",
        f"curl -sO {config.base_url}/apt/pool/main/w/wazuh-agent/{package}",
        "",
        "# 2. Installation et enrolement",
        f"sudo WAZUH_MANAGER='{config.manager}' \\",
        f"     WAZUH_MANAGER_PORT='{config.agent_port}' \\",
        f"     WAZUH_REGISTRATION_SERVER='{config.manager}' \\",
        f"     WAZUH_REGISTRATION_PORT='{config.enrollment_port}' \\",
        f"     WAZUH_AGENT_NAME='{request.name}' \\",
        f"     dpkg -i ./{package}",
        "",
        "# 3. Demarrage du service",
        "sudo systemctl daemon-reload",
        "sudo systemctl enable wazuh-agent",
        "sudo systemctl start wazuh-agent",
    ]

    verify_commands = [
        "sudo systemctl status wazuh-agent",
        "sudo tail -n 20 /var/ossec/logs/ossec.log",
    ]

    notes = [
        "Sur Red Hat, CentOS, Fedora ou Amazon Linux, remplacez les deux "
        f"premières étapes par :  sudo WAZUH_MANAGER='{config.manager}' "
        f"WAZUH_MANAGER_PORT='{config.agent_port}' "
        f"WAZUH_REGISTRATION_SERVER='{config.manager}' "
        f"WAZUH_REGISTRATION_PORT='{config.enrollment_port}' "
        f"WAZUH_AGENT_NAME='{request.name}' rpm -ihv "
        f"{config.base_url}/yum/wazuh-agent-{config.package_version}.x86_64.rpm",
        _ports_note(config),
    ]

    return instructions, commands, verify_commands, notes


def _windows_instructions(
    request: ServerProvisionRequest, config: EnrollmentConfig
) -> tuple[list[str], list[str], list[str], list[str]]:
    package = f"wazuh-agent-{config.package_version}.msi"

    instructions = [
        "Ouvrez PowerShell en tant qu'administrateur sur le serveur.",
        "Téléchargez l'installeur MSI de Wazuh Agent.",
        "Installez-le en passant l'adresse du manager et le nom du serveur : "
        "l'enrôlement est alors automatique.",
        "Démarrez le service WazuhSvc.",
        "Vérifiez que le service est bien démarré.",
        "Revenez ici et cliquez sur \"Vérifier la connexion\".",
    ]

    commands = _header(request, config) + [
        "# 1. Telechargement",
        f"Invoke-WebRequest -Uri '{config.base_url}/windows/{package}' "
        "-OutFile \"$env:TEMP\\wazuh-agent.msi\"",
        "",
        "# 2. Installation et enrolement",
        "msiexec.exe /i \"$env:TEMP\\wazuh-agent.msi\" /q "
        f"WAZUH_MANAGER='{config.manager}' "
        f"WAZUH_MANAGER_PORT='{config.agent_port}' "
        f"WAZUH_REGISTRATION_SERVER='{config.manager}' "
        f"WAZUH_REGISTRATION_PORT='{config.enrollment_port}' "
        f"WAZUH_AGENT_NAME='{request.name}'",
        "",
        "# 3. Demarrage du service",
        "NET START WazuhSvc",
    ]

    verify_commands = [
        "Get-Service -Name WazuhSvc",
        "Get-Content 'C:\\Program Files (x86)\\ossec-agent\\ossec.log' -Tail 20",
    ]

    notes = [
        "PowerShell doit être lancé en tant qu'administrateur, sinon "
        "l'installation échoue silencieusement.",
        _ports_note(config),
    ]

    return instructions, commands, verify_commands, notes


def build_instructions(request: ServerProvisionRequest) -> ServerInstallInstructions:
    """Produit la procedure d'installation adaptee au systeme choisi.

    Aucune commande n'est executee : le resultat est purement informatif.
    Leve `ProvisioningConfigError` si la configuration d'enrolement du backend
    ne permet pas de produire une procedure exacte : une commande fausse
    coute plus cher qu'un message d'erreur.
    """
    config = validate_enrollment_config(target_ip=request.ip)

    builder = _linux_instructions if request.os == "linux" else _windows_instructions
    instructions, commands, verify_commands, notes = builder(request, config)

    logger.info(
        "Instructions %s generees pour le serveur %s (%s), manager %s",
        request.os,
        request.name,
        request.ip,
        config.manager,
    )

    return ServerInstallInstructions(
        server=ProvisionedServer(
            name=request.name,
            ip=request.ip,
            os=request.os,
            description=request.description,
        ),
        manager_address=config.manager,
        enrollment_port=config.enrollment_port,
        agent_port=config.agent_port,
        agent_version=config.version,
        instructions=instructions,
        commands=commands,
        verify_commands=verify_commands,
        notes=notes,
    )


# --------------------------------------------------------------------------
# Recherche d'un agent correspondant
# --------------------------------------------------------------------------


def exclude_manager(agents: list[Agent]) -> list[Agent]:
    """Retire l'agent 000 : c'est le manager, pas un serveur supervise."""
    return [agent for agent in agents if agent.id != MANAGER_AGENT_ID]


def find_matching_agents(
    agents: list[Agent],
    name: str,
    ip: Optional[str] = None,
) -> list[Agent]:
    """Agents correspondant au serveur demande, par nom ou par IP.

    L'agent 000 est toujours ignore. La comparaison des noms est
    insensible a la casse et aux espaces de bord.
    """
    wanted_name = (name or "").strip().lower()
    wanted_ip = (ip or "").strip()

    matches: list[Agent] = []
    for agent in exclude_manager(agents):
        same_name = bool(wanted_name) and (agent.name or "").strip().lower() == wanted_name
        same_ip = bool(wanted_ip) and (agent.ip or "").strip() == wanted_ip

        if same_name or same_ip:
            matches.append(agent)

    return matches


async def check_server(
    client: WazuhClient,
    request: ServerCheckRequest,
) -> ServerConnectionStatus:
    """Interroge le Wazuh Manager et dit si le serveur est enrole.

    Ne leve pas d'erreur metier : un agent absent est une reponse normale.
    Les pannes de l'API Wazuh remontent en `WazuhError`, traduite en reponse
    HTTP propre par la couche routes.
    """
    agents = await client.get_agents()
    matches = find_matching_agents(agents, name=request.name, ip=request.ip)

    if not matches:
        logger.info("Aucun agent ne correspond a %s (%s)", request.name, request.ip)
        return ServerConnectionStatus(
            connected=False,
            status="pending",
            message="Agent non détecté",
        )

    if len(matches) > 1:
        logger.info(
            "%s agents correspondent a %s (%s)", len(matches), request.name, request.ip
        )
        return ServerConnectionStatus(
            connected=False,
            status="multiple",
            message=(
                f"{len(matches)} agents correspondent à ce serveur. "
                "Précisez le nom ou l'adresse IP."
            ),
            matches=matches,
        )

    agent = matches[0]
    active = (agent.status or "").lower() == "active"

    return ServerConnectionStatus(
        connected=active,
        status="connected" if active else "pending",
        message=(
            "Serveur connecté"
            if active
            else (
                "Agent enrôlé mais inactif "
                f"(statut Wazuh : {i18n.agent_status_label(agent.status)})"
            )
        ),
        agent=agent,
        matches=matches,
    )
