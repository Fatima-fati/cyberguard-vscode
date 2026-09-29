"""Couche de presentation francaise : referentiels de libelles + traduction.

Point d'entree unique du projet pour tout ce qui est *lu par un humain*.
Rien ici ne modifie les donnees techniques de Wazuh : les modeles gardent
`rule.description`, `rule.id`, `agent.id`, `full_log`, les horodatages et
les statuts internes tels quels. Les libelles francais sont *ajoutes* a
cote (champs `*_label`, `description_fr`), jamais substitues en base.

    Wazuh original
      -> donnees techniques conservees (models.py, store.py)
      -> normalisation / traduction (ce module)
      -> champs destines a l'UI (`*_label`, `description_fr`)
      -> interface francaise

Deux services :

1. **Referentiels** : severites, statuts d'agent, statuts de notification,
   de remediation, classifications d'incident, actions d'audit.
2. **Traduction** : `localize_security_text()` (alias
   `translate_alert_message()`) convertit une phrase de securite anglaise
   (typiquement une `rule.description` Wazuh) en francais, sans jamais
   toucher aux identifiants techniques (IP, chemins, CVE, commandes,
   utilisateurs, ports, hashs) ni aux termes de securite reconnus
   (SQL injection, XSS, CSRF, SSH, brute force, malware, rootkit...).
"""

import re
from typing import Optional

# --------------------------------------------------------------------------
# 1. Referentiels de libelles
# --------------------------------------------------------------------------

# Severite interne (jamais modifiee, la logique metier s'en sert) -> libelle.
SEVERITY_LABELS: dict[str, str] = {
    "LOW": "FAIBLE",
    "MEDIUM": "MOYENNE",
    "HIGH": "ÉLEVÉE",
    "CRITICAL": "CRITIQUE",
}

# Statut d'agent renvoye par la Wazuh Manager API.
AGENT_STATUS_LABELS: dict[str, str] = {
    "active": "ACTIVE",
    "disconnected": "DÉCONNECTÉ",
    "pending": "EN ATTENTE",
    "never_connected": "JAMAIS CONNECTÉ",
    "connected": "CONNECTÉ",
    "multiple": "PLUSIEURS CORRESPONDANCES",
    "running": "EN COURS",
    "stopped": "ARRÊTÉ",
    "unknown": "INCONNU",
}

# Cycle de vie d'une notification : ou en est l'UTILISATEUR vis-a-vis
# d'elle. N'indique rien sur l'analyse IA (voir ANALYSIS_STATUS_LABELS).
NOTIFICATION_STATUS_LABELS: dict[str, str] = {
    "new": "Nouvelle",
    "acknowledged": "Vue",
    "dismissed": "Ignorée",
    "resolved": "Résolue",
}

# Cycle de vie de l'ANALYSE IA d'une notification. Independant du statut
# ci-dessus : ouvrir une notification ne l'analyse pas.
ANALYSIS_STATUS_LABELS: dict[str, str] = {
    "pending": "En attente d'analyse",
    "analyzing": "Analyse en cours",
    "analyzed": "Analysée",
    "failed": "Échec de l'analyse",
}

# Cycle de vie d'une remediation.
REMEDIATION_STATUS_LABELS: dict[str, str] = {
    "not_available": "Indisponible",
    "pending": "En préparation",
    "proposed": "Proposée",
    "awaiting_confirmation": "En attente de confirmation",
    "approved": "Approuvée",
    "rejected": "Refusée",
    "applied": "Appliquée",
    "failed": "Échouée",
    "cancelled": "Annulée",
}

# Nature de la correction proposee.
REMEDIATION_TYPE_LABELS: dict[str, str] = {
    "code_patch": "Correction de code",
    "configuration_change": "Changement de configuration",
    "account_action": "Action sur un compte",
    "network_rule": "Règle réseau",
    "manual_only": "Intervention manuelle",
    "none": "Aucune",
}

# Type d'incident retenu par l'analyse IA (EVENT_TYPES).
CLASSIFICATION_LABELS: dict[str, str] = {
    "authentication_failure": "Échec d'authentification",
    "brute_force": "Attaque par brute force",
    "malware": "Logiciel malveillant (malware)",
    "privilege_escalation": "Élévation de privilèges",
    "suspicious_process": "Processus suspect",
    "network_attack": "Attaque réseau",
    "configuration_weakness": "Faiblesse de configuration",
    "vulnerability": "Vulnérabilité",
    "file_integrity_violation": "Modification de fichier sensible",
    "policy_violation": "Violation de politique",
    "system_event": "Événement système",
    "unknown": "Non déterminé",
}

# Origine d'une notification.
SOURCE_LABELS: dict[str, str] = {
    "wazuh": "Niveau Wazuh",
    "ia": "Agent IA",
}

# Actions tracees dans le journal d'audit.
AUDIT_ACTION_LABELS: dict[str, str] = {
    "NOTIFICATION_CREATED": "Notification créée",
    "NOTIFICATION_ENRICHED": "Notification enrichie par l'analyse IA",
    "NOTIFICATION_ACKNOWLEDGED": "Notification consultée",
    "ANALYSIS_STARTED": "Analyse IA lancée",
    "ANALYSIS_FAILED": "Analyse IA en échec",
    "NOTIFICATION_DISMISSED": "Notification ignorée",
    "REMEDIATION_PREVIEWED": "Correction prévisualisée",
    "REMEDIATION_PROPOSED": "Correction proposée",
    "REMEDIATION_APPROVED": "Correction approuvée",
    "REMEDIATION_APPLIED": "Correction appliquée",
    "REMEDIATION_REJECTED": "Correction refusée",
    "REMEDIATION_FAILED": "Correction en échec",
    "REMEDIATION_ROLLED_BACK": "Correction annulée",
    "REMEDIATION_ROLLBACK_FAILED": "Échec de l'annulation de la correction",
}

# Groupes de regles Wazuh les plus frequents. Un groupe inconnu reste
# affiche tel quel : c'est un identifiant technique Wazuh.
RULE_GROUP_LABELS: dict[str, str] = {
    "authentication_failed": "échec d'authentification",
    "authentication_failures": "échecs d'authentification répétés",
    "authentication_success": "authentification réussie",
    "invalid_login": "connexion invalide",
    "attacks": "attaque",
    "web_scan": "scan web",
    "recon": "reconnaissance",
    "sql_injection": "SQL injection",
    "web_attack": "attaque web",
    "rootcheck": "contrôle d'intégrité système",
    "syscheck": "surveillance de fichiers",
    "vulnerability-detector": "détection de vulnérabilités",
    "policy_violation": "violation de politique",
    "service_availability": "disponibilité de service",
    "connection_attempt": "tentative de connexion",
    "firewall": "pare-feu",
    "virus": "logiciel malveillant",
    "intrusion_detection": "détection d'intrusion",
    "account_changed": "compte modifié",
    "adduser": "ajout d'utilisateur",
    "privilege_escalation": "élévation de privilèges",
}


def _lookup(table: dict[str, str], value: Optional[str], default: str = "") -> str:
    """Libelle d'une valeur interne, sans jamais lever."""
    if value is None:
        return default
    key = str(value).strip()
    return table.get(key) or table.get(key.lower()) or default or key


def severity_label(value: Optional[str]) -> str:
    return _lookup(SEVERITY_LABELS, value)


def agent_status_label(value: Optional[str]) -> str:
    """Libelle d'un statut d'agent Wazuh. `status` brut reste disponible."""
    if not value:
        return AGENT_STATUS_LABELS["unknown"]
    return _lookup(AGENT_STATUS_LABELS, value)


def notification_status_label(value: Optional[str]) -> str:
    return _lookup(NOTIFICATION_STATUS_LABELS, value)


def analysis_status_label(value: Optional[str]) -> str:
    """Libelle de l'etat de l'analyse IA (pending/analyzing/analyzed/failed)."""
    return _lookup(ANALYSIS_STATUS_LABELS, value or "pending")


def remediation_status_label(value: Optional[str]) -> str:
    return _lookup(REMEDIATION_STATUS_LABELS, value)


def remediation_type_label(value: Optional[str]) -> str:
    return _lookup(REMEDIATION_TYPE_LABELS, value)


def classification_label(value: Optional[str]) -> str:
    """Libelle d'un type d'incident. Une valeur inconnue est traduite."""
    if not value:
        return CLASSIFICATION_LABELS["unknown"]
    key = str(value).strip().lower()
    if key in CLASSIFICATION_LABELS:
        return CLASSIFICATION_LABELS[key]
    return localize_security_text(key.replace("_", " "))


def source_label(value: Optional[str]) -> str:
    return _lookup(SOURCE_LABELS, value)


def audit_action_label(value: Optional[str]) -> str:
    """Libelle d'une action d'audit. L'action brute reste dans `action`."""
    if not value:
        return ""
    key = str(value).strip()
    return AUDIT_ACTION_LABELS.get(key.upper()) or localize_security_text(
        key.replace("_", " ").lower()
    )


def rule_group_label(value: Optional[str]) -> str:
    """Libelle d'un groupe de regles Wazuh (identifiant technique sinon)."""
    if not value:
        return ""
    return RULE_GROUP_LABELS.get(str(value).strip().lower(), str(value))


def rule_groups_label(groups: Optional[list[str]]) -> str:
    """Groupes Wazuh mis en forme pour l'affichage."""
    return ", ".join(rule_group_label(group) for group in (groups or []) if group)


# --------------------------------------------------------------------------
# 2. Traduction des phrases de securite
# --------------------------------------------------------------------------

# Fragments jamais traduits : ce sont des donnees techniques. Ils sont
# extraits du texte avant traduction, puis reinseres a l'identique.
_PROTECTED = re.compile(
    r"""
      CVE-\d{4}-\d{4,7}                                   # identifiant CVE
    | (?:[A-Za-z]:)?[\\/](?:[\w.+\-]+[\\/])*[\w.+\-]+     # chemin de fichier
    | \b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b                # adresse IPv4 (+ port)
    | \b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b            # adresse MAC
    | \b[0-9A-Fa-f]{32,}\b                                # empreinte / hash
    | \b[\w.+\-]+@[\w.\-]+\.\w+\b                         # adresse e-mail
    | '[^']{1,120}' | "[^"]{1,120}"                       # valeur citee
    | \b[A-Za-z][\w.\-]*\(\)                              # appel de fonction
    | \b(?:HKLM|HKCU|HKEY_[A-Z_]+)\\[^\s]+                # cle de registre
    """,
    re.VERBOSE,
)

# Termes de securite reconnus, laisses en anglais (noms propres ou
# concepts standards du domaine). Ils ne sont donc dans aucun glossaire.
KEPT_TECHNICAL_TERMS: tuple[str, ...] = (
    "SQL injection", "XSS", "CSRF", "SSRF", "SSH", "SSL", "TLS", "brute force",
    "malware", "ransomware", "rootkit", "backdoor", "phishing", "spoofing",
    "buffer overflow", "shellcode", "payload", "exploit", "CVE", "OWASP",
    "MITRE", "ATT&CK", "Wazuh", "OpenAI", "Docker", "Linux", "Windows",
    "PowerShell", "sudo", "root", "syslog", "netstat", "firewall", "proxy",
    "scan", "shell", "socket", "hash", "token", "cookie", "cron", "sshd",
    "PAM", "systemd", "Shellshock", "netcat", "audit", "checksum",
)

# Marqueurs permettant de decider si une phrase est bien de l'anglais.
_ENGLISH_MARKERS = re.compile(
    r"(?<![\w-])(?:the|and|or|of|for|from|with|to|by|on|in|is|was|were|has|have|"
    r"been|not|no|new|user|users|file|files|system|failed|failure|failures|"
    r"success|successful|attempt|attempts|login|logon|logged|password|account|"
    r"detected|changed|added|deleted|removed|created|modified|started|stopped|"
    r"disconnected|connected|multiple|error|attack|denied|allowed|blocked|"
    r"session|service|server|port|ports|process|command|group|policy|rule|"
    r"agent|event|events|time|source|address|possible|invalid|unknown|"
    r"exceeded|opened|closed|enabled|disabled|locked|installed|uninstalled)"
    r"(?![\w-])",
    re.IGNORECASE,
)


def _split_prefix(text: str) -> tuple[str, str]:
    """Isole un prefixe technique ('sshd: ...', 'PAM: ...', 'Windows: ...').

    Le prefixe est un nom de composant : il n'est jamais traduit.
    """
    # Un seul mot avant le deux-points : c'est un nom de composant
    # (sshd, PAM, systemd, Windows...). Des qu'il y a un espace, c'est une
    # phrase ("Vulnerability detected: ...") et on ne la coupe pas.
    match = re.match(r"^([A-Za-z][\w.+\-]{0,28})\s*:\s+(.+)$", text)
    if not match:
        return "", text
    return match.group(1), match.group(2)


# --- Tier 1 : descriptions Wazuh courantes, traduites en phrases naturelles

_SENTENCE_SOURCES: tuple[tuple[str, str], ...] = (
    # -- SSH / authentification -----------------------------------------
    (r"(?:user )?authentication (?:failed|failure) for (?:user )?(\S+)\.?",
     r"Échec d'authentification pour l'utilisateur \1"),
    (r"(?:user )?authentication (?:failed|failure)\.?", "Échec d'authentification"),
    (r"authentication success(?:ful)?\.?", "Authentification réussie"),
    (r"multiple authentication failures(?: detected)?\.?",
     "Plusieurs échecs d'authentification ont été détectés"),
    (r"attempt to login using a non[- ]?existent user\.?",
     "Tentative de connexion avec un utilisateur inexistant"),
    (r"attempt to login using a denied user\.?",
     "Tentative de connexion avec un utilisateur interdit"),
    (r"brute force trying to get access to the system\.?",
     "Tentative d'accès au système par brute force"),
    (r"maximum authentication attempts exceeded(?: for .*)?\.?",
     "Nombre maximal de tentatives d'authentification dépassé"),
    (r"multiple failed logins in a small period of time\.?",
     "Plusieurs échecs de connexion en peu de temps"),
    (r"user login failed\.?", "Échec de connexion de l'utilisateur"),
    (r"user missed the password more than one time\.?",
     "L'utilisateur s'est trompé de mot de passe à plusieurs reprises"),
    (r"login session opened\.?", "Session utilisateur ouverte"),
    (r"login session closed\.?", "Session utilisateur fermée"),
    (r"insecure connection attempt \(scan\)\.?",
     "Tentative de connexion non sécurisée (scan)"),
    (r"possible attack on the ssh server(?: \(or version gathering\))?\.?",
     "Attaque possible sur le serveur SSH (ou collecte de version)"),
    (r"reverse lookup error \(bad isp or attack\)\.?",
     "Erreur de résolution DNS inverse (FAI défaillant ou attaque)"),
    (r"connection closed by authenticating user.*",
     "Connexion fermée par l'utilisateur en cours d'authentification"),
    (r"successful sudo to root executed\.?",
     "Commande sudo vers root exécutée avec succès"),
    (r"first time (?:this )?user executed sudo\.?",
     "Première utilisation de sudo par cet utilisateur"),
    # -- Windows --------------------------------------------------------
    (r"(?:windows )?logon failure(?: - unknown user or bad password)?\.?",
     "Échec d'ouverture de session (utilisateur inconnu ou mot de passe incorrect)"),
    (r"(?:windows )?logon success(?:ful)?\.?", "Ouverture de session réussie"),
    (r"multiple windows logon failures\.?",
     "Plusieurs échecs d'ouverture de session Windows"),
    (r"windows audit log(?: was)? cleared\.?",
     "Le journal d'audit Windows a été effacé"),
    (r"(?:windows )?user account (?:was )?changed\.?", "Compte utilisateur modifié"),
    (r"(?:windows )?user account (?:was )?created\.?", "Compte utilisateur créé"),
    (r"(?:windows )?user account (?:was )?deleted\.?", "Compte utilisateur supprimé"),
    (r"(?:windows )?user account (?:was )?enabled\.?", "Compte utilisateur activé"),
    (r"(?:windows )?user account (?:was )?disabled\.?", "Compte utilisateur désactivé"),
    (r"(?:user )?account (?:was )?locked out\.?", "Compte utilisateur verrouillé"),
    (r"service startup type was changed\.?",
     "Le type de démarrage du service a été modifié"),
    # -- Agents Wazuh ---------------------------------------------------
    (r"(?:ossec |wazuh )?agent disconnected\.?", "L'agent Wazuh s'est déconnecté"),
    (r"(?:ossec |wazuh )?agent started\.?", "L'agent Wazuh a démarré"),
    (r"(?:ossec |wazuh )?agent stopped\.?", "L'agent Wazuh s'est arrêté"),
    (r"(?:new )?(?:ossec |wazuh )?agent connected\.?",
     "Un agent Wazuh s'est connecté"),
    (r"(?:ossec |wazuh )?agent removed\.?", "Un agent Wazuh a été supprimé"),
    # -- Integrite / fichiers -------------------------------------------
    (r"integrity checksum changed(?: again)?(?: \(\d+\w* time\))?\.?",
     "La somme de contrôle d'intégrité d'un fichier a changé"),
    (r"file added to the system\.?", "Un fichier a été ajouté au système"),
    (r"file deleted\.?", "Un fichier a été supprimé"),
    (r"file modified\.?", "Un fichier a été modifié"),
    (r"host[- ]based anomaly detection event \(rootcheck\)\.?",
     "Anomalie détectée sur l'hôte (rootcheck)"),
    (r"rootkit detected(?: by rootcheck)?\.?", "Rootkit détecté sur le système"),
    (r"listened ports status \(netstat\) changed(?: \(new port opened or closed\))?\.?",
     "L'état des ports en écoute (netstat) a changé"),
    # -- Web / reseau ---------------------------------------------------
    (r"web server 400 error code\.?", "Code d'erreur 400 renvoyé par le serveur web"),
    (r"multiple web server 400 error codes from same source ip\.?",
     "Plusieurs codes d'erreur 400 provenant de la même adresse IP source"),
    (r"common web attack\.?", "Attaque web courante détectée"),
    (r"sql injection attempt\.?", "Tentative de SQL injection"),
    (r"xss \(cross site scripting\) attempt\.?",
     "Tentative de XSS (Cross Site Scripting)"),
    (r"shellshock attack detected\.?", "Attaque Shellshock détectée"),
    (r"netcat listening for incoming connections\.?",
     "netcat est en écoute de connexions entrantes"),
    (r"firewall drop event\.?", "Paquet bloqué par le pare-feu"),
    (r"ip address blocked.*", "Adresse IP bloquée"),
    # -- Systeme --------------------------------------------------------
    (r"system audit event\.?", "Événement d'audit système"),
    (r"new user added to the system\.?",
     "Un nouvel utilisateur a été ajouté au système"),
    (r"new dpkg \(debian package\) (?:installed|requested to install)\.?",
     "Nouveau paquet Debian (dpkg) installé"),
    (r"(?:new )?yum package installed\.?", "Nouveau paquet Yum installé"),
    (r"software (?:package )?installed\.?", "Logiciel installé"),
    (r"service started\.?", "Service démarré"),
    (r"service stopped\.?", "Service arrêté"),
    (r"non standard syslog message \(size too large\)\.?",
     "Message syslog non standard (taille trop importante)"),
    (r"log file rotated\.?", "Fichier de journal alterné (rotation)"),
    (r"log file size reduced\.?", "Taille du fichier de journal réduite"),
)

_SENTENCE_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(rf"^{pattern}$", re.IGNORECASE), replacement)
    for pattern, replacement in _SENTENCE_SOURCES
]


# --- Tier 2 : glossaire, applique quand aucune phrase complete ne matche.
# La substitution se fait en une seule passe : la sequence la plus longue
# l'emporte, et une valeur deja traduite n'est jamais retraduite.
_GLOSSARY: dict[str, str] = {
    # Locutions
    "multiple authentication failures detected":
        "plusieurs échecs d'authentification ont été détectés",
    "multiple authentication failures": "plusieurs échecs d'authentification",
    "authentication failures": "échecs d'authentification",
    "authentication failure": "échec d'authentification",
    "authentication failed": "échec d'authentification",
    "authentication success": "authentification réussie",
    "failed authentication": "échec d'authentification",
    "multiple failed logins": "plusieurs échecs de connexion",
    "failed logins": "échecs de connexion",
    "failed login": "échec de connexion",
    "login failed": "échec de connexion",
    "login failure": "échec de connexion",
    "logon failure": "échec d'ouverture de session",
    "logon success": "ouverture de session réussie",
    "successful login": "connexion réussie",
    "unsuccessful login": "échec de connexion",
    "in a small period of time": "en peu de temps",
    "non-existent user": "utilisateur inexistant",
    "non existent user": "utilisateur inexistant",
    "unknown user or bad password": "utilisateur inconnu ou mot de passe incorrect",
    "bad password": "mot de passe incorrect",
    "wrong password": "mot de passe incorrect",
    "invalid user": "utilisateur invalide",
    "illegal user": "utilisateur non autorisé",
    "maximum authentication attempts exceeded":
        "nombre maximal de tentatives d'authentification dépassé",
    "connection attempt": "tentative de connexion",
    "connection closed": "connexion fermée",
    "connection reset by peer": "connexion réinitialisée par le pair",
    "received disconnect from": "déconnexion reçue de",
    "login session opened": "session ouverte",
    "login session closed": "session fermée",
    "session opened": "session ouverte",
    "session closed": "session fermée",
    "privilege escalation": "élévation de privilèges",
    "integrity checksum changed": "somme de contrôle d'intégrité modifiée",
    "checksum changed": "somme de contrôle modifiée",
    "file added to the system": "fichier ajouté au système",
    "added to the system": "ajouté au système",
    "host-based anomaly detection": "détection d'anomalie sur l'hôte",
    "anomaly detection": "détection d'anomalie",
    "listened ports status": "état des ports en écoute",
    "new port opened or closed": "nouveau port ouvert ou fermé",
    "listening for incoming connections": "en écoute de connexions entrantes",
    "incoming connections": "connexions entrantes",
    "outgoing connections": "connexions sortantes",
    "web server": "serveur web",
    "error code": "code d'erreur",
    "error codes": "codes d'erreur",
    "source ip": "adresse IP source",
    "ip address": "adresse IP",
    "same source": "même source",
    "common web attack": "attaque web courante",
    "web attack": "attaque web",
    "system audit event": "événement d'audit système",
    "audit log cleared": "journal d'audit effacé",
    "audit log": "journal d'audit",
    "log file": "fichier de journal",
    "size too large": "taille trop importante",
    "startup type": "type de démarrage",
    "user account": "compte utilisateur",
    "locked out": "verrouillé",
    "access denied": "accès refusé",
    "permission denied": "permission refusée",
    "port scan": "balayage de ports",
    "denial of service": "déni de service",
    "command execution": "exécution de commande",
    "remote code execution": "exécution de code à distance",
    "suspicious process": "processus suspect",
    "suspicious activity": "activité suspecte",
    "vulnerability detected": "vulnérabilité détectée",
    "of user": "de l'utilisateur",
    "in package": "dans le paquet",
    "on the system": "sur le système",
    "to the system": "au système",
    "from the system": "du système",
    "on the server": "sur le serveur",
    "for user": "pour l'utilisateur",
    "by user": "par l'utilisateur",
    "the user": "l'utilisateur",
    "the system": "le système",
    "the file": "le fichier",
    "the server": "le serveur",
    "the service": "le service",
    "the agent": "l'agent",
    "the account": "le compte",
    "the network": "le réseau",
    "more than": "plus de",
    "has been": "a été",
    "have been": "ont été",
    "was not": "n'a pas été",
    "is not": "n'est pas",
    # Mots
    "attempts": "tentatives",
    "attempt": "tentative",
    "failures": "échecs",
    "failure": "échec",
    "failed": "en échec",
    "successful": "réussi",
    "success": "succès",
    "detected": "détecté",
    "blocked": "bloqué",
    "denied": "refusé",
    "allowed": "autorisé",
    "started": "démarré",
    "stopped": "arrêté",
    "restarted": "redémarré",
    "disconnected": "déconnecté",
    "connected": "connecté",
    "changed": "modifié",
    "modified": "modifié",
    "added": "ajouté",
    "deleted": "supprimé",
    "removed": "supprimé",
    "created": "créé",
    "installed": "installé",
    "uninstalled": "désinstallé",
    "enabled": "activé",
    "disabled": "désactivé",
    "opened": "ouvert",
    "closed": "fermé",
    "exceeded": "dépassé",
    "multiple": "plusieurs",
    "several": "plusieurs",
    "unknown": "inconnu",
    "invalid": "invalide",
    "insecure": "non sécurisé",
    "users": "utilisateurs",
    "user": "utilisateur",
    "files": "fichiers",
    "file": "fichier",
    "system": "système",
    "password": "mot de passe",
    "account": "compte",
    "login": "connexion",
    "logon": "ouverture de session",
    "server": "serveur",
    "network": "réseau",
    "ports": "ports",
    "process": "processus",
    "command": "commande",
    "group": "groupe",
    "policy": "politique",
    "rule": "règle",
    "event": "événement",
    "events": "événements",
    "error": "erreur",
    "attack": "attaque",
    "attacks": "attaques",
    "address": "adresse",
    "time": "temps",
    "package": "paquet",
    "software": "logiciel",
    "vulnerability": "vulnérabilité",
    "warning": "avertissement",
    "level": "niveau",
    "new": "nouveau",
    "old": "ancien",
    "same": "même",
    # Mots-outils : sans eux la phrase resterait du franglais.
    "and": "et",
    "or": "ou",
    "of": "de",
    "for": "pour",
    "from": "depuis",
    "with": "avec",
    "without": "sans",
    "by": "par",
    "on": "sur",
    "in": "dans",
    "into": "dans",
    "to": "vers",
    "at": "à",
    "is": "est",
    "was": "était",
    "were": "étaient",
    "are": "sont",
    "not": "non",
    "than": "que",
    "this": "ce",
    "that": "ce",
    "an": "un",
    "the": "le",
}

_GLOSSARY_PATTERN = re.compile(
    r"(?<![\w'-])(?:"
    + "|".join(re.escape(term) for term in sorted(_GLOSSARY, key=len, reverse=True))
    + r")(?![\w'-])",
    re.IGNORECASE,
)


def _apply_glossary(text: str) -> str:
    """Traduit locution par locution, en une seule passe."""
    return _GLOSSARY_PATTERN.sub(lambda match: _GLOSSARY[match.group(0).lower()], text)


def _translate_outside_protected(text: str) -> str:
    """Applique le glossaire en dehors des fragments techniques proteges."""
    result: list[str] = []
    cursor = 0

    for match in _PROTECTED.finditer(text):
        result.append(_apply_glossary(text[cursor : match.start()]))
        result.append(match.group(0))  # identifiant technique : intact
        cursor = match.end()

    result.append(_apply_glossary(text[cursor:]))
    return "".join(result)


def _polish(text: str) -> str:
    """Espaces, ponctuation, majuscule initiale."""
    cleaned = re.sub(r"\s+", " ", text).strip()
    cleaned = re.sub(r"\s+([,.;!?])", r"\1", cleaned)
    if not cleaned:
        return cleaned

    for index, char in enumerate(cleaned):
        if char.isalpha():
            return cleaned[:index] + char.upper() + cleaned[index + 1 :]
    return cleaned


def localize_security_text(text: Optional[str]) -> str:
    """Traduit en francais une phrase de securite (description Wazuh...).

    Garanties :
    - les identifiants techniques (IP, chemins, CVE, hashs, valeurs citees,
      appels de fonction, cles de registre) sont extraits avant traduction
      et reinseres tels quels ;
    - les termes de securite reconnus (SQL injection, XSS, SSH, brute
      force, malware...) ne figurent dans aucun glossaire : ils restent en
      anglais ;
    - un texte vide, deja francais ou purement technique est renvoye
      inchange : jamais de traduction aveugle.

    Le texte d'origine n'est jamais modifie a la source : cette fonction
    produit une *copie* destinee a l'affichage.
    """
    if not text:
        return ""

    raw = re.sub(r"\s+", " ", str(text)).strip()
    if not raw:
        return ""

    prefix, body = _split_prefix(raw)
    ends_with_period = body.endswith(".")

    translated: Optional[str] = None

    # Tier 1 : la phrase entiere est reconnue -> traduction naturelle.
    for pattern, replacement in _SENTENCE_RULES:
        match = pattern.match(body)
        if match:
            translated = match.expand(replacement)
            break

    # Tier 2 : traduction locution par locution, hors donnees techniques.
    if translated is None:
        if not _ENGLISH_MARKERS.search(body):
            # Ni anglais reconnaissable, ni phrase connue : c'est deja du
            # francais ou du texte purement technique. On n'y touche pas.
            return raw
        translated = _translate_outside_protected(body)

    result = _polish(translated)
    if ends_with_period and not result.endswith((".", "!", "?")):
        result += "."

    return f"{prefix} : {result}" if prefix else result


# Alias : meme fonction, nom oriente "message d'alerte".
translate_alert_message = localize_security_text


# --------------------------------------------------------------------------
# 3. Analyse de code (extension VS Code)
# --------------------------------------------------------------------------

# Categories de vulnerabilite. Les noms d'attaque reconnus restent en
# anglais (SQL injection, XSS, CSRF, SSRF, XXE) : ce sont les termes du
# metier, ceux qu'un developpeur retrouvera dans la documentation.
VULNERABILITY_CATEGORY_LABELS: dict[str, str] = {
    "sql_injection": "SQL injection",
    "command_injection": "Injection de commande système",
    "xss": "XSS (Cross Site Scripting)",
    "path_traversal": "Traversée de répertoire",
    "insecure_deserialization": "Désérialisation non sécurisée",
    "hardcoded_secret": "Secret écrit en dur",
    "weak_cryptography": "Cryptographie faible",
    "ssrf": "SSRF (requête falsifiée côté serveur)",
    "xxe": "XXE (entités XML externes)",
    "insecure_random": "Aléatoire non sécurisé",
    "broken_access_control": "Contrôle d'accès défaillant",
    "csrf": "CSRF (falsification de requête)",
    "open_redirect": "Redirection ouverte",
    "unsafe_eval": "Évaluation dynamique de code",
    "insecure_configuration": "Configuration non sécurisée",
    "unknown": "Non déterminé",
}

# Cycle de vie d'un finding de code.
CODE_FINDING_STATUS_LABELS: dict[str, str] = {
    "open": "Ouvert",
    "dismissed": "Ignoré (faux positif)",
    "fixed": "Corrigé",
}

# Origine d'un finding.
CODE_FINDING_SOURCE_LABELS: dict[str, str] = {
    "rule": "Règle de détection",
    "ia": "Analyse IA",
}


def code_category_label(value: Optional[str]) -> str:
    """Libelle d'une categorie de vulnerabilite."""
    if not value:
        return VULNERABILITY_CATEGORY_LABELS["unknown"]
    key = str(value).strip().lower()
    return VULNERABILITY_CATEGORY_LABELS.get(
        key, localize_security_text(key.replace("_", " "))
    )


def code_finding_status_label(value: Optional[str]) -> str:
    return _lookup(CODE_FINDING_STATUS_LABELS, value or "open")


def code_finding_source_label(value: Optional[str]) -> str:
    return _lookup(CODE_FINDING_SOURCE_LABELS, value or "rule")


# --------------------------------------------------------------------------
# 6. Securite projet (phase 2) : secrets, dependances, vulnerabilites
# --------------------------------------------------------------------------

# Familles de detection. `API` et `GIT` sont declarees mais ne sont
# produites par aucun moteur : leur libelle existe pour que l'ajout d'un
# moteur n'oblige pas a toucher a l'interface.
SECURITY_CATEGORY_LABELS: dict[str, str] = {
    "SECRET": "Secret exposé",
    "DEPENDENCY": "Dépendance vulnérable",
    "CODE": "Vulnérabilité de code",
    "CONFIGURATION": "Configuration non sécurisée",
    "API": "Sécurité d'API",
    "GIT": "Sécurité Git",
}

# Confiance de la detection. Volontairement distincte de la gravite : une
# detection certaine d'un probleme mineur et une detection douteuse d'un
# probleme majeur ne doivent pas se ressembler a l'ecran.
CONFIDENCE_LABELS: dict[str, str] = {
    "HIGH": "ÉLEVÉE",
    "MEDIUM": "MOYENNE",
    "LOW": "FAIBLE",
}

# Etat du fournisseur de vulnerabilites.
#
# Chaque libelle dit ce qui s'est passe ET ce qu'on peut en conclure.
# Aucun ne se confond avec « aucune vulnerabilite » : c'est precisement la
# confusion que cette phase s'interdit.
PROVIDER_STATUS_LABELS: dict[str, str] = {
    "available": "Base de vulnérabilités interrogée",
    "partial": "Base interrogée partiellement",
    "disabled": "Vérification désactivée",
    "unavailable": "Base de vulnérabilités injoignable",
    "timeout": "Base de vulnérabilités hors délai",
    "rate_limited": "Base de vulnérabilités saturée (quota atteint)",
    "error": "Base de vulnérabilités en erreur",
}

# Message affiche a l'utilisateur pour chaque etat. Le principe tenu :
# « le fournisseur n'a pas repondu » ne s'ecrit JAMAIS « aucune
# vulnerabilite ». Un etat non concluant produit « impossible de
# verifier », qui invite a reessayer plutot qu'a se rassurer.
PROVIDER_STATUS_MESSAGES: dict[str, str] = {
    "available": (
        "Dépendances comparées à la base de vulnérabilités publique."
    ),
    "partial": (
        "Une partie des dépendances seulement a pu être comparée à la base "
        "de vulnérabilités. Les autres restent non vérifiées."
    ),
    "disabled": (
        "Vérification des vulnérabilités désactivée : les dépendances sont "
        "inventoriées mais non vérifiées. "
        "Activez DEPENDENCY_VULNERABILITY_ENABLED pour les comparer à la "
        "base publique."
    ),
    "unavailable": (
        "Impossible de vérifier les vulnérabilités des dépendances : la "
        "base publique est injoignable. Ce n'est pas un résultat sain, "
        "c'est une absence de résultat."
    ),
    "timeout": (
        "Impossible de vérifier les vulnérabilités des dépendances : la "
        "base publique n'a pas répondu dans le délai imparti."
    ),
    "rate_limited": (
        "Impossible de vérifier les vulnérabilités des dépendances : le "
        "quota d'interrogation de la base publique est atteint. Réessayez "
        "plus tard."
    ),
    "error": (
        "Impossible de vérifier les vulnérabilités des dépendances : la "
        "base publique a répondu une erreur."
    ),
}


def security_category_label(value: Optional[str]) -> str:
    """Libelle d'une famille de finding de securite."""
    if not value:
        return SECURITY_CATEGORY_LABELS["CODE"]
    return SECURITY_CATEGORY_LABELS.get(
        str(value).strip().upper(), str(value).strip().upper()
    )


def confidence_label(value: Optional[str]) -> str:
    return _lookup(CONFIDENCE_LABELS, (value or "MEDIUM").upper(), "MOYENNE")


def provider_status_label(value: Optional[str]) -> str:
    return _lookup(
        PROVIDER_STATUS_LABELS, value or "disabled", "État du fournisseur inconnu"
    )


def provider_status_message(value: Optional[str]) -> str:
    """Phrase affichee a l'utilisateur pour l'etat du fournisseur.

    Repli volontairement pessimiste : un etat inconnu d'une version future
    doit produire « impossible de verifier », jamais un silence qui se
    lirait comme un feu vert.
    """
    return PROVIDER_STATUS_MESSAGES.get(
        value or "disabled",
        "Impossible de vérifier les vulnérabilités des dépendances.",
    )
