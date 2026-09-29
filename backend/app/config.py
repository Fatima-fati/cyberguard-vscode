"""Configuration de l'application, chargee depuis backend/.env."""

from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"


class Settings(BaseSettings):

    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Application ---
    app_name: str = "Wazuh Supervision"
    # Interface d'ecoute par defaut : la boucle locale. Le backend detient
    # des identifiants et diffuse des extraits de code ; l'exposer au
    # reseau doit etre une decision, pas un defaut. Voir docs/SECURITY.md
    # (« mode developpement local » contre « deploiement distant »).
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    cors_origins: str = "http://localhost:5173"

    # --- Authentification locale de l'extension ---
    # Le backend n'a qu'un appelant legitime : l'extension de cet
    # utilisateur. Un jeton local partage suffit a ecarter les autres
    # processus de la machine. Active par defaut : le desactiver est un
    # choix explicite, annonce au demarrage.
    agent_auth_enabled: bool = True
    # Jeton impose par l'environnement (conteneur, service gere). Vide =
    # le backend genere le sien et l'ecrit dans `agent_token_path`.
    agent_auth_token: str = ""
    # Emplacement du fichier de jeton. Vide = ~/.wazuh-security/agent-token,
    # donc hors du depot : un secret range dans le projet finit commite.
    agent_token_path: str = ""

    # --- Wazuh Manager API ---
    wazuh_api_url: str = "https://localhost:55000"
    wazuh_api_user: str = "wazuh-wui"
    wazuh_api_password: str = ""

    # --- Enrolement des agents (ajout d'un serveur) ---
    # Adresse que les agents utilisent pour joindre le manager. Elle est
    # independante de WAZUH_API_URL (qui ne sert qu'a l'API REST, port 55000)
    # et n'en est JAMAIS deduite : une URL d'API en 127.0.0.1 est normale,
    # alors qu'un agent distant ne peut rien en faire. Vide = fonctionnalite
    # "Ajouter un serveur" desactivee, avec une erreur explicite.
    wazuh_manager_address: str = Field(
        default="",
        validation_alias=AliasChoices("WAZUH_MANAGER_ADDRESS", "WAZUH_MANAGER_URL"),
    )
    wazuh_enrollment_port: int = Field(default=1515, ge=1, le=65535)
    wazuh_agent_port: int = Field(default=1514, ge=1, le=65535)
    # Version et depot des paquets agent : centralises ici, jamais en dur
    # dans les instructions generees.
    wazuh_agent_version: str = "4.14.6"
    wazuh_packages_base_url: str = "https://packages.wazuh.com/4.x"

    # --- Wazuh Indexer (alertes) ---
    indexer_url: str = "https://localhost:9200"
    indexer_user: str = "admin"
    indexer_password: str = ""
    indexer_index: str = "wazuh-alerts-4.x-*"

    # --- TLS ---
    verify_ssl: bool = False

    # --- Reseau ---
    connect_timeout_seconds: float = 5.0
    request_timeout_seconds: float = 15.0
    agents_limit: int = 500
    # Marge de securite avant expiration du JWT (renouvellement anticipe).
    token_leeway_seconds: int = 60
    # Duree de repli si le JWT n'expose pas de date d'expiration.
    token_default_ttl_seconds: int = 900

    # --- Surveillance ---
    # POLL_INTERVAL (ou POLL_INTERVAL_SECONDS) dans le .env
    poll_interval: int = Field(
        default=10,
        ge=1,
        validation_alias=AliasChoices("POLL_INTERVAL", "POLL_INTERVAL_SECONDS"),
    )
    alert_fetch_size: int = 50
    critical_level: int = 10
    # Niveau a partir duquel le navigateur affiche une notification systeme.
    # Transmis au frontend par GET /api/config.
    notify_level: int = Field(
        default=10,
        ge=0,
        le=15,
        validation_alias=AliasChoices("NOTIFY_LEVEL", "NOTIFY_FROM_LEVEL"),
    )
    # Delai minimal (secondes) entre deux notifications navigateur pour un
    # meme couple agent + regle, afin d'eviter les rafales.
    notify_cooldown: int = Field(default=300, ge=0)
    # Chevauchement temporel : on re-interroge un peu avant le curseur pour
    # ne perdre aucune alerte arrivee en retard dans l'Indexer.
    poll_overlap_seconds: int = 30
    # Fenetre consultee au tout premier demarrage (aucun curseur en base).
    initial_lookback_seconds: int = 300
    # Nombre d'identifiants gardes en memoire pour le dedoublonnage rapide.
    dedupe_cache_size: int = 2000

    # --- Agent IA (OpenAI) ---
    # La cle reste cote backend : elle n'est jamais renvoyee au frontend
    # ni journalisee.
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    openai_base_url: str = "https://api.openai.com/v1"
    openai_timeout_seconds: float = 30.0
    openai_max_output_tokens: int = 900
    # Analyse automatique des nouvelles alertes par le poller
    ai_analysis_enabled: bool = False
    # Niveau Wazuh minimum pour declencher une analyse automatique
    ai_analysis_min_level: int = Field(default=7, ge=0, le=15)
    # Analyses simultanees maximum (protege le cout et l'API)
    ai_max_concurrency: int = Field(default=2, ge=1, le=10)
    # Fenetre (heures) utilisee pour mesurer la repetition d'une alerte
    ai_repetition_window_hours: int = Field(default=24, ge=1)

    # --- Notifications IA (alertes HIGH / CRITICAL) ---
    ai_high_notification_enabled: bool = True
    ai_critical_notification_enabled: bool = True
    # Delai minimal entre deux notifications pour un meme couple
    # serveur + type d'incident (secondes)
    ai_notification_cooldown: int = Field(default=300, ge=0)

    # --- Remediation assistee ---
    ai_remediation_enabled: bool = True
    # Une correction n'est JAMAIS appliquee sans confirmation explicite.
    # Passer ce reglage a false n'est pas supporte : il est lu, mais le
    # backend refuse malgre tout d'appliquer sans confirmation.
    ai_remediation_require_confirmation: bool = True
    ai_remediation_backup: bool = True
    ai_remediation_max_file_size: int = Field(default=1_000_000, ge=1024)
    # Racine autorisee pour l'ecriture. Vide = aucune ecriture possible :
    # le backend ne peut pas modifier un fichier situe sur une machine
    # distante, il refuse alors proprement au lieu de faire semblant.
    ai_remediation_root: str = ""

    # --- Analyse de code (extension VS Code) ---
    # Detection deterministe : active par defaut, ne coute rien et ne
    # depend d'aucun service externe.
    code_analysis_enabled: bool = True
    # Enrichissement IA des findings. FAUX en phase 1 : aucun appel a
    # OpenAI n'est effectue depuis l'analyse de code.
    code_ai_enrichment_enabled: bool = False
    # Taille maximale du contenu accepte par POST /api/code/scan.
    code_max_content_bytes: int = Field(default=400_000, ge=1024)
    # Plafond de findings par scan : borne le cout et le bruit.
    code_max_findings_per_scan: int = Field(default=100, ge=1, le=1000)
    # Nombre maximum de findings renvoyes par GET /api/code/findings.
    code_findings_page_size: int = Field(default=100, ge=1, le=500)

    # --- Decouverte de projet (phase 1) ---
    # Plafond de fichiers indexes pour un projet. Au-dela, l'index est
    # tronque et la troncature est **annoncee** : afficher une couverture
    # partielle comme complete serait un mensonge de securite.
    project_max_indexed_files: int = Field(default=20_000, ge=100, le=200_000)
    # Nombre maximum de fichiers importants / sensibles / manifestes
    # remontes dans le contexte. Borne la taille de la reponse.
    project_max_listed_files: int = Field(default=200, ge=10, le=2000)
    # Version du format de decouverte. Un contexte produit par une version
    # anterieure est rejoue plutot que lu de travers.
    project_discovery_version: str = "1.0.0"

    # --- Securite projet (phase 2) : secrets et dependances ---
    #
    # Aucun de ces reglages ne touche a Wazuh : la detection de secrets,
    # l'inventaire des dependances et l'analyse de vulnerabilites
    # fonctionnent avec Wazuh completement arrete ou absent.

    # Reception des balayages de secrets soumis par l'extension. La
    # detection elle-meme tourne sur le poste du developpeur : le backend
    # ne lit jamais son disque.
    secret_detection_enabled: bool = True
    # Plafond de secrets enregistres pour un projet. Au-dela, le decompte
    # est un minorant et la troncature est annoncee.
    secret_max_findings: int = Field(default=500, ge=10, le=5000)

    # Reception des analyses de securite d'API soumises par l'extension.
    # Meme principe que les secrets : la detection tourne sur le poste,
    # le backend recoit des constats.
    api_security_enabled: bool = True
    # Plafond de signalements d'API enregistres pour un projet.
    api_max_findings: int = Field(default=500, ge=10, le=5000)

    # Inventaire des dependances soumis par l'extension.
    dependency_inventory_enabled: bool = True
    project_max_dependencies: int = Field(default=3000, ge=50, le=50_000)

    # Interrogation d'une base publique de vulnerabilites.
    #
    # C'est la SEULE sortie reseau de la securite projet. Ce qui sort se
    # limite a un nom de paquet, son ecosysteme et sa version — ce qu'un
    # registre public connait deja. Mettre ce reglage a false conserve
    # l'inventaire et affiche « verification desactivee », jamais « aucune
    # vulnerabilite » : une absence de resultat ne doit pas se lire comme
    # un feu vert.
    dependency_vulnerability_enabled: bool = True
    vulnerability_provider: str = "osv"
    osv_api_url: str = "https://api.osv.dev"
    osv_timeout_seconds: float = Field(default=12.0, ge=1.0, le=120.0)
    # Paquets interroges en une passe. Au-dela, le resultat est annonce
    # partiel plutot que presente comme complet.
    osv_max_packages: int = Field(default=1000, ge=10, le=10_000)
    # Vulnerabilites decrites en detail. Un projet qui en tirerait des
    # milliers ne doit pas produire des milliers de requetes.
    osv_max_vulnerability_details: int = Field(default=80, ge=5, le=500)

    # --- Assistant IA de securite (phase 6) ---
    #
    # L'assistant EXPLIQUE des findings deja produits par les moteurs
    # deterministes. Il n'en cree aucun, n'en supprime aucun, et ne touche
    # pas a leur gravite : aucune route de cette phase n'ecrit dans
    # `security_findings`, et un test le verifie sur le code source.
    #
    # Trois interrupteurs independants, et c'est voulu :
    #   * OPENAI_API_KEY vide      -> aucun assistant, le reste fonctionne ;
    #   * SECURITY_AI_ASSISTANT_ENABLED=false -> assistant coupe, cle presente ;
    #   * SECURITY_AI_CHAT_ENABLED=false      -> explications oui, chat non.
    security_ai_assistant_enabled: bool = True
    security_ai_chat_enabled: bool = True
    # Findings joints au contexte envoye au modele. Borne le cout et la
    # surface : au-dela, le contexte est annonce tronque plutot que
    # presente comme complet.
    security_ai_max_context_findings: int = Field(default=25, ge=1, le=200)
    # Findings « voisins » joints a l'explication d'un finding precis
    # (meme fichier ou meme categorie). Sert a la mise en relation.
    security_ai_max_related_findings: int = Field(default=5, ge=0, le=25)
    # Tours de conversation conserves dans le chat. Au-dela, les plus
    # anciens sont abandonnes : un historique sans borne ferait grossir le
    # prompt sans fin.
    security_ai_chat_history_turns: int = Field(default=6, ge=0, le=30)

    # --- Remediation assistee (phase 7) ---
    #
    # L'assistant PROPOSE une modification bornee d'un fichier ; il ne
    # l'applique jamais. L'extension montre un apercu, demande une
    # confirmation explicite, applique, puis relance les moteurs
    # deterministes : c'est leur verdict, pas celui de l'IA, qui dit si le
    # probleme a disparu. Aucune route de cette phase n'ecrit un fichier ni
    # un finding.
    security_ai_fix_enabled: bool = True
    # Lignes de contexte transmises de part et d'autre de la ligne visee.
    security_ai_fix_context_lines: int = Field(default=8, ge=1, le=30)
    # Plage maximale que le correctif peut remplacer, en lignes.
    security_ai_fix_max_range_lines: int = Field(default=10, ge=1, le=40)
    # Lignes maximales du texte de remplacement.
    security_ai_fix_max_replacement_lines: int = Field(default=20, ge=1, le=80)

    # --- Posture et CI/CD (phase 8) ---
    #
    # Politique appliquee par `POST /api/project/{uid}/ci-check` quand la
    # requete ne precise rien. `warn` par defaut : un controle qui bloque
    # un pipeline sans qu'on le lui ait demande est retire, pas corrige.
    # Aucune de ces valeurs ne fait intervenir l'IA ni Wazuh.
    ci_policy_mode: str = "warn"
    # Conditions separees par des virgules. Voir
    # `app.security.posture_schemas.CI_CONDITIONS`.
    ci_fail_on: str = (
        "critical_findings,high_findings,secrets_present,vulnerable_dependencies"
    )
    ci_warn_on: str = (
        "analysis_incomplete,vulnerability_provider_unavailable,unsupported_languages"
    )

    # --- Temps reel (SSE) ---
    # Intervalle des battements de coeur envoyes aux clients connectes
    sse_heartbeat_seconds: int = 15
    # Taille de la file par client : au-dela, les evenements les plus vieux
    # sont abandonnes plutot que de bloquer le poller
    sse_queue_size: int = 100
    # Nombre maximum de navigateurs connectes simultanement
    sse_max_clients: int = 50
    # Delai de reconnexion suggere au navigateur (millisecondes)
    sse_retry_ms: int = 3000
    # Nombre maximum d'alertes rejouees apres une reconnexion
    sse_replay_limit: int = 50

    # --- Base de donnees ---
    database_path: str = str(DATA_DIR / "alerts.db")

    # --- Notifications e-mail ---
    email_enabled: bool = False
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    email_from: str = ""
    email_to: str = ""

    # --- Notifications Discord ---
    discord_enabled: bool = False
    discord_webhook_url: str = ""

    @property
    def remediation_root_path(self) -> Optional[Path]:
        """Racine autorisee pour les corrections, si elle est configuree."""
        if not self.ai_remediation_root.strip():
            return None
        return Path(self.ai_remediation_root.strip()).resolve()

    @property
    def ai_enabled(self) -> bool:
        """L'agent IA est utilisable des qu'une cle API est configuree."""
        return bool(self.openai_api_key.strip())

    @property
    def security_ai_available(self) -> bool:
        """L'assistant de securite est-il utilisable ici et maintenant ?

        Deux conditions, toutes deux necessaires : un fournisseur
        configure (`ai_enabled`) et l'activation explicite de l'assistant.
        Une seule des deux qui manque suffit a repondre « indisponible » —
        jamais « aucun probleme », jamais une explication inventee.
        """
        return self.ai_enabled and self.security_ai_assistant_enabled

    @property
    def security_ai_chat_available(self) -> bool:
        """Le chat de securite est-il utilisable ?

        Le chat s'appuie sur l'assistant : le couper ne laisse pas un chat
        orphelin.
        """
        return self.security_ai_available and self.security_ai_chat_enabled

    @property
    def manager_address(self) -> str:
        """Adresse du manager annoncee aux agents, telle que configuree.

        Aucune valeur de repli : renvoie une chaine vide tant que
        WAZUH_MANAGER_ADDRESS n'est pas renseigne. Deduire l'adresse de
        WAZUH_API_URL produirait un 127.0.0.1 inutilisable depuis un serveur
        distant ; la validation de `app.server_provisioning` prefere une
        erreur claire a une commande fausse.
        """
        return self.wazuh_manager_address.strip()

    @property
    def cors_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def binds_loopback_only(self) -> bool:
        """L'ecoute est-elle limitee a la machine locale ?

        Sert au message de demarrage : un backend joignable depuis le
        reseau est un choix legitime en deploiement, mais il doit etre
        visible dans les journaux, pas decouvert apres coup.
        """
        host = self.api_host.strip().strip("[]").lower()
        return host in {"127.0.0.1", "localhost", "::1"} or host.startswith("127.")


@lru_cache
def get_settings() -> Settings:
    """Instance unique des reglages (mise en cache)."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return Settings()


settings = get_settings()
