"""Contrat de l'assistant IA de securite (phase 6).

Ce que cette phase ajoute, et ce qu'elle refuse d'ajouter
---------------------------------------------------------

L'assistant **explique** un `SecurityFinding` deja produit par un moteur
deterministe. Il ne le cree pas, ne le supprime pas, ne le requalifie pas.
Cette frontiere n'est pas tenue par une consigne de prompt — un modele ne
respecte aucune consigne de facon garantie — mais par la **forme des
types** declares ici :

    ce que le modele peut renvoyer     ce qu'il ne peut PAS renvoyer
    ------------------------------     -----------------------------
    une explication                    une gravite
    l'enjeu, en clair                  un score de risque
    l'impact pour ce projet            un statut de finding
    une lecture de la preuve           un identifiant de finding
    une recommandation                 un chemin de fichier
    un exemple securise                une ligne de code du projet
    des concepts lies
    « le contexte est insuffisant »

`AiFindingExplanation` ne declare aucun champ `severity`, `risk_score`,
`status` ni `finding_id`. Un modele qui en renvoie un le voit ignore par
Pydantic : il n'existe aucun chemin de code pour le lire, donc aucun pour
l'ecrire. C'est la raison pour laquelle ces modeles **n'heritent pas** de
`ModelVerdict`, qui porte precisement `severity` et `risk_score` : heriter
aurait ete plus court, et aurait ouvert la porte que cette phase ferme.

La gravite affichee reste celle du moteur : `SecurityFindingAiAnalysis`
la **recopie** du finding persiste (`deterministic_severity`) et ne la
calcule jamais.

Marquage
--------

`ai_generated` est un `Literal[True]` : il ne peut pas etre mis a faux, y
compris par erreur de programmation. `disclaimer` voyage avec chaque
reponse pour que l'interface n'ait pas a rediger sa propre mise en garde —
une phrase ecrite a deux endroits finit par ne plus etre affichee d'un
cote.
"""

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.ai.schemas import Severity, clamp_confidence_value, clean_string_list
from app.project.ai_contract import AiProjectContext

# --------------------------------------------------------------------------
# Mise en garde, definie une seule fois
# --------------------------------------------------------------------------

# Affichee telle quelle par l'extension. Le backend la redige pour qu'il
# n'existe qu'une seule formulation : une mise en garde recopiee cote
# client finit par diverger, ou par disparaitre d'un ecran.
AI_DISCLAIMER = (
    "Explication générée par une IA à partir du signalement produit par "
    "les moteurs de détection. Elle peut être incomplète ou inexacte : "
    "vérifiez-la avant d'agir. La gravité affichée reste celle du moteur "
    "déterministe — l'IA ne la modifie jamais."
)

# Reponse servie quand l'assistant n'a pas de quoi repondre. Le modele est
# invite a la produire lui-meme ; cette constante sert de repli cote
# backend, pour ne jamais afficher une explication vide qui passerait pour
# « rien a signaler ».
INSUFFICIENT_CONTEXT_MESSAGE = (
    "Le contexte disponible ne suffit pas pour répondre de façon fiable."
)

MAX_TEXT_LENGTH = 2000
MAX_LIST_ITEMS = 8
MAX_EXAMPLE_LENGTH = 1200
MAX_QUESTION_LENGTH = 1000
MAX_CHAT_TURN_LENGTH = 1200


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_flag(value: Any) -> bool:
    """« true », « oui », 1 : un modele ecrit un booleen a sa facon.

    Le doute profite a la prudence : une valeur illisible vaut « contexte
    insuffisant » plutot que « contexte suffisant ». Une seule definition,
    partagee par les trois sorties de modele de cette phase — trois
    lectures du meme booleen finiraient par differer, et c'est la plus
    optimiste qui deciderait.
    """
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in {"true", "1", "oui", "yes"}


def _clean_text(value: Any, limit: int = MAX_TEXT_LENGTH) -> str:
    """Texte de modele normalise : jamais `None`, jamais sans borne."""
    if value is None:
        return ""
    text = " ".join(str(value).split())
    return text[:limit]


# --------------------------------------------------------------------------
# Ce que le modele recoit — la frontiere
# --------------------------------------------------------------------------


class AiFindingDigest(BaseModel):
    """Un finding reduit a ce qu'un modele a besoin d'en savoir.

    Enumeration explicite, jamais une copie de `SecurityFinding` : un
    champ ajoute demain au finding n'atteint pas le prompt par accident.
    Meme discipline que `app.project.ai_contract`, et pour la meme raison.

    Ce qui est volontairement absent :

    - `project_uid` et `id` — des identifiants internes ; le modele n'en
      fait rien et les citerait dans sa reponse ;
    - `status` et `created_at` — l'assistant explique un probleme, il ne
      commente pas le cycle de vie d'une ligne en base ;
    - le contenu du fichier — `evidence` est une preuve **expurgee et
      bornee**, et c'est tout ce qui traverse.

    `file` est un chemin **relatif** a la racine du projet. Il traverse
    parce que l'impact contextuel en depend (« dans un fichier de
    configuration » n'est pas « dans un test ») et parce que
    l'utilisateur le voit deja a l'ecran. Un chemin absolu, lui, revele le
    nom de l'utilisateur et l'arborescence du poste : il n'existe nulle
    part dans ce modele.
    """

    category: str
    # Gravite du moteur, transmise comme **contexte en lecture seule**.
    # Le modele la commente, ne la remplace pas : rien dans sa reponse ne
    # peut revenir ici.
    severity: str
    confidence: str
    title: str = ""
    description: str = ""
    file: Optional[str] = None
    line: int = 0
    # Preuve deja expurgee par `app.security.redaction`, reexpurgee avant
    # l'envoi par `app.ai.security_context`.
    evidence: str = ""
    # Remediation deterministe, quand le moteur en fournit une : le modele
    # doit pouvoir l'enrichir plutot que d'en inventer une concurrente.
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    detection_engine: str = ""


class AiFindingCounts(BaseModel):
    """Volumes du projet. Des nombres, jamais des chemins ni des preuves."""

    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    by_category: dict[str, int] = Field(default_factory=dict)


class AiSecurityContext(BaseModel):
    """Tout ce qui est envoye au modele, et rien d'autre.

    Un seul type pour les trois usages (explication, resume, chat) : trois
    contextes distincts auraient trois frontieres a verifier, et la plus
    permissive des trois aurait decide de ce qui sort.

    `project` vaut `None` quand le projet n'a jamais ete indexe. Ce n'est
    pas une erreur : l'assistant doit alors dire qu'il ignore le contexte
    du projet, pas l'inventer.
    """

    project: Optional[AiProjectContext] = None
    # Le finding a expliquer. `None` pour un resume ou une question
    # generale.
    finding: Optional[AiFindingDigest] = None
    # Findings voisins ou selectionnes, deja bornes par la configuration.
    findings: list[AiFindingDigest] = Field(default_factory=list)
    counts: AiFindingCounts = Field(default_factory=AiFindingCounts)
    # Vrai quand tous les findings du projet n'ont pas tenu dans le
    # contexte. Une couverture partielle se dit au modele comme a
    # l'utilisateur : sans cela une reponse rassurante serait fausse.
    truncated: bool = False
    # Etat du fournisseur de vulnerabilites, repris tel quel. Le modele
    # doit pouvoir dire « les dependances n'ont pas pu etre verifiees »
    # plutot que « aucune vulnerabilite ».
    vulnerability_check_conclusive: bool = False
    vulnerability_provider_status: str = "disabled"


# --------------------------------------------------------------------------
# Ce que le modele renvoie
# --------------------------------------------------------------------------


class AiFindingExplanation(BaseModel):
    """Explication d'un finding, telle que le modele la produit.

    Aucun champ decisionnel : ni gravite, ni score, ni statut, ni
    identifiant. Un modele qui en renverrait un le voit ignore — c'est la
    garantie structurelle de cette phase, et un test le verifie sur
    `model_fields`.
    """

    model_config = ConfigDict(extra="ignore")

    # Obligatoire, et non vide. Une explication sans explication n'est pas
    # une reponse incomplete a rattraper : c'est une reponse inexploitable,
    # et `run_model` la transforme en erreur plutot qu'en fiche vide qui se
    # lirait « rien a signaler ». Meme quand le contexte est insuffisant, le
    # modele doit ECRIRE qu'il l'est.
    explanation: str = Field(min_length=1)
    why_it_matters: str = ""
    project_impact: str = ""
    evidence_interpretation: str = ""
    # Recommandation redigee. Elle s'ajoute a la remediation deterministe,
    # elle ne la remplace pas dans la base.
    recommendation: str = ""
    remediation_steps: list[str] = Field(default_factory=list)
    # Exemple de code ou de configuration securise. Vide est une reponse
    # acceptable : tous les problemes ne s'illustrent pas par un extrait.
    secure_example: str = ""
    secure_example_language: str = ""
    related_concepts: list[str] = Field(default_factory=list)
    # Formulation courte, destinee a un developpeur presse.
    developer_summary: str = ""
    # Le modele declare lui-meme qu'il manque d'elements. C'est une
    # reponse valide, et l'interface l'affiche comme telle.
    insufficient_context: bool = False
    missing_information: list[str] = Field(default_factory=list)
    confidence: float = 0.0

    @field_validator("confidence", mode="before")
    @classmethod
    def clamp_confidence(cls, value: Any) -> float:
        return clamp_confidence_value(value)

    @field_validator("insufficient_context", mode="before")
    @classmethod
    def read_flag(cls, value: Any) -> bool:
        return _read_flag(value)

    @field_validator(
        "explanation",
        "why_it_matters",
        "project_impact",
        "evidence_interpretation",
        "recommendation",
        "developer_summary",
        mode="before",
    )
    @classmethod
    def clean_prose(cls, value: Any) -> str:
        return _clean_text(value)

    @field_validator("secure_example", mode="before")
    @classmethod
    def clean_example(cls, value: Any) -> str:
        """L'exemple garde ses sauts de ligne : c'est du code.

        Seule la borne s'applique. Un exemple tronque reste lisible ;
        un exemple sans borne ferait grossir l'affichage sans fin.
        """
        if value is None:
            return ""
        return str(value)[:MAX_EXAMPLE_LENGTH]

    @field_validator("secure_example_language", mode="before")
    @classmethod
    def clean_language(cls, value: Any) -> str:
        return _clean_text(value, 30).lower()

    @field_validator(
        "remediation_steps", "related_concepts", "missing_information", mode="before"
    )
    @classmethod
    def clean_lists(cls, value: Any) -> list[str]:
        return clean_string_list(value, MAX_LIST_ITEMS)


class AiFindingsSummary(BaseModel):
    """Resume de plusieurs findings, tel que le modele le produit.

    `priority_order` cite des **titres** de findings, jamais des
    identifiants ni des gravites : l'ordre suggere par le modele est un
    avis de lecture, pas une requalification. La gravite affichee reste
    celle des moteurs.
    """

    model_config = ConfigDict(extra="ignore")

    # Obligatoire et non vide, comme `AiFindingExplanation.explanation`.
    summary: str = Field(min_length=1)
    themes: list[str] = Field(default_factory=list)
    relationships: list[str] = Field(default_factory=list)
    priority_order: list[str] = Field(default_factory=list)
    insufficient_context: bool = False
    missing_information: list[str] = Field(default_factory=list)

    @field_validator("summary", mode="before")
    @classmethod
    def clean_prose(cls, value: Any) -> str:
        return _clean_text(value)

    @field_validator("insufficient_context", mode="before")
    @classmethod
    def read_flag(cls, value: Any) -> bool:
        return _read_flag(value)

    @field_validator(
        "themes", "relationships", "priority_order", "missing_information", mode="before"
    )
    @classmethod
    def clean_lists(cls, value: Any) -> list[str]:
        return clean_string_list(value, MAX_LIST_ITEMS)


class AiChatAnswer(BaseModel):
    """Reponse du modele a une question sur la securite du projet."""

    model_config = ConfigDict(extra="ignore")

    # Obligatoire et non vide : une reponse vide affichee dans un chat se
    # lirait « il n'y a rien a dire », ce qui n'est pas la meme chose que
    # « le modele n'a rien renvoye ».
    answer: str = Field(min_length=1)
    insufficient_context: bool = False
    missing_information: list[str] = Field(default_factory=list)
    related_concepts: list[str] = Field(default_factory=list)

    @field_validator("answer", mode="before")
    @classmethod
    def clean_prose(cls, value: Any) -> str:
        return _clean_text(value)

    @field_validator("insufficient_context", mode="before")
    @classmethod
    def read_flag(cls, value: Any) -> bool:
        return _read_flag(value)

    @field_validator("missing_information", "related_concepts", mode="before")
    @classmethod
    def clean_lists(cls, value: Any) -> list[str]:
        return clean_string_list(value, MAX_LIST_ITEMS)


# --------------------------------------------------------------------------
# Ce que l'extension recoit
# --------------------------------------------------------------------------


class SecurityFindingAiAnalysis(BaseModel):
    """Explication IA d'un finding, prete a etre affichee.

    Les champs `deterministic_*` sont **recopies** du finding persiste.
    Ils ne sont jamais recalcules, et aucun champ de la reponse du modele
    ne les alimente : c'est ce qui rend verifiable l'affirmation « l'IA ne
    modifie pas la gravite ».
    """

    finding_id: str
    project_uid: str

    # --- Marquage ------------------------------------------------------
    # `Literal[True]` : la marque ne peut pas etre retiree, meme par
    # erreur de programmation.
    ai_generated: Literal[True] = True
    disclaimer: str = AI_DISCLAIMER
    model: str = ""
    analyzed_at: str = Field(default_factory=_now_iso)
    # Servie depuis le cache : aucun appel au modele n'a eu lieu.
    cached: bool = False

    # --- Recopie du finding deterministe -------------------------------
    category: str = ""
    deterministic_severity: Severity = "MEDIUM"
    deterministic_confidence: str = "MEDIUM"
    deterministic_title: str = ""
    deterministic_remediation: str = ""
    detection_engine: str = ""
    file: Optional[str] = None
    line: int = 0

    # --- Ce que le modele a produit ------------------------------------
    explanation: str = ""
    why_it_matters: str = ""
    project_impact: str = ""
    evidence_interpretation: str = ""
    recommendation: str = ""
    remediation_steps: list[str] = Field(default_factory=list)
    secure_example: str = ""
    secure_example_language: str = ""
    related_concepts: list[str] = Field(default_factory=list)
    developer_summary: str = ""
    insufficient_context: bool = False
    missing_information: list[str] = Field(default_factory=list)
    confidence: float = 0.0

    # --- Couverture ----------------------------------------------------
    # Dit au lecteur sur quoi l'explication s'appuie. Sans ces deux
    # champs, une explication produite sans contexte de projet serait
    # indiscernable d'une explication informee.
    project_context_available: bool = False
    related_findings_considered: int = 0


class SecurityFindingsAiSummary(BaseModel):
    """Resume IA de plusieurs findings d'un meme projet."""

    project_uid: str
    ai_generated: Literal[True] = True
    disclaimer: str = AI_DISCLAIMER
    model: str = ""
    analyzed_at: str = Field(default_factory=_now_iso)

    summary: str = ""
    themes: list[str] = Field(default_factory=list)
    relationships: list[str] = Field(default_factory=list)
    priority_order: list[str] = Field(default_factory=list)
    insufficient_context: bool = False
    missing_information: list[str] = Field(default_factory=list)

    # Couverture : combien de findings ont ete lus, combien existent.
    # L'ecart est la zone d'ombre, et il est annonce.
    findings_considered: int = 0
    findings_available: int = 0
    truncated: bool = False
    severity_counts: AiFindingCounts = Field(default_factory=AiFindingCounts)
    project_context_available: bool = False


class SecurityAiSummaryRequest(BaseModel):
    """Selection de findings a resumer.

    Liste vide = tous les findings ouverts du projet, bornes cote serveur.
    C'est le cas d'usage courant (« explique-moi l'ensemble »), et la borne
    appartient au backend : un client d'une autre version ne doit pas
    pouvoir faire grossir le prompt en demandant tout.
    """

    finding_ids: list[str] = Field(default_factory=list, max_length=200)


class SecurityChatTurn(BaseModel):
    """Un tour de conversation, tel que l'extension le renvoie."""

    role: Literal["user", "assistant"]
    # « message » et non « content » : le contrat reserve les noms de la
    # famille « content » au contenu de fichier, que rien ici ne porte.
    message: str = Field(default="", max_length=MAX_CHAT_TURN_LENGTH)


class SecurityChatRequest(BaseModel):
    """Question posee sur la securite du projet ouvert.

    L'historique est fourni par le client et **borne par le backend** :
    une conversation sans limite ferait grossir le prompt sans fin, et
    rien ne garantit qu'un client d'une autre version respecte la borne.
    """

    question: str = Field(min_length=1, max_length=MAX_QUESTION_LENGTH)
    history: list[SecurityChatTurn] = Field(default_factory=list)
    # Restreint la question a un finding precis, quand la conversation
    # part de la fiche d'un signalement.
    finding_id: Optional[str] = Field(default=None, max_length=64)


class SecurityChatResponse(BaseModel):
    """Reponse a une question, marquee comme generee par une IA."""

    project_uid: str
    ai_generated: Literal[True] = True
    disclaimer: str = AI_DISCLAIMER
    model: str = ""
    answered_at: str = Field(default_factory=_now_iso)

    # Question telle qu'elle a ete transmise au modele : **expurgee**.
    # L'interface affiche celle-ci, pas celle qu'elle a envoyee : c'est
    # ainsi que l'utilisateur voit qu'un secret colle par megarde a ete
    # masque avant de sortir.
    question: str = ""
    answer: str = ""
    insufficient_context: bool = False
    missing_information: list[str] = Field(default_factory=list)
    related_concepts: list[str] = Field(default_factory=list)

    findings_considered: int = 0
    findings_available: int = 0
    truncated: bool = False
    project_context_available: bool = False
    history_turns_used: int = 0


class SecurityAiHealth(BaseModel):
    """Ce que l'assistant de securite sait faire, ici et maintenant.

    Consultee par l'extension **avant** d'offrir le moindre bouton IA :
    annoncer une capacite qui repondra 503 coute plus cher que de ne rien
    annoncer.
    """

    status: str = "ok"
    # Utilisable des maintenant ? Un seul booleen a lire cote client, pour
    # qu'aucun chemin de code n'ait a recomposer la condition.
    available: bool = False
    chat_available: bool = False
    # Phase 7 : la remediation assistee (proposition de correctif) est-elle
    # disponible ? Elle s'appuie sur l'assistant et a son propre reglage.
    fix_available: bool = False
    # Les trois raisons possibles d'une indisponibilite, separees : le
    # remede differe.
    provider_configured: bool = False
    assistant_enabled: bool = False
    chat_enabled: bool = False
    # Vide quand l'assistant est indisponible : annoncer un modele qui ne
    # sera pas appele serait faux.
    model: str = ""
    # Phrase prete a afficher. Jamais « aucun probleme » : « indisponible ».
    reason: str = ""
    disclaimer: str = AI_DISCLAIMER
    max_context_findings: int = 0
    # Rappels explicites, verifies par des tests sur le code source.
    modifies_findings: Literal[False] = False
    modifies_severity: Literal[False] = False
    requires_wazuh: Literal[False] = False
