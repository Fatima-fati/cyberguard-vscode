"""Contrat de la remediation assistee (phase 7).

Le chemin complet, et qui fait quoi :

    extension  lit le fichier, en extrait quelques lignes EXPURGEES
    backend    verifie l'eligibilite, reexpurge, interroge le modele,
               valide STRICTEMENT la reponse, renvoie une proposition
    extension  revalide, montre un apercu, demande confirmation, applique,
               relance les moteurs deterministes, dit ce qu'ils voient

**Aucun maillon backend n'ecrit un fichier ni un finding.** La proposition
est une description ; seul l'editeur ecrit, apres un clic de l'utilisateur.

Trois types :

- `SecurityFixRequest` : ce que l'extension envoie. Un extrait borne du
  fichier, deja expurge, et l'empreinte du fichier entier — jamais le
  fichier lui-meme ;
- `AiFixSuggestion` : ce que le modele peut repondre. **Strict** :
  `extra="forbid"`, donc un modele qui glisse `severity`, `status`,
  `delete_finding` ou `sql` voit sa reponse entiere rejetee, pas
  simplement nettoyee. Un modele qui tente d'agir hors de son role n'est
  pas un modele a qui l'on fait confiance pour le reste de la reponse ;
- `SecurityFixProposal` : ce que l'extension recoit. La gravite y est
  recopiee du finding, et une proposition indisponible dit pourquoi.
"""

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.ai.schemas import Severity, clean_string_list
from app.ai.security_schemas import AI_DISCLAIMER
from app.paths import clean_relative_path

# Bornes du contrat. Elles sont aussi appliquees par la configuration
# (plus restrictive par defaut) : celles-ci sont le plafond absolu.
MAX_EXCERPT_LINES = 61
MAX_LINE_LENGTH = 500
MAX_REPLACEMENT_LINES = 80
MAX_TEXT = 1500

FIX_DISCLAIMER = (
    "Modification proposée par une IA. Rien n'est appliqué sans votre "
    "confirmation. Relisez-la : après application, ce sont les moteurs de "
    "détection — pas l'IA — qui diront si le problème a disparu."
)

# Champs qu'un modele ne doit jamais renvoyer. Nommes pour que le refus
# dise ce qui a ete tente, plutot qu'une « reponse incomplete » opaque.
FORBIDDEN_MODEL_FIELDS = frozenset(
    {
        "severity",
        "risk_score",
        "status",
        "fixed",
        "resolved",
        "delete",
        "delete_finding",
        "finding_id",
        "sql",
        "query",
        "command",
        "commands",
        "shell",
        "script",
        "file",
        "file_path",
        "path",
    }
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clean_prose(value: Any, limit: int = MAX_TEXT) -> str:
    if value is None:
        return ""
    return " ".join(str(value).split())[:limit]


# --------------------------------------------------------------------------
# Requete de l'extension
# --------------------------------------------------------------------------


class SecurityFixRequest(BaseModel):
    """Demande de correctif pour un finding existant.

    `excerpt_lines` est l'objet meme de la route — comme `content` pour
    `POST /api/code/scan` : un extrait **borne** autour de la ligne visee,
    deja expurge par l'extension, reexpurge ici, et **jamais persiste**.

    `content_hash` est l'empreinte du fichier entier au moment de
    l'extraction. Le backend ne peut pas la verifier — il n'a pas le
    fichier — mais il la renvoie : c'est l'extension qui, avant d'ecrire,
    refuse d'appliquer une proposition a un fichier qui a change.
    """

    file_path: str
    content_hash: str = Field(min_length=8, max_length=128)
    language: str = Field(default="", max_length=40)
    # Ligne sur laquelle porte le correctif. Pour un finding localise, elle
    # doit etre celle du finding. Pour une dependance (ligne 0 cote
    # moteur), c'est la ligne de declaration trouvee par l'extension.
    target_line: int = Field(ge=1)
    excerpt_start_line: int = Field(ge=1)
    excerpt_lines: list[str] = Field(min_length=1, max_length=MAX_EXCERPT_LINES)

    @field_validator("file_path")
    @classmethod
    def check_path(cls, value: str) -> str:
        return clean_relative_path(value)

    @field_validator("excerpt_lines")
    @classmethod
    def bound_lines(cls, value: list[str]) -> list[str]:
        for line in value:
            if "\n" in line or "\r" in line:
                raise ValueError("Une ligne d'extrait ne contient pas de saut de ligne")
            if len(line) > MAX_LINE_LENGTH:
                raise ValueError(
                    f"Ligne d'extrait trop longue (maximum {MAX_LINE_LENGTH})"
                )
        return value

    @model_validator(mode="after")
    def target_inside_excerpt(self) -> "SecurityFixRequest":
        last = self.excerpt_start_line + len(self.excerpt_lines) - 1
        if not self.excerpt_start_line <= self.target_line <= last:
            raise ValueError("La ligne visee doit appartenir a l'extrait transmis")
        return self

    @property
    def excerpt_end_line(self) -> int:
        return self.excerpt_start_line + len(self.excerpt_lines) - 1

    def line(self, number: int) -> str:
        return self.excerpt_lines[number - self.excerpt_start_line]


# --------------------------------------------------------------------------
# Reponse du modele — stricte
# --------------------------------------------------------------------------


class AiFixSuggestion(BaseModel):
    """Ce que le modele peut repondre, et rien d'autre.

    `feasible: false` est une reponse valide : le modele dit qu'aucune
    modification bornee et sure n'existe, et l'extension affiche la
    remediation manuelle. `explanation` reste obligatoire dans les deux cas.
    """

    model_config = ConfigDict(extra="forbid")

    feasible: bool
    explanation: str = Field(min_length=1)
    reason: str = ""
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    replacement_lines: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    manual_steps: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def refuse_forbidden_fields(cls, value: Any) -> Any:
        """Nomme le champ interdit, pour un refus lisible dans le journal."""
        if isinstance(value, dict):
            present = sorted(FORBIDDEN_MODEL_FIELDS & set(value))
            if present:
                raise ValueError(
                    "La reponse porte des champs interdits : " + ", ".join(present)
                )
        return value

    @field_validator("feasible", mode="before")
    @classmethod
    def strict_bool(cls, value: Any) -> bool:
        """Un vrai booleen, rien d'autre.

        « oui », 1 ou "true" sont refuses : une reponse ambigue sur la
        question « peut-on modifier ce fichier ? » est une reponse a
        rejeter, pas a interpreter.
        """
        if not isinstance(value, bool):
            raise ValueError("feasible doit etre un booleen")
        return value

    @field_validator("explanation", "reason", mode="before")
    @classmethod
    def prose(cls, value: Any) -> str:
        return _clean_prose(value)

    @field_validator("start_line", "end_line", mode="before")
    @classmethod
    def strict_line(cls, value: Any) -> Optional[int]:
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("un numero de ligne est un entier")
        return value

    @field_validator("replacement_lines", mode="before")
    @classmethod
    def strict_lines(cls, value: Any) -> list[str]:
        """Liste de chaines, bornee. Une chaine seule est ambigue : refusee."""
        if value is None:
            return []
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ValueError("replacement_lines doit etre une liste de chaines")
        if len(value) > MAX_REPLACEMENT_LINES:
            raise ValueError("remplacement trop long")
        return value

    @field_validator("warnings", "manual_steps", mode="before")
    @classmethod
    def clean_lists(cls, value: Any) -> list[str]:
        return [_clean_prose(item, 400) for item in clean_string_list(value, 8)]


# --------------------------------------------------------------------------
# Reponse a l'extension
# --------------------------------------------------------------------------

FixKind = Literal["security", "code"]


class SecurityFixProposal(BaseModel):
    """Proposition de correctif, ou refus motive.

    `available: false` ne signifie jamais « rien a corriger » : il
    signifie « pas de modification automatique sure », et `refusal` dit
    pourquoi, `manual_steps` quoi faire a la main.
    """

    finding_id: str
    project_uid: str
    kind: FixKind = "security"

    ai_generated: Literal[True] = True
    disclaimer: str = FIX_DISCLAIMER
    model: str = ""
    generated_at: str = Field(default_factory=_now_iso)

    # --- Recopie du finding deterministe ---
    category: str = ""
    deterministic_severity: Severity = "MEDIUM"
    deterministic_title: str = ""

    # --- Proposition ---
    available: bool = False
    refusal: str = ""
    file: str = ""
    # Empreinte recue, renvoyee telle quelle : c'est contre elle que
    # l'extension verifie le fichier avant d'ecrire.
    base_content_hash: str = ""
    start_line: int = 0
    end_line: int = 0
    replacement_lines: list[str] = Field(default_factory=list)

    explanation: str = ""
    reason: str = ""
    warnings: list[str] = Field(default_factory=list)
    manual_steps: list[str] = Field(default_factory=list)
