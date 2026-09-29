"""Ce qu'une couche IA pourra recevoir du contexte de projet — et pas plus.

**L'assistant IA n'existe pas encore.** Ce module ne l'implemente pas : il
fixe, des maintenant, la frontiere de ce qui pourra sortir vers un modele.
La raison d'ecrire ce contrat en avance est simple : quand l'assistant
arrivera, la tentation sera de lui passer « tout le contexte, ce sera plus
pratique ». Un type qui ne peut pas porter un secret rend cette facilite
impossible.

Frontiere retenue
-----------------

Passe au modele                     Ne passe jamais
---------------                     ---------------
langages et proportions             chemin absolu du workspace
frameworks et leur preuve           root_hash (identifiant interne)
types de projet                     chemins des fichiers sensibles
volumes et couverture               contenu de fichier, meme un extrait
presence d'un depot Git             hote du remote Git
                                    valeur d'un secret, empreinte incluse

Sur les chemins de fichiers sensibles : `security_sensitive_files` est
utile a l'utilisateur, qui sait ou est son `.env`. Il n'apporte rien a un
modele et transformerait le prompt en carte des fichiers a lire. Seul le
**nombre** traverse.

Les phases ulterieures ajouteront des briques a ce contexte (findings,
dependances, changements Git, endpoints). Chacune devra etendre ce contrat
explicitement, avec le meme critere : *ce champ est-il necessaire pour que
le modele explique un finding ?* Si la reponse est non, il reste dehors.
"""

from typing import Optional

from pydantic import BaseModel, Field

from app.project.schemas import ProjectSecurityContext


class AiFrameworkHint(BaseModel):
    """Framework et sa preuve, sans le chemin du fichier qui l'atteste.

    La preuve est conservee parce qu'elle aide le modele a nuancer
    (« declare dans un manifeste » n'est pas « utilise dans le code »).
    Le chemin, lui, ne sert qu'a l'utilisateur.
    """

    framework: str
    evidence: str
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class AiProjectContext(BaseModel):
    """Projection du contexte de projet destinee a un futur prompt.

    Construite exclusivement par `build_ai_project_context()`. Aucun champ
    libre : ajouter une information au prompt demande d'ajouter un champ
    ici, donc de le decider.
    """

    project_name: str
    project_types: list[str] = Field(default_factory=list)
    primary_language: Optional[str] = None
    # Langage -> part en pourcentage. Le nombre de fichiers n'apporte rien
    # de plus au modele que la proportion.
    language_shares: dict[str, int] = Field(default_factory=dict)
    frameworks: list[AiFrameworkHint] = Field(default_factory=list)

    indexed_file_count: int = 0
    source_file_count: int = 0
    # Nombre seul : jamais les chemins. Permet au modele de dire « ce
    # projet contient 3 fichiers sensibles » sans savoir lesquels.
    sensitive_file_count: int = 0
    # Une couverture partielle doit etre dite au modele comme a
    # l'utilisateur : sans elle, une reponse rassurante serait fausse.
    index_truncated: bool = False

    git_repository_detected: bool = False


def build_ai_project_context(context: ProjectSecurityContext) -> AiProjectContext:
    """Reduit un contexte complet a ce qu'un modele peut recevoir.

    Enumeration explicite champ par champ, jamais une copie du modele
    source : un champ ajoute demain a `ProjectSecurityContext` n'atteint
    pas le prompt par accident.
    """
    return AiProjectContext(
        project_name=context.project_name,
        project_types=list(context.project_types),
        primary_language=context.primary_language,
        language_shares={item.language: item.share for item in context.languages},
        frameworks=[
            AiFrameworkHint(
                framework=item.framework,
                evidence=item.evidence,
                confidence=item.confidence,
            )
            for item in context.frameworks
        ],
        indexed_file_count=context.file_statistics.indexed,
        source_file_count=context.file_statistics.source,
        sensitive_file_count=context.file_statistics.sensitive,
        index_truncated=context.file_statistics.truncated,
        git_repository_detected=context.git_repository_detected,
    )
