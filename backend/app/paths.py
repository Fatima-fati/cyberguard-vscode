"""Validation des chemins relatifs soumis par l'extension.

Extrait ici parce que deux contrats en dependent — le contexte de projet
(`app.project.schemas`) et les findings de securite
(`app.security.schemas`) — et qu'une regle de securite dupliquee finit par
diverger. Un module sans aucune dependance : il peut donc etre importe des
deux cotes sans creer de cycle.

Trois refus, pour trois raisons distinctes :

- **chemin absolu** : il revelerait l'arborescence du poste, que le backend
  n'a aucune raison de connaitre ;
- **segment `..`** : une remontee n'a pas de sens dans un index dont la
  racine est le projet, et c'est le motif classique de traversee ;
- **chemin vide** : un chemin vide n'identifie rien.
"""

MAX_PATH_LENGTH = 1024


def clean_relative_path(value: str, max_length: int = MAX_PATH_LENGTH) -> str:
    """Normalise et valide un chemin relatif a la racine d'un projet.

    Les separateurs Windows sont ramenes a `/` : le meme fichier doit
    produire le meme chemin quel que soit le poste, sinon deux findings
    portant sur la meme ligne ne se dedoublonnent pas.
    """
    path = (value or "").strip().replace("\\", "/")
    if not path:
        raise ValueError("Le chemin du fichier est obligatoire")
    if len(path) > max_length:
        raise ValueError(f"Chemin trop long (maximum {max_length} caracteres)")
    if path.startswith("/") or (len(path) > 1 and path[1] == ":"):
        raise ValueError("Le chemin doit etre relatif a la racine du projet")
    if ".." in path.split("/"):
        raise ValueError("Le chemin ne peut pas remonter l'arborescence")
    return path
