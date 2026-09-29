"""Proposition de correctif pour un finding de code.

**Ce module n'ecrit jamais.** Il ne connait pas le chemin reel du fichier
sur le poste du developpeur, ne l'ouvre pas, ne le modifie pas. Il decrit
une modification ; c'est l'editeur qui l'appliquera, apres confirmation
explicite de l'utilisateur (phase 2/3).

C'est une garantie plus forte que celle de `app.ai.remediation` (qui,
lui, peut ecrire sous `AI_REMEDIATION_ROOT`) : ici, aucune ecriture n'est
possible, meme mal configuree.

Phase 1 : les correctifs proposes sont **deterministes**, derives de la
regle declenchee. Quand aucune reecriture mecanique n'est sure — le cas
de la SQL injection, qui demande de restructurer l'appel — la proposition
est explicitement indisponible et les etapes manuelles sont fournies.
"""

import difflib
import logging
import re
from typing import Callable, Optional

from app.code.schemas import CodeFixProposal

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# Reecritures mecaniques sures
# --------------------------------------------------------------------------
#
# Une entree par regle. La fonction recoit la ligne d'origine et renvoie
# la ligne corrigee, ou None si elle ne sait pas faire sur CETTE ligne.
# Regle d'or : ne jamais proposer une reecriture qui change le sens du
# programme au-dela de la correction de securite.


def _fix_tls_verify(line: str) -> Optional[str]:
    patched = re.sub(r"verify\s*=\s*False", "verify=True", line)
    patched = re.sub(
        r"rejectUnauthorized\s*:\s*false", "rejectUnauthorized: true", patched
    )
    patched = re.sub(
        r"InsecureSkipVerify\s*:\s*true", "InsecureSkipVerify: false", patched
    )
    return patched if patched != line else None


def _fix_debug(line: str) -> Optional[str]:
    patched = re.sub(r"DEBUG\s*=\s*True", "DEBUG = False", line)
    patched = re.sub(r"debug\s*=\s*True", "debug=False", patched)
    return patched if patched != line else None


def _fix_weak_hash(line: str) -> Optional[str]:
    """MD5/SHA-1 -> SHA-256.

    Volontairement limite au hachage generique. Si la ligne concerne un
    mot de passe, la bonne reponse est bcrypt/Argon2, pas SHA-256 : on
    refuse alors la reecriture automatique.
    """
    if re.search(r"(?i)password|passwd|pwd", line):
        return None

    patched = re.sub(r"hashlib\.md5\s*\(", "hashlib.sha256(", line)
    patched = re.sub(r"hashlib\.sha1\s*\(", "hashlib.sha256(", patched)
    patched = re.sub(
        r"createHash\s*\(\s*[\"'](?:md5|sha1)[\"']",
        "createHash('sha256'",
        patched,
        flags=re.IGNORECASE,
    )
    return patched if patched != line else None


def _fix_yaml_load(line: str) -> Optional[str]:
    patched = re.sub(r"yaml\.load\s*\(", "yaml.safe_load(", line)
    return patched if patched != line else None


def _fix_cors_wildcard(line: str) -> Optional[str]:
    """Le joker est remplace par un emplacement a completer, pas devine."""
    if not re.search(r"[\"']\*[\"']", line):
        return None
    return re.sub(
        r"[\"']\*[\"']", '"https://votre-domaine.example"', line, count=1
    )


# rule_id -> reecriture, resume affiche
MECHANICAL_FIXES: dict[str, tuple[Callable[[str], Optional[str]], str]] = {
    "CONF001": (
        _fix_tls_verify,
        "Réactive la vérification du certificat TLS.",
    ),
    "CONF002": (
        _fix_debug,
        "Désactive le mode debug.",
    ),
    "CONF003": (
        _fix_cors_wildcard,
        "Remplace l'origine joker par un domaine explicite à compléter.",
    ),
    "CRYPTO001": (
        _fix_weak_hash,
        "Remplace l'algorithme obsolète par SHA-256.",
    ),
    "DESER001": (
        _fix_yaml_load,
        "Utilise `yaml.safe_load`, qui n'instancie pas d'objets arbitraires.",
    ),
}


# Regles pour lesquelles aucune reecriture d'une seule ligne n'est sure.
# La raison est affichee telle quelle a l'utilisateur.
NO_SAFE_FIX: dict[str, str] = {
    "SQLI001": (
        "Corriger une SQL injection demande de restructurer l'appel "
        "(requête paramétrée), ce qui dépasse la réécriture d'une ligne."
    ),
    "SQLI002": (
        "Corriger une SQL injection demande de restructurer l'appel "
        "(requête paramétrée), ce qui dépasse la réécriture d'une ligne."
    ),
    "CMDI001": (
        "Remplacer un appel shell par une liste d'arguments change la "
        "structure de l'appel : la réécriture automatique risquerait de "
        "modifier le comportement du programme."
    ),
    "CMDI002": (
        "Remplacer un appel shell par une API dédiée dépend du contexte "
        "applicatif : aucune réécriture mécanique n'est sûre."
    ),
    "XSS001": (
        "Le choix entre `textContent` et un assainissement HTML dépend de "
        "l'intention : seul le développeur peut trancher."
    ),
    "XSS002": (
        "L'échappement correct dépend du contexte d'insertion (HTML, "
        "attribut, URL, JavaScript)."
    ),
    "SECRET001": (
        "Un secret ne se corrige pas en place : il doit être révoqué puis "
        "rechargé depuis l'environnement."
    ),
    "SECRET002": (
        "Un secret ne se corrige pas en place : il doit être révoqué puis "
        "rechargé depuis l'environnement."
    ),
    "PATH001": (
        "La validation du chemin dépend du répertoire autorisé par "
        "l'application."
    ),
    "EVAL001": (
        "Supprimer une évaluation dynamique suppose de savoir ce que la "
        "chaîne représente (données, choix, code)."
    ),
    "RANDOM001": (
        "Le générateur de remplacement dépend de l'usage exact "
        "(jeton, sel, identifiant) et de la longueur attendue."
    ),
    "SSRF001": (
        "La liste des destinations autorisées relève de la configuration "
        "applicative."
    ),
    "XXE001": (
        "Le durcissement de l'analyseur XML dépend de la bibliothèque "
        "utilisée."
    ),
    "REDIR001": (
        "Les destinations légitimes de redirection dépendent de "
        "l'application."
    ),
}


def build_diff(file_path: str, line_number: int, before: str, after: str) -> str:
    """Diff unifie d'une modification d'une seule ligne."""
    return "\n".join(
        difflib.unified_diff(
            [before],
            [after],
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            lineterm="",
            n=0,
        )
    )


def propose(
    finding_row: dict,
    current_line: Optional[str] = None,
) -> CodeFixProposal:
    """Construit la proposition de correctif d'un finding.

    `current_line` est la ligne telle qu'elle est **aujourd'hui** dans
    l'editeur. Si elle est fournie et differe de l'extrait analyse, la
    proposition est refusee : le fichier a bouge depuis le scan.
    """
    rule_id = finding_row["rule_id"]
    file_path = finding_row.get("scan_file_path") or ""
    line_number = finding_row["line_start"]
    recommendations = finding_row.get("_recommendations") or []

    proposal = CodeFixProposal(
        finding_uid=finding_row["finding_uid"],
        available=False,
        line=line_number,
        file_path=file_path,
        manual_steps=list(recommendations),
    )

    if finding_row["status"] != "open":
        proposal.blockers = [
            "Ce finding n'est plus ouvert : aucune correction n'est proposée."
        ]
        return proposal

    reason = NO_SAFE_FIX.get(rule_id)
    if reason is not None:
        proposal.blockers = [reason]
        proposal.explanation = (
            "Aucune correction automatique sûre : appliquez les "
            "recommandations manuellement."
        )
        return proposal

    entry = MECHANICAL_FIXES.get(rule_id)
    if entry is None:
        proposal.blockers = [
            f"Aucune correction automatique n'est définie pour la règle {rule_id}."
        ]
        return proposal

    rewrite, summary = entry

    # La ligne de reference : celle fournie par l'editeur, sinon l'extrait
    # conserve au moment du scan.
    snippet = finding_row["snippet"] or ""
    source_line = current_line if current_line is not None else snippet

    if not source_line.strip():
        proposal.blockers = [
            "La ligne d'origine n'est plus disponible : relancez une analyse "
            "du fichier."
        ]
        return proposal

    if current_line is not None and current_line.strip() != snippet.strip():
        proposal.blockers = [
            "La ligne a changé depuis l'analyse : relancez une analyse avant "
            "d'appliquer une correction."
        ]
        return proposal

    if "[REDACTED]" in source_line:
        proposal.blockers = [
            "La ligne contient un secret masqué par le backend : la "
            "correction doit être faite dans l'éditeur, sans passer par le "
            "serveur."
        ]
        return proposal

    patched = rewrite(source_line)
    if patched is None:
        proposal.blockers = [
            "Aucune réécriture sûre n'a pu être produite pour cette ligne "
            "précise."
        ]
        return proposal

    proposal.available = True
    proposal.original_line = source_line
    proposal.replacement_line = patched
    proposal.explanation = summary
    proposal.diff = build_diff(file_path or "fichier", line_number, source_line, patched)
    return proposal
