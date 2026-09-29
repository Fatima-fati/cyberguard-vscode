"""Expurgation des preuves avant persistance.

Ceinture et bretelles. Le moteur de detection tourne **cote extension**,
sur le poste du developpeur, et n'envoie deja qu'une preuve expurgee. Ce
module ne lui fait pas confiance : toute preuve qui arrive au backend
repasse ici avant d'etre ecrite en base.

Pourquoi ne pas se contenter de la garantie du client ? Parce qu'une
extension d'une version anterieure, une extension modifiee, ou un appel
direct sur la route (le backend ecoute en local, d'autres processus de la
machine peuvent l'atteindre) produiraient une preuve non expurgee. La
seule garantie qui tienne est celle appliquee du cote qui ecrit.

Ce que ce module garantit sur ce qui est ecrit en base :

- aucun jeton de 12 caracteres ou plus n'y figure en entier ;
- une preuve ne depasse jamais `MAX_EVIDENCE_LENGTH` caracteres ;
- l'operation est **idempotente** : reappliquer l'expurgation a une preuve
  deja expurgee ne la degrade pas davantage.
"""

import re
from typing import Optional

from app.ai.sanitizer import SECRET_PATTERNS, redact_secrets

# Masque unique, pour que la relecture d'une preuve reste reconnaissable.
MASK = "********"

# Au-dela, une preuve n'aide plus a localiser : elle recopie du code.
MAX_EVIDENCE_LENGTH = 220

# Nombre de caracteres de tete conserves d'un jeton masque. Assez pour
# reconnaitre la nature de la cle (« sk-proj- », « AKIA », « ghp_ »), trop
# peu pour la rejouer.
VISIBLE_PREFIX = 8

# Un jeton : suite de caracteres d'alphabet de cle, assez longue pour
# qu'un secret puisse s'y cacher. En dessous de ce seuil, on laisse — un
# nom de variable ne doit pas devenir illisible.
_TOKEN = re.compile(r"[A-Za-z0-9_\-+/=.]{12,}")

# Formes de cles a tres forte signature. Elles sont masquees avant tout
# examen de forme : une cle d'acces AWS purement alphabetique ressemble a
# un mot, et seule sa signature la distingue.
_HIGH_SIGNAL: tuple[re.Pattern, ...] = (
    re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{20,}"),
    re.compile(r"\bglpat-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"\bnpm_[A-Za-z0-9]{20,}"),
)

# Longueur maximale d'un mot ou d'un segment d'identifiant laisse en
# clair. Vingt caracteres couvrent le vocabulaire francais et anglais
# ainsi que les noms de variables usuels ; au-dela, un jeton alphabetique
# ressemble davantage a une cle qu'a un mot.
_MAX_WORD_LENGTH = 20


def _is_probably_not_secret(token: str) -> bool:
    """Ce jeton est-il un mot ou un identifiant plutot qu'une valeur ?

    Le discriminant retenu tient en trois observations :

    - **un chiffre dans un jeton long** est le propre des cles
      (`AKIAIOSFODNN7EXAMPLE`), pas des mots ni des noms de variables
      usuels. Presence d'un chiffre : on masque ;
    - **un nom compose** (`AWS_SECRET_ACCESS_KEY`, `app.project.schemas`)
      se decoupe en segments courts et alphabetiques. C'est exactement ce
      qu'une preuve doit pouvoir nommer, et une cle n'a pas cette forme ;
    - **un mot isole** reste sous vingt caracteres. Au-dela, le doute
      profite a l'expurgation.

    En cas d'hesitation, ce predicat repond « c'est peut-etre un secret » :
    masquer un mot rend une phrase moins lisible, laisser passer une cle
    la rend rejouable.
    """
    if token.isdigit():
        return True
    if any(character.isdigit() for character in token):
        return False

    segments = [part for part in re.split(r"[._\-]", token) if part]
    if not segments or not all(part.isalpha() for part in segments):
        return False
    if len(segments) > 1:
        return all(len(part) <= _MAX_WORD_LENGTH for part in segments)

    # Un mot isole tout en capitales et long n'existe pas en prose : les
    # noms de constantes, eux, portent des tirets bas et sont traites
    # au-dessus. Reste la forme des identifiants de cle.
    if token.isupper() and len(token) >= 16:
        return False
    return len(token) <= _MAX_WORD_LENGTH


def _mask_token(match: re.Match) -> str:
    """Masque un jeton en conservant sa tete."""
    token = match.group(0)

    # Deja masque : on n'ajoute pas un masque au masque.
    if MASK in token:
        return token

    if _is_probably_not_secret(token):
        return token

    keep = min(VISIBLE_PREFIX, max(0, len(token) - 4))
    return f"{token[:keep]}{MASK}"


def redact_text(value: Optional[str], limit: int = MAX_EVIDENCE_LENGTH) -> str:
    """Texte libre expurge et borne.

    Deux passes, dans cet ordre :

    1. les motifs nommes de `app.ai.sanitizer` — ils connaissent les
       formes « cle=valeur » et gardent le nom du champ, qui est
       precisement l'information utile ;
    2. un balayage generique — tout jeton assez long qui aurait survecu.

    La seconde passe est celle qui rend la garantie verifiable : elle ne
    depend d'aucune liste de fournisseurs, donc une cle d'un service
    inconnu de la liste est masquee quand meme.

    `limit` est le seul parametre : une preuve de finding se contente de
    `MAX_EVIDENCE_LENGTH`, une question posee a l'assistant de securite
    (phase 6) a besoin de plus de place. Les deux passent par **cette**
    fonction — deux expurgations distinctes finiraient par diverger, et
    c'est la moins stricte des deux qui deciderait de ce qui sort.
    """
    if not value:
        return ""

    # Les sauts de ligne feraient d'une preuve un extrait de fichier.
    text = " ".join(_redact_passes(str(value)).split())

    if len(text) > limit:
        text = text[:limit].rstrip() + " […]"

    return text


def _redact_passes(text: str) -> str:
    """Les deux passes d'expurgation, sans toucher a la mise en forme."""
    text = redact_secrets(text) or ""
    for pattern in _HIGH_SIGNAL:
        text = pattern.sub(lambda match: f"{match.group(0)[:VISIBLE_PREFIX]}{MASK}", text)
    return _TOKEN.sub(_mask_token, text)


def redact_code_line(value: Optional[str], limit: int = 500) -> str:
    """Une ligne de code expurgee, indentation conservee (phase 7).

    Memes passes que `redact_text`, pour qu'une ligne transmise a
    l'assistant de remediation ne soit jamais moins expurgee qu'une
    preuve. Seule difference : les blancs ne sont pas ecrases. Un modele
    qui propose un correctif doit voir l'indentation, sinon il en invente
    une et le remplacement casse le fichier.
    """
    if not value:
        return ""
    line = " ".join(str(value).splitlines())
    text = _redact_passes(line)
    return text[:limit]


# Affectation d'un litteral a un nom de secret : `password = "hunter2..."`.
# Une lecture d'environnement (`os.environ["API_KEY"]`) n'est pas un
# litteral : elle ne correspond pas, et c'est precisement la correction
# qu'on attend.
#
# Le nom est reconnu par sa FIN (`OPENAI_KEY`, `db_password`,
# `githubToken`) : c'est la que les conventions de nommage placent la
# nature de la valeur. Le filet est large a dessein — un faux positif
# refuse un correctif, un faux negatif en ecrirait un secret.
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)[A-Za-z0-9_.\-]*(pass(?:word|wd)?|pwd|secret|token|key|credentials?)"
    r"[\"']?\s*(?::=|=>|[:=])\s*[\"'][^\"'\s]{6,}[\"']"
)


def contains_secret_literal(value: Optional[str]) -> bool:
    """Le texte ecrit-il une valeur de secret en clair ? (phase 7)

    Sert a refuser un correctif qui remplacerait un secret par un autre —
    ou qui en inventerait un. Trois familles de signaux : les formes de
    cle a tres forte signature, les motifs nommes du sanitizer (jeton
    Bearer, cle `sk-`, bloc de cle privee, JWT), et l'affectation d'un
    litteral a un nom de secret.
    """
    if not value:
        return False
    if any(pattern.search(value) for pattern in _HIGH_SIGNAL):
        return True
    # Motifs nommes, hors « cle=valeur » : celui-ci reconnaitrait aussi
    # `api_key = os.getenv(...)`, qui est la bonne correction.
    if any(pattern.search(value) for pattern in SECRET_PATTERNS[1:]):
        return True
    return bool(_SECRET_ASSIGNMENT.search(value))


def contains_redaction_marker(value: Optional[str]) -> bool:
    """La chaine porte-t-elle une marque d'expurgation ?

    Sert a refuser un correctif qui recopierait une valeur masquee : ecrit
    dans le fichier, `********` remplacerait le vrai code par le masque.
    """
    if not value:
        return False
    return MASK in value or "[REDACTED]" in value


def redact_evidence(value: Optional[str]) -> str:
    """Preuve prete a etre ecrite en base.

    Cas particulier de `redact_text` : la borne est celle d'une preuve,
    au-dela de laquelle un extrait cesse de localiser et recopie du code.
    """
    return redact_text(value, MAX_EVIDENCE_LENGTH)


def looks_redacted(value: Optional[str]) -> bool:
    """La preuve porte-t-elle une marque d'expurgation ?

    Sert aux tests et au journal : une preuve sans masque **n'est pas**
    forcement une fuite (« Mot de passe declare en dur » n'a rien a
    masquer), mais une preuve qui contient un jeton long sans masque en
    est une.
    """
    if not value:
        return True
    if MASK in value or "[REDACTED]" in value:
        return True
    if any(pattern.search(value) for pattern in _HIGH_SIGNAL):
        return False
    return all(_is_probably_not_secret(token) for token in _TOKEN.findall(value))
