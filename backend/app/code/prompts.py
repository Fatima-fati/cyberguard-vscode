"""Prompts de l'analyse de code. **Non utilises en phase 1.**

Aucun appel a OpenAI n'est effectue tant que `CODE_AI_ENRICHMENT_ENABLED`
n'est pas active (phase 3). Ce module existe des maintenant pour que le
contrat avec le modele soit ecrit, relu et testable sans depenser un
jeton.

Difference assumee avec `app.ai.prompts` : trier une alerte SIEM et
relire du code sont deux metiers. Ce qui est reellement commun — la
consigne de langue et la liste des termes techniques a conserver — est
partage via `LANGUAGE_RULE` et `KEPT_TERMS`, importes de `app.i18n`.
"""

import json

from app.i18n import KEPT_TECHNICAL_TERMS
from app.code.schemas import VULNERABILITY_CATEGORIES

# Consigne de langue, identique a celle de l'analyse d'alertes.
LANGUAGE_RULE = f"""LANGUE - REGLE ABSOLUE :
Tu réponds EXCLUSIVEMENT en français, dans TOUS les champs textuels.
Utilise une terminologie professionnelle et compréhensible. Ne réponds
JAMAIS en anglais, même partiellement.

Restent en anglais, et uniquement eux, les noms propres et concepts de
sécurité reconnus : {", ".join(KEPT_TECHNICAL_TERMS[:24])}.

Ne traduis jamais les identifiants techniques : noms de variables, de
fonctions, de fichiers, de méthodes, chemins, CWE, OWASP, codes HTTP.
Ils sont recopiés tels quels."""


SYSTEM_PROMPT = f"""Tu es un analyste senior en sécurité applicative. On te
donne un extrait de code signalé par une règle de détection, avec son
contexte. Tu dis si le signalement est fondé et tu l'expliques à un
développeur qui n'est pas spécialiste sécurité.

{LANGUAGE_RULE}

Ta démarche :
1. Vérifier si le motif détecté correspond à un vrai problème dans CE
   contexte, ou s'il s'agit d'un faux positif. Dis-le franchement.
2. Expliquer ce qui ne va pas, en langage simple.
3. Décrire les conséquences concrètes si le problème est exploité.
4. Proposer une correction précise et réaliste.

Règles impératives :
- Distingue les FAITS lus dans l'extrait de tes HYPOTHÈSES. Formule-les
  comme tels ("le code concatène...", "si cette valeur vient d'une
  requête HTTP, alors...").
- N'affirme jamais qu'une donnée vient de l'utilisateur si l'extrait ne le
  montre pas : dis que cela dépend de l'appelant.
- N'invente aucun nom de variable, de fonction ou de fichier absent de
  l'extrait.
- Les valeurs [REDACTED] sont des secrets masqués par le backend. Signale
  leur présence, ne tente jamais de les deviner.
- Tu ne proposes ni n'exécutes aucune commande système.
- `false_positive: true` est une réponse parfaitement acceptable.
- Les noms des clés JSON restent en anglais ; seules leurs VALEURS
  textuelles sont en français.

Tu réponds exclusivement par un objet JSON valide, sans texte autour."""


RESPONSE_SCHEMA_HINT = {
    "category": f"valeur technique : un choix parmi {list(VULNERABILITY_CATEGORIES)}",
    "severity": "LOW | MEDIUM | HIGH | CRITICAL (valeur technique)",
    "risk_score": "entier de 0 a 100",
    "confidence": "nombre de 0 a 100 traduisant ta certitude",
    "false_positive": "true si la regle s'est trompee dans ce contexte",
    "title": "EN FRANCAIS - titre court du probleme",
    "explanation": "EN FRANCAIS - ce qui ne va pas dans cet extrait",
    "why_dangerous": "EN FRANCAIS - pourquoi c'est risque, en clair",
    "potential_impact": ["EN FRANCAIS - consequence concrete si exploite"],
    "recommendations": ["EN FRANCAIS - action precise pour corriger"],
    "risk_factors": ["EN FRANCAIS - element ayant pese dans l'evaluation"],
    "fix_available": "true si une correction tenant sur une ligne existe",
    "fix_summary": "EN FRANCAIS - ce que la correction changerait",
}


def build_user_prompt(
    rule_id: str,
    category: str,
    file_path: str,
    language: str,
    line: int,
    excerpt: str,
) -> str:
    """Message utilisateur : le signalement, l'extrait, les consignes.

    `excerpt` doit **deja** avoir traverse `app.ai.sanitizer.redact_secrets`
    avant d'arriver ici : ce module ne fait aucune expurgation lui-meme.
    """
    payload = {
        "rule_id": rule_id,
        "category": category,
        "file_path": file_path,
        "language": language,
        "line": line,
    }

    return (
        "Analyse le signalement suivant.\n\n"
        "SIGNALEMENT (JSON) :\n"
        f"{json.dumps(payload, ensure_ascii=False, indent=2)}\n\n"
        "EXTRAIT DE CODE :\n"
        f"```{language}\n{excerpt}\n```\n\n"
        "Une règle de détection a signalé cette ligne. Une règle est un "
        "indice, pas une preuve : confirme ou infirme.\n\n"
        "Réponds par un JSON respectant exactement ces clés :\n"
        f"{json.dumps(RESPONSE_SCHEMA_HINT, ensure_ascii=False, indent=2)}"
    )
