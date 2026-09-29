"""Regles deterministes de detection : motifs, categories, CWE, OWASP.

Ce module fonctionne **sans OpenAI** et sans reseau. C'est la premiere
ligne de l'analyse : rapide, gratuite, explicable, et utile meme quand
l'agent IA est eteint.

Honnetete du resultat
---------------------
Une expression reguliere ne prouve rien. Elle signale un **motif
suspect** : chaque regle porte donc une `confidence` et un texte redige
au conditionnel ("cette ligne semble construire...", "verifiez que...").
Le vocabulaire du projet parle de *finding detecte par une regle*, jamais
de vulnerabilite confirmee. La confirmation viendra de l'analyse IA
(phase 3) et surtout du developpeur.

Ajouter une regle
-----------------
Une entree dans `RULES`, rien d'autre : le scanner, le catalogue
(`GET /api/code/rules`), les statistiques et les tests la prennent en
compte automatiquement. Incrementer `RULES_VERSION` quand le catalogue
change, pour que l'extension sache qu'un re-scan est pertinent.
"""

import logging
import re
from typing import Optional

from pydantic import BaseModel, Field

from app.ai.sanitizer import REDACTED, redact_secrets
from app.code.schemas import CodeLocation, RuleHit

logger = logging.getLogger(__name__)

# Version du catalogue. A incrementer a chaque ajout ou modification de
# regle : elle est stockee avec chaque scan et exposee par /health.
RULES_VERSION = "1.0.1"

# Longueur maximale d'un extrait conserve et renvoye.
MAX_SNIPPET_LENGTH = 240

# Marqueurs permettant a un developpeur de faire taire une ligne.
IGNORE_MARKERS = ("nosec", "wazuh-security: ignore", "security: ignore")

# Debuts de ligne consideres comme du commentaire, par langage.
COMMENT_PREFIXES: dict[str, tuple[str, ...]] = {
    "python": ("#",),
    "ruby": ("#",),
    "yaml": ("#",),
    "javascript": ("//", "*", "/*"),
    "typescript": ("//", "*", "/*"),
    "java": ("//", "*", "/*"),
    "csharp": ("//", "*", "/*"),
    "go": ("//", "*", "/*"),
    "php": ("//", "#", "*", "/*"),
    "sql": ("--",),
    "other": ("#", "//", "--", "*"),
}

# Langages auxquels une regle peut s'appliquer sans restriction.
ANY_LANGUAGE: tuple[str, ...] = ()


class SecurityRule(BaseModel):
    """Une regle de detection, entierement declarative."""

    rule_id: str
    category: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    severity: str = "MEDIUM"
    # Confiance dans le motif lui-meme (0-1). Elle pondere le score de
    # risque : un motif large ne doit pas produire un score de motif sur.
    confidence: float = 0.5
    # Langages concernes. Vide = tous.
    languages: tuple[str, ...] = ANY_LANGUAGE
    # Description affichee dans le catalogue.
    description: str = ""
    # Motif declencheur.
    pattern: re.Pattern
    # Motif d'exception : si present sur la ligne, la regle ne declenche pas.
    unless: Optional[re.Pattern] = None

    title: str = ""
    explanation: str = ""
    why_dangerous: str = ""
    potential_impact: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)

    model_config = {"arbitrary_types_allowed": True}

    def applies_to(self, language: str) -> bool:
        return not self.languages or language in self.languages


def _rx(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE)


# --------------------------------------------------------------------------
# Catalogue
# --------------------------------------------------------------------------
#
# Chaque regle repond a quatre questions posees par l'extension :
#   - qu'est-ce qui est incorrect ?          -> title / explanation
#   - pourquoi est-ce dangereux ?            -> why_dangerous
#   - quelles consequences ?                 -> potential_impact
#   - comment corriger ?                     -> recommendations

RULES: tuple[SecurityRule, ...] = (
    # ---------------------------------------------------------- 1. SQL
    SecurityRule(
        rule_id="SQLI001",
        category="sql_injection",
        cwe="CWE-89",
        owasp="A03:2021 - Injection",
        severity="CRITICAL",
        confidence=0.8,
        description=(
            "Requete SQL construite par concatenation ou interpolation de "
            "variables."
        ),
        pattern=_rx(
            # Le groupe optionnel (?:[\"'][^\"';\n]*)? couvre l'idiome le
            # plus repandu de la concatenation SQL : la valeur est
            # entouree d'apostrophes *dans* la requete, si bien que la
            # chaine se termine par deux guillemets colles --
            #     query = "SELECT ... WHERE nom = '" + nom + "'"
            # Sans lui, [^\"';\n]* s'arretait sur l'apostrophe interieure
            # et l'operateur de concatenation n'etait plus au rendez-vous :
            # la ligne la plus classique d'injection SQL passait au travers.
            # Le `$` final admet les variables PHP ($mail) au meme titre
            # que les identifiants Python ou Java.
            r"(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|WHERE|VALUES)"
            r"[^\"';\n]*(?:[\"'][^\"';\n]*)?[\"']\s*(?:\+|\.|%)\s*[\w$]"
            r"|[\"'][^\"'\n]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)"
            r"[^\"'\n]*[\"']\s*(?:\+|\.)\s*[\w$]"
        ),
        title="Requête SQL construite par concaténation",
        explanation=(
            "Cette ligne semble assembler une requête SQL en collant une "
            "variable au texte de la requête. La valeur devient alors une "
            "partie de l'instruction exécutée par la base."
        ),
        why_dangerous=(
            "Si la variable provient d'une saisie utilisateur, celle-ci peut "
            "refermer la chaîne et ajouter ses propres instructions SQL : "
            "c'est une SQL injection."
        ),
        potential_impact=[
            "Lecture de données auxquelles l'utilisateur n'a pas droit",
            "Modification ou suppression de données",
            "Contournement de l'authentification",
        ],
        recommendations=[
            "Utiliser une requête paramétrée : passer les valeurs en "
            "arguments plutôt que de les concaténer.",
            "Si un fragment doit être dynamique (nom de table, tri), le "
            "choisir dans une liste blanche fermée.",
        ],
    ),
    SecurityRule(
        rule_id="SQLI002",
        category="sql_injection",
        cwe="CWE-89",
        owasp="A03:2021 - Injection",
        severity="CRITICAL",
        confidence=0.75,
        languages=("python", "javascript", "typescript", "php"),
        description="Requete SQL construite par f-string, .format() ou template.",
        pattern=_rx(
            r"(?:f[\"']|`)[^\"'`\n]*"
            r"(?:SELECT|INSERT\s+INTO|UPDATE\s+\w|DELETE\s+FROM)"
            r"[^\"'`\n]*(?:\{\w|\$\{|\$\w)"
            r"|[\"'][^\"'\n]*(?:SELECT|INSERT|UPDATE|DELETE)[^\"'\n]*[\"']"
            r"\s*\.\s*format\s*\("
            r"|[\"'][^\"'\n]*(?:SELECT|INSERT|UPDATE|DELETE)[^\"'\n]*%s[^\"'\n]*[\"']\s*%"
        ),
        title="Requête SQL construite par interpolation",
        explanation=(
            "La requête est assemblée par une f-string, un template ou "
            "`.format()`. La valeur interpolée fait partie de l'instruction "
            "envoyée à la base."
        ),
        why_dangerous=(
            "L'interpolation ne protège rien : une valeur contenant une "
            "apostrophe ou un point-virgule modifie la requête exécutée."
        ),
        potential_impact=[
            "Exfiltration du contenu de la base",
            "Élévation de privilèges applicatifs",
        ],
        recommendations=[
            "Remplacer l'interpolation par des paramètres liés "
            "(`?`, `%s`, `:nom` selon le pilote).",
        ],
    ),
    # ------------------------------------------------ 2. Command injection
    SecurityRule(
        rule_id="CMDI001",
        category="command_injection",
        cwe="CWE-78",
        owasp="A03:2021 - Injection",
        severity="CRITICAL",
        confidence=0.85,
        languages=("python",),
        description="Commande systeme construite avec une variable (os.system, subprocess).",
        pattern=_rx(
            r"os\.system\s*\([^)\n]*(?:\+|f[\"']|%|\.format\()"
            r"|os\.popen\s*\([^)\n]*(?:\+|f[\"']|%|\.format\()"
            r"|subprocess\.(?:run|call|check_output|check_call|Popen)\s*\("
            r"[^)\n]*shell\s*=\s*True"
        ),
        title="Commande système construite dynamiquement",
        explanation=(
            "La commande passée au système est assemblée à partir de "
            "variables, ou exécutée via un shell (`shell=True`)."
        ),
        why_dangerous=(
            "Le shell interprète `;`, `&&`, `|` et les substitutions : une "
            "valeur bien choisie permet d'exécuter une autre commande que "
            "celle prévue."
        ),
        potential_impact=[
            "Exécution de commandes arbitraires sur le serveur",
            "Prise de contrôle complète de la machine",
        ],
        recommendations=[
            "Utiliser `subprocess.run([...])` avec une liste d'arguments et "
            "`shell=False`.",
            "Valider la valeur contre une liste blanche si elle vient de "
            "l'utilisateur.",
        ],
    ),
    SecurityRule(
        rule_id="CMDI002",
        category="command_injection",
        cwe="CWE-78",
        owasp="A03:2021 - Injection",
        severity="CRITICAL",
        confidence=0.8,
        languages=("javascript", "typescript", "php", "java", "ruby"),
        description="Execution d'une commande systeme depuis JS, PHP, Java ou Ruby.",
        pattern=_rx(
            r"child_process\.(?:exec|execSync)\s*\("
            r"|\bexec\s*\(\s*[`\"'][^`\"'\n]*(?:\$\{|\"\s*\+)"
            r"|\b(?:shell_exec|passthru|proc_open|popen)\s*\("
            r"|\bsystem\s*\(\s*[\"'$]"
            r"|Runtime\.getRuntime\(\)\.exec\s*\("
            r"|%x\{|\bIO\.popen\s*\("
        ),
        title="Exécution d'une commande système",
        explanation=(
            "Cette ligne lance une commande du système d'exploitation. Si "
            "une partie de la commande vient d'une entrée utilisateur, elle "
            "est interprétée par le shell."
        ),
        why_dangerous=(
            "Un attaquant capable d'influencer la chaîne peut enchaîner ses "
            "propres commandes."
        ),
        potential_impact=[
            "Exécution de code arbitraire côté serveur",
            "Vol ou destruction de fichiers",
        ],
        recommendations=[
            "Préférer une API dédiée plutôt qu'un appel shell.",
            "Si le shell est indispensable, échapper strictement les "
            "arguments et n'accepter que des valeurs d'une liste blanche.",
        ],
    ),
    # ------------------------------------------------------------- 3. XSS
    SecurityRule(
        rule_id="XSS001",
        category="xss",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
        severity="HIGH",
        confidence=0.7,
        languages=("javascript", "typescript"),
        description="Ecriture de HTML brut dans le DOM (innerHTML, document.write).",
        pattern=_rx(
            r"\.innerHTML\s*(?:=|\+=)"
            r"|\.outerHTML\s*="
            r"|document\.write(?:ln)?\s*\("
            r"|\.insertAdjacentHTML\s*\("
            r"|dangerouslySetInnerHTML"
        ),
        unless=_rx(r"innerHTML\s*=\s*[\"'`]\s*[\"'`]"),
        title="Insertion de HTML non échappé dans la page",
        explanation=(
            "Cette ligne injecte du HTML directement dans le document. Le "
            "contenu inséré est interprété par le navigateur, balises et "
            "scripts compris."
        ),
        why_dangerous=(
            "Si la valeur contient du HTML fourni par un utilisateur, du "
            "JavaScript peut s'exécuter dans le navigateur des visiteurs : "
            "c'est une XSS."
        ),
        potential_impact=[
            "Vol de session ou de cookies",
            "Actions effectuées à l'insu de l'utilisateur",
            "Défiguration de la page",
        ],
        recommendations=[
            "Utiliser `textContent` quand le contenu n'est pas du HTML.",
            "Si du HTML est nécessaire, l'assainir avec une bibliothèque "
            "dédiée (DOMPurify) avant insertion.",
        ],
    ),
    SecurityRule(
        rule_id="XSS002",
        category="xss",
        cwe="CWE-79",
        owasp="A03:2021 - Injection",
        severity="HIGH",
        confidence=0.75,
        languages=("php", "python"),
        description="Affichage direct d'une entree utilisateur, sans echappement.",
        pattern=_rx(
            r"echo\s+[^;\n]*\$_(?:GET|POST|REQUEST|COOKIE)"
            r"|print\s+[^;\n]*\$_(?:GET|POST|REQUEST)"
            r"|render_template_string\s*\("
            r"|\bMarkup\s*\(\s*(?:f[\"']|\w+\s*\+|\w+\s*%)"
        ),
        unless=_rx(r"htmlspecialchars|htmlentities|\|\s*e\b|escape\("),
        title="Entrée utilisateur affichée sans échappement",
        explanation=(
            "La valeur affichée provient directement de la requête HTTP et "
            "n'est pas échappée avant d'atteindre la page."
        ),
        why_dangerous=(
            "Tout HTML contenu dans cette valeur sera interprété par le "
            "navigateur, ce qui permet d'y glisser du script."
        ),
        potential_impact=[
            "Exécution de script dans le navigateur des visiteurs",
            "Détournement de compte",
        ],
        recommendations=[
            "Échapper la valeur avant affichage (`htmlspecialchars`, "
            "auto-échappement du moteur de template).",
            "Ne jamais désactiver l'échappement automatique sur une donnée "
            "d'origine externe.",
        ],
    ),
    # --------------------------------------------------- 4. Secret en dur
    SecurityRule(
        rule_id="SECRET001",
        category="hardcoded_secret",
        cwe="CWE-798",
        owasp="A07:2021 - Identification and Authentication Failures",
        severity="HIGH",
        confidence=0.7,
        description="Mot de passe, cle ou jeton ecrit en dur dans le code.",
        pattern=_rx(
            r"\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|token|"
            r"access[_-]?key|secret[_-]?key|private[_-]?key|credential)\b"
            r"\s*[:=]\s*[\"'][^\"'\n]{6,}[\"']"
        ),
        # Une valeur lue dans l'environnement ou un placeholder evident
        # n'est pas un secret en dur.
        unless=_rx(
            r"os\.(?:getenv|environ)|process\.env|getenv\(|System\.getenv|"
            r"config\.|settings\.|\bENV\[|Deno\.env|"
            r"[\"'](?:changeme|xxx+|your[_-]?|<[^>]+>|\*{3,}|placeholder|"
            r"example|dummy|todo|none|null)"
        ),
        title="Secret potentiellement écrit en dur",
        explanation=(
            "Une valeur ressemblant à un mot de passe, une clé d'API ou un "
            "jeton est écrite directement dans le code source."
        ),
        why_dangerous=(
            "Le code est versionné, partagé et souvent copié : un secret "
            "qui y figure se retrouve dans l'historique Git et chez toute "
            "personne ayant accès au dépôt. Le révoquer devient la seule "
            "issue."
        ),
        potential_impact=[
            "Accès non autorisé au service concerné",
            "Fuite persistante via l'historique du dépôt",
        ],
        recommendations=[
            "Déplacer la valeur dans une variable d'environnement ou un "
            "gestionnaire de secrets.",
            "Si la valeur a déjà été commitée, la révoquer et en générer "
            "une nouvelle : la retirer du code ne suffit pas.",
        ],
    ),
    SecurityRule(
        rule_id="SECRET002",
        category="hardcoded_secret",
        cwe="CWE-798",
        owasp="A07:2021 - Identification and Authentication Failures",
        severity="CRITICAL",
        confidence=0.95,
        description="Cle d'API reconnaissable a son format (OpenAI, AWS, JWT, cle privee).",
        pattern=_rx(
            r"\bsk-[A-Za-z0-9_\-]{20,}"
            r"|\bAKIA[0-9A-Z]{16}\b"
            r"|\bgh[pousr]_[A-Za-z0-9]{20,}"
            r"|\bxox[baprs]-[A-Za-z0-9-]{10,}"
            r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
            r"|\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"
        ),
        title="Clé secrète reconnaissable dans le code",
        explanation=(
            "Cette ligne contient une valeur dont le format correspond à "
            "une clé d'API connue, un jeton JWT ou une clé privée."
        ),
        why_dangerous=(
            "Ces formats sont directement exploitables : un robot qui "
            "parcourt les dépôts publics les trouve en quelques minutes."
        ),
        potential_impact=[
            "Utilisation frauduleuse du service (et de sa facturation)",
            "Accès aux données du compte associé",
        ],
        recommendations=[
            "Révoquer immédiatement la clé exposée.",
            "La recharger depuis l'environnement, jamais depuis le code.",
        ],
    ),
    # -------------------------------------------------- 5. Path traversal
    SecurityRule(
        rule_id="PATH001",
        category="path_traversal",
        cwe="CWE-22",
        owasp="A01:2021 - Broken Access Control",
        severity="HIGH",
        confidence=0.65,
        description="Chemin de fichier construit a partir d'une variable.",
        pattern=_rx(
            r"\b(?:open|readFile|readFileSync|writeFile|writeFileSync|"
            r"file_get_contents|file_put_contents|fopen|readlink|sendFile|"
            r"send_file|unlink|remove)\s*\("
            r"[^)\n]*(?:\+\s*\w|f[\"'][^\"'\n]*\{|\$\{|\$_(?:GET|POST|REQUEST)|"
            r"\.\s*join\s*\([^)\n]*(?:req|request|param|user|input))"
            r"|(?:req|request)\.(?:query|params|body)\.\w+\s*\)?\s*$"
            r"(?<=join\()"
        ),
        unless=_rx(r"os\.path\.basename|secure_filename|path\.basename|realpath"),
        title="Chemin de fichier assemblé à partir d'une variable",
        explanation=(
            "Le chemin ouvert ou écrit est construit en concaténant une "
            "valeur variable au lieu d'être fixe ou validé."
        ),
        why_dangerous=(
            "Une valeur contenant `../` permet de sortir du répertoire "
            "prévu et d'atteindre d'autres fichiers du système."
        ),
        potential_impact=[
            "Lecture de fichiers sensibles (/etc/passwd, fichiers .env)",
            "Écrasement de fichiers applicatifs",
        ],
        recommendations=[
            "Ne conserver que le nom de base du fichier "
            "(`os.path.basename`, `secure_filename`).",
            "Résoudre le chemin final et vérifier qu'il reste sous le "
            "répertoire autorisé avant d'ouvrir.",
        ],
    ),
    # ----------------------------------------------------- 6. Unsafe eval
    SecurityRule(
        rule_id="EVAL001",
        category="unsafe_eval",
        cwe="CWE-95",
        owasp="A03:2021 - Injection",
        severity="CRITICAL",
        confidence=0.85,
        description="Evaluation dynamique de code (eval, exec, new Function).",
        pattern=_rx(
            r"(?<![\w.])eval\s*\("
            r"|(?<![\w.])exec\s*\(\s*[\"'f]"
            r"|new\s+Function\s*\("
            r"|setTimeout\s*\(\s*[\"'`]"
            r"|setInterval\s*\(\s*[\"'`]"
            r"|(?<![\w.])assert\s*\(\s*\$"
        ),
        title="Évaluation dynamique de code",
        explanation=(
            "Cette ligne transforme une chaîne de caractères en code exécuté "
            "par l'interpréteur."
        ),
        why_dangerous=(
            "Si la chaîne peut être influencée de l'extérieur, l'attaquant "
            "choisit le code qui s'exécute, avec les droits de "
            "l'application."
        ),
        potential_impact=[
            "Exécution de code arbitraire dans le processus applicatif",
            "Accès à toutes les données manipulées par l'application",
        ],
        recommendations=[
            "Remplacer par une analyse explicite : `json.loads` pour des "
            "données, une table de correspondance pour un choix.",
            "Ne jamais évaluer une chaîne construite à partir d'une entrée.",
        ],
    ),
    SecurityRule(
        rule_id="DESER001",
        category="insecure_deserialization",
        cwe="CWE-502",
        owasp="A08:2021 - Software and Data Integrity Failures",
        severity="HIGH",
        confidence=0.8,
        description="Deserialisation d'un format capable d'instancier du code.",
        pattern=_rx(
            r"pickle\.loads?\s*\("
            r"|cPickle\.loads?\s*\("
            r"|yaml\.load\s*\((?![^)\n]*SafeLoader)"
            r"|(?<![\w.])unserialize\s*\("
            r"|ObjectInputStream\s*\("
            r"|marshal\.loads?\s*\("
        ),
        title="Désérialisation d'une source non fiable",
        explanation=(
            "Le format désérialisé ici peut reconstruire des objets "
            "arbitraires, et donc déclencher du code pendant la lecture."
        ),
        why_dangerous=(
            "Une charge utile spécialement construite s'exécute au moment "
            "de la désérialisation, avant toute validation applicative."
        ),
        potential_impact=[
            "Exécution de code à distance",
            "Compromission du processus serveur",
        ],
        recommendations=[
            "Utiliser un format de données inerte : JSON.",
            "Pour YAML, utiliser `yaml.safe_load`.",
        ],
    ),
    # ------------------------------------------------ 7. Cryptographie
    SecurityRule(
        rule_id="CRYPTO001",
        category="weak_cryptography",
        cwe="CWE-327",
        owasp="A02:2021 - Cryptographic Failures",
        severity="MEDIUM",
        confidence=0.75,
        description="Algorithme de hachage ou de chiffrement obsolete (MD5, SHA-1, DES, RC4, ECB).",
        pattern=_rx(
            r"hashlib\.(?:md5|sha1)\s*\("
            r"|createHash\s*\(\s*[\"'](?:md5|sha1)[\"']"
            r"|(?<![\w.])md5\s*\("
            r"|MessageDigest\.getInstance\s*\(\s*[\"'](?:MD5|SHA-?1)[\"']"
            r"|(?:DES|RC4|Blowfish)/|Cipher\.getInstance\s*\(\s*[\"'](?:DES|RC4)"
            r"|[\"'][^\"'\n]*/ECB/"
        ),
        title="Algorithme cryptographique obsolète",
        explanation=(
            "L'algorithme utilisé ici (MD5, SHA-1, DES, RC4 ou mode ECB) "
            "est considéré comme cassé ou trop faible."
        ),
        why_dangerous=(
            "Des collisions ou des attaques pratiques existent : le "
            "condensat ou le chiffrement n'apporte plus la garantie "
            "attendue. Le mode ECB, lui, laisse transparaître la structure "
            "du texte clair."
        ),
        potential_impact=[
            "Mots de passe retrouvés hors ligne",
            "Intégrité contournable",
        ],
        recommendations=[
            "Pour un condensat : SHA-256 ou SHA-3.",
            "Pour un mot de passe : bcrypt, scrypt ou Argon2, jamais un "
            "simple hachage.",
            "Pour du chiffrement : AES en mode GCM.",
        ],
    ),
    SecurityRule(
        rule_id="RANDOM001",
        category="insecure_random",
        cwe="CWE-338",
        owasp="A02:2021 - Cryptographic Failures",
        severity="MEDIUM",
        confidence=0.6,
        description="Generateur aleatoire non cryptographique utilise pour un secret.",
        pattern=_rx(
            r"(?:token|secret|password|otp|nonce|salt|session|reset)\w*\s*=\s*"
            r"(?:random\.|Math\.random|rand\s*\(|mt_rand\s*\(|new\s+Random\s*\()"
        ),
        title="Valeur secrète tirée d'un générateur prévisible",
        explanation=(
            "Le générateur utilisé est conçu pour la simulation, pas pour "
            "la sécurité : sa suite est prédictible à partir de quelques "
            "valeurs."
        ),
        why_dangerous=(
            "Un jeton, un OTP ou un identifiant de session prévisible peut "
            "être deviné, ce qui revient à contourner l'authentification."
        ),
        potential_impact=[
            "Prédiction de jetons de réinitialisation ou de session",
            "Usurpation de compte",
        ],
        recommendations=[
            "Utiliser un générateur cryptographique : `secrets` (Python), "
            "`crypto.randomBytes` (Node), `SecureRandom` (Java).",
        ],
    ),
    # ------------------------------------------ 8. Configuration risquee
    SecurityRule(
        rule_id="CONF001",
        category="insecure_configuration",
        cwe="CWE-295",
        owasp="A05:2021 - Security Misconfiguration",
        severity="HIGH",
        confidence=0.9,
        description="Verification du certificat TLS desactivee.",
        pattern=_rx(
            r"verify\s*=\s*False"
            r"|rejectUnauthorized\s*:\s*false"
            r"|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)"
            r"|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0"
            r"|InsecureSkipVerify\s*:\s*true"
            r"|TrustServerCertificate\s*=\s*true"
            r"|ServicePointManager\.ServerCertificateValidationCallback"
        ),
        title="Vérification du certificat TLS désactivée",
        explanation=(
            "La connexion chiffrée est établie sans vérifier l'identité du "
            "serveur distant."
        ),
        why_dangerous=(
            "Le chiffrement protège encore le transport, mais plus rien ne "
            "garantit l'interlocuteur : une interception active devient "
            "indétectable."
        ),
        potential_impact=[
            "Interception des identifiants transmis",
            "Injection de réponses falsifiées",
        ],
        recommendations=[
            "Réactiver la vérification et installer l'autorité de "
            "certification interne si le certificat est auto-signé.",
            "Réserver strictement cette désactivation à un environnement de "
            "développement isolé.",
        ],
    ),
    SecurityRule(
        rule_id="CONF002",
        category="insecure_configuration",
        cwe="CWE-489",
        owasp="A05:2021 - Security Misconfiguration",
        severity="MEDIUM",
        confidence=0.8,
        description="Mode debug ou hote non restreint dans la configuration.",
        pattern=_rx(
            r"DEBUG\s*=\s*True"
            r"|debug\s*=\s*True\s*\)"
            r"|app\.run\s*\([^)\n]*debug\s*=\s*True"
            r"|ALLOWED_HOSTS\s*=\s*\[\s*[\"']\*[\"']\s*\]"
            r"|app\.config\[[\"']DEBUG[\"']\]\s*=\s*True"
        ),
        title="Mode debug activé",
        explanation=(
            "Le mode debug expose la pile d'appels, la configuration et "
            "parfois une console interactive."
        ),
        why_dangerous=(
            "En production, ces pages livrent la structure de "
            "l'application, des chemins internes et parfois des secrets ; "
            "certaines consoles permettent d'exécuter du code."
        ),
        potential_impact=[
            "Divulgation de la configuration interne",
            "Exécution de code via la console de debug",
        ],
        recommendations=[
            "Piloter ce réglage par une variable d'environnement et le "
            "laisser désactivé par défaut.",
        ],
    ),
    SecurityRule(
        rule_id="CONF003",
        category="insecure_configuration",
        cwe="CWE-942",
        owasp="A05:2021 - Security Misconfiguration",
        severity="MEDIUM",
        confidence=0.7,
        description="CORS ouvert a toutes les origines avec credentials.",
        pattern=_rx(
            r"Access-Control-Allow-Origin[\"']?\s*[:,]\s*[\"']\*"
            r"|allow_origins\s*=\s*\[\s*[\"']\*[\"']\s*\]"
            r"|origin\s*:\s*[\"']\*[\"']"
            r"|cors\s*\(\s*\{\s*origin\s*:\s*true"
        ),
        title="CORS ouvert à toutes les origines",
        explanation=(
            "L'API accepte les requêtes de n'importe quel site, sans "
            "restriction d'origine."
        ),
        why_dangerous=(
            "Combiné à l'envoi de cookies ou de jetons, cela permet à un "
            "site tiers de lire les réponses de l'API au nom de "
            "l'utilisateur connecté."
        ),
        potential_impact=[
            "Lecture de données authentifiées par un site tiers",
            "Actions déclenchées depuis un domaine non maîtrisé",
        ],
        recommendations=[
            "Lister explicitement les origines autorisées.",
            "Ne jamais associer `*` à l'envoi d'identifiants.",
        ],
    ),
    # ------------------------------------------------------ Compléments
    SecurityRule(
        rule_id="SSRF001",
        category="ssrf",
        cwe="CWE-918",
        owasp="A10:2021 - Server-Side Request Forgery",
        severity="HIGH",
        confidence=0.6,
        description="Requete sortante vers une URL fournie par l'utilisateur.",
        pattern=_rx(
            r"(?:requests\.(?:get|post|put|delete)|urlopen|axios\.(?:get|post)|"
            r"fetch|file_get_contents|HttpClient)\s*\(\s*"
            r"(?:[\w.]*(?:req|request|params|query|body|input|user)[\w.]*"
            r"|f[\"'][^\"'\n]*\{|`[^`\n]*\$\{)"
        ),
        title="Requête sortante vers une URL non maîtrisée",
        explanation=(
            "L'adresse appelée provient d'une valeur variable, "
            "potentiellement fournie par l'utilisateur."
        ),
        why_dangerous=(
            "Le serveur peut être amené à interroger des ressources "
            "internes inaccessibles depuis l'extérieur (métadonnées cloud, "
            "services d'administration)."
        ),
        potential_impact=[
            "Accès aux services internes du réseau",
            "Vol de jetons d'instance cloud",
        ],
        recommendations=[
            "N'accepter que des URL d'une liste blanche de domaines.",
            "Refuser les adresses privées et de bouclage après résolution.",
        ],
    ),
    SecurityRule(
        rule_id="XXE001",
        category="xxe",
        cwe="CWE-611",
        owasp="A05:2021 - Security Misconfiguration",
        severity="HIGH",
        confidence=0.65,
        description="Analyseur XML autorisant les entites externes.",
        pattern=_rx(
            r"etree\.XMLParser\s*\((?![^)\n]*resolve_entities\s*=\s*False)"
            r"|libxml_disable_entity_loader\s*\(\s*false"
            r"|DocumentBuilderFactory\.newInstance\s*\(\s*\)"
            r"|XMLReaderFactory\.createXMLReader\s*\("
        ),
        title="Analyse XML sans protection contre les entités externes",
        explanation=(
            "L'analyseur XML est créé sans désactiver explicitement les "
            "entités externes."
        ),
        why_dangerous=(
            "Un document XML peut alors demander la lecture de fichiers "
            "locaux ou déclencher des requêtes réseau depuis le serveur."
        ),
        potential_impact=[
            "Lecture de fichiers du serveur",
            "Déni de service par expansion d'entités",
        ],
        recommendations=[
            "Désactiver les entités externes et les DTD sur l'analyseur.",
            "Utiliser `defusedxml` côté Python.",
        ],
    ),
    SecurityRule(
        rule_id="REDIR001",
        category="open_redirect",
        cwe="CWE-601",
        owasp="A01:2021 - Broken Access Control",
        severity="MEDIUM",
        confidence=0.6,
        description="Redirection vers une destination fournie par l'utilisateur.",
        pattern=_rx(
            r"(?:redirect|sendRedirect|Location\s*:)\s*\(?\s*"
            r"[\w.]*(?:req|request|params|query|next|url|return_to|redirect_uri)"
            r"[\w.]*\s*\)?"
        ),
        unless=_rx(r"url_for\(|route\(|reverse\("),
        title="Redirection vers une destination non validée",
        explanation=(
            "La destination de la redirection vient d'une valeur fournie "
            "dans la requête."
        ),
        why_dangerous=(
            "Un lien légitime de votre domaine peut alors envoyer "
            "l'utilisateur vers un site contrôlé par un attaquant, ce qui "
            "rend le hameçonnage très crédible."
        ),
        potential_impact=[
            "Hameçonnage appuyé sur la réputation du domaine",
            "Vol de jeton lors d'un retour d'authentification",
        ],
        recommendations=[
            "N'autoriser que des chemins internes, ou une liste blanche de "
            "domaines.",
        ],
    ),
)


RULES_BY_ID: dict[str, SecurityRule] = {rule.rule_id: rule for rule in RULES}


# --------------------------------------------------------------------------
# Moteur
# --------------------------------------------------------------------------


def _is_comment(line: str, language: str) -> bool:
    stripped = line.strip()
    prefixes = COMMENT_PREFIXES.get(language, COMMENT_PREFIXES["other"])
    return any(stripped.startswith(prefix) for prefix in prefixes)


def _is_ignored(line: str) -> bool:
    lowered = line.lower()
    return any(marker in lowered for marker in IGNORE_MARKERS)


# Formats que SECRET002 reconnait et que le sanitizer du projet ignore :
# AWS, GitHub, Slack. Sans eux, l'extrait recopiait en base la cle meme que
# la regle venait de signaler (`AWS_ACCESS_KEY_ID` echappe au motif
# cle=valeur : aucune frontiere de mot avant `_ID`).
_SIGNATURE_SECRETS = re.compile(
    r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"
    r"|\bgh[pousr]_[A-Za-z0-9]{20,}"
    r"|\bxox[baprs]-[A-Za-z0-9-]{10,}"
)


def redact_snippet(text: str) -> str:
    """Expurge un extrait de code : sanitizer du projet, puis les formats
    de cle que seul ce moteur detecte."""
    return _SIGNATURE_SECRETS.sub(REDACTED, redact_secrets(text) or "")


def _snippet(line: str) -> str:
    """Extrait affichable : tronque et **expurge de tout secret**.

    `redact_secrets` est celui du projet (`app.ai.sanitizer`) : le meme
    qui protege les journaux Wazuh avant envoi au modele. Un secret
    detecte n'est donc jamais recopie tel quel en base ni renvoye.
    """
    cleaned = redact_snippet(line.strip())
    if len(cleaned) > MAX_SNIPPET_LENGTH:
        cleaned = cleaned[:MAX_SNIPPET_LENGTH] + " ..."
    return cleaned


def scan_content(
    content: str,
    language: str = "other",
    changed_lines: Optional[list[int]] = None,
    max_findings: Optional[int] = None,
) -> list[RuleHit]:
    """Applique le catalogue au contenu et retourne les declenchements.

    - Analyse ligne par ligne : rapide, borne, et chaque finding porte un
      emplacement exact utilisable par l'editeur.
    - `changed_lines` restreint l'analyse aux lignes modifiees.
    - Les lignes de commentaire et celles portant un marqueur d'exclusion
      sont ignorees.
    - Le contenu n'est jamais journalise ni execute.
    """
    hits: list[RuleHit] = []
    focus = set(changed_lines or [])
    applicable = [rule for rule in RULES if rule.applies_to(language)]

    for number, line in enumerate(content.splitlines(), start=1):
        if focus and number not in focus:
            continue
        if not line.strip() or _is_comment(line, language) or _is_ignored(line):
            continue

        for rule in applicable:
            match = rule.pattern.search(line)
            if match is None:
                continue
            if rule.unless is not None and rule.unless.search(line):
                continue

            hits.append(
                RuleHit(
                    rule_id=rule.rule_id,
                    category=rule.category,
                    cwe=rule.cwe,
                    owasp=rule.owasp,
                    base_severity=rule.severity,
                    rule_confidence=rule.confidence,
                    title=rule.title,
                    explanation=rule.explanation,
                    why_dangerous=rule.why_dangerous,
                    potential_impact=list(rule.potential_impact),
                    recommendations=list(rule.recommendations),
                    location=CodeLocation(
                        line_start=number,
                        line_end=number,
                        column_start=match.start(),
                        column_end=match.end(),
                        snippet=_snippet(line),
                    ),
                )
            )

            if max_findings is not None and len(hits) >= max_findings:
                logger.info(
                    "Plafond de %s findings atteint, analyse interrompue",
                    max_findings,
                )
                return hits

    return hits


def catalogue() -> list[SecurityRule]:
    """Toutes les regles, pour GET /api/code/rules."""
    return list(RULES)
