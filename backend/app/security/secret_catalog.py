"""Vocabulaire des types de secrets : titre, explication, remediation.

Pourquoi ce catalogue vit cote backend alors que la detection tourne cote
extension
---------------------------------------------------------------------------

La detection doit etre locale : lire un fichier pour y chercher un secret
et envoyer ce fichier a un serveur pour la meme raison seraient deux
choses tres differentes, et seule la premiere est acceptable. Mais la
**redaction** du message affiche n'a aucune raison d'etre dupliquee dans
chaque client : elle suit le meme principe que `app.code.rules`, ou le
backend redige et l'extension met en forme.

Consequence pratique : une extension d'une version anterieure, qui
connaitrait moins de types ou les nommerait moins bien, produit quand meme
un message correct — c'est le backend qui resout le libelle a partir du
`secret_type`.

Le type inconnu n'est pas une erreur : `_FALLBACK` produit un message
prudent, et le finding reste affiche. Taire un secret parce qu'on ne sait
pas le nommer serait le pire des deux mondes.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SecretTypeInfo:
    """Ce qu'on dit a l'utilisateur d'un type de secret donne."""

    title: str
    description: str
    remediation: str
    references: tuple[str, ...] = field(default=("CWE-798",))


# Remediation commune a toutes les cles de fournisseur : l'ordre des deux
# gestes n'est pas indifferent. **Revoquer d'abord** — tant que la cle est
# valide, la retirer du code ne protege de rien : elle reste dans
# l'historique Git, dans les caches de build et sur les postes qui ont
# clone le depot.
_ROTATE_FIRST = (
    "Révoquez immédiatement cette clé chez le fournisseur, puis retirez-la "
    "du code et remplacez-la par une variable d'environnement ou un "
    "gestionnaire de secrets. La révocation passe en premier : tant que la "
    "clé est valide, elle reste exploitable depuis l'historique Git."
)

_ROTATE_CREDENTIAL = (
    "Changez ce mot de passe, puis retirez-le du code et chargez-le depuis "
    "une variable d'environnement ou un gestionnaire de secrets. Le "
    "changement passe en premier : la valeur reste lisible dans "
    "l'historique Git même après suppression du fichier."
)

CATALOGUE: dict[str, SecretTypeInfo] = {
    "openai_api_key": SecretTypeInfo(
        title="Clé d'API OpenAI écrite en dur",
        description=(
            "Une clé d'API OpenAI apparaît dans le code source. Toute "
            "personne ayant accès au dépôt peut l'utiliser, et la "
            "consommation sera facturée au propriétaire du compte."
        ),
        remediation=_ROTATE_FIRST,
    ),
    "anthropic_api_key": SecretTypeInfo(
        title="Clé d'API Anthropic écrite en dur",
        description=(
            "Une clé d'API Anthropic apparaît dans le code source. Elle "
            "donne accès au compte et à sa facturation."
        ),
        remediation=_ROTATE_FIRST,
    ),
    "aws_access_key_id": SecretTypeInfo(
        title="Identifiant de clé d'accès AWS écrit en dur",
        description=(
            "Un identifiant de clé d'accès AWS apparaît dans le code. "
            "Associé à sa clé secrète, il ouvre l'accès aux ressources du "
            "compte AWS."
        ),
        remediation=_ROTATE_FIRST,
        references=("CWE-798", "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"),
    ),
    "aws_secret_access_key": SecretTypeInfo(
        title="Clé secrète AWS écrite en dur",
        description=(
            "Une clé secrète AWS apparaît dans le code. C'est la moitié "
            "authentifiante d'une paire d'accès : sa divulgation suffit à "
            "compromettre le compte si l'identifiant est connu."
        ),
        remediation=_ROTATE_FIRST,
    ),
    "github_token": SecretTypeInfo(
        title="Jeton GitHub écrit en dur",
        description=(
            "Un jeton d'accès GitHub apparaît dans le code. Selon ses "
            "portées, il permet de lire ou de modifier des dépôts, des "
            "workflows et des secrets d'organisation."
        ),
        remediation=_ROTATE_FIRST,
    ),
    "gitlab_token": SecretTypeInfo(
        title="Jeton GitLab écrit en dur",
        description=(
            "Un jeton d'accès GitLab apparaît dans le code. Il peut donner "
            "accès aux dépôts et aux pipelines du groupe."
        ),
        remediation=_ROTATE_FIRST,
    ),
    "slack_token": SecretTypeInfo(
        title="Jeton Slack écrit en dur",
        description=(
            "Un jeton d'API Slack apparaît dans le code. Il permet de lire "
            "et d'écrire dans l'espace de travail au nom de l'application."
        ),
        remediation=_ROTATE_FIRST,
    ),
    "slack_webhook": SecretTypeInfo(
        title="URL de webhook Slack écrite en dur",
        description=(
            "Une URL de webhook Slack apparaît dans le code. Elle constitue "
            "à elle seule une autorisation de publier dans le canal."
        ),
        remediation=(
            "Révoquez ce webhook dans la configuration Slack, puis chargez "
            "la nouvelle URL depuis une variable d'environnement."
        ),
    ),
    "discord_webhook": SecretTypeInfo(
        title="URL de webhook Discord écrite en dur",
        description=(
            "Une URL de webhook Discord apparaît dans le code. Elle "
            "constitue à elle seule une autorisation de publier dans le "
            "salon."
        ),
        remediation=(
            "Supprimez ce webhook dans la configuration Discord, puis "
            "chargez la nouvelle URL depuis une variable d'environnement."
        ),
    ),
    "google_api_key": SecretTypeInfo(
        title="Clé d'API Google écrite en dur",
        description=(
            "Une clé d'API Google apparaît dans le code. Sans restriction "
            "de référent ou d'adresse IP, elle est utilisable par "
            "n'importe qui."
        ),
        remediation=_ROTATE_FIRST,
    ),
    "stripe_secret_key": SecretTypeInfo(
        title="Clé secrète Stripe écrite en dur",
        description=(
            "Une clé secrète Stripe apparaît dans le code. Elle autorise "
            "des opérations sur le compte de paiement."
        ),
        remediation=_ROTATE_FIRST,
    ),
    "sendgrid_api_key": SecretTypeInfo(
        title="Clé d'API SendGrid écrite en dur",
        description=(
            "Une clé d'API SendGrid apparaît dans le code. Elle permet "
            "d'envoyer des courriels au nom du domaine configuré."
        ),
        remediation=_ROTATE_FIRST,
    ),
    "npm_token": SecretTypeInfo(
        title="Jeton npm écrit en dur",
        description=(
            "Un jeton d'authentification npm apparaît dans le code. Il "
            "peut permettre de publier des paquets sous l'identité du "
            "propriétaire."
        ),
        remediation=_ROTATE_FIRST,
    ),
    "private_key": SecretTypeInfo(
        title="Clé privée écrite en dur",
        description=(
            "Un bloc de clé privée apparaît dans le code. Une clé privée "
            "n'a aucune raison de figurer dans un dépôt : elle authentifie "
            "son porteur."
        ),
        remediation=(
            "Retirez ce bloc du dépôt, révoquez la clé et générez-en une "
            "nouvelle. Considérez comme compromis tout ce que cette clé "
            "protégeait."
        ),
        references=("CWE-798", "CWE-321"),
    ),
    "jwt_token": SecretTypeInfo(
        title="Jeton JWT écrit en dur",
        description=(
            "Un jeton JWT apparaît dans le code. S'il n'est pas expiré, il "
            "constitue une session utilisable telle quelle."
        ),
        remediation=(
            "Retirez ce jeton du code. S'il correspond à une session "
            "réelle, invalidez-la et faites tourner la clé de signature."
        ),
        references=("CWE-798", "CWE-522"),
    ),
    "jwt_secret": SecretTypeInfo(
        title="Clé de signature JWT écrite en dur",
        description=(
            "La clé qui signe les jetons de l'application apparaît dans le "
            "code. Qui la connaît peut forger un jeton valide pour "
            "n'importe quel utilisateur, y compris un administrateur."
        ),
        remediation=(
            "Faites tourner cette clé de signature — tous les jetons émis "
            "deviennent alors invalides — et chargez la nouvelle valeur "
            "depuis une variable d'environnement."
        ),
        references=("CWE-798", "CWE-321"),
    ),
    "bearer_token": SecretTypeInfo(
        title="Jeton Bearer écrit en dur",
        description=(
            "Un en-tête d'autorisation Bearer contient un jeton écrit en "
            "dur. Il authentifie directement l'appelant auprès du service "
            "visé."
        ),
        remediation=(
            "Retirez ce jeton du code, révoquez-le auprès du service "
            "concerné et chargez-le depuis la configuration."
        ),
        references=("CWE-798", "CWE-522"),
    ),
    "basic_auth": SecretTypeInfo(
        title="Identifiants HTTP Basic écrits en dur",
        description=(
            "Un en-tête d'autorisation Basic contient des identifiants "
            "encodés en Base64. L'encodage Base64 n'est pas un "
            "chiffrement : la valeur est lisible en clair."
        ),
        remediation=_ROTATE_CREDENTIAL,
        references=("CWE-798", "CWE-522"),
    ),
    "generic_api_key": SecretTypeInfo(
        title="Clé d'API écrite en dur",
        description=(
            "Une valeur affectée à une variable de type clé d'API apparaît "
            "dans le code."
        ),
        remediation=_ROTATE_FIRST,
    ),
    "oauth_client_secret": SecretTypeInfo(
        title="Secret client OAuth écrit en dur",
        description=(
            "Un secret client OAuth apparaît dans le code. Avec "
            "l'identifiant client, il permet d'obtenir des jetons au nom "
            "de l'application."
        ),
        remediation=_ROTATE_FIRST,
    ),
    "password": SecretTypeInfo(
        title="Mot de passe écrit en dur",
        description=(
            "Un mot de passe est affecté directement dans le code ou dans "
            "un fichier de configuration versionné."
        ),
        remediation=_ROTATE_CREDENTIAL,
        references=("CWE-798", "CWE-259"),
    ),
    "database_credentials": SecretTypeInfo(
        title="Identifiants de base de données dans une URL de connexion",
        description=(
            "Une URL de connexion à une base de données contient un mot de "
            "passe en clair. Elle donne accès aux données de "
            "l'application."
        ),
        remediation=(
            "Changez ce mot de passe, puis composez l'URL de connexion à "
            "partir de variables d'environnement plutôt que de l'écrire "
            "entièrement dans le code."
        ),
        references=("CWE-798", "CWE-259"),
    ),
    "connection_string_password": SecretTypeInfo(
        title="Mot de passe dans une chaîne de connexion",
        description=(
            "Une chaîne de connexion contient un mot de passe en clair."
        ),
        remediation=_ROTATE_CREDENTIAL,
        references=("CWE-798", "CWE-259"),
    ),
    "azure_storage_key": SecretTypeInfo(
        title="Clé de compte de stockage Azure écrite en dur",
        description=(
            "Une clé de compte de stockage Azure apparaît dans le code. "
            "Elle donne un accès complet au compte de stockage."
        ),
        remediation=_ROTATE_FIRST,
    ),
    "gcp_service_account": SecretTypeInfo(
        title="Compte de service Google Cloud écrit en dur",
        description=(
            "Un fichier de compte de service Google Cloud, clé privée "
            "comprise, apparaît dans le dépôt. Il authentifie une identité "
            "de l'infrastructure."
        ),
        remediation=(
            "Supprimez ce fichier du dépôt, révoquez la clé dans la "
            "console Google Cloud et utilisez une identité de charge de "
            "travail plutôt qu'un fichier de clé."
        ),
    ),
    "mailgun_api_key": SecretTypeInfo(
        title="Clé d'API Mailgun écrite en dur",
        description=(
            "Une clé d'API Mailgun apparaît dans le code. Elle permet "
            "d'envoyer des courriels au nom du domaine configuré."
        ),
        remediation=_ROTATE_FIRST,
    ),
}

# Type non reconnu. Le message reste prudent — « ressemble à » — parce que
# c'est exactement l'etat de la connaissance a ce moment-la.
_FALLBACK = SecretTypeInfo(
    title="Valeur sensible écrite en dur",
    description=(
        "Une valeur qui ressemble à un identifiant ou à une clé apparaît "
        "dans le code source."
    ),
    remediation=(
        "Vérifiez la nature de cette valeur. S'il s'agit bien d'un secret, "
        "faites-la tourner puis chargez-la depuis une variable "
        "d'environnement ou un gestionnaire de secrets."
    ),
)


def describe(secret_type: str) -> SecretTypeInfo:
    """Vocabulaire associe a un type de secret. Jamais `None`."""
    return CATALOGUE.get((secret_type or "").strip().lower(), _FALLBACK)


def known_types() -> tuple[str, ...]:
    """Types reconnus, pour les tests et le diagnostic."""
    return tuple(sorted(CATALOGUE))
