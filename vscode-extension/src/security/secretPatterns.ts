/**
 * Catalogue des motifs de détection de secrets.
 *
 * Un motif est un **indice**, jamais une preuve. Le vocabulaire du projet
 * le dit partout : « secret détecté par une règle », pas « secret
 * confirmé ». Chaque entrée porte donc une confiance, et cette confiance
 * voyage jusqu'à l'écran.
 *
 * Deux familles, et l'ordre compte
 * --------------------------------
 *
 *     SIGNATURE   la valeur se reconnaît seule : `sk-proj-…`, `AKIA…`,
 *                 `ghp_…`. Confiance haute, aucun contexte nécessaire.
 *
 *     AFFECTATION une variable au nom évocateur reçoit une valeur :
 *                 `api_key = "…"`. Confiance moindre — c'est le nom de la
 *                 variable qui alerte, pas la valeur.
 *
 * Les motifs de signature sont évalués **avant** les motifs d'affectation.
 * Une clé OpenAI est aussi, littéralement, « une valeur affectée à une
 * variable nommée `api_key` » : sans cet ordre, elle serait signalée deux
 * fois, dont une sous un libellé générique moins utile.
 *
 * Indépendance au langage
 * -----------------------
 *
 * Les motifs d'affectation acceptent `=`, `:`, `=>` et `:=` avec ou sans
 * guillemets. Un seul jeu de motifs couvre ainsi Python, JavaScript,
 * TypeScript, JSON, YAML, TOML, Java, PHP, Go, C#, Ruby et les fichiers de
 * configuration — plutôt qu'une table par langage, qui aurait divergé au
 * premier ajout.
 *
 * Ajouter un motif : une entrée dans `SECRET_PATTERNS`, rien d'autre. Le
 * scanner, les statistiques et les tests la prennent en compte
 * automatiquement. Incrémenter `PATTERNS_VERSION` à chaque changement.
 *
 * Aucune dépendance à `vscode` : ce module est testable en Node pur.
 */

import type { Confidence, Severity } from './securityTypes'

/** Version du catalogue, enregistrée avec chaque balayage. */
export const PATTERNS_VERSION = '1.0.0'

export interface SecretPattern {
  /** Identifiant stable de la règle. Apparaît dans les findings. */
  readonly id: string
  /** Type de secret : clé du catalogue de libellés, côté backend. */
  readonly secretType: string
  /** Libellé anglais court, utilisé dans la preuve expurgée. */
  readonly label: string
  readonly severity: Severity
  readonly confidence: Confidence
  /**
   * Motif, **sans** drapeau global : le scanner le rejoue ligne par ligne
   * et gère lui-même l'itération. Un `lastIndex` partagé entre deux
   * fichiers produirait des détections manquantes, au hasard.
   */
  readonly pattern: RegExp
  /**
   * Groupe de capture portant la valeur. `0` = la correspondance entière.
   *
   * C'est ce groupe, et lui seul, qui est soumis au contrôle de faux
   * positifs puis expurgé.
   */
  readonly valueGroup: number
  /** Caractères de tête conservés dans la preuve. Jamais plus de 8. */
  readonly keep: number
  /**
   * La valeur doit-elle avoir une entropie suffisante ?
   *
   * Vrai pour les motifs d'affectation, dont le déclencheur est le nom de
   * la variable : sans ce contrôle, `password = "admin"` et
   * `password = "aB3xK9pQ7mZ2"` auraient la même confiance.
   */
  readonly requiresEntropy: boolean
}

/**
 * Longueur minimale d'une valeur candidate pour les motifs d'affectation.
 *
 * En dessous, on est presque toujours face à un drapeau (`"true"`), un
 * mode (`"none"`) ou un identifiant court — pas face à un secret.
 */
export const MIN_ASSIGNED_VALUE_LENGTH = 8

/**
 * Noms de variables qui annoncent un secret.
 *
 * Réutilisé par plusieurs motifs d'affectation ; centralisé pour qu'un
 * ajout profite à tous.
 */
const SECRET_NAMES =
  'api[_-]?key|apikey|api[_-]?secret|app[_-]?secret|client[_-]?secret|' +
  'secret[_-]?key|private[_-]?token|access[_-]?token|auth[_-]?token|' +
  'refresh[_-]?token|session[_-]?secret|encryption[_-]?key|signing[_-]?key'

const PASSWORD_NAMES =
  'password|passwd|pwd|db[_-]?pass(?:word)?|database[_-]?password|' +
  'mysql[_-]?password|postgres[_-]?password|admin[_-]?password|' +
  'root[_-]?password|smtp[_-]?password'

/** Séparateur d'affectation, toutes syntaxes confondues. */
const ASSIGN = String.raw`\s*(?::=|=>|[:=])\s*`

/**
 * Valeur entre guillemets, ou nue jusqu'au premier séparateur.
 *
 * Les accolades sont **exclues** de la capture. Sans cela, `${API_KEY}`
 * produirait la capture partielle `${API_KEY` — qui ne ressemble plus à
 * aucune forme de substitution connue et passerait le contrôle de faux
 * positifs. Couper au plus tôt vaut mieux que rattraper ensuite.
 */
const VALUE = String.raw`["'\`]?([^\s"'\`,;)\[\]{}<>]{8,200})["'\`]?`

// --------------------------------------------------------------------------
// Motifs de signature — la valeur se reconnaît seule
// --------------------------------------------------------------------------

const SIGNATURE_PATTERNS: readonly SecretPattern[] = [
  {
    id: 'secret.openai_api_key',
    secretType: 'openai_api_key',
    label: 'OpenAI API key detected',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    // (?!ant-) ecarte les cles Anthropic, qui partagent le prefixe
    // `sk-`. Une exclusion explicite plutot qu'un ordre d'evaluation :
    // la dependance a l'ordre se serait cassee au premier motif insere
    // entre les deux, sans que rien ne le signale.
    pattern: /\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/,
    valueGroup: 0,
    keep: 8,
    requiresEntropy: false,
  },
  {
    id: 'secret.anthropic_api_key',
    secretType: 'anthropic_api_key',
    label: 'Anthropic API key detected',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}/,
    valueGroup: 0,
    keep: 8,
    requiresEntropy: false,
  },
  {
    id: 'secret.aws_access_key_id',
    secretType: 'aws_access_key_id',
    label: 'AWS access key ID detected',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    // Préfixes AWS : utilisateur, session, bearer, rôle de service.
    pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/,
    valueGroup: 0,
    keep: 4,
    requiresEntropy: false,
  },
  {
    id: 'secret.aws_secret_access_key',
    secretType: 'aws_secret_access_key',
    label: 'AWS secret access key detected',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    // La clé secrète n'a pas de préfixe : seul le nom de la variable
    // permet de la reconnaître, avec sa longueur exacte de 40.
    pattern: /aws[_-]?secret[_-]?access[_-]?key["'\s]*[:=]\s*["']?([A-Za-z0-9/+=]{40})/i,
    valueGroup: 1,
    keep: 4,
    requiresEntropy: false,
  },
  {
    id: 'secret.github_token',
    secretType: 'github_token',
    label: 'GitHub token detected',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})/,
    valueGroup: 0,
    keep: 4,
    requiresEntropy: false,
  },
  {
    id: 'secret.gitlab_token',
    secretType: 'gitlab_token',
    label: 'GitLab token detected',
    severity: 'HIGH',
    confidence: 'HIGH',
    pattern: /\bglpat-[A-Za-z0-9_-]{16,}/,
    valueGroup: 0,
    keep: 6,
    requiresEntropy: false,
  },
  {
    id: 'secret.slack_token',
    secretType: 'slack_token',
    label: 'Slack token detected',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    pattern: /\bxox[abposr]-[A-Za-z0-9-]{10,}/,
    valueGroup: 0,
    keep: 5,
    requiresEntropy: false,
  },
  {
    id: 'secret.slack_webhook',
    secretType: 'slack_webhook',
    label: 'Slack webhook URL detected',
    severity: 'HIGH',
    confidence: 'HIGH',
    pattern: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_/+]{16,}/,
    valueGroup: 0,
    keep: 8,
    requiresEntropy: false,
  },
  {
    id: 'secret.discord_webhook',
    secretType: 'discord_webhook',
    label: 'Discord webhook URL detected',
    severity: 'HIGH',
    confidence: 'HIGH',
    pattern:
      /https:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d{10,}\/[A-Za-z0-9_-]{30,}/,
    valueGroup: 0,
    keep: 8,
    requiresEntropy: false,
  },
  {
    id: 'secret.google_api_key',
    secretType: 'google_api_key',
    label: 'Google API key detected',
    severity: 'HIGH',
    confidence: 'HIGH',
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/,
    valueGroup: 0,
    keep: 8,
    requiresEntropy: false,
  },
  {
    id: 'secret.stripe_secret_key',
    secretType: 'stripe_secret_key',
    label: 'Stripe secret key detected',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    pattern: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}/,
    valueGroup: 0,
    keep: 8,
    requiresEntropy: false,
  },
  {
    id: 'secret.stripe_test_key',
    secretType: 'stripe_secret_key',
    label: 'Stripe test key detected',
    severity: 'MEDIUM',
    // Une clé de test n'ouvre aucun accès aux paiements réels. La
    // signaler reste utile — elle trahit une clé écrite en dur — mais la
    // classer critique diluerait les vraies alertes.
    confidence: 'HIGH',
    pattern: /\b(?:sk|rk)_test_[A-Za-z0-9]{16,}/,
    valueGroup: 0,
    keep: 8,
    requiresEntropy: false,
  },
  {
    id: 'secret.sendgrid_api_key',
    secretType: 'sendgrid_api_key',
    label: 'SendGrid API key detected',
    severity: 'HIGH',
    confidence: 'HIGH',
    pattern: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/,
    valueGroup: 0,
    keep: 3,
    requiresEntropy: false,
  },
  {
    id: 'secret.mailgun_api_key',
    secretType: 'mailgun_api_key',
    label: 'Mailgun API key detected',
    severity: 'HIGH',
    confidence: 'MEDIUM',
    pattern: /\bkey-[0-9a-zA-Z]{32}\b/,
    valueGroup: 0,
    keep: 4,
    requiresEntropy: false,
  },
  {
    id: 'secret.npm_token',
    secretType: 'npm_token',
    label: 'npm token detected',
    severity: 'HIGH',
    confidence: 'HIGH',
    pattern: /\bnpm_[A-Za-z0-9]{30,}/,
    valueGroup: 0,
    keep: 4,
    requiresEntropy: false,
  },
  {
    id: 'secret.private_key',
    secretType: 'private_key',
    label: 'Private key block detected',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    // L'en-tête suffit : le corps de la clé n'est jamais capturé, donc
    // jamais présent en mémoire au-delà de la ligne lue.
    pattern: /-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/,
    valueGroup: 0,
    keep: 0,
    requiresEntropy: false,
  },
  {
    id: 'secret.azure_storage_key',
    secretType: 'azure_storage_key',
    label: 'Azure storage account key detected',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    pattern: /AccountKey=([A-Za-z0-9+/=]{40,})/,
    valueGroup: 1,
    keep: 4,
    requiresEntropy: false,
  },
  {
    id: 'secret.gcp_service_account',
    secretType: 'gcp_service_account',
    label: 'Google Cloud service account key detected',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    pattern: /"type"\s*:\s*"service_account"/,
    valueGroup: 0,
    keep: 0,
    requiresEntropy: false,
  },
  {
    id: 'secret.jwt_token',
    secretType: 'jwt_token',
    label: 'JWT detected',
    severity: 'HIGH',
    // Un JWT peut être expiré, ou de démonstration : la forme est
    // formelle, l'exploitabilité ne l'est pas.
    confidence: 'MEDIUM',
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/,
    valueGroup: 0,
    keep: 6,
    requiresEntropy: false,
  },
  {
    id: 'secret.database_url',
    secretType: 'database_credentials',
    label: 'Database URL with credentials detected',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    // Le mot de passe est le seul groupe capturé : l'hôte et la base ne
    // sont pas repris dans la preuve.
    pattern:
      /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|mssql|ftp|sftp):\/\/[^\s:@/"']+:([^\s:@/"']{3,})@/,
    valueGroup: 1,
    keep: 2,
    requiresEntropy: false,
  },
  {
    id: 'secret.connection_string_password',
    secretType: 'connection_string_password',
    label: 'Connection string password detected',
    severity: 'HIGH',
    confidence: 'MEDIUM',
    // Forme ADO.NET / JDBC : `Server=…;Password=…;`
    pattern: /\b(?:Password|Pwd)\s*=\s*([^;"'\s]{4,})\s*;/i,
    valueGroup: 1,
    keep: 2,
    requiresEntropy: false,
  },
  {
    id: 'secret.authorization_bearer',
    secretType: 'bearer_token',
    label: 'Bearer token detected',
    severity: 'HIGH',
    confidence: 'MEDIUM',
    pattern: /\bBearer\s+([A-Za-z0-9._~+/-]{20,}={0,2})/,
    valueGroup: 1,
    keep: 4,
    requiresEntropy: false,
  },
  {
    id: 'secret.authorization_basic',
    secretType: 'basic_auth',
    label: 'Basic authorization header detected',
    severity: 'HIGH',
    confidence: 'MEDIUM',
    pattern: /\bBasic\s+([A-Za-z0-9+/]{16,}={0,2})/,
    valueGroup: 1,
    keep: 4,
    requiresEntropy: false,
  },
]

// --------------------------------------------------------------------------
// Motifs d'affectation — c'est le nom de la variable qui alerte
// --------------------------------------------------------------------------

const ASSIGNMENT_PATTERNS: readonly SecretPattern[] = [
  {
    id: 'secret.jwt_secret',
    secretType: 'jwt_secret',
    label: 'JWT signing secret detected',
    severity: 'CRITICAL',
    confidence: 'MEDIUM',
    pattern: new RegExp(
      String.raw`\b(?:jwt[_-]?secret|jwt[_-]?signing[_-]?key|jwt[_-]?key|token[_-]?secret)\b` +
        ASSIGN +
        VALUE,
      'i'
    ),
    valueGroup: 1,
    keep: 3,
    requiresEntropy: true,
  },
  {
    id: 'secret.oauth_client_secret',
    secretType: 'oauth_client_secret',
    label: 'OAuth client secret detected',
    severity: 'HIGH',
    confidence: 'MEDIUM',
    pattern: new RegExp(
      String.raw`\b(?:client[_-]?secret|consumer[_-]?secret|oauth[_-]?secret)\b` +
        ASSIGN +
        VALUE,
      'i'
    ),
    valueGroup: 1,
    keep: 3,
    requiresEntropy: true,
  },
  {
    id: 'secret.generic_api_key',
    secretType: 'generic_api_key',
    label: 'API key detected',
    severity: 'HIGH',
    confidence: 'MEDIUM',
    pattern: new RegExp(String.raw`\b(?:${SECRET_NAMES})\b` + ASSIGN + VALUE, 'i'),
    valueGroup: 1,
    keep: 3,
    requiresEntropy: true,
  },
  {
    id: 'secret.password_assignment',
    secretType: 'password',
    label: 'Hardcoded password detected',
    severity: 'HIGH',
    confidence: 'MEDIUM',
    pattern: new RegExp(
      String.raw`\b(?:${PASSWORD_NAMES})\b` + ASSIGN + String.raw`["'\`]?([^\s"'\`,;)\]}<>]{4,200})["'\`]?`,
      'i'
    ),
    valueGroup: 1,
    keep: 2,
    // Un mot de passe faible reste un mot de passe : l'entropie module la
    // confiance, elle ne supprime pas le finding.
    requiresEntropy: true,
  },
]

/**
 * Catalogue complet, dans l'ordre d'évaluation.
 *
 * Signature d'abord, affectation ensuite : voir l'en-tête du fichier.
 */
export const SECRET_PATTERNS: readonly SecretPattern[] = [
  ...SIGNATURE_PATTERNS,
  ...ASSIGNMENT_PATTERNS,
]

/** Retrouve un motif par son identifiant. Sert aux tests et au diagnostic. */
export function patternById(id: string): SecretPattern | undefined {
  return SECRET_PATTERNS.find((pattern) => pattern.id === id)
}
