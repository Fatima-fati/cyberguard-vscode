/**
 * Règles de sécurité d'API. Déterministes, locales, motivées.
 *
 * Chaque règle porte, en plus de son motif, **la raison pour laquelle
 * elle existe** et le niveau de confiance qu'on peut accorder à sa
 * détection. Ces deux informations ne sont pas décoratives : c'est ce qui
 * permet de tenir la règle que la phase s'impose —
 *
 *     ne jamais affirmer qu'une API est vulnérable
 *     quand la preuve ne le montre pas
 *
 * La confiance, et ce qu'elle décide
 * ----------------------------------
 *
 *     HIGH     le motif prouve le problème à lui seul
 *              `allow_origins=["*"]` avec `allow_credentials=True`
 *     MEDIUM   le motif montre une forme risquée, dont le contexte
 *              pourrait innocenter — un `http://` peut viser un service
 *              interne
 *     LOW      indice, pas preuve. Plafonné à MEDIUM à l'affichage par
 *              `cappedSeverity`, qui est déjà la règle du projet
 *
 * Le backend applique `apply_confidence` : une détection de faible
 * confiance ne s'affiche **jamais** en CRITICAL. Une liste de findings
 * critiques dont un sur deux est faux cesse d'être lue, et le jour où un
 * vrai problème y figure, il passe inaperçu.
 *
 * Aucune dépendance à `vscode` : ce module est testable en Node pur.
 */

import type { Confidence, Severity } from '../security/securityTypes'

/** Identifiant d'un problème d'API. Stable : il sert d'empreinte. */
export type ApiIssueType =
  | 'unauthenticated_endpoint'
  | 'missing_authorization'
  | 'cors_wildcard_with_credentials'
  | 'cors_wildcard'
  | 'insecure_transport'
  | 'debug_endpoint_exposed'
  | 'debug_mode_enabled'
  | 'tls_verification_disabled'
  | 'hardcoded_api_credential'
  | 'permissive_api_configuration'

export interface ApiRule {
  readonly id: string
  readonly issue: ApiIssueType
  readonly severity: Severity
  readonly confidence: Confidence
  readonly title: string
  /** Ce que le motif établit. Affiché tel quel. */
  readonly description: string
  /** Ce qu'il faut faire. Jamais « corrigez ceci » sans dire comment. */
  readonly remediation: string
  readonly references: readonly string[]
}

// --------------------------------------------------------------------------
// Règles portées par une route
// --------------------------------------------------------------------------

export const RULE_UNAUTHENTICATED: ApiRule = {
  id: 'API-AUTH-001',
  issue: 'unauthenticated_endpoint',
  severity: 'HIGH',
  confidence: 'MEDIUM',
  title: 'Endpoint modifiant un état sans authentification apparente',
  description:
    'Cette route accepte une méthode qui modifie un état (POST, PUT, ' +
    'PATCH ou DELETE) et aucune marque d’authentification n’a été ' +
    'trouvée à proximité de sa déclaration, ni globalement dans ce ' +
    'fichier.',
  remediation:
    'Vérifiez que cette route est bien protégée. Si l’authentification ' +
    'est posée ailleurs (middleware monté dans un autre fichier, ' +
    'configuration du serveur), ce signalement est un faux positif : ' +
    'écartez-le. Sinon, ajoutez la dépendance ou le décorateur ' +
    'd’authentification de votre framework.',
  references: ['CWE-306', 'OWASP API2:2023'],
}

export const RULE_PUBLIC_STATE_CHANGE: ApiRule = {
  id: 'API-AUTH-002',
  issue: 'unauthenticated_endpoint',
  severity: 'HIGH',
  confidence: 'HIGH',
  title: 'Endpoint explicitement public alors qu’il modifie un état',
  description:
    'Cette route se déclare explicitement ouverte (AllowAny, ' +
    'permission_classes vides, AllowAnonymous) et accepte une méthode ' +
    'qui modifie un état. La décision est écrite dans le code : ce n’est ' +
    'pas une omission.',
  remediation:
    'Confirmez que cette route doit être atteignable sans ' +
    'authentification. Une inscription ou un webhook signé le ' +
    'justifient ; une suppression de ressource, presque jamais.',
  references: ['CWE-306', 'OWASP API2:2023'],
}

export const RULE_SENSITIVE_PUBLIC: ApiRule = {
  id: 'API-AUTH-003',
  issue: 'unauthenticated_endpoint',
  severity: 'HIGH',
  confidence: 'MEDIUM',
  title: 'Route sensible sans authentification apparente',
  description:
    'Le chemin de cette route désigne une surface habituellement ' +
    'réservée (administration, configuration, données utilisateur, ' +
    'export) et aucune marque d’authentification n’a été trouvée.',
  remediation:
    'Vérifiez la protection de cette route. Si elle est protégée ' +
    'ailleurs, écartez ce signalement ; l’agent ne voit que ce qui est ' +
    'écrit dans ce fichier.',
  references: ['CWE-306', 'OWASP API1:2023'],
}

export const RULE_MISSING_AUTHORIZATION: ApiRule = {
  id: 'API-AUTHZ-001',
  issue: 'missing_authorization',
  severity: 'MEDIUM',
  confidence: 'MEDIUM',
  title: 'Route sensible authentifiée sans contrôle d’autorisation',
  description:
    'Cette route vérifie **qui** appelle, mais aucune vérification de ' +
    'rôle, de permission ou de portée n’a été trouvée. Savoir qui ' +
    'appelle ne dit pas qu’il a le droit d’appeler : c’est la faille ' +
    'd’API la plus répandue.',
  remediation:
    'Ajoutez une vérification de rôle ou de permission adaptée à votre ' +
    'framework, ou confirmez que tout utilisateur authentifié a ' +
    'légitimement accès à cette ressource.',
  references: ['CWE-862', 'OWASP API5:2023'],
}

// --------------------------------------------------------------------------
// Règles portées par une ligne de configuration
// --------------------------------------------------------------------------

/** Une règle applicable ligne par ligne, avec son motif. */
export interface LineRule extends ApiRule {
  readonly pattern: RegExp
  /**
   * Second motif à chercher **dans tout le fichier** pour confirmer.
   *
   * Sert au cas CORS : `allow_origins=["*"]` seul est discutable ;
   * accompagné de `allow_credentials=True`, il est formellement
   * dangereux, parce que le navigateur enverra les cookies de session à
   * n’importe quelle origine.
   */
  readonly confirmedBy?: RegExp
  /** Motif qui **annule** la règle quand il est présent sur la ligne. */
  readonly unless?: RegExp
}

export const LINE_RULES: readonly LineRule[] = [
  // --- CORS -------------------------------------------------------------
  {
    id: 'API-CORS-001',
    issue: 'cors_wildcard_with_credentials',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    title: 'CORS ouvert à toute origine avec envoi des identifiants',
    description:
      'La configuration CORS accepte toutes les origines (*) **et** ' +
      'autorise l’envoi des identifiants. Le navigateur transmettra donc ' +
      'les cookies de session à une page hébergée par n’importe qui, qui ' +
      'pourra agir au nom de l’utilisateur connecté.',
    remediation:
      'Remplacez le joker par la liste explicite des origines ' +
      'autorisées. Les deux réglages ne doivent jamais coexister — la ' +
      'plupart des navigateurs refusent d’ailleurs cette combinaison, ce ' +
      'qui masque le problème en développement.',
    references: ['CWE-942', 'OWASP API8:2023'],
    pattern:
      /(?:allow_origins|origin|Access-Control-Allow-Origin|AllowedOrigins|allowedOrigins)\s*[=:]\s*\[?\s*['"`]\*['"`]/i,
    confirmedBy:
      /(?:allow_credentials|credentials|AllowCredentials|withCredentials)\s*[=:]\s*(?:True|true|1)/,
  },
  {
    id: 'API-CORS-002',
    issue: 'cors_wildcard',
    severity: 'MEDIUM',
    confidence: 'MEDIUM',
    title: 'CORS ouvert à toute origine',
    description:
      'La configuration CORS accepte toutes les origines. Sans envoi ' +
      'd’identifiants, l’impact reste limité, mais toute page du web peut ' +
      'lire les réponses de cette API.',
    remediation:
      'Restreignez les origines à celles que vous contrôlez. Si l’API ' +
      'est publique et ne renvoie aucune donnée privée, ce réglage peut ' +
      'être intentionnel : écartez alors ce signalement.',
    references: ['CWE-942', 'OWASP API8:2023'],
    pattern:
      /(?:allow_origins|Access-Control-Allow-Origin|AllowedOrigins|allowedOrigins)\s*[=:]\s*\[?\s*['"`]\*['"`]/i,
  },
  {
    id: 'API-CORS-003',
    issue: 'permissive_api_configuration',
    severity: 'LOW',
    confidence: 'MEDIUM',
    title: 'CORS autorisant toutes les méthodes et tous les en-têtes',
    description:
      'La configuration CORS accepte toutes les méthodes ou tous les ' +
      'en-têtes. Ce n’est pas une faille en soi, mais cela élargit la ' +
      'surface exposée au-delà de ce que l’API utilise réellement.',
    remediation:
      'Déclarez les méthodes et en-têtes effectivement employés.',
    references: ['CWE-942'],
    pattern: /(?:allow_methods|allow_headers|allowedMethods|allowedHeaders)\s*[=:]\s*\[?\s*['"`]\*['"`]/i,
  },

  // --- Transport --------------------------------------------------------
  {
    id: 'API-TLS-001',
    issue: 'tls_verification_disabled',
    severity: 'HIGH',
    confidence: 'HIGH',
    title: 'Vérification du certificat TLS désactivée',
    description:
      'Cet appel désactive la vérification du certificat du serveur. La ' +
      'connexion reste chiffrée, mais n’importe qui en position ' +
      'd’intermédiaire peut la déchiffrer et la modifier : le chiffrement ' +
      'sans authentification du pair ne protège de rien.',
    remediation:
      'Rétablissez la vérification. Pour un certificat interne, ajoutez ' +
      'l’autorité de certification au magasin de confiance plutôt que de ' +
      'désactiver le contrôle.',
    references: ['CWE-295', 'OWASP API8:2023'],
    pattern:
      /\b(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*(?:,|=>)\s*(?:false|0)|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|ServerCertificateCustomValidationCallback)/i,
  },
  {
    id: 'API-TLS-002',
    issue: 'insecure_transport',
    severity: 'MEDIUM',
    confidence: 'MEDIUM',
    title: 'Appel d’API en HTTP non chiffré',
    description:
      'Une URL d’API en `http://` apparaît dans ce fichier. Le trafic — ' +
      'y compris les jetons d’authentification qu’il transporte — circule ' +
      'en clair.',
    remediation:
      'Utilisez `https://`. Si cette adresse désigne un service interne ' +
      'non exposé, ce signalement est un faux positif : écartez-le.',
    references: ['CWE-319', 'OWASP API8:2023'],
    // Les adresses locales sont exclues : un `http://127.0.0.1:8000` de
    // développement n'est pas un problème de transport, et le signaler
    // noierait les vrais cas.
    pattern: /['"`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|host\.docker\.internal)[\w.-]+/i,
    unless: /\bxmlns\b|\bschemaLocation\b|w3\.org|\.dtd\b|\bDOCTYPE\b/i,
  },

  // --- Débogage et surfaces exposées ------------------------------------
  {
    id: 'API-DEBUG-001',
    issue: 'debug_mode_enabled',
    severity: 'HIGH',
    confidence: 'HIGH',
    title: 'Mode débogage activé',
    description:
      'Le mode débogage est activé. Il expose des traces d’exécution, ' +
      'la configuration et, selon le framework, une console d’évaluation ' +
      'de code accessible depuis une page d’erreur.',
    remediation:
      'Désactivez le mode débogage et pilotez-le par une variable ' +
      'd’environnement, jamais par une valeur écrite dans le code.',
    references: ['CWE-489', 'OWASP API8:2023'],
    pattern:
      /\b(?:DEBUG\s*[=:]\s*True|debug\s*[=:]\s*true|app\.run\s*\([^)]*debug\s*=\s*True|APP_DEBUG\s*=\s*true)\b/,
    unless: /\bif\b|\benv\b|\bgetenv\b|\benviron\b|process\.env|#\s*|\/\/\s*/i,
  },
  {
    id: 'API-DEBUG-002',
    issue: 'debug_endpoint_exposed',
    severity: 'MEDIUM',
    confidence: 'MEDIUM',
    title: 'Surface de diagnostic exposée',
    description:
      'Une route de diagnostic, de supervision ou d’introspection est ' +
      'déclarée. Ces surfaces révèlent la configuration, les dépendances ' +
      'et parfois des variables d’environnement.',
    remediation:
      'Restreignez l’accès à ces routes, ou désactivez-les hors ' +
      'développement.',
    references: ['CWE-489'],
    // Le `/` de tete est exige : sans lui, la simple chaine `"DEBUG"`
    // d'un `DEBUG = os.environ.get("DEBUG")` etait prise pour une route
    // de diagnostic exposee — un faux positif sur la forme meme que l'on
    // recommande par ailleurs.
    pattern:
      /['"`]\/(?:debug|__debug__|actuator|_profiler|phpinfo|trace|heapdump|env|metrics|_status)(?:['"`/]|$)/i,
  },

  // --- Identifiants -----------------------------------------------------
  {
    id: 'API-CRED-001',
    issue: 'hardcoded_api_credential',
    severity: 'HIGH',
    confidence: 'MEDIUM',
    title: 'Identifiant d’API écrit en dur dans un en-tête',
    description:
      'Un en-tête `Authorization` porte une valeur littérale. Elle est ' +
      'versionnée avec le code, visible de tous ceux qui y ont accès, et ' +
      'survit à toute rotation d’identifiant.',
    remediation:
      'Lisez ce jeton depuis une variable d’environnement ou un coffre. ' +
      'Considérez la valeur présente comme compromise et révoquez-la.',
    references: ['CWE-798', 'OWASP API8:2023'],
    pattern:
      /['"`]?Authorization['"`]?\s*[=:]\s*['"`](?:Bearer|Basic|Token|ApiKey)\s+[^'"`\s$<{]{8,}['"`]/i,
  },
  {
    id: 'API-CRED-002',
    issue: 'hardcoded_api_credential',
    severity: 'HIGH',
    confidence: 'HIGH',
    title: 'Identifiants intégrés à une URL d’API',
    description:
      'Une URL porte un identifiant et un mot de passe. Ces valeurs ' +
      'apparaissent dans les journaux du serveur, dans l’historique du ' +
      'shell et dans les traces réseau.',
    remediation:
      'Retirez les identifiants de l’URL et passez-les par un en-tête ' +
      'construit à partir d’une variable d’environnement. Révoquez la ' +
      'valeur présente.',
    references: ['CWE-798', 'CWE-522'],
    pattern: /['"`]https?:\/\/[^'"`\s/@]+:[^'"`\s/@]{3,}@[\w.-]+/i,
  },
]

/**
 * Chemins de routes qui désignent une surface habituellement réservée.
 *
 * Volontairement court : chaque entrée doit pouvoir se défendre.
 *
 * `users`, `orders`, `accounts` en sont **absents**, et délibérément :
 * ce sont des noms de ressource ordinaires, et exiger un contrôle de
 * rôle sur chaque `/api/users` produirait exactement le bruit que cette
 * phase existe pour éviter. `/admin/users` reste couvert — par `admin`.
 */
const SENSITIVE_PATH = /(?:^|\/)(?:admin|administration|internal|private|config|settings|debug|actuator|tokens?|keys?|secrets?|credentials?|export|dump|backup|exec|shell|sudo|impersonate)(?:\/|$|\{|:)/i

/** Ce chemin désigne-t-il une surface réservée ? */
export function isSensitivePath(path: string): boolean {
  return SENSITIVE_PATH.test(path)
}
