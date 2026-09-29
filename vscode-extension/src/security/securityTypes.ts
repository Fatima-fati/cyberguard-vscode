/**
 * Types de la sécurité projet, côté extension.
 *
 * Miroir de `backend/app/security/schemas.py`, relié mécaniquement par
 * `contract/api-contract.json` et ses deux tests : une divergence fait
 * échouer un build plutôt que de se manifester chez l'utilisateur.
 *
 * Où tourne quoi, et pourquoi
 * ---------------------------
 *
 *     détection des secrets    EXTENSION   lire un fichier pour y chercher
 *                                          un secret est une opération
 *                                          locale ; l'envoyer à un serveur
 *                                          pour la même raison n'en serait
 *                                          pas une
 *     inventaire dépendances   EXTENSION   les manifestes sont sur le poste
 *     base de vulnérabilités   BACKEND     c'est lui qui détient la sortie
 *                                          réseau, et lui seul
 *     persistance, libellés    BACKEND     une seule définition du
 *                                          vocabulaire affiché
 *
 * Conséquence directe sur ce fichier : ce qui monte vers le backend ne
 * porte **jamais** la valeur d'un secret, seulement une preuve expurgée.
 *
 * Aucune dépendance à `vscode` : ce module est testable en Node pur.
 */

/** Gravité, échelle unique du projet. */
export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

/**
 * Confiance de la détection.
 *
 * Distincte de la gravité, et jamais confondue avec elle : un mot de passe
 * de production est grave même si le motif est incertain, un placeholder
 * est sans gravité même si le motif est formel.
 */
export type Confidence = 'HIGH' | 'MEDIUM' | 'LOW'

/** Familles de détection. `API` et `GIT` sont déclarées mais non produites. */
export type SecurityCategory =
  | 'SECRET'
  | 'DEPENDENCY'
  | 'CODE'
  | 'CONFIGURATION'
  | 'API'
  | 'GIT'

export type SecurityFindingStatus = 'open' | 'dismissed' | 'fixed'

export type DependencyEcosystem =
  | 'npm'
  | 'pypi'
  | 'maven'
  | 'composer'
  | 'go'
  | 'rubygems'
  | 'cargo'
  | 'nuget'
  | 'unknown'

/** Un lockfile donne une version exacte ; un manifeste, souvent une contrainte. */
export type DependencySource = 'manifest' | 'lockfile'

/**
 * État du fournisseur de vulnérabilités.
 *
 * Seuls `available` et `partial` autorisent à conclure. Tous les autres
 * signifient « on ne sait pas », jamais « rien à signaler ».
 */
export type ProviderStatus =
  | 'available'
  | 'partial'
  | 'disabled'
  | 'unavailable'
  | 'timeout'
  | 'rate_limited'
  | 'error'

// --------------------------------------------------------------------------
// Finding unifié
// --------------------------------------------------------------------------

/** Un signalement de sécurité, quelle que soit sa famille. */
export interface SecurityFinding {
  id: string
  project_uid: string
  category: SecurityCategory
  severity: Severity
  severity_label: string
  confidence: Confidence
  confidence_label: string
  category_label: string
  title: string
  description: string
  /** Chemin relatif à la racine du projet. `null` si le finding n'y est pas lié. */
  file: string | null
  line_start: number
  line_end: number
  /** Preuve **expurgée**. Jamais la valeur réelle d'un secret. */
  evidence: string
  remediation: string
  references: string[]
  detection_engine: string
  status: SecurityFindingStatus
  status_label: string
  created_at: string
}

// --------------------------------------------------------------------------
// Secrets : ce qui monte vers le backend
// --------------------------------------------------------------------------

/**
 * Un secret détecté localement, décrit **sans sa valeur**.
 *
 * `evidence_redacted` est produit par `redaction.ts` et ne contient jamais
 * plus que les premiers caractères de la valeur. Le backend le ré-expurge
 * à la réception : la garantie ne dépend donc pas de ce module seul.
 */
export interface SecretFindingSubmission {
  rule_id: string
  file_path: string
  line: number
  column: number | null
  secret_type: string
  severity: Severity
  confidence: Confidence
  evidence_redacted: string
  title: string
  description: string
  remediation: string
  references: string[]
}

export interface SecretScanSubmission {
  findings: SecretFindingSubmission[]
  scanned_files: number
  skipped_files: number
  engine: string
  engine_version: string
  truncated: boolean
  warnings: string[]
}

export interface SecretStatistics {
  total: number
  critical: number
  high: number
  medium: number
  low: number
  files_with_secrets: number
  scanned_files: number
  truncated: boolean
  engine: string
  last_scan: string | null
}

export interface SecretScanResult {
  project_uid: string
  findings: SecurityFinding[]
  statistics: SecretStatistics
  warnings: string[]
}

// --------------------------------------------------------------------------
// Dépendances
// --------------------------------------------------------------------------

export interface DependencyRecord {
  name: string
  ecosystem: DependencyEcosystem
  /** Vide quand le manifeste ne déclare qu'une contrainte : non interrogeable. */
  version: string
  direct: boolean
  manifest: string
  source: DependencySource
}

export interface DependencyInventorySubmission {
  dependencies: DependencyRecord[]
  manifests_read: number
  truncated: boolean
  warnings: string[]
  inventory_version: string
  check_vulnerabilities: boolean
}

export interface EcosystemSummary {
  ecosystem: string
  total: number
  direct: number
  vulnerable: number
  verified: number
}

export interface DependencyStatistics {
  total: number
  direct: number
  transitive: number
  vulnerable: number
  /** Jamais « sain » : c'est exactement ce que personne n'a pu regarder. */
  unverified: number
  manifests_read: number
  truncated: boolean
  last_inventory: string | null
}

export interface VulnerabilityStatistics {
  total: number
  critical: number
  high: number
  medium: number
  low: number
  packages_affected: number
  packages_checked: number
  packages_unverified: number
  provider: string
  provider_status: ProviderStatus
  provider_status_label: string
  /**
   * Phrase déjà rédigée par le backend.
   *
   * L'extension l'affiche telle quelle plutôt que de composer la sienne :
   * c'est ce qui garantit qu'aucun chemin de code côté client ne peut
   * écrire « aucune vulnérabilité » à partir d'un fournisseur muet.
   */
  message: string
  /** Peut-on conclure quoi que ce soit de ces chiffres ? */
  conclusive: boolean
  last_check: string | null
}

export interface DependencyScanResult {
  project_uid: string
  findings: SecurityFinding[]
  dependency_statistics: DependencyStatistics
  vulnerability_statistics: VulnerabilityStatistics
  ecosystems: EcosystemSummary[]
  warnings: string[]
}

// --------------------------------------------------------------------------
// Sécurité d'API (phase 5)
// --------------------------------------------------------------------------

/**
 * Un problème de sécurité d'API constaté **sur le poste**.
 *
 * Même forme que `SecretFindingSubmission`, et pour la même raison : la
 * détection est locale, et ce qui traverse la frontière HTTP est un
 * constat — où, quelle règle, quelle confiance — jamais le contenu du
 * fichier analysé.
 *
 * `evidence` est un extrait **de déclaration** : la ligne qui déclare la
 * route ou pose la configuration. Jamais le corps d'un gestionnaire, où
 * se trouveraient des données métier.
 */
export interface ApiFindingSubmission {
  rule_id: string
  file_path: string
  line: number
  /** Type de problème. Sert de discriminant à l'empreinte backend. */
  issue_type: string
  /** Chemin de la route, quand la déclaration le porte littéralement. */
  endpoint: string
  /** `GET`, `POST`… ou vide quand la règle ne porte pas sur une route. */
  http_method: string
  /** Framework qui a permis la détection. Vide si non déterminé. */
  framework: string
  severity: Severity
  confidence: Confidence
  evidence: string
  title: string
  description: string
  remediation: string
  references: string[]
}

export interface ApiScanSubmission {
  findings: ApiFindingSubmission[]
  scanned_files: number
  /** Routes relevées, y compris celles qui ne posent aucun problème. */
  endpoints_detected: number
  engine: string
  engine_version: string
  truncated: boolean
  warnings: string[]
}

export interface ApiStatistics {
  total: number
  critical: number
  high: number
  medium: number
  low: number
  /** Routes relevées. Dit la couverture, pas le risque. */
  endpoints_detected: number
  /** Endpoints pour lesquels aucune authentification n'a été vue. */
  unauthenticated_endpoints: number
  files_with_findings: number
  scanned_files: number
  truncated: boolean
  engine: string
  /** `null` signifie « jamais analysé », pas « aucun problème ». */
  last_scan: string | null
}

export interface ApiScanResult {
  project_uid: string
  findings: SecurityFinding[]
  statistics: ApiStatistics
  warnings: string[]
}

// --------------------------------------------------------------------------
// État du moteur
// --------------------------------------------------------------------------

export interface SecurityEngineHealth {
  status: string
  secret_detection_enabled: boolean
  dependency_inventory_enabled: boolean
  vulnerability_check_enabled: boolean
  /** Phase 5. Absent sur un backend plus ancien : lu comme « absent ». */
  api_security_enabled?: boolean
  /**
   * Phase 6. L'assistant IA est-il utilisable ? Absent sur un backend plus
   * ancien : lu comme « absent ». Faux ne signifie jamais « rien à
   * expliquer » — seulement « l'assistant n'est pas là ».
   */
  ai_assistant_enabled?: boolean
  vulnerability_provider: string
  supported_ecosystems: string[]
  /** Constat : ces fonctions tournent avec Wazuh complètement arrêté. */
  requires_wazuh: boolean
}
