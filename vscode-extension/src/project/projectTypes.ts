/**
 * Types du contexte de projet, côté extension.
 *
 * Miroir de `backend/app/project/schemas.py`. Les deux descriptions sont
 * reliées mécaniquement par `contract/api-contract.json` et ses deux
 * tests : une divergence fait échouer un build plutôt que de se
 * manifester à l'exécution chez l'utilisateur.
 *
 * Distinction à garder en tête
 * ----------------------------
 *
 *     ProjectSecurityContext   ce que le BACKEND connaît
 *                              → aucun chemin absolu, jamais
 *
 *     LocalProjectView         ce que l'EXTENSION ajoute pour l'affichage
 *                              → contient le chemin local, qui ne quitte
 *                                jamais la machine
 *
 * Le §14 de la commande demandait `workspacePath` dans le modèle. Il y est,
 * mais côté extension seulement : l'audit (§9.7) interdit de persister un
 * chemin absolu côté backend, parce qu'il révèle le nom de l'utilisateur et
 * l'arborescence du poste. Les deux exigences sont donc tenues, chacune
 * là où elle a du sens.
 *
 * Aucune dépendance à `vscode` : ce module est testable en Node pur.
 */

import type {
  ApiStatistics,
  DependencyStatistics,
  EcosystemSummary,
  SecretStatistics,
  VulnerabilityStatistics,
} from '../security/securityTypes'

/** Nature d'un fichier, telle que le backend la classe. */
export type FileKind =
  | 'source'
  | 'manifest'
  | 'config'
  | 'infra'
  | 'test'
  | 'sensitive'
  | 'documentation'
  | 'other'

/**
 * État du traitement d'un projet.
 *
 * Décrit où en est l'agent, **pas** la qualité du projet : aucun score de
 * sécurité n'existe à cette phase, et un chiffre sans son explication
 * serait trompeur.
 */
export type ProjectStatus =
  | 'discovery'
  | 'security_scan'
  | 'analysis'
  | 'ready'
  | 'error'

export interface DetectedLanguage {
  language: string
  file_count: number
  /** Part des fichiers de code, en pourcentage entier. */
  share: number
  /** Le moteur a-t-il des règles pour ce langage ? Affiché tel quel. */
  analysis_supported: boolean
}

export interface DetectedFramework {
  framework: string
  /** Ce qui atteste ce framework. Jamais vide. */
  evidence: string
  /** Fichier qui porte la preuve. */
  source: string
  confidence: number
}

export interface ClassifiedFile {
  path: string
  kind: FileKind
  type: string
  reason: string
}

export interface FileStatistics {
  discovered: number
  indexed: number
  source: number
  manifests: number
  configuration: number
  tests: number
  sensitive: number
  /** Aussi important que les nombres : une couverture partielle se dit. */
  truncated: boolean
}

/** Contexte tel que le backend le renvoie. Aucun chemin absolu. */
export interface ProjectSecurityContext {
  project_uid: string
  project_name: string
  root_hash: string
  status: ProjectStatus
  project_types: string[]
  primary_language: string | null
  languages: DetectedLanguage[]
  frameworks: DetectedFramework[]
  file_statistics: FileStatistics
  manifests: ClassifiedFile[]
  important_files: ClassifiedFile[]
  configuration_files: ClassifiedFile[]
  /** Chemin, type et raison. Jamais le contenu. */
  security_sensitive_files: ClassifiedFile[]
  git_repository_detected: boolean
  git_remote_host: string | null

  // --- Sécurité projet (phase 2) ---------------------------------------
  //
  // **Des nombres, jamais des valeurs.** Ces quatre champs disent combien
  // de secrets ont été repérés et dans combien de fichiers, combien de
  // dépendances le projet tire et combien sont vulnérables. Aucun ne peut
  // porter la valeur d'un secret : leurs types ne contiennent que des
  // entiers, des libellés d'écosystème et un état de fournisseur.
  //
  // Le détail — quel fichier, quelle ligne, quelle preuve expurgée — vit
  // dans les findings, pas ici.
  secret_statistics: SecretStatistics
  /**
   * Décomptes de sécurité d'API (phase 5).
   *
   * Des nombres et des libellés, jamais un chemin de route sensible ni
   * un extrait de configuration. `last_scan: null` signifie « jamais
   * analysé », pas « aucun problème » — l'interface écrit les deux
   * différemment.
   */
  api_statistics: ApiStatistics
  dependency_statistics: DependencyStatistics
  dependency_ecosystems: EcosystemSummary[]
  /**
   * Porte `provider_status` et `conclusive`.
   *
   * Sans eux, un `total: 0` se lirait comme un feu vert alors qu'il peut
   * signifier « la base n'a pas répondu ».
   */
  vulnerability_statistics: VulnerabilityStatistics

  warnings: string[]
  last_discovery: string | null
  discovery_version: string
}

export interface ProjectRegistration {
  project_uid: string
  project_name: string
  root_hash: string
  status: ProjectStatus
  known: boolean
  last_discovery: string | null
}

// --------------------------------------------------------------------------
// Soumission
// --------------------------------------------------------------------------

/** Une entrée de l'index. Métadonnée seulement. */
export interface IndexedFile {
  path: string
  content_hash: string | null
  size: number
  mtime: string | null
}

/**
 * Preuve extraite d'un manifeste : **des noms, jamais des versions.**
 *
 * Un `requirements.txt` peut contenir
 * `--index-url https://user:motdepasse@dépôt.example/simple`. N'extraire
 * que les noms de paquets écarte cette fuite par construction, sans avoir
 * à s'en souvenir à chaque évolution du lecteur de manifeste.
 */
export interface ManifestEvidence {
  path: string
  ecosystem: string
  dependency_names: string[]
}

/** Présence du dépôt et hôte du remote. Jamais l'URL, qui peut porter un jeton. */
export interface GitMetadata {
  detected: boolean
  remote_host: string | null
}

export interface ProjectIndexSubmission {
  files: IndexedFile[]
  manifests: ManifestEvidence[]
  git: GitMetadata
  discovered_count: number
  truncated: boolean
  warnings: string[]
  discovery_version: string
}

export interface ProjectDiscoverSubmission {
  root_hash: string
  project_name: string
  discovery_version: string
}

// --------------------------------------------------------------------------
// Vue locale
// --------------------------------------------------------------------------

/**
 * Ce que l'extension conserve en mémoire pour l'affichage.
 *
 * `workspacePath` ne franchit jamais la frontière HTTP : il sert à
 * l'infobulle de la vue et aux messages destinés à l'utilisateur, qui
 * connaît déjà son propre disque.
 */
export interface LocalProjectView {
  /** Chemin local du dossier ouvert. **Ne quitte jamais la machine.** */
  readonly workspacePath: string
  /** Nom affiché, repris du dossier. */
  readonly projectName: string
  /** Identifiant stable, calculé localement puis confirmé par le backend. */
  readonly projectId: string
  readonly rootHash: string
  readonly status: ProjectStatus
  /** Contexte du backend, absent tant qu'aucune découverte n'a abouti. */
  readonly context: ProjectSecurityContext | undefined
  /** Message d'erreur déjà traduit, quand `status` vaut `error`. */
  readonly error: string | undefined
  /** Horodatage local de la dernière découverte réussie. */
  readonly lastDiscovery: Date | undefined
}

/** Résultat d'un parcours local, avant soumission au backend. */
export interface DiscoveryResult {
  readonly files: IndexedFile[]
  readonly manifests: ManifestEvidence[]
  readonly git: GitMetadata
  /** Fichiers rencontrés avant plafonnement. */
  readonly discoveredCount: number
  readonly truncated: boolean
  /**
   * Ce que la découverte n'a pas pu faire.
   *
   * Remonté à l'utilisateur tel quel : une troncature ou un dossier
   * illisible passés sous silence donneraient une couverture apparente
   * supérieure à la réalité.
   */
  readonly warnings: string[]
  /** Vrai si l'opération a été interrompue avant la fin. */
  readonly cancelled: boolean
}
