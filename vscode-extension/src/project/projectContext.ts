/**
 * Contexte de projet : état en mémoire et synchronisation avec le backend.
 *
 * Responsabilités séparées, dans cet ordre :
 *
 *     projectDiscovery.ts   parcourt le disque        (aucun état)
 *     projectIdentity.ts    calcule l'identité        (aucun état)
 *     projectContext.ts     orchestre et conserve     (cet état)
 *     backendClient.ts      parle HTTP                (aucun état métier)
 *
 * Ce module ne parcourt aucun dossier et ne construit aucune requête : il
 * enchaîne les quatre étapes et détient la seule copie vivante du
 * contexte. Tout mettre dans `extension.ts` aurait mélangé l'activation,
 * les commandes et cet état — c'est ce que l'audit reproche au fichier de
 * 544 lignes.
 *
 * Garanties tenues ici :
 *
 * - **une découverte à la fois** — un second appel pendant qu'une
 *   découverte tourne est refusé, pas mis en file : deux parcours
 *   concurrents doubleraient le coût pour un résultat identique ;
 * - **jamais bloquant** — l'appelant reçoit une promesse, l'interface reste
 *   réactive, l'annulation est coopérative ;
 * - **jamais silencieux** — chaque issue (succès, avertissements,
 *   annulation, échec) produit un état observable et un message ;
 * - **le chemin local ne sort pas** — seul `root_hash` part au backend.
 */

import type { BackendClient } from '../api/backendClient'
import { BackendError } from '../api/backendClient'
import { FR } from '../i18n/fr'
import {
  DependencyInventoryAccumulator,
  manifestKind,
} from '../security/dependencyInventory'
import type {
  ProjectSecurityOutcome,
  ProjectSecurityService,
} from '../security/projectSecurityService'
import { SecretScanAccumulator } from '../security/secretScanner'
import { ApiScanAccumulator } from '../apisec/apiScanner'
import type { SecurityFinding } from '../security/securityTypes'
import {
  discoverProject,
  type DiscoveryFileSystem,
  type IgnoreMatcher,
} from './projectDiscovery'
import { projectNameOf, rootHashOf, shortProjectId } from './projectIdentity'
import type { BaselineSnapshot } from '../monitor/securityBaseline'
import type {
  GitMetadata,
  IndexedFile,
  LocalProjectView,
  ProjectSecurityContext,
  ProjectStatus,
} from './projectTypes'

/** Version du format de découverte, envoyée au backend. */
export const DISCOVERY_VERSION = '1.0.0'

export type ContextListener = (view: LocalProjectView | undefined) => void
export type Unsubscribe = () => void

export interface DiscoveryRequest {
  readonly workspacePath: string
  /** Dépôt Git : présence et hôte. Fourni par l'appelant, jamais déduit ici. */
  readonly git?: GitMetadata
  readonly ignore?: IgnoreMatcher
  readonly isCancelled?: () => boolean
  readonly onProgress?: (indexed: number) => void
  /**
   * Analyses de sécurité à mener pendant le même parcours (phase 2).
   *
   * Absent = découverte seule, exactement comme en phase 1. Le défaut
   * n'analyse donc rien de plus qu'avant : c'est l'appelant qui décide,
   * d'après les réglages de l'utilisateur et l'état du backend.
   */
  readonly security?: ProjectSecurityRequest
}

export interface ProjectSecurityRequest {
  readonly secrets: boolean
  readonly dependencies: boolean
  /**
   * Analyse de sécurité d'API (phase 5).
   *
   * Se greffe sur le **même** parcours et sur le même crochet
   * `onFileText` que la détection de secrets : la découverte lit déjà ces
   * fichiers, et un second passage coûterait autant que le premier pour
   * ne rien apprendre de plus.
   */
  readonly api?: boolean
  /**
   * Autoriser le backend à interroger la base publique de vulnérabilités.
   *
   * L'extension ne l'interroge jamais elle-même : elle demande, et le
   * backend — seul détenteur de la sortie réseau — décide.
   */
  readonly checkVulnerabilities: boolean
}

export interface ProjectContextOptions {
  readonly client: BackendClient
  readonly log: (message: string) => void
  /** Remplaçable dans les tests. */
  readonly fileSystem?: DiscoveryFileSystem
  readonly maxFiles?: number
  /**
   * Service de sécurité projet (phase 2).
   *
   * Absent = la découverte se comporte exactement comme en phase 1. La
   * dépendance est injectée plutôt qu'importée en dur pour que ce module
   * reste testable sans backend de sécurité.
   */
  readonly security?: ProjectSecurityService
}

export interface DiscoveryOutcome {
  readonly ok: boolean
  readonly view: LocalProjectView | undefined
  /** Message destiné à l'utilisateur. Toujours présent. */
  readonly message: string
  readonly warnings: readonly string[]
  readonly cancelled: boolean
  /**
   * Findings de sécurité produits pendant ce parcours (phase 2).
   *
   * Vide quand aucune analyse de sécurité n'a été demandée — ce qui n'est
   * pas la même chose que « aucun problème ». L'appelant distingue les
   * deux par `securityMessage`, absent dans le premier cas.
   */
  readonly securityFindings: readonly SecurityFinding[]
  /** Bilan de l'analyse de sécurité, quand elle a eu lieu. */
  readonly securityMessage: string | undefined
  /**
   * Instantané par fichier de ce parcours (phase 3).
   *
   * Alimente le registre de la surveillance continue, qui s'en sert pour
   * remplacer la contribution d'un seul fichier sans relire le projet.
   * `undefined` quand aucune analyse de sécurité n'a eu lieu : sans
   * parcours de référence, la surveillance n'a rien sur quoi s'appuyer et
   * refuse de soumettre — voir `SecurityBaseline.isEstablished`.
   */
  readonly securityBaseline: BaselineSnapshot | undefined
  /**
   * Index du parcours, pour amorcer le cache d'empreintes (phase 3).
   *
   * Reprendre `size`, `mtime` et `content_hash` déjà calculés évite de
   * relire tout le projet pour reconstituer ce qu'on vient de mesurer.
   */
  readonly indexedFiles: readonly IndexedFile[]
}

export class ProjectContextService {
  private readonly client: BackendClient
  private readonly log: (message: string) => void
  private readonly fileSystem: DiscoveryFileSystem | undefined
  private readonly maxFiles: number | undefined
  private readonly security: ProjectSecurityService | undefined

  private view: LocalProjectView | undefined
  private running = false
  private readonly listeners = new Set<ContextListener>()

  constructor(options: ProjectContextOptions) {
    this.client = options.client
    this.log = options.log
    this.fileSystem = options.fileSystem
    this.maxFiles = options.maxFiles
    this.security = options.security
  }

  /** Contexte courant, ou `undefined` si aucune découverte n'a abouti. */
  current(): LocalProjectView | undefined {
    return this.view
  }

  /**
   * Identifiant du projet courant, pour les requêtes d'analyse et le flux.
   *
   * `undefined` quand aucun projet n'est établi : un fichier ouvert hors
   * dossier reste analysable, simplement sans contexte.
   */
  projectUid(): string | undefined {
    return this.view?.context?.project_uid ?? undefined
  }

  get isRunning(): boolean {
    return this.running
  }

  onChange(listener: ContextListener): Unsubscribe {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  /** Oublie le contexte : changement de dossier, ou vidage de la vue. */
  clear(): void {
    this.view = undefined
    this.emit()
  }

  /**
   * Découvre le projet et synchronise son contexte avec le backend.
   *
   * Trois échanges, dans cet ordre imposé :
   *
   *     POST /api/project/discover        -> project_uid
   *     parcours local                    -> index + manifestes
   *     POST /api/project/{uid}/index     -> contexte
   *
   * L'enregistrement passe avant le parcours : sans `project_uid`, un index
   * n'aurait nulle part où aller, et faire parcourir un monorepo pour
   * découvrir ensuite que le backend est éteint serait du travail perdu.
   */
  async discover(request: DiscoveryRequest): Promise<DiscoveryOutcome> {
    if (this.running) {
      return this.outcome(false, FR.project.alreadyRunning, [], false)
    }

    const rootHash = rootHashOf(request.workspacePath)
    const projectName = projectNameOf(request.workspacePath, rootHash)
    const shortId = shortProjectId(rootHash)

    this.running = true
    // Le journal porte l'identifiant, jamais le chemin : une trace copiée
    // dans un rapport de bug ne doit pas révéler l'arborescence du poste.
    this.log(`découverte du projet ${projectName} [${shortId}] démarrée`)

    this.setStatus(request.workspacePath, projectName, rootHash, 'discovery')

    try {
      const registration = await this.client.discoverProject({
        root_hash: rootHash,
        project_name: projectName,
        discovery_version: DISCOVERY_VERSION,
      })

      // Les analyses de securite se greffent sur le parcours existant.
      //
      // Un second passage sur le disque couterait autant que le premier
      // pour ne rien apprendre de plus : la decouverte lit deja chaque
      // fichier eligible pour en calculer l'empreinte, et chaque manifeste
      // pour en tirer des noms. Les accumulateurs recoivent ce texte
      // pendant qu'il est en memoire, puis l'oublient.
      const wantsSecrets = request.security?.secrets === true
      const wantsDependencies = request.security?.dependencies === true
      const wantsApi = request.security?.api === true
      const secretScan = new SecretScanAccumulator()
      const inventory = new DependencyInventoryAccumulator()
      const apiScan = new ApiScanAccumulator()

      const discovery = await discoverProject({
        workspaceRoot: request.workspacePath,
        ...(this.fileSystem ? { fileSystem: this.fileSystem } : {}),
        ...(request.ignore ? { ignore: request.ignore } : {}),
        ...(request.git ? { git: request.git } : {}),
        ...(this.maxFiles !== undefined ? { maxFiles: this.maxFiles } : {}),
        ...(request.isCancelled ? { isCancelled: request.isCancelled } : {}),
        ...(request.onProgress ? { onProgress: request.onProgress } : {}),
        ...(wantsSecrets || wantsApi
          ? {
              // Un seul crochet pour deux moteurs : le texte est rendu
              // pendant qu'il est en mémoire, et chacun décide s'il le
              // regarde. Deux crochets feraient lire le fichier deux fois.
              onFileText: (path, text) => {
                if (wantsSecrets) {
                  secretScan.consider(path, text)
                }
                if (wantsApi) {
                  apiScan.consider(path, text)
                }
              },
              onFileSkipped: () => secretScan.skip(),
            }
          : {}),
        ...(wantsDependencies
          ? {
              wantsManifest: (fileName) => manifestKind(fileName) !== undefined,
              onManifestText: (path, fileName, text) =>
                inventory.consider(fileName, path, text),
            }
          : {}),
        onLog: (message) => this.log(`[${shortId}] ${message}`),
      })

      if (discovery.cancelled) {
        // Un index partiel décrirait un projet qui n'existe pas. On ne le
        // soumet pas, et le contexte précédent — s'il y en avait un —
        // reste préférable à une demi-vérité.
        this.running = false
        this.setStatus(request.workspacePath, projectName, rootHash, 'ready')
        this.log(`découverte du projet [${shortId}] interrompue`)
        return this.outcome(false, FR.project.discoveryCancelled, [], true)
      }

      const context = await this.client.submitProjectIndex(
        registration.project_uid,
        {
          files: discovery.files,
          manifests: discovery.manifests,
          git: discovery.git,
          discovered_count: discovery.discoveredCount,
          truncated: discovery.truncated,
          warnings: [...discovery.warnings],
          discovery_version: DISCOVERY_VERSION,
        }
      )

      this.view = {
        workspacePath: request.workspacePath,
        projectName: context.project_name || projectName,
        projectId: shortId,
        rootHash,
        status: context.status,
        context,
        error: undefined,
        lastDiscovery: new Date(),
      }
      this.running = false
      this.emit()

      // Volumes et identifiants seulement : aucun chemin de fichier, et
      // surtout aucun chemin de fichier sensible.
      this.log(
        `contexte du projet [${shortId}] établi — ` +
          `${context.file_statistics.indexed} fichier(s) indexé(s), ` +
          `${context.languages.length} langage(s), ` +
          `${context.frameworks.length} framework(s), ` +
          `${context.file_statistics.sensitive} fichier(s) sensible(s)` +
          (context.file_statistics.truncated ? ' [index tronqué]' : '')
      )
      for (const warning of context.warnings) {
        this.log(`[${shortId}] avertissement : ${warning}`)
      }

      const message =
        context.warnings.length > 0
          ? FR.project.discoveryWithWarnings(context.warnings.length)
          : FR.project.discoveryDone(
              this.view.projectName,
              context.file_statistics.indexed,
              context.file_statistics.sensitive
            )

      // La securite vient APRES l'index, et son echec n'annule pas la
      // decouverte : un contexte de projet etabli vaut par lui-meme, meme
      // si le balayage de secrets n'a pas pu etre enregistre.
      const security = await this.runSecurity(
        registration.project_uid,
        request,
        secretScan,
        inventory,
        apiScan,
        shortId
      )

      return {
        ok: true,
        view: this.view,
        message,
        warnings: [...context.warnings, ...security.warnings],
        cancelled: false,
        securityFindings: security.findings,
        securityMessage: security.message,
        // L'instantané n'est produit que si les deux moteurs ont
        // réellement tourné. Un registre alimenté par un parcours
        // partiel ferait croire à la surveillance qu'elle connaît des
        // fichiers jamais analysés, et sa première soumission
        // effacerait ce que le backend savait d'eux.
        securityBaseline:
          wantsSecrets && wantsDependencies
            ? buildBaselineSnapshot(secretScan, inventory, apiScan)
            : undefined,
        indexedFiles: discovery.files,
      }
    } catch (error) {
      this.running = false
      return this.fail(request.workspacePath, projectName, rootHash, shortId, error)
    }
  }

  // ---------------- Interne ----------------

  /**
   * Traduit un échec en état observable et en message actionnable.
   *
   * Le backend injoignable est distingué du reste : c'est de loin la cause
   * la plus fréquente, et sa correction ne ressemble à aucune autre.
   */
  private fail(
    workspacePath: string,
    projectName: string,
    rootHash: string,
    shortId: string,
    error: unknown
  ): DiscoveryOutcome {
    const unreachable = error instanceof BackendError && error.status === 0
    const detail =
      error instanceof BackendError
        ? error.message
        : error instanceof Error
          ? error.message
          : FR.errors.unexpected

    const message = unreachable
      ? FR.project.backendUnavailable
      : FR.project.discoveryFailed(detail)

    // La trace porte le détail technique ; l'utilisateur reçoit la
    // consigne. Aucune trace d'exécution ne remonte à l'écran.
    this.log(
      `découverte du projet [${shortId}] en échec — ${detail}` +
        (error instanceof BackendError && error.detail ? ` (${error.detail})` : '')
    )

    this.view = {
      workspacePath,
      projectName,
      projectId: shortId,
      rootHash,
      status: 'error',
      // Le contexte précédent est conservé s'il existait : un échec de
      // rafraîchissement ne doit pas effacer ce qu'on savait déjà.
      context: this.view?.context,
      error: message,
      lastDiscovery: this.view?.lastDiscovery,
    }
    this.emit()

    return this.outcome(false, message, [], false)
  }

  private setStatus(
    workspacePath: string,
    projectName: string,
    rootHash: string,
    status: ProjectStatus
  ): void {
    this.view = {
      workspacePath,
      projectName,
      projectId: shortProjectId(rootHash),
      rootHash,
      status,
      context: this.view?.rootHash === rootHash ? this.view.context : undefined,
      error: undefined,
      lastDiscovery:
        this.view?.rootHash === rootHash ? this.view.lastDiscovery : undefined,
    }
    this.emit()
  }

  /**
   * Soumet ce que les accumulateurs ont collecté pendant le parcours.
   *
   * Ne lève jamais : une analyse de sécurité en échec laisse la découverte
   * réussie. Retourne des listes vides quand aucune analyse n'a été
   * demandée — ce qui n'est pas « aucun problème », et c'est pourquoi
   * `message` reste alors `undefined`. L'appelant distingue ainsi « rien
   * trouvé » de « rien cherché ».
   */
  private async runSecurity(
    projectUid: string,
    request: DiscoveryRequest,
    secretScan: SecretScanAccumulator,
    inventory: DependencyInventoryAccumulator,
    apiScan: ApiScanAccumulator,
    shortId: string
  ): Promise<{
    findings: SecurityFinding[]
    message: string | undefined
    warnings: string[]
  }> {
    const service = this.security
    const wanted = request.security
    if (
      !service ||
      !wanted ||
      (!wanted.secrets && !wanted.dependencies && wanted.api !== true)
    ) {
      return { findings: [], message: undefined, warnings: [] }
    }

    try {
      const outcome = await service.submit({
        projectUid,
        secrets: secretScan.result(),
        inventory: inventory.result(),
        api: apiScan.result(),
        checkVulnerabilities: wanted.checkVulnerabilities,
        submitSecrets: wanted.secrets,
        submitDependencies: wanted.dependencies,
        submitApi: wanted.api === true,
      })

      // Le contexte détenu localement porte des compteurs périmés : le
      // backend vient de les recalculer. On les reprend plutôt que de
      // relancer une requête de lecture pour les mêmes chiffres.
      this.applySecurityStatistics(outcome)

      return {
        findings: [...outcome.findings],
        message: outcome.message,
        warnings: [...outcome.warnings],
      }
    } catch (error) {
      const detail = error instanceof Error ? error.message : FR.errors.unexpected
      this.log(`[${shortId}] analyse de sécurité du projet en échec — ${detail}`)
      return {
        findings: [],
        message: FR.security.scanFailed,
        warnings: [FR.security.scanFailed],
      }
    }
  }

  /**
   * Reporte dans la vue locale les compteurs que le backend vient de
   * recalculer.
   *
   * Les champs absents ne sont pas touchés : un balayage de secrets ne
   * doit pas remettre à zéro ce qu'on sait des dépendances.
   */
  private applySecurityStatistics(outcome: ProjectSecurityOutcome): void {
    const context = this.view?.context
    if (!context) {
      return
    }

    if (outcome.secrets) {
      context.secret_statistics = outcome.secrets.statistics
    }
    if (outcome.api) {
      context.api_statistics = outcome.api.statistics
    }
    if (outcome.dependencies) {
      context.dependency_statistics = outcome.dependencies.dependency_statistics
      context.dependency_ecosystems = outcome.dependencies.ecosystems
      context.vulnerability_statistics =
        outcome.dependencies.vulnerability_statistics
    }

    this.emit()
  }

  private outcome(
    ok: boolean,
    message: string,
    warnings: readonly string[],
    cancelled: boolean
  ): DiscoveryOutcome {
    return {
      ok,
      view: this.view,
      message,
      warnings,
      cancelled,
      // Aucune analyse de securite n'a eu lieu sur ce chemin : la liste
      // est vide et le message absent. Les deux ensemble disent « on n'a
      // pas regarde », jamais « rien a signaler ».
      securityFindings: [],
      securityMessage: undefined,
      // Aucun parcours exploitable : la surveillance continue reste sans
      // registre, donc muette, plutôt que d'en adopter un vide.
      securityBaseline: undefined,
      indexedFiles: [],
    }
  }

  private emit(): void {
    for (const listener of [...this.listeners]) {
      try {
        listener(this.view)
      } catch {
        // Un consommateur défaillant — une vue en cours de démontage, par
        // exemple — ne doit pas interrompre la notification des autres.
      }
    }
  }
}

/**
 * Assemble l'instantané que la surveillance continue adoptera.
 *
 * Les deux accumulateurs viennent d'être remplis par le parcours : rien
 * n'est relu, rien n'est recalculé. C'est exactement le point que la
 * préparation de la phase 3 annonçait — le détail par fichier est
 * disponible au moment où il coûte le moins cher.
 */
function buildBaselineSnapshot(
  secretScan: SecretScanAccumulator,
  inventory: DependencyInventoryAccumulator,
  apiScan: ApiScanAccumulator
): BaselineSnapshot {
  const secrets = secretScan.perFile()
  const dependencies = inventory.perManifest()
  const api = apiScan.perFile()

  return {
    scannedPaths: secrets.scannedPaths,
    secretsByFile: secrets.secretsByFile,
    dependenciesByManifest: dependencies.dependenciesByManifest,
    apiByFile: api.apiByFile,
    endpointsDetected: api.endpointsDetected,
    skippedFiles: secrets.skippedFiles,
    truncated: secrets.truncated || dependencies.truncated || api.truncated,
  }
}

/**
 * Contexte relu depuis le backend, sans nouveau parcours.
 *
 * Sert au démarrage quand le projet est déjà connu : afficher le contexte
 * de la session précédente pendant qu'une découverte tourne vaut mieux
 * qu'une vue vide. L'absence de contexte n'est pas une erreur — un projet
 * enregistré mais jamais indexé répond 404, et c'est une réponse normale.
 */
export async function fetchExistingContext(
  client: BackendClient,
  projectUid: string
): Promise<ProjectSecurityContext | undefined> {
  try {
    return await client.getProjectContext(projectUid)
  } catch (error) {
    if (error instanceof BackendError && error.status === 404) {
      return undefined
    }
    throw error
  }
}
