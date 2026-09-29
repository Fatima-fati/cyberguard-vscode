/**
 * Surveillance continue du projet ouvert (phase 3).
 *
 * Ce que cette phase change, en une phrase : l'agent cesse d'attendre
 * qu'on lui demande quelque chose. Il regarde le dossier, et quand un
 * fichier bouge, il réanalyse **ce fichier** — pas le projet.
 *
 * Le chemin complet d'un changement
 * ---------------------------------
 *
 *     FileSystemWatcher
 *        │  create / change / delete
 *        ▼
 *     classifyChange()          dossier exclu ? binaire ? sensible ?
 *        │                      code, manifeste, ou simple texte ?
 *        ▼
 *     SignatureCache            taille, date, empreinte — a-t-il vraiment
 *        │                      changé ? sinon on s'arrête ici
 *        ▼
 *     ScanQueue                 anti-rebond, dédoublonnage, priorité,
 *        │                      concurrence bornée, annulation
 *        ▼
 *     moteurs EXISTANTS         ScanController  →  /api/code/scan
 *                               scanForSecrets  →  /api/project/…/secrets
 *                               parseDependencies → …/dependencies
 *        │
 *        ▼
 *     findings EXISTANTS        le backend reste la source, la vue et les
 *                               diagnostics ne changent pas d'un octet
 *
 * Trois décisions qui méritent leur explication
 * ---------------------------------------------
 *
 * **Aucune seconde architecture de findings.** Le surveillant ne fabrique
 * aucun finding : il alimente les moteurs de la phase 2, et les findings
 * reviennent du backend par `GET /api/project/{uid}/findings`, exactement
 * comme après un balayage complet. C'est une relecture de plus, et c'est
 * le prix à payer pour n'avoir qu'une seule vérité affichée.
 *
 * **Le lot soumis est toujours complet.** Les routes de sécurité
 * réconcilient : soumettre le seul fichier modifié effacerait les
 * constats de tous les autres. `SecurityBaseline` reconstitue le lot
 * entier depuis le dernier parcours, sans relire le disque — c'est la
 * pièce qui rend l'analyse incrémentale possible sans toucher au backend.
 *
 * **Rien n'est soumis sans parcours de référence.** Tant qu'aucune
 * découverte n'a abouti dans cette session, le registre est vide, et un
 * lot vide annoncerait « ce projet n'a plus aucun secret ». La
 * surveillance attend donc, et le dit.
 *
 * Ce que ce module ne fait pas
 * ----------------------------
 *
 *     lire un fichier sensible      un `.env` modifié est journalisé, pas ouvert
 *     appeler Wazuh                 aucune ligne, ici comme ailleurs
 *     analyser Git, l'API, l'IA     phases 4, 5 et 6
 *     bloquer l'éditeur             rien n'est attendu sur le fil de l'UI
 */

import * as path from 'node:path'

import * as vscode from 'vscode'

import type { ScanController } from '../analysis/scanController'
import { contentHash } from '../analysis/contentHash'
import { FR } from '../i18n/fr'
import { MAX_HASH_BYTES, type IgnoreMatcher } from '../project/projectDiscovery'
import { parseDependencies } from '../security/dependencyInventory'
import type { ProjectSecurityService } from '../security/projectSecurityService'
import { scanForSecrets } from '../security/secretScanner'
import { isApiRelevant, scanForApiIssues } from '../apisec/apiScanner'
import type { SecurityFinding } from '../security/securityTypes'
import type { StatusBar } from '../ui/statusBar'
import {
  classifyChange,
  requiresWork,
  type ChangeClassification,
} from './changeClassification'
import { SignatureCache, demandsAnalysis, type FileSignature } from './fileSignature'
import {
  DEFAULT_DEBOUNCE_MS,
  ScanQueue,
  type MonitorState,
  type ScanJob,
} from './scanQueue'
import { SecurityBaseline, type BaselineSnapshot } from './securityBaseline'

export interface ProjectMonitorOptions {
  readonly controller: ScanController
  readonly security: ProjectSecurityService
  readonly statusBar: StatusBar
  /** Projet courant, résolu à chaque travail : il change avec le dossier. */
  readonly projectUid: () => string | undefined
  readonly workspaceRoot: () => string | undefined
  /** `.gitignore` du projet, relu quand le dossier change. */
  readonly ignore: () => IgnoreMatcher
  /** Réglages de l'utilisateur, relus à chaque fois — jamais capturés. */
  readonly isEnabled: () => boolean
  readonly wantsCode: () => boolean
  readonly wantsSecrets: () => boolean
  /** Analyse de sécurité d'API (phase 5). */
  readonly wantsApi: () => boolean
  readonly wantsDependencies: () => boolean
  readonly checkVulnerabilities: () => boolean
  readonly debounceMs: () => number
  /** Le backend porte-t-il le moteur de sécurité projet ? */
  readonly projectSecurityEnabled: () => boolean
  /**
   * Publie les findings relus après un travail.
   *
   * Branché sur `applySecurityFindings` d'`extension.ts` : le surveillant
   * ne touche ni au registre, ni aux diagnostics, ni aux bulles.
   */
  readonly onSecurityFindings: (findings: readonly SecurityFinding[]) => void
  readonly log: (message: string) => void
}

/**
 * Ce qu'un travail a produit.
 *
 * `touched` : l'état d'un moteur a changé pour ce fichier. `submitted` :
 * le backend a reçu ce nouvel état et les findings ont été republiés.
 * La différence compte pour la remédiation (phase 7) : un changement non
 * soumis ne prouve rien — le finding affiché serait l'ancien.
 */
export interface ExecutionOutcome {
  readonly touched: boolean
  readonly submitted: boolean
}

const NOTHING: ExecutionOutcome = { touched: false, submitted: false }

export class ProjectMonitor implements vscode.Disposable {
  private readonly options: ProjectMonitorOptions
  private readonly signatures = new SignatureCache()
  private readonly baseline = new SecurityBaseline()
  private readonly queue: ScanQueue

  private watcher: vscode.FileSystemWatcher | undefined
  private readonly subscriptions: vscode.Disposable[] = []
  /**
   * Chemins que l'utilisateur vient de toucher, et qui passent devant.
   *
   * Alimenté par `onDidSaveTextDocument` : le surveillant ne devine pas
   * ce qui est à l'écran, il l'apprend de l'éditeur.
   */
  private readonly recentlyEdited = new Set<string>()
  /**
   * Signatures mesurées mais pas encore confirmées.
   *
   * Retenues seulement quand l'analyse aboutit, pour qu'un échec laisse
   * le fichier « à réanalyser » plutôt que « déjà vu ».
   */
  private readonly freshSignatures = new Map<string, FileSignature>()
  private disposed = false
  private started = false

  constructor(options: ProjectMonitorOptions) {
    this.options = options
    this.queue = new ScanQueue({
      // Le resolveur, pas sa valeur : le reglage est relu a chaque
      // armement de l'anti-rebond.
      debounceMs: () => options.debounceMs(),
      run: async (job, signal) => {
        await this.execute(job, signal)
      },
      onStateChange: (state) => this.showState(state),
      onError: (file, error) => {
        this.options.log(FR.monitor.failed(file, describe(error)))
      },
      onDropped: () => {
        this.options.log(FR.monitor.saturated(this.queue.droppedCount))
      },
      onLog: (message) => this.options.log(message),
    })
  }

  /**
   * Adopte le résultat d'une découverte complète.
   *
   * C'est le seul point d'entrée du registre : la surveillance ne
   * fabrique jamais son propre état de référence, elle reprend celui d'un
   * parcours qui a réellement eu lieu.
   */
  adopt(outcome: {
    readonly securityBaseline: BaselineSnapshot | undefined
    readonly indexedFiles: readonly {
      readonly path: string
      readonly size: number
      readonly mtime: string | null
      readonly content_hash: string | null
    }[]
  }): void {
    // Le cache d'empreintes est amorcé même sans analyse de sécurité :
    // il sert aussi à l'analyse de code, qui ne dépend d'aucun registre.
    if (outcome.indexedFiles.length > 0) {
      this.signatures.adopt(outcome.indexedFiles)
    }

    if (outcome.securityBaseline) {
      this.baseline.adopt(outcome.securityBaseline)
      this.options.log(
        `surveillance : registre de référence adopté — ` +
          `${this.baseline.trackedFiles} fichier(s) suivi(s), ` +
          `${this.baseline.filesWithSecrets} porteur(s) de constat, ` +
          `${this.baseline.trackedManifests} manifeste(s)`
      )
    }
  }

  /**
   * Réanalyse un fichier **tout de suite**, hors file d'attente (phase 7).
   *
   * Sert après un correctif assisté : c'est le verdict des moteurs
   * déterministes — pas celui de l'IA — qui dit si le problème a disparu.
   * Même chemin qu'un changement ordinaire (`execute`) : mêmes moteurs,
   * même registre, même soumission, même relecture des findings. Aucun
   * second moteur, aucun raccourci.
   *
   * Retourne `undefined` quand l'analyse n'a pas pu avoir lieu (registre
   * de référence absent, fichier jamais lu) : l'appelant annonce alors une
   * vérification impossible plutôt qu'un résultat.
   */
  async rescanFile(relative: string): Promise<ExecutionOutcome | undefined> {
    if (this.disposed || !this.baseline.isEstablished) {
      return undefined
    }
    const classification = classifyChange(relative, { ignore: this.options.ignore() })
    if (classification.kind === 'sensitive' || !requiresWork(classification)) {
      return undefined
    }
    try {
      return await this.execute(
        { path: relative, analyses: classification.analyses, removed: false, priority: 'high' },
        new AbortController().signal
      )
    } catch (error) {
      this.options.log(FR.monitor.failed(relative, describe(error)))
      return undefined
    }
  }

  /** Démarre la surveillance. Sans effet si elle tourne déjà. */
  start(): void {
    if (this.disposed || this.started) {
      return
    }

    const folder = vscode.workspace.workspaceFolders?.[0]
    if (!folder) {
      // Aucun dossier ouvert : il n'y a rien à surveiller, et ce n'est
      // pas une panne. L'analyse à la demande reste disponible.
      return
    }

    // `**/*` plutôt qu'une liste d'extensions : les exclusions de la
    // phase 1 décident de ce qui compte, et elles sont plus riches qu'un
    // motif glob. Un filtre trop étroit ici ferait manquer un
    // `docker-compose.yml` ou un `.npmrc` créé en cours de route.
    this.watcher = vscode.workspace.createFileSystemWatcher(
      new vscode.RelativePattern(folder, '**/*')
    )

    this.subscriptions.push(
      this.watcher,
      this.watcher.onDidCreate((uri) => this.onChanged(uri, false)),
      this.watcher.onDidChange((uri) => this.onChanged(uri, false)),
      this.watcher.onDidDelete((uri) => this.onChanged(uri, true)),
      // La sauvegarde n'ajoute pas un travail : elle **marque** le chemin
      // comme prioritaire. Le watcher produira l'événement de son côté,
      // et le dédoublonnage de la file fera le reste.
      vscode.workspace.onDidSaveTextDocument((document) => {
        const relative = this.toRelative(document.uri)
        if (relative) {
          this.recentlyEdited.add(relative)
        }
      })
    )

    this.started = true
    this.showState(this.queue.currentState)
    this.options.log(FR.monitor.started(this.options.debounceMs()))

    if (!this.baseline.isEstablished) {
      this.options.log(FR.monitor.awaitingBaseline)
    }
  }

  /** Arrête la surveillance et abandonne tout travail en cours. */
  stop(): void {
    if (!this.started) {
      return
    }
    this.started = false
    this.queue.cancelAll()
    for (const subscription of this.subscriptions) {
      subscription.dispose()
    }
    this.subscriptions.length = 0
    this.watcher = undefined
    this.recentlyEdited.clear()
    this.options.statusBar.clearMonitorState()
    this.options.log(FR.monitor.stopped)
  }

  /**
   * Oublie tout : changement de dossier ouvert.
   *
   * Le registre et le cache d'empreintes décrivent **un** projet. Les
   * conserver d'un dossier à l'autre ferait soumettre les constats du
   * précédent sous l'identifiant du suivant — un mélange de projets, qui
   * est exactement ce que le cloisonnement interdit.
   */
  reset(): void {
    this.queue.cancelAll()
    this.signatures.clear()
    this.baseline.clear()
    this.recentlyEdited.clear()
  }

  dispose(): void {
    this.disposed = true
    this.stop()
    this.queue.dispose()
  }

  /** État courant de la file. Utile au journal et aux tests. */
  get state(): MonitorState {
    return this.queue.currentState
  }

  get isRunning(): boolean {
    return this.started
  }

  // ---------------- Réception des événements ----------------

  private onChanged(uri: vscode.Uri, removed: boolean): void {
    if (this.disposed || !this.started || !this.options.isEnabled()) {
      return
    }

    const relative = this.toRelative(uri)
    if (!relative) {
      return
    }

    const classification = classifyChange(relative, { ignore: this.options.ignore() })

    if (classification.kind === 'sensitive') {
      // Jamais lu, même modifié : la règle de la phase 1 ne cède pas
      // parce qu'un fichier vient de bouger. On le dit, et on s'arrête.
      this.options.log(FR.monitor.sensitiveChanged(relative))
      return
    }

    if (!requiresWork(classification)) {
      this.options.log(FR.monitor.skipped(relative, classification.reason))
      return
    }

    if (removed) {
      // Une suppression est certaine : inutile de la confronter au cache
      // d'empreintes, il n'y a plus rien à mesurer.
      this.signatures.forget(relative)
      this.enqueue(relative, classification, true)
      return
    }

    // La comparaison lit le disque : elle est asynchrone, et l'événement
    // rend la main tout de suite. Rien n'attend sur le fil de l'interface.
    void this.considerChange(relative, classification)
  }

  /**
   * Le fichier a-t-il réellement changé ?
   *
   * C'est ici qu'on évite l'essentiel du travail inutile : un `Ctrl+S`
   * sans modification, un formateur qui réécrit à l'identique, un
   * `git checkout` qui restaure la même version.
   */
  private async considerChange(
    relative: string,
    classification: ChangeClassification
  ): Promise<void> {
    const signature = await this.signatureOf(relative, classification)
    if (!signature) {
      // Disparu entre l'événement et la mesure : traité comme une
      // suppression plutôt qu'ignoré, sinon le registre garderait un
      // constat sur un fichier qui n'existe plus.
      this.signatures.forget(relative)
      this.enqueue(relative, classification, true)
      return
    }

    const verdict = this.signatures.compare(relative, signature)
    if (!demandsAnalysis(verdict)) {
      if (verdict === 'touched') {
        this.signatures.refreshTimestamp(relative, signature.mtimeMs)
      }
      this.options.log(FR.monitor.unchanged(relative))
      this.recentlyEdited.delete(relative)
      return
    }

    // La signature n'est retenue **qu'après** une analyse réussie : la
    // retenir ici ferait qu'un échec réseau rendrait le fichier « déjà
    // vu », donc jamais réanalysé.
    this.enqueue(relative, classification, false, signature)
  }

  /** Mesure taille, date et — quand c'est raisonnable — empreinte. */
  private async signatureOf(
    relative: string,
    classification: ChangeClassification
  ): Promise<FileSignature | undefined> {
    const root = this.options.workspaceRoot()
    if (!root) {
      return undefined
    }

    const uri = vscode.Uri.file(path.join(root, relative))
    let stat: vscode.FileStat
    try {
      stat = await vscode.workspace.fs.stat(uri)
    } catch {
      return undefined
    }

    if (stat.type !== vscode.FileType.File) {
      return undefined
    }

    // Au-delà du plafond, ou pour un fichier qu'on ne lit pas : taille et
    // date suffisent à détecter un changement, et la lecture serait pure
    // perte. `null` dit « pas d'empreinte », jamais « inchangé ».
    if (!classification.readable || stat.size > MAX_HASH_BYTES) {
      return { size: stat.size, mtimeMs: stat.mtime, hash: null }
    }

    try {
      const bytes = await vscode.workspace.fs.readFile(uri)
      return {
        size: stat.size,
        mtimeMs: stat.mtime,
        hash: contentHash(Buffer.from(bytes).toString('utf8')),
      }
    } catch {
      return { size: stat.size, mtimeMs: stat.mtime, hash: null }
    }
  }

  private enqueue(
    relative: string,
    classification: ChangeClassification,
    removed: boolean,
    signature?: FileSignature
  ): void {
    // Le fichier que l'utilisateur vient de sauvegarder passe devant la
    // rafale de fond : c'est celui qu'il a sous les yeux.
    const priority = this.recentlyEdited.has(relative) ? 'high' : 'normal'

    if (signature) {
      this.freshSignatures.set(relative, signature)
    }

    this.options.log(
      FR.monitor.queued(relative, removed ? 'supprimé' : classification.kind, priority)
    )
    this.queue.submit({
      path: relative,
      analyses: classification.analyses,
      removed,
      priority,
    })
  }

  // ---------------- Exécution d'un travail ----------------

  private async execute(job: ScanJob, signal: AbortSignal): Promise<ExecutionOutcome> {
    const root = this.options.workspaceRoot()
    // Le projet est résolu **au démarrage du travail**, pas à la
    // construction : le dossier ouvert peut avoir changé entre
    // l'événement et l'analyse, et soumettre sous l'identifiant du
    // précédent mélangerait deux projets.
    const projectUid = this.options.projectUid()
    if (!root || signal.aborted) {
      return NOTHING
    }

    const done: string[] = []

    if (job.analyses.code && job.removed) {
      // Supprimé : plus aucune analyse ne passera sur ce fichier. Ses
      // diagnostics et findings de code resteraient sinon affichés.
      this.options.controller.forgetDeleted(
        vscode.Uri.file(path.join(root, job.path)),
        job.path
      )
    }

    if (job.analyses.code && this.options.wantsCode() && !job.removed) {
      if (await this.analyzeCode(root, job.path, signal)) {
        done.push('code')
      }
    }

    // Le même déclencheur sert les deux moteurs : un fichier texte qui
    // change est relu une fois, et chacun décide s'il le regarde. Les
    // réglages restent distincts — la surveillance n'est pas une porte
    // dérobée pour faire tourner ce que l'utilisateur a désactivé.
    const text =
      job.analyses.secrets && !job.removed &&
      (this.options.wantsSecrets() || this.options.wantsApi())
        ? await this.readText(root, job.path)
        : undefined

    const touchedSecrets =
      job.analyses.secrets && this.options.wantsSecrets()
        ? await this.refreshSecrets(root, job, signal, text)
        : false

    const touchedApi =
      job.analyses.secrets && this.options.wantsApi()
        ? this.refreshApi(job, text)
        : false

    const touchedDependencies =
      job.analyses.dependencies && this.options.wantsDependencies()
        ? await this.refreshDependencies(root, job, signal)
        : false

    if (signal.aborted) {
      return NOTHING
    }

    const touched = touchedSecrets || touchedDependencies || touchedApi
    let delivered = false

    if (touched) {
      const submitted = await this.submit(
        projectUid,
        touchedSecrets,
        touchedDependencies,
        touchedApi
      )
      delivered = submitted
      if (submitted) {
        done.push(
          ...[
            touchedSecrets && 'secrets',
            touchedApi && 'API',
            touchedDependencies && 'dépendances',
          ].filter((value): value is string => typeof value === 'string')
        )
      }
    }

    // La signature n'est retenue qu'ici : le fichier est officiellement
    // « vu » une fois son analyse passée.
    const fresh = this.freshSignatures.get(job.path)
    if (fresh) {
      this.freshSignatures.delete(job.path)
      if (!signal.aborted) {
        this.signatures.remember(job.path, fresh)
      }
    }
    this.recentlyEdited.delete(job.path)

    if (done.length > 0) {
      this.options.log(FR.monitor.analyzed(job.path, done.join(', ')))
    }
    return { touched, submitted: delivered }
  }

  /**
   * Analyse de code : le contrôleur existant, sans détour.
   *
   * `scanBatch` plutôt que `scanNow` : il est silencieux par
   * construction. Une surveillance qui ouvre une boîte de dialogue à
   * chaque fichier refusé par le filtre serait insupportable — donc
   * désactivée.
   */
  private async analyzeCode(
    root: string,
    relative: string,
    signal: AbortSignal
  ): Promise<boolean> {
    try {
      const document = await vscode.workspace.openTextDocument(
        vscode.Uri.file(path.join(root, relative))
      )
      if (signal.aborted) {
        return false
      }
      // `documentFilter.evaluate()` reste juge : le classement par
      // extension n'a servi qu'à décider d'ouvrir le document.
      return await this.options.controller.scanBatch(document)
    } catch (error) {
      this.options.log(FR.monitor.failed(relative, describe(error)))
      return false
    }
  }

  /**
   * Remet à jour la contribution d'un fichier au balayage de secrets.
   *
   * Retourne `true` seulement si l'état a **réellement** changé : un
   * fichier réanalysé qui rend les mêmes constats ne justifie aucune
   * soumission, et le trajet réseau serait pure perte.
   */
  private async refreshSecrets(
    root: string,
    job: ScanJob,
    signal: AbortSignal,
    preRead: string | undefined
  ): Promise<boolean> {
    if (!this.baseline.isEstablished) {
      this.options.log(FR.monitor.awaitingBaseline)
      return false
    }

    if (job.removed) {
      return this.baseline.removeFile(job.path)
    }

    const text = preRead ?? (await this.readText(root, job.path))
    if (signal.aborted) {
      return false
    }
    if (text === undefined) {
      // Illisible ou trop gros : on ne peut plus rien affirmer de son
      // contenu. Le retirer vaut mieux que de laisser un constat périmé.
      return this.baseline.removeFile(job.path)
    }

    const outcome = scanForSecrets(job.path, text)
    return this.baseline.setFileSecrets(job.path, outcome.findings)
  }

  /**
   * Remet à jour la contribution d'un fichier à l'analyse d'API.
   *
   * Synchrone : le texte a déjà été lu pour les secrets, et le moteur
   * d'API n'est que des expressions régulières. Relire le fichier pour
   * lui serait exactement le second passage que la phase 3 évite.
   */
  private refreshApi(job: ScanJob, text: string | undefined): boolean {
    if (!this.baseline.isEstablished) {
      return false
    }
    if (job.removed || text === undefined) {
      return this.baseline.removeApiFile(job.path)
    }
    if (!isApiRelevant(job.path)) {
      // Le fichier n'a jamais pu porter de route : rien à retirer, rien
      // à ajouter. Le dire ici évite un aller-retour inutile.
      return false
    }

    const outcome = scanForApiIssues(job.path, text)
    return this.baseline.setFileApiFindings(
      job.path,
      outcome.findings,
      outcome.routes.length
    )
  }

  /** Idem pour l'inventaire des dépendances d'un manifeste. */
  private async refreshDependencies(
    root: string,
    job: ScanJob,
    signal: AbortSignal
  ): Promise<boolean> {
    if (!this.baseline.isEstablished) {
      return false
    }

    if (job.removed) {
      return this.baseline.removeManifest(job.path)
    }

    const text = await this.readText(root, job.path)
    if (signal.aborted) {
      return false
    }
    if (text === undefined) {
      return this.baseline.removeManifest(job.path)
    }

    const fileName = job.path.slice(job.path.lastIndexOf('/') + 1)
    return this.baseline.setManifest(
      job.path,
      parseDependencies(fileName, job.path, text)
    )
  }

  /**
   * Soumet le lot complet et republie les findings.
   *
   * Deux points portent toute la phase :
   *
   * - le lot est **reconstitué** par le registre, jamais réduit au
   *   fichier modifié : les routes réconcilient, et un lot partiel
   *   effacerait le reste ;
   * - les findings sont **relus** chez le backend plutôt que déduits de
   *   la réponse. Une soumission de secrets seule ne renvoie que des
   *   secrets, et republier cela ferait disparaître les dépendances
   *   vulnérables de la vue.
   */
  private async submit(
    projectUid: string | undefined,
    secrets: boolean,
    dependencies: boolean,
    api: boolean
  ): Promise<boolean> {
    if (!projectUid || !this.options.projectSecurityEnabled()) {
      this.options.log(FR.monitor.disabledByBackend)
      return false
    }

    const outcome = await this.options.security.submit({
      projectUid,
      secrets: this.baseline.secretScan(),
      inventory: this.baseline.inventory(),
      api: this.baseline.apiScan(),
      checkVulnerabilities: this.options.checkVulnerabilities(),
      submitSecrets: secrets,
      submitDependencies: dependencies,
      submitApi: api,
    })

    if (!outcome.ok) {
      return false
    }

    // Cloisonnement : le dossier ouvert a pu changer pendant l'aller-
    // retour. Republier sous un autre projet afficherait les findings
    // d'un projet sous le nom d'un autre.
    if (this.options.projectUid() !== projectUid) {
      this.options.log(
        'résultat de surveillance écarté : le projet ouvert a changé pendant l’analyse'
      )
      return false
    }

    const findings = await this.options.security.fetchExisting(projectUid)
    if (this.options.projectUid() !== projectUid) {
      return false
    }

    this.options.onSecurityFindings(findings)
    return true
  }

  // ---------------- Utilitaires ----------------

  private async readText(root: string, relative: string): Promise<string | undefined> {
    try {
      const uri = vscode.Uri.file(path.join(root, relative))
      const stat = await vscode.workspace.fs.stat(uri)
      if (stat.size > MAX_HASH_BYTES) {
        return undefined
      }
      const bytes = await vscode.workspace.fs.readFile(uri)
      return Buffer.from(bytes).toString('utf8')
    } catch {
      return undefined
    }
  }

  /**
   * Chemin relatif au dossier ouvert, séparateurs normalisés.
   *
   * `undefined` dès que le fichier est hors du dossier : la surveillance
   * ne déborde jamais du workspace, même si l'éditeur signale le
   * changement.
   */
  private toRelative(uri: vscode.Uri): string | undefined {
    const root = this.options.workspaceRoot()
    if (!root || uri.scheme !== 'file') {
      return undefined
    }
    const relative = path.relative(root, uri.fsPath)
    if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) {
      return undefined
    }
    return relative.split(path.sep).join('/')
  }

  private showState(state: MonitorState): void {
    if (!this.started) {
      return
    }
    const detail =
      state === 'ANALYZING'
        ? `${this.queue.pendingCount + this.queue.readyCount} en attente, ${
            this.queue.runningCount
          } en cours`
        : undefined
    this.options.statusBar.setMonitorState(state, detail)
  }
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

/** Anti-rebond par défaut, réexporté pour les réglages. */
export { DEFAULT_DEBOUNCE_MS }
