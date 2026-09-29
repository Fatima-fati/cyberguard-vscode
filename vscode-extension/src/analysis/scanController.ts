/**
 * Pilotage des analyses : anti-rebond, annulation, affichage.
 *
 * Règles tenues ici :
 *
 * - **VS Code n'est jamais bloqué.** Tout est asynchrone ; aucune attente
 *   n'est faite sur le fil de l'interface.
 * - **Une seule analyse par fichier à la fois.** Une nouvelle sauvegarde
 *   annule celle en cours plutôt que d'ouvrir une seconde requête.
 * - **Le contenu n'est ni journalisé, ni conservé.** Il est lu, envoyé,
 *   puis oublié : rien n'entre dans `globalState` ni `workspaceState`.
 * - **Le résultat est rattaché au document analysé**, et ignoré si le
 *   contenu a changé entre-temps.
 */

import * as path from 'node:path'
import * as vscode from 'vscode'

import {
  BackendClient,
  BackendError,
  ScanCancelledError,
  type CodeFinding,
  type CodeScanResult,
} from '../api/backendClient'
import type { StreamEvent } from '../api/streamClient'
import { contentHash, contentSize, shortHash } from './contentHash'
import { GitignoreMatcher, evaluate } from './documentFilter'
import type { DiagnosticsProvider } from '../diagnostics/provider'
import type { FindingsStore } from '../state/findingsStore'
import type { NotificationCenter } from '../ui/notifications'
import type { StatusBar } from '../ui/statusBar'
import { FR } from '../i18n/fr'

/** Délai d'anti-rebond : plusieurs sauvegardes rapprochées = un seul scan. */
const DEBOUNCE_MS = 800

/**
 * Patience accordée au flux temps réel avant de relire l'analyse.
 *
 * Passé ce délai sans événement `code_scan` de fin, l'enrichissement est
 * relu par `GET /api/code/scans/{scan_uid}`. Assez long pour laisser le
 * modèle travailler, assez court pour que l'éditeur ne reste pas
 * indéfiniment sur « analyse IA… ».
 */
const ENRICHMENT_FALLBACK_MS = 30_000

interface PendingScan {
  timer: NodeJS.Timeout | undefined
  controller: AbortController | undefined
  /** Empreinte du contenu de l'analyse en vol, pour détecter l'obsolescence. */
  hash: string | undefined
}

export interface ScanControllerOptions {
  client: BackendClient
  diagnostics: DiagnosticsProvider
  statusBar: StatusBar
  output: vscode.OutputChannel
  /** Registre alimentant la vue « Security ». */
  store: FindingsStore
  /** Bulles de sécurité, dédupliquées par empreinte. */
  notifications: NotificationCenter
  /**
   * Projet courant, consulté à chaque analyse.
   *
   * Injecté plutôt que lu ici : le contrôleur n'a pas à connaître le
   * service de contexte, et l'identifiant change au fil des découvertes —
   * une valeur capturée à la construction serait périmée. `undefined` est
   * légitime : un fichier ouvert hors de tout dossier reste analysable.
   */
  projectUid?: () => string | undefined
}

/** Réglages d'une analyse ponctuelle. */
interface ScanOptions {
  /** Un refus de filtre ou une panne restent-ils dans le canal de sortie ? */
  silent: boolean
  /** Les sévérités CRITICAL/HIGH déclenchent-elles une notification ? */
  notify: boolean
  /** Force l'enrichissement IA, quel que soit le réglage utilisateur. */
  forceAi?: boolean
}

export class ScanController implements vscode.Disposable {
  private readonly client: BackendClient
  private readonly diagnostics: DiagnosticsProvider
  private readonly statusBar: StatusBar
  private readonly output: vscode.OutputChannel
  private readonly store: FindingsStore
  private readonly notifications: NotificationCenter
  private readonly projectUid: () => string | undefined

  /** État par document, indexé par URI. */
  private readonly pending = new Map<string, PendingScan>()
  /** Chemin envoyé au backend -> document correspondant, pour router le SSE. */
  private readonly scannedPaths = new Map<string, vscode.Uri>()
  /**
   * Analyses dont l'enrichissement IA est annoncé en cours.
   *
   * Indexées par **chemin de fichier**, pas par `scan_uid` : une analyse
   * plus récente doit annuler la relecture de la précédente, dont le
   * résultat écraserait le plus récent.
   */
  private readonly awaitingEnrichment = new Map<
    string,
    { scanUid: string; timer: NodeJS.Timeout }
  >()
  private gitignore: GitignoreMatcher = GitignoreMatcher.empty()
  private disposed = false

  constructor(options: ScanControllerOptions) {
    this.client = options.client
    this.diagnostics = options.diagnostics
    this.statusBar = options.statusBar
    this.output = options.output
    this.store = options.store
    this.notifications = options.notifications
    this.projectUid = options.projectUid ?? (() => undefined)
    this.reloadGitignore()
  }

  /** Recharge le `.gitignore` du workspace (ouverture, changement de dossier). */
  reloadGitignore(): void {
    this.gitignore = GitignoreMatcher.load(workspaceRoot())
  }

  /**
   * Analyse déclenchée par une sauvegarde : passe par l'anti-rebond.
   *
   * Ne notifie jamais l'utilisateur d'un refus de filtre : un fichier non
   * pertinent doit rester silencieux.
   */
  scheduleScan(document: vscode.TextDocument): void {
    if (this.disposed) {
      return
    }

    const key = document.uri.toString()
    const state = this.pending.get(key) ?? { timer: undefined, controller: undefined, hash: undefined }

    // Une sauvegarde plus récente remplace la précédente : on annule le
    // minuteur ET la requête en vol, s'il y en a une.
    if (state.timer) {
      clearTimeout(state.timer)
    }
    state.controller?.abort()
    state.controller = undefined

    state.timer = setTimeout(() => {
      state.timer = undefined
      void this.runScan(document, { silent: true, notify: true })
    }, DEBOUNCE_MS)

    this.pending.set(key, state)
  }

  /**
   * Analyse déclenchée à la demande : immédiate, et qui explique un refus.
   *
   * `forceAi` correspond à l'action « Analyze with AI » : c'est le même
   * scan, avec le drapeau `ai_enrichment` de `/api/code/scan` forcé. Rien
   * n'est analysé côté extension, et aucun second agent n'est créé.
   */
  async scanNow(
    document: vscode.TextDocument,
    options: { forceAi?: boolean } = {}
  ): Promise<void> {
    const key = document.uri.toString()
    const state = this.pending.get(key)
    if (state?.timer) {
      clearTimeout(state.timer)
      state.timer = undefined
    }
    await this.runScan(document, {
      silent: false,
      notify: true,
      forceAi: options.forceAi === true,
    })
  }

  /**
   * Analyse d'un fichier au sein d'un balayage du workspace.
   *
   * Silencieuse par construction : sur trois cents fichiers, une
   * notification par résultat serait ingérable. Le résumé est produit une
   * seule fois par l'appelant.
   *
   * Retourne `false` si le fichier a été écarté par le filtre ou si
   * l'analyse a échoué.
   */
  async scanBatch(
    document: vscode.TextDocument,
    token?: vscode.CancellationToken
  ): Promise<boolean> {
    if (token?.isCancellationRequested) {
      return false
    }
    return this.runScan(document, { silent: true, notify: false })
  }

  /**
   * Applique un événement du flux temps réel.
   *
   * Un seul type est traité : `code_finding`, un finding requalifié par le
   * modèle. L'état terminal d'une analyse — terminée ou en échec — n'est
   * pas déduit du flux mais relu par `GET /api/code/scans/{scan_uid}` :
   * une seule source, qui fonctionne aussi quand le flux est coupé.
   */
  applyStreamEvent(event: StreamEvent): void {
    // Le client SSE ne livre que `code_finding` : ce contrôle est une
    // ceinture, pas la bretelle.
    if (event.event !== 'code_finding') {
      return
    }
    this.applyEnrichedFinding(event.data as CodeFinding & { file_path?: string })
  }

  /**
   * Oublie un fichier supprimé du disque.
   *
   * Aucune analyse ne repassera sur lui : sans cela, ses diagnostics et
   * ses findings de code resteraient affichés pour un fichier disparu.
   * Les findings de sécurité projet suivent leur propre chemin
   * (`SecurityBaseline.removeFile`).
   */
  forgetDeleted(uri: vscode.Uri, relativePath: string): void {
    const known = this.scannedPaths.get(relativePath) ?? uri
    for (const target of [known, uri]) {
      const key = target.toString()
      const state = this.pending.get(key)
      if (state?.timer) {
        clearTimeout(state.timer)
      }
      state?.controller?.abort()
      this.pending.delete(key)
      this.diagnostics.clear(target)
    }
    this.scannedPaths.delete(relativePath)
    this.store.removeFile(relativePath)
  }

  /** Oublie l'état d'un document fermé. */
  forget(document: vscode.TextDocument): void {
    const key = document.uri.toString()
    const state = this.pending.get(key)
    if (state?.timer) {
      clearTimeout(state.timer)
    }
    state?.controller?.abort()
    this.pending.delete(key)
    this.diagnostics.clear(document.uri)

    for (const [filePath, uri] of this.scannedPaths) {
      if (uri.toString() === key) {
        this.scannedPaths.delete(filePath)
      }
    }
  }

  /**
   * Vide l'affichage : diagnostics, vue « Security » et routage SSE.
   *
   * Rien n'est supprimé côté backend — les findings restent dans la base
   * et reviennent à la prochaine analyse ou au prochain rafraîchissement.
   */
  clearAll(): void {
    for (const state of this.pending.values()) {
      if (state.timer) {
        clearTimeout(state.timer)
        state.timer = undefined
      }
      state.controller?.abort()
      state.controller = undefined
    }
    this.scannedPaths.clear()
    this.clearEnrichmentFallbacks()
    this.diagnostics.clearAll()
    this.store.clear()
    // L'utilisateur repart d'une vue vide : il doit pouvoir être prévenu à
    // nouveau des problèmes qu'il vient d'effacer de l'affichage.
    this.notifications.reset()
    this.statusBar.setIdle()
    this.log('vue Security vidée (les findings restent enregistrés côté backend)')
  }

  dispose(): void {
    this.disposed = true
    this.clearEnrichmentFallbacks()
    for (const state of this.pending.values()) {
      if (state.timer) {
        clearTimeout(state.timer)
      }
      state.controller?.abort()
    }
    this.pending.clear()
  }

  // ---------------- Interne ----------------

  private async runScan(
    document: vscode.TextDocument,
    options: ScanOptions
  ): Promise<boolean> {
    const root = workspaceRoot()
    const relativePath = toRelativePath(document.uri, root)

    // Le contenu est lu ici et n'existe que le temps de la requête.
    const content = document.getText()
    const size = contentSize(content)

    this.debug('runScan() START')
    this.debug(`  uri          : ${document.uri.toString()}`)
    this.debug(`  scheme       : ${document.uri.scheme}`)
    this.debug(`  fsPath       : ${document.uri.fsPath}`)
    this.debug(`  relativePath : ${relativePath}`)
    this.debug(`  languageId   : ${document.languageId}`)
    this.debug(`  isUntitled   : ${document.isUntitled} · ${size} octet(s)`)
    this.debug(`  workspace    : ${root ?? '(aucun dossier ouvert)'}`)

    const decision = evaluate(
      {
        fsPath: document.uri.fsPath,
        relativePath,
        languageId: document.languageId,
        isUntitled: document.isUntitled,
        size,
        workspaceRoot: root,
      },
      this.gitignore
    )

    this.debug(
      `  filtre       : ${decision.accepted ? 'accepté' : 'refusé'}` +
        (decision.accepted
          ? ` — langage envoyé « ${decision.language} »`
          : ` — ${decision.reason}`)
    )

    if (!decision.accepted) {
      this.diagnostics.clear(document.uri)
      // Un refus est toujours tracé : l'utilisateur doit pouvoir
      // comprendre pourquoi son fichier n'a pas été analysé.
      this.log(`${relativePath} non analysé — ${decision.reason}`)
      if (!options.silent) {
        void vscode.window.showInformationMessage(FR.scanUnsupported(decision.reason))
      }
      this.debug('runScan() END — document écarté par le filtre')
      return false
    }

    const key = document.uri.toString()
    const hash = contentHash(content)
    const state = this.pending.get(key) ?? { timer: undefined, controller: undefined, hash: undefined }

    // Analyse déjà en vol sur exactement ce contenu : inutile d'en lancer
    // une seconde. Le backend la servirait depuis son cache, mais autant
    // ne pas faire l'aller-retour.
    if (state.controller && state.hash === hash) {
      this.log(`${relativePath} — analyse déjà en cours (${shortHash(hash)})`)
      this.debug('runScan() END — analyse identique déjà en vol')
      return false
    }

    state.controller?.abort()
    const controller = new AbortController()
    state.controller = controller
    state.hash = hash
    this.pending.set(key, state)

    this.statusBar.setScanning()

    const aiRequested = options.forceAi === true || aiEnrichmentEnabled()
    const projectUid = this.projectUid() ?? null
    // La charge utile est décrite par sa forme, jamais par son contenu :
    // le code de l'utilisateur ne doit apparaître dans aucun journal.
    this.debug(
      `  payload      : file_path=${relativePath} · language=${decision.language} · ` +
        `content_hash=${shortHash(hash)} · content=${size} octet(s) (non journalisé) · ` +
        `workspace=${workspaceName() ?? 'null'} · project=${projectUid ?? 'null'} · ` +
        `ai_enrichment=${aiRequested}`
    )
    this.debug('  appel du backend POST /api/code/scan …')

    let result: CodeScanResult
    try {
      result = await this.client.scan(
        {
          file_path: relativePath,
          language: decision.language,
          content,
          content_hash: hash,
          workspace: workspaceName(),
          // Rattache le scan a son projet : c'est ce qui permet au backend
          // de filtrer les findings et de n'adresser le flux temps reel
          // qu'a ce projet.
          project_uid: projectUid,
          // Le drapeau est transmis au backend, qui reste seul juge : il
          // ignore la demande si `CODE_AI_ENRICHMENT_ENABLED` est faux.
          ai_enrichment: aiRequested,
        },
        controller.signal
      )
    } catch (error) {
      // Une annulation est un déroulement normal, pas une panne.
      if (error instanceof ScanCancelledError || controller.signal.aborted) {
        this.log(`${relativePath} — analyse annulée (contenu remplacé)`)
        this.debug('runScan() END — analyse annulée')
        return false
      }

      this.handleFailure(error, relativePath, options.silent)
      this.debug('runScan() END — échec de la requête')
      return false
    } finally {
      if (state.controller === controller) {
        state.controller = undefined
      }
    }

    this.debug(
      `  réponse      : ${result.findings_count} finding(s) · ` +
        `${result.counts.critical}C ${result.counts.high}H ${result.counts.medium}M ` +
        `${result.counts.low}L · statut=${result.analysis_status} · ` +
        `cache=${result.cached} · règles=${result.rules_version} · scan_uid=${result.scan_uid}`
    )
    for (const finding of result.findings) {
      this.debug(
        `    · ${finding.rule_id} ${finding.severity} ligne ` +
          `${finding.location?.line_start ?? '?'} — ${finding.title}`
      )
    }

    // Le document a-t-il changé pendant l'analyse ? Si oui, le résultat
    // ne décrit plus ce qui est à l'écran : on ne l'affiche pas.
    if (contentHash(document.getText()) !== hash) {
      this.log(`${relativePath} — résultat ignoré, le fichier a changé depuis l'envoi`)
      // Silencieux jusqu'ici : l'utilisateur voyait une commande sans
      // effet. Il doit savoir que son résultat a été écarté, et pourquoi.
      if (!options.silent) {
        void vscode.window.showWarningMessage(FR.scanStale)
      }
      this.debug('runScan() END — résultat obsolète, fichier modifié pendant l’analyse')
      return false
    }

    // L'empreinte accompagne les findings : c'est elle qui permettra de
    // refuser un correctif si le fichier bouge après l'analyse.
    this.diagnostics.publish(document, result.findings, hash)
    // La vue « Security » est alimentée par la même réponse HTTP : un seul
    // aller-retour sert l'éditeur et la vue.
    this.store.replaceFile(result.file_path || relativePath, result.findings)
    this.scannedPaths.set(relativePath, document.uri)
    this.debug(
      `  store        : ${result.findings.length} finding(s) enregistré(s) pour ` +
        `${result.file_path || relativePath} — vue Security notifiée`
    )

    // L'enrichissement IA est en route : les findings déterministes sont
    // déjà affichés, le modèle va les affiner.
    if (result.analysis_status === 'pending' || result.analysis_status === 'analyzing') {
      this.statusBar.setEnriching(result.counts, path.basename(relativePath))
      this.log(`${relativePath} — enrichissement IA en cours côté backend`)
      // Le flux SSE annoncera la fin. S'il ne le fait pas, ce minuteur ira
      // relire l'analyse par sa route de repli.
      this.armEnrichmentFallback(result.scan_uid, relativePath)
    } else {
      // Analyse terminée : toute relecture programmée pour ce fichier
      // porte sur une analyse dépassée.
      this.cancelEnrichmentFallback(relativePath)
      this.statusBar.setResult(result.counts, path.basename(relativePath))
    }
    this.log(
      `${relativePath} — ${result.findings_count} finding(s) ` +
        `[${result.counts.critical}C ${result.counts.high}H ` +
        `${result.counts.medium}M ${result.counts.low}L]` +
        `${result.cached ? ' (cache)' : ''} · règles ${result.rules_version} · ${shortHash(hash)}`
    )

    if (options.notify) {
      // Le centre de notifications décide seul de ce qui mérite une bulle :
      // il connaît ce qui a déjà été annoncé, pas nous.
      this.notifications.consider(result.findings)
    }

    // Analyse demandée à la main et sans rien à signaler : le centre de
    // notifications se tait par construction, et l'utilisateur se
    // retrouverait devant une commande apparemment sans effet. La barre
    // d'état ne suffit pas — elle est discrète et peut afficher le
    // résultat d'un autre fichier.
    if (!options.silent && result.findings_count === 0) {
      void vscode.window.showInformationMessage(
        FR.scanClean(path.basename(relativePath))
      )
    }

    this.debug('runScan() END — analyse terminée')
    return true
  }

  /**
   * Remplace un finding par sa version qualifiée par le modèle.
   *
   * La vue « Security » est mise à jour même quand le fichier n'est plus
   * ouvert : c'est le cas courant après un balayage du workspace. Les
   * diagnostics, eux, n'ont de sens que sur un document ouvert.
   *
   * Le store refuse les findings qu'il ne peut rattacher à ce workspace :
   * `/api/stream` est partagé avec l'interface web, et la vue ne doit
   * jamais afficher le code d'un autre poste.
   */
  private applyEnrichedFinding(finding: CodeFinding & { file_path?: string }): void {
    const tracked = this.store.upsertIfTracked(finding)
    if (!tracked) {
      this.log(
        `finding SSE ignoré — ${finding.file_path ?? 'chemin inconnu'} n'a pas été ` +
          'analysé depuis cet éditeur'
      )
      return
    }

    this.log(
      `${finding.file_path} — ${finding.rule_id} enrichi par l'IA ` +
        `(${finding.severity}, ${finding.risk_score}/100${
          finding.status === 'dismissed' ? ', écarté comme faux positif' : ''
        })`
    )

    // Le même problème, réévalué : le centre de notifications reconnaît
    // son empreinte et se tait, sauf si l'IA aggrave le diagnostic.
    this.notifications.consider([finding])

    const document = this.documentFor(finding.file_path)
    if (!document) {
      return
    }

    const counts = this.diagnostics.upsert(document, finding)
    if (!counts) {
      return
    }

    this.statusBar.setEnriching(counts, path.basename(document.uri.fsPath))
  }

  // ---------------- Repli du flux temps réel ----------------

  /**
   * Programme la relecture d'une analyse dont l'enrichissement est en cours.
   *
   * Le flux SSE apporte les findings requalifiés au fil de l'eau ; il
   * n'annonce pas l'état terminal. C'est cette relecture qui le donne, et
   * elle fonctionne aussi bien quand le flux est coupé — d'où une seule
   * source d'état final, au lieu de deux qui pourraient diverger.
   *
   * Une seule relecture en attente par fichier : une analyse plus récente
   * remplace la précédente, dont le résultat n'a plus d'intérêt.
   */
  private armEnrichmentFallback(scanUid: string, relativePath: string): void {
    if (!scanUid || this.disposed) {
      return
    }

    this.cancelEnrichmentFallback(relativePath)

    this.awaitingEnrichment.set(relativePath, {
      scanUid,
      timer: setTimeout(() => {
        this.awaitingEnrichment.delete(relativePath)
        void this.reconcileScan(scanUid, relativePath)
      }, ENRICHMENT_FALLBACK_MS),
    })
  }

  /**
   * Abandonne la relecture en attente pour ce fichier.
   *
   * Appelée dès qu'une analyse plus récente aboutit : appliquer le
   * résultat d'une analyse dépassée écraserait le plus récent.
   */
  private cancelEnrichmentFallback(relativePath: string): void {
    const pending = this.awaitingEnrichment.get(relativePath)
    if (pending) {
      clearTimeout(pending.timer)
      this.awaitingEnrichment.delete(relativePath)
    }
  }

  /** Annule toutes les relectures programmées. */
  private clearEnrichmentFallbacks(): void {
    for (const pending of this.awaitingEnrichment.values()) {
      clearTimeout(pending.timer)
    }
    this.awaitingEnrichment.clear()
  }

  /**
   * Relit une analyse par `GET /api/code/scans/{scan_uid}`.
   *
   * Aucune ré-analyse : le backend répond depuis ce qu'il a déjà en base,
   * le contenu du fichier n'est pas retransmis. L'échec est silencieux —
   * les findings déterministes sont affichés depuis longtemps, et une
   * relecture ratée ne remet rien en cause.
   */
  private async reconcileScan(scanUid: string, relativePath: string): Promise<void> {
    if (this.disposed) {
      return
    }

    let result: CodeScanResult
    try {
      result = await this.client.getScan(scanUid)
    } catch (error) {
      const message =
        error instanceof BackendError ? error.message : FR.errors.unexpected
      this.log(`${relativePath} — relecture de l'analyse impossible : ${message}`)
      // La barre d'état ne doit pas rester bloquée sur « analyse IA… ».
      this.settleStatusBar(relativePath)
      return
    }

    if (result.analysis_status === 'pending' || result.analysis_status === 'analyzing') {
      // Le modèle travaille encore : on laisse une seconde chance, sans
      // insister au-delà.
      this.log(`${relativePath} — enrichissement toujours en cours, relecture différée`)
      this.armEnrichmentFallback(scanUid, relativePath)
      return
    }

    this.log(
      `${relativePath} — analyse relue sans le flux temps réel ` +
        `(${result.analysis_status}, ${result.findings_count} finding(s))`
    )

    // La vue Security est mise à jour dans tous les cas : elle ne dépend
    // pas d'un document ouvert.
    this.store.replaceFile(result.file_path || relativePath, result.findings)
    this.notifications.consider(result.findings)

    const uri = this.scannedPaths.get(relativePath)
    const document = uri
      ? vscode.workspace.textDocuments.find(
          (candidate) => candidate.uri.toString() === uri.toString()
        )
      : undefined

    if (!document) {
      return
    }

    // Les diagnostics ne sont republiés que si le document à l'écran est
    // toujours celui qui a été analysé.
    if (contentHash(document.getText()) !== result.content_hash) {
      this.log(`${relativePath} — document modifié depuis, diagnostics conservés`)
      return
    }

    this.diagnostics.publish(document, result.findings, result.content_hash)

    if (result.analysis_status === 'failed') {
      // Les findings des règles restent valables : rien n'est effacé.
      this.statusBar.setEnrichmentFailed(
        result.counts,
        path.basename(relativePath),
        result.analysis_error ?? ''
      )
      this.notifications.reportEnrichmentFailure(result.analysis_error ?? '')
      return
    }

    this.statusBar.setResult(result.counts, path.basename(relativePath))
  }

  /** Sort la barre d'état de l'état « enrichissement en cours ». */
  private settleStatusBar(relativePath: string): void {
    const uri = this.scannedPaths.get(relativePath)
    if (!uri) {
      return
    }
    this.statusBar.setResult(this.diagnostics.counts(uri), path.basename(relativePath))
  }

  /** Document ouvert correspondant au chemin annoncé par le backend. */
  private documentFor(filePath: string | undefined): vscode.TextDocument | undefined {
    if (!filePath) {
      return undefined
    }

    const uri = this.scannedPaths.get(filePath)
    if (!uri) {
      return undefined
    }

    return vscode.workspace.textDocuments.find(
      (candidate) => candidate.uri.toString() === uri.toString()
    )
  }

  private handleFailure(error: unknown, relativePath: string, silent: boolean): void {
    const message =
      error instanceof BackendError ? error.message : FR.errors.unexpected
    const detail =
      error instanceof BackendError
        ? error.detail
        : error instanceof Error
          ? error.message
          : String(error)

    if (error instanceof BackendError && error.status === 0) {
      this.statusBar.setBackendUnavailable()
    } else {
      this.statusBar.setIdle()
    }

    // La trace technique reste dans le canal de sortie ; l'utilisateur ne
    // voit qu'une phrase compréhensible.
    this.log(`${relativePath} — échec : ${message}${detail ? ` (${detail})` : ''}`)

    if (!silent) {
      void vscode.window.showErrorMessage(FR.scanFailed(message))
    }
  }

  private log(message: string): void {
    const stamp = new Date().toISOString().slice(11, 19)
    this.output.appendLine(`[${stamp}] ${message}`)
  }

  /**
   * Trace de diagnostic, etape par etape, dans le canal de sortie.
   *
   * Destinee a repondre a une seule question quand rien ne s'affiche :
   * *ou le traitement s'est-il arrete ?* Chaque etape du chemin en laisse
   * une, y compris les sorties anticipees. Le contenu des fichiers n'y
   * figure jamais : seulement des chemins, des tailles et des empreintes.
   */
  private debug(message: string): void {
    this.log(`[WAZUH DEBUG] ${message}`)
  }
}

// --------------------------------------------------------------------------
// Utilitaires workspace
// --------------------------------------------------------------------------

/** Racine du premier dossier ouvert, ou `undefined` si aucun. */
export function workspaceRoot(): string | undefined {
  return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath
}

/**
 * Identifiant de workspace transmis au backend.
 *
 * Le **nom** du dossier, pas son chemin absolu : le backend n'a besoin
 * que d'un identifiant pour regrouper les scans, pas de l'arborescence du
 * poste de travail.
 */
export function workspaceName(): string | null {
  return vscode.workspace.workspaceFolders?.[0]?.name ?? null
}

/** Chemin relatif au workspace, séparateurs normalisés. */
function toRelativePath(uri: vscode.Uri, root: string | undefined): string {
  if (!root) {
    return path.basename(uri.fsPath)
  }
  const relative = path.relative(root, uri.fsPath)
  // Fichier hors du workspace : on ne remonte pas l'arborescence du poste.
  if (relative.startsWith('..')) {
    return path.basename(uri.fsPath)
  }
  return relative.split(path.sep).join('/')
}

function aiEnrichmentEnabled(): boolean {
  return vscode.workspace
    .getConfiguration('wazuhSecurity')
    .get<boolean>('aiEnrichment', false)
}
