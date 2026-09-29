/**
 * File d'analyses de la surveillance continue.
 *
 * Le problème résolu
 * ------------------
 *
 * Un éditeur produit des changements par rafales : un formateur réécrit
 * dix fichiers, un `git checkout` en touche deux cents, une sauvegarde
 * automatique tombe toutes les secondes. Envoyer une analyse par
 * événement rendrait l'extension inutilisable — et, pire, ferait attendre
 * VS Code.
 *
 * Cinq garanties, et où chacune est tenue
 * ---------------------------------------
 *
 *     anti-rebond        `submit` reprogramme le minuteur du chemin au
 *                        lieu d'empiler un second travail
 *     aucun doublon      un chemin n'a **jamais** deux entrées : les
 *                        analyses demandées fusionnent
 *     un seul à la fois  un chemin déjà en cours n'est pas relancé en
 *                        parallèle ; le travail en vol est annulé
 *     annulation         chaque exécution reçoit un `AbortSignal`, et
 *                        `cancel` / `cancelAll` l'utilisent réellement
 *     jamais bloquant    rien n'est `await` ici ; la file rend la main
 *                        immédiatement et se vide toute seule
 *
 * Ce module ne connaît ni VS Code, ni le backend, ni les secrets : il
 * reçoit une fonction `run` et l'appelle au bon moment. C'est ce qui rend
 * l'ordonnancement vérifiable sans éditeur, sans réseau et **sans
 * minuteur réel** — les minuteurs sont injectables, et les tests les
 * pilotent à la main.
 */

import type { RequiredAnalyses } from './changeClassification'
import { mergeAnalyses } from './changeClassification'

/** État de la surveillance, tel que la barre d'état l'affiche. */
export type MonitorState = 'READY' | 'ANALYZING' | 'ERROR'

/**
 * Priorité d'un travail.
 *
 * `high` est réservé au fichier que l'utilisateur vient d'éditer ou de
 * sauvegarder. La distinction n'est pas décorative : quand un
 * `git checkout` remplit la file de deux cents fichiers, celui qui est
 * sous les yeux du développeur doit être analysé **en premier**, pas en
 * deux-centième position. C'est la différence entre une surveillance
 * qu'on remarque et une qu'on subit.
 */
export type ScanPriority = 'high' | 'normal'

/** Ce qu'un changement demande à la file. */
export interface ScanJob {
  /** Chemin relatif à la racine du projet, séparateurs normalisés. */
  readonly path: string
  readonly analyses: RequiredAnalyses
  /** Le fichier a-t-il disparu ? Une suppression est aussi un changement. */
  readonly removed: boolean
  /** Défaut : `normal`. Voir `ScanPriority`. */
  readonly priority?: ScanPriority
}

/**
 * Minuteurs injectables.
 *
 * Les tests fournissent une horloge qu'ils font avancer eux-mêmes :
 * vérifier un anti-rebond en attendant réellement 800 ms produirait des
 * tests lents et intermittents.
 */
export interface QueueTimers {
  setTimeout(callback: () => void, delayMs: number): unknown
  clearTimeout(handle: unknown): void
}

const REAL_TIMERS: QueueTimers = {
  setTimeout: (callback, delayMs) => setTimeout(callback, delayMs),
  clearTimeout: (handle) => clearTimeout(handle as NodeJS.Timeout),
}

/** Anti-rebond par défaut : plusieurs sauvegardes rapprochées = un travail. */
export const DEFAULT_DEBOUNCE_MS = 1_200

/**
 * Travaux menés de front.
 *
 * Deux, pas davantage : chaque analyse de code est un aller-retour HTTP
 * vers le backend, et saturer celui-ci depuis l'éditeur dégraderait
 * l'analyse à la demande — celle que l'utilisateur attend vraiment.
 */
export const DEFAULT_MAX_CONCURRENT = 2

/**
 * Plafond de travaux retenus, en attente et prêts confondus.
 *
 * La contre-pression n'est pas une optimisation : sans elle, un
 * `git checkout` de branche sur un monorepo, ou un `npm install` qui
 * réécrit des milliers de fichiers, ferait grandir cette file sans borne
 * — et avec elle la mémoire de l'éditeur.
 *
 * Quand le plafond mord, ce sont les travaux **ordinaires les plus
 * anciens** qui sont abandonnés, jamais un travail prioritaire : le
 * fichier que l'utilisateur édite garde sa place quoi qu'il arrive. Un
 * abandon est toujours journalisé — une file qui perd des travaux en
 * silence ferait croire à une surveillance complète qui n'a pas eu lieu,
 * et c'est le pire des mensonges pour un outil de sécurité.
 */
export const DEFAULT_MAX_QUEUED = 500

export interface ScanQueueOptions {
  /** Exécute un travail. Doit respecter `signal`, et ne jamais lever. */
  readonly run: (job: ScanJob, signal: AbortSignal) => Promise<void>
  /**
   * Anti-rebond, fixe ou résolu à chaque usage.
   *
   * La forme fonction existe pour un cas précis : le réglage de
   * l'utilisateur. Une valeur capturée à la construction obligerait à
   * redémarrer l'éditeur pour qu'un changement prenne effet.
   */
  readonly debounceMs?: number | (() => number)
  readonly maxConcurrent?: number
  /** Contre-pression : plafond de travaux retenus. Voir `DEFAULT_MAX_QUEUED`. */
  readonly maxQueued?: number
  /** Notifié à chaque transition d'état, jamais à l'identique. */
  readonly onStateChange?: (state: MonitorState) => void
  /** Échec d'un travail. L'annulation n'en est pas un. */
  readonly onError?: (path: string, error: unknown) => void
  /** Travail abandonné par contre-pression. Jamais silencieux. */
  readonly onDropped?: (path: string, queued: number) => void
  readonly onLog?: (message: string) => void
  readonly timers?: QueueTimers
}

interface PendingEntry {
  analyses: RequiredAnalyses
  removed: boolean
  priority: ScanPriority
  timer: unknown
  /** Rang d'arrivée : départage les abandons de contre-pression. */
  sequence: number
}

interface RunningEntry {
  controller: AbortController
  /** Le travail a-t-il été devancé par un changement plus récent ? */
  superseded: boolean
}

export class ScanQueue {
  private readonly run: (job: ScanJob, signal: AbortSignal) => Promise<void>
  private readonly debounceMs: () => number
  private readonly maxConcurrent: number
  private readonly maxQueued: number
  private readonly onStateChange: ((state: MonitorState) => void) | undefined
  private readonly onError: ((path: string, error: unknown) => void) | undefined
  private readonly onDropped: ((path: string, queued: number) => void) | undefined
  private readonly onLog: ((message: string) => void) | undefined
  private readonly timers: QueueTimers

  /** Compteur d'arrivée, pour que la contre-pression sache qui est le plus ancien. */
  private sequence = 0
  /** Travaux abandonnés par contre-pression depuis le dernier `cancelAll`. */
  private dropped = 0

  /** Chemins en attente de la fin de leur anti-rebond. */
  private readonly pending = new Map<string, PendingEntry>()
  /** Chemins prêts, dans l'ordre d'arrivée. Jamais deux fois le même. */
  private readonly ready: ScanJob[] = []
  /** Chemins en cours d'analyse. Au plus un travail par chemin. */
  private readonly running = new Map<string, RunningEntry>()

  private lastFailed = false
  private state: MonitorState = 'READY'
  private disposed = false

  constructor(options: ScanQueueOptions) {
    this.run = options.run
    const debounce = options.debounceMs ?? DEFAULT_DEBOUNCE_MS
    this.debounceMs =
      typeof debounce === 'function' ? debounce : () => debounce
    this.maxConcurrent = Math.max(1, options.maxConcurrent ?? DEFAULT_MAX_CONCURRENT)
    this.maxQueued = Math.max(1, options.maxQueued ?? DEFAULT_MAX_QUEUED)
    this.onStateChange = options.onStateChange
    this.onError = options.onError
    this.onDropped = options.onDropped
    this.onLog = options.onLog
    this.timers = options.timers ?? REAL_TIMERS
  }

  /**
   * Soumet un changement.
   *
   * Rend la main immédiatement : rien n'est analysé dans cet appel. Peut
   * être appelée aussi souvent que l'éditeur le veut — c'est exactement
   * son rôle d'absorber les rafales.
   */
  submit(job: ScanJob): void {
    if (this.disposed) {
      return
    }

    // Un travail déjà en cours sur ce chemin porte sur un contenu
    // périmé : on l'annule plutôt que d'ouvrir une seconde analyse du
    // même fichier. Son résultat ne décrirait plus ce qui est sur disque.
    const active = this.running.get(job.path)
    if (active && !active.superseded) {
      active.superseded = true
      active.controller.abort()
      this.log(`${job.path} — analyse en cours annulée, le fichier a changé`)
    }

    const priority = job.priority ?? 'normal'
    const existing = this.pending.get(job.path)
    if (existing) {
      // Aucun doublon : on fusionne dans l'entrée existante et on
      // reprogramme. Dix sauvegardes en deux secondes = un seul travail.
      this.timers.clearTimeout(existing.timer)
      existing.analyses = mergeAnalyses(existing.analyses, job.analyses)
      // La suppression est l'état le plus récent qui compte : un fichier
      // recréé après effacement n'est plus supprimé.
      existing.removed = job.removed
      // La priorité ne redescend jamais : un fichier que l'utilisateur a
      // touché reste prioritaire, même si un événement de fond le
      // resoumet ensuite en `normal`.
      if (priority === 'high') {
        existing.priority = 'high'
      }
      existing.timer = this.arm(job.path)
      this.touchState()
      return
    }

    // Un chemin déjà prêt qu'on resoumet : on le remet en attente pour
    // repasser par l'anti-rebond, plutôt que de le laisser partir avec
    // des analyses incomplètes. Là encore, jamais deux entrées.
    const readyIndex = this.ready.findIndex((queued) => queued.path === job.path)
    if (readyIndex >= 0) {
      const [queued] = this.ready.splice(readyIndex, 1)
      if (queued) {
        this.pending.set(job.path, {
          analyses: mergeAnalyses(queued.analyses, job.analyses),
          removed: job.removed,
          priority:
            queued.priority === 'high' || priority === 'high' ? 'high' : 'normal',
          timer: this.arm(job.path),
          sequence: (this.sequence += 1),
        })
        this.touchState()
        return
      }
    }

    this.pending.set(job.path, {
      analyses: job.analyses,
      removed: job.removed,
      priority,
      timer: this.arm(job.path),
      sequence: (this.sequence += 1),
    })

    this.applyBackpressure()
    this.touchState()
  }

  /**
   * Ramène la file sous son plafond, en abandonnant les travaux
   * ordinaires les plus anciens.
   *
   * Les travaux prioritaires ne sont jamais abandonnés : ils
   * correspondent à ce que l'utilisateur a sous les yeux. Si la file
   * n'était **que** prioritaire, on ne supprime rien — mieux vaut une
   * file un peu trop longue qu'un fichier édité jamais analysé.
   */
  private applyBackpressure(): void {
    let total = this.pending.size + this.ready.length
    if (total <= this.maxQueued) {
      return
    }

    // Les prêts d'abord — ce sont les plus anciens par construction — puis
    // les attentes, du plus ancien au plus récent.
    const victims: string[] = []
    for (const queued of this.ready) {
      if ((queued.priority ?? 'normal') === 'normal') {
        victims.push(queued.path)
      }
    }
    const waiting = [...this.pending.entries()]
      .filter(([, entry]) => entry.priority === 'normal')
      .sort((a, b) => a[1].sequence - b[1].sequence)
      .map(([path]) => path)
    victims.push(...waiting)

    for (const path of victims) {
      if (total <= this.maxQueued) {
        break
      }
      // `cancel` traite les trois emplacements possibles, et n'abandonne
      // ici que des travaux qui n'ont pas encore commencé.
      const pending = this.pending.get(path)
      if (pending) {
        this.timers.clearTimeout(pending.timer)
        this.pending.delete(path)
      } else {
        const index = this.ready.findIndex((queued) => queued.path === path)
        if (index < 0) {
          continue
        }
        this.ready.splice(index, 1)
      }

      total -= 1
      this.dropped += 1
      this.onDropped?.(path, total)
      this.log(
        `${path} — travail abandonné : file de surveillance saturée ` +
          `(${this.maxQueued} travaux)`
      )
    }
  }

  /**
   * Abandonne tout travail portant sur ce chemin.
   *
   * En attente, prêt ou en cours : les trois sont traités. Sert au
   * fichier supprimé dont on n'a plus rien à dire, et au changement de
   * dossier ouvert.
   */
  cancel(path: string): void {
    const pending = this.pending.get(path)
    if (pending) {
      this.timers.clearTimeout(pending.timer)
      this.pending.delete(path)
    }

    const index = this.ready.findIndex((job) => job.path === path)
    if (index >= 0) {
      this.ready.splice(index, 1)
    }

    const active = this.running.get(path)
    if (active) {
      active.superseded = true
      active.controller.abort()
    }

    this.touchState()
  }

  /** Abandonne tout. L'état repart de `READY`. */
  cancelAll(): void {
    for (const entry of this.pending.values()) {
      this.timers.clearTimeout(entry.timer)
    }
    this.pending.clear()
    this.ready.length = 0

    for (const entry of this.running.values()) {
      entry.superseded = true
      entry.controller.abort()
    }

    this.lastFailed = false
    this.dropped = 0
    this.touchState()
  }

  dispose(): void {
    this.disposed = true
    this.cancelAll()
  }

  /** État courant, sans effet de bord. */
  get currentState(): MonitorState {
    return this.state
  }

  get pendingCount(): number {
    return this.pending.size
  }

  get readyCount(): number {
    return this.ready.length
  }

  get runningCount(): number {
    return this.running.size
  }

  /** Travaux abandonnés par contre-pression. Utile au journal et aux tests. */
  get droppedCount(): number {
    return this.dropped
  }

  /** Chemins prêts, dans l'ordre où ils partiront. Réservé aux tests. */
  get readyOrder(): readonly string[] {
    return this.ready.map((job) => job.path)
  }

  /** Reste-t-il quelque chose à faire ? Utile aux tests et au journal. */
  get isIdle(): boolean {
    return this.pending.size === 0 && this.ready.length === 0 && this.running.size === 0
  }

  // ---------------- Interne ----------------

  private arm(path: string): unknown {
    // Résolu à chaque armement, jamais capturé : changer le réglage ne
    // doit pas demander de redémarrer l'éditeur.
    return this.timers.setTimeout(() => this.release(path), this.debounceMs())
  }

  /** L'anti-rebond est écoulé : le chemin passe des attentes aux prêts. */
  private release(path: string): void {
    const entry = this.pending.get(path)
    if (!entry || this.disposed) {
      return
    }
    this.pending.delete(path)

    // Ceinture : la file des prêts ne porte jamais deux fois un chemin.
    // Elle ne devrait pas pouvoir arriver ici — un chemin prêt n'est plus
    // en attente — mais un doublon se traduirait par une double analyse,
    // ce qui est précisément ce que cette file existe pour empêcher.
    const known = this.ready.find((job) => job.path === path)
    if (known) {
      const merged: ScanJob = {
        path,
        analyses: mergeAnalyses(known.analyses, entry.analyses),
        removed: entry.removed,
        priority:
          known.priority === 'high' || entry.priority === 'high' ? 'high' : 'normal',
      }
      this.ready[this.ready.indexOf(known)] = merged
      this.pump()
      return
    }

    this.enqueueReady({
      path,
      analyses: entry.analyses,
      removed: entry.removed,
      priority: entry.priority,
    })
    this.pump()
  }

  /**
   * Insère un travail prêt en respectant sa priorité.
   *
   * Les prioritaires passent devant les ordinaires, et l'ordre d'arrivée
   * est conservé **à l'intérieur** de chaque bande : le fichier édité en
   * premier reste analysé en premier. Une insertion linéaire suffit — la
   * file est plafonnée, et une structure plus savante coûterait plus à
   * lire qu'elle ne ferait gagner.
   */
  private enqueueReady(job: ScanJob): void {
    if ((job.priority ?? 'normal') === 'normal') {
      this.ready.push(job)
      return
    }

    const firstNormal = this.ready.findIndex(
      (queued) => (queued.priority ?? 'normal') === 'normal'
    )
    if (firstNormal < 0) {
      this.ready.push(job)
      return
    }
    this.ready.splice(firstNormal, 0, job)
  }

  /** Démarre autant de travaux que la limite de parallélisme l'autorise. */
  private pump(): void {
    while (
      !this.disposed &&
      this.running.size < this.maxConcurrent &&
      this.ready.length > 0
    ) {
      // Un chemin déjà en cours attend son tour : « une seule analyse par
      // fichier à la fois » est une garantie, pas une tendance.
      const index = this.ready.findIndex((job) => !this.running.has(job.path))
      if (index < 0) {
        break
      }
      const [job] = this.ready.splice(index, 1)
      if (job) {
        this.start(job)
      }
    }

    this.touchState()
  }

  private start(job: ScanJob): void {
    const controller = new AbortController()
    const entry: RunningEntry = { controller, superseded: false }
    this.running.set(job.path, entry)
    this.touchState()

    // `void` volontaire : la file ne s'attend jamais elle-même, et
    // l'appelant n'attend jamais la file. C'est ce qui garantit que la
    // surveillance ne bloque pas l'éditeur.
    void this.execute(job, entry)
  }

  private async execute(job: ScanJob, entry: RunningEntry): Promise<void> {
    try {
      await this.run(job, entry.controller.signal)
      if (!entry.controller.signal.aborted) {
        this.lastFailed = false
      }
    } catch (error) {
      // Une annulation est un déroulement normal, pas une panne : elle ne
      // doit jamais faire passer la barre d'état en erreur.
      if (entry.controller.signal.aborted || isAbort(error)) {
        this.log(`${job.path} — analyse annulée`)
      } else {
        this.lastFailed = true
        this.onError?.(job.path, error)
      }
    } finally {
      if (this.running.get(job.path) === entry) {
        this.running.delete(job.path)
      }
      // Le suivant démarre ici, jamais avant : c'est ce qui fait tenir la
      // limite de parallélisme.
      this.pump()
    }
  }

  /**
   * Recalcule l'état et ne notifie qu'en cas de changement réel.
   *
   * Une bascule `ANALYZING → ANALYZING` ferait clignoter la barre d'état
   * à chaque fichier d'une rafale.
   */
  private touchState(): void {
    const next: MonitorState = !this.isIdle
      ? 'ANALYZING'
      : this.lastFailed
        ? 'ERROR'
        : 'READY'

    if (next === this.state) {
      return
    }
    this.state = next
    this.onStateChange?.(next)
  }

  private log(message: string): void {
    this.onLog?.(message)
  }
}

function isAbort(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'name' in error &&
    (error as { name?: unknown }).name === 'AbortError'
  )
}
