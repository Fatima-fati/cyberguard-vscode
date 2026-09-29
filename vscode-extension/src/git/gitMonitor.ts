/**
 * Surveillance de l'état du dépôt.
 *
 * Ce que ce module observe, via `vscode.git` et rien d'autre :
 *
 *     ouverture / fermeture d'un dépôt
 *     changement de branche
 *     changements indexés et non indexés
 *
 * Le piège, et comment il est évité
 * ---------------------------------
 *
 * `repository.state.onDidChange` se déclenche **très** souvent : à chaque
 * frappe dans un fichier suivi, à chaque `git status` interne de
 * l'éditeur. Relancer une analyse à chaque événement coûterait plus cher
 * que tout le reste de l'extension réunie.
 *
 * Deux garde-fous, dans cet ordre :
 *
 * 1. **Empreinte d'état** — branche, commit, volumétrie. Un événement qui
 *    ne change pas l'empreinte est abandonné sans rien faire ;
 * 2. **Anti-rebond** — les événements survivants sont regroupés.
 *
 * Ce que ce module ne fait jamais
 * -------------------------------
 *
 * **Relancer une découverte de projet.** Changer de branche modifie des
 * fichiers, parfois des milliers ; c'est précisément le moment où un
 * parcours complet serait le plus coûteux et le moins utile. Seule
 * l'attribution est recalculée — le diff, et le classement des findings
 * déjà connus. Un test le vérifie.
 */

import * as vscode from 'vscode'

import { FR } from '../i18n/fr'
import {
  branchNameOf,
  findRepository,
  resolveGitApi,
  stateFingerprint,
  type GitApi,
  type GitRepository,
} from './gitApi'
import { remoteHostOf } from './remoteUrl'

/** Anti-rebond : regroupe les rafales d'événements du dépôt. */
export const DEFAULT_GIT_DEBOUNCE_MS = 900

export interface GitMonitorOptions {
  readonly workspaceRoot: () => string | undefined
  readonly isEnabled: () => boolean
  /** Relance l'analyse. Doit être non bloquante et ne jamais lever. */
  readonly onChanged: (context: { readonly branchChanged: boolean }) => void
  readonly log: (message: string) => void
  readonly debounceMs?: number
  readonly resolveApi?: () => Promise<GitApi | undefined>
}

export class GitMonitor implements vscode.Disposable {
  private readonly options: GitMonitorOptions
  private readonly subscriptions: vscode.Disposable[] = []

  private repository: GitRepository | undefined
  private fingerprint = ''
  private branch: string | null = null
  private timer: NodeJS.Timeout | undefined
  private started = false
  private disposed = false

  constructor(options: GitMonitorOptions) {
    this.options = options
  }

  /** Dépôt courant, ou `undefined`. Consulté par le service et la vue. */
  current(): GitRepository | undefined {
    return this.repository
  }

  currentBranch(): string | null {
    return this.branch
  }

  /**
   * Démarre la surveillance.
   *
   * Ne lève jamais : l'extension Git peut être absente ou désactivée, et
   * c'est un état normal — la phase 4 s'éteint, le reste continue.
   */
  async start(): Promise<void> {
    if (this.disposed || this.started) {
      return
    }

    const api = await (this.options.resolveApi ?? resolveGitApi)()
    if (!api) {
      this.options.log(FR.git.apiUnavailable)
      return
    }

    this.started = true

    // Un dépôt peut s'ouvrir après l'activation — le clone est en cours,
    // ou le dossier vient d'être `git init`. S'abonner évite d'exiger un
    // redémarrage de l'éditeur.
    if (api.onDidOpenRepository) {
      this.subscriptions.push(api.onDidOpenRepository(() => void this.attach(api)))
    }
    if (api.onDidCloseRepository) {
      this.subscriptions.push(
        api.onDidCloseRepository(() => {
          this.options.log(FR.git.repositoryClosed)
          void this.attach(api)
        })
      )
    }

    await this.attach(api)
    this.options.log(FR.git.monitorStarted)
  }

  stop(): void {
    if (!this.started) {
      return
    }
    this.started = false
    this.cancelTimer()
    for (const subscription of this.subscriptions) {
      subscription.dispose()
    }
    this.subscriptions.length = 0
    this.repository = undefined
    this.fingerprint = ''
    this.branch = null
    this.options.log(FR.git.monitorStopped)
  }

  dispose(): void {
    this.disposed = true
    this.stop()
  }

  // ---------------- Interne ----------------

  /** (Ré)attache la surveillance au dépôt du dossier ouvert. */
  private async attach(api: GitApi): Promise<void> {
    const repository = findRepository(api, this.options.workspaceRoot())
    this.repository = repository

    if (!repository) {
      this.fingerprint = 'no-repository'
      this.branch = null
      return
    }

    const host = remoteHostOf(
      repository.state?.remotes?.[0]?.fetchUrl ??
        repository.state?.remotes?.[0]?.pushUrl
    )
    // L'hôte seul dans le journal : une URL de remote peut porter un jeton.
    this.options.log(FR.git.repositoryOpened(host ?? FR.git.noRemote))

    this.fingerprint = stateFingerprint(repository)
    this.branch = branchNameOf(repository)

    const event = repository.state?.onDidChange
    if (event) {
      this.subscriptions.push(event(() => this.onStateChanged()))
    }
  }

  /**
   * Un événement du dépôt est arrivé. Mérite-t-il une analyse ?
   *
   * L'empreinte tranche : sans elle, une frappe dans un fichier suivi
   * relancerait tout le travail.
   */
  private onStateChanged(): void {
    if (this.disposed || !this.started || !this.options.isEnabled()) {
      return
    }

    const next = stateFingerprint(this.repository)
    if (next === this.fingerprint) {
      return
    }

    const branch = branchNameOf(this.repository)
    const branchChanged = branch !== this.branch

    this.fingerprint = next
    this.branch = branch

    if (branchChanged) {
      // Dit explicitement dans le journal : c'est la question que se pose
      // l'utilisateur quand il voit l'agent réagir à un `checkout`.
      this.options.log(FR.git.branchChanged(branch ?? FR.git.detachedHead))
    }

    this.schedule(branchChanged)
  }

  private schedule(branchChanged: boolean): void {
    this.cancelTimer()
    this.timer = setTimeout(() => {
      this.timer = undefined
      try {
        this.options.onChanged({ branchChanged })
      } catch {
        // Un consommateur défaillant ne doit pas arrêter la surveillance.
      }
    }, this.options.debounceMs ?? DEFAULT_GIT_DEBOUNCE_MS)
  }

  private cancelTimer(): void {
    if (this.timer) {
      clearTimeout(this.timer)
      this.timer = undefined
    }
  }
}
