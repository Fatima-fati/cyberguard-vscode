/**
 * Barre d'état : résumé permanent du dernier scan.
 *
 * Trois états seulement, pour rester lisible d'un coup d'œil : analyse en
 * cours, résultat, backend injoignable.
 */

import * as vscode from 'vscode'

import type { SeverityCounts } from '../api/backendClient'
import type { MonitorState } from '../monitor/scanQueue'
import { describeCounts as describe, isAlarming } from './statusSummary'
import { FR } from '../i18n/fr'

export class StatusBar implements vscode.Disposable {
  private readonly item: vscode.StatusBarItem
  /**
   * Second élément, présent seulement quand le backend n’est pas local.
   *
   * Créé à la demande plutôt qu’affiché vide en permanence : dans le cas
   * normal — un backend sur la boucle locale — il n’y a rien à signaler, et
   * une icône inerte finirait par ne plus être vue. Quand le code quitte la
   * machine, en revanche, la marque doit rester visible tout le temps.
   */
  private remote: vscode.StatusBarItem | undefined

  /**
   * Troisième élément : l'état de la surveillance continue (phase 3).
   *
   * Séparé du résumé de scan, et pas fondu dedans, pour une raison de
   * lecture : le premier élément répond « qu'a-t-on trouvé dans ce
   * fichier ? », celui-ci répond « l'agent regarde-t-il encore ? ». Les
   * confondre ferait disparaître l'état de surveillance dès qu'un scan
   * affiche un résultat — précisément quand on veut savoir si la
   * surveillance tient toujours.
   *
   * Créé à la demande : sans dossier ouvert, ou surveillance désactivée,
   * il n'y a rien à annoncer et un élément inerte finirait par ne plus
   * être vu.
   */
  private monitor: vscode.StatusBarItem | undefined

  constructor() {
    this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100)
    this.item.command = 'wazuhSecurity.scanCurrentFile'
    this.setIdle()
    this.item.show()
  }

  /**
   * Signale en permanence un backend distant.
   *
   * L’hôte seul, jamais l’URL complète : elle pourrait être longue, et rien
   * de plus que l’hôte n’est utile à l’écran.
   */
  setRemoteBackend(host: string): void {
    if (!this.remote) {
      this.remote = vscode.window.createStatusBarItem(
        vscode.StatusBarAlignment.Right,
        99
      )
      this.remote.command = 'wazuhSecurity.checkBackend'
    }
    this.remote.text = `$(globe) ${host}`
    this.remote.tooltip = FR.backendUrl.remoteActive(host)
    this.remote.backgroundColor = new vscode.ThemeColor(
      'statusBarItem.warningBackground'
    )
    this.remote.show()
  }

  /** Retire la marque : le backend est redevenu local. */
  clearRemoteBackend(): void {
    this.remote?.dispose()
    this.remote = undefined
  }

  /**
   * Affiche l'état de la surveillance continue.
   *
   * Trois états, et trois seulement — `READY`, `ANALYZING`, `ERROR` :
   * au-delà, l'élément cesserait d'être lisible d'un coup d'œil, ce qui
   * est tout ce qu'on lui demande. Le détail (combien de fichiers en
   * attente, lequel a échoué) va dans l'infobulle et dans le canal de
   * sortie, pas dans la barre.
   *
   * L'état canonique est repris tel quel dans l'infobulle : c'est ce nom
   * qui apparaît dans le journal, et pouvoir rapprocher les deux à l'œil
   * vaut mieux qu'une traduction qu'il faudrait deviner.
   */
  setMonitorState(state: MonitorState, detail?: string): void {
    if (!this.monitor) {
      this.monitor = vscode.window.createStatusBarItem(
        vscode.StatusBarAlignment.Right,
        98
      )
      this.monitor.command = 'wazuhSecurity.scanProjectSecurity'
    }

    this.monitor.text = `${FR.monitor.icon[state]} ${FR.monitor.label[state]}`
    this.monitor.tooltip = [FR.monitor.tooltip[state], detail, `[${state}]`]
      .filter((part) => part)
      .join('\n')
    this.monitor.backgroundColor =
      state === 'ERROR'
        ? new vscode.ThemeColor('statusBarItem.warningBackground')
        : undefined
    this.monitor.show()
  }

  /** Retire l'élément : surveillance arrêtée, ou aucun dossier ouvert. */
  clearMonitorState(): void {
    this.monitor?.dispose()
    this.monitor = undefined
  }

  setIdle(): void {
    this.item.text = `$(shield) ${FR.statusIdle}`
    this.item.tooltip = FR.statusTooltipIdle
    this.item.backgroundColor = undefined
  }

  setScanning(): void {
    this.item.text = `$(sync~spin) ${FR.statusScanning}`
    this.item.tooltip = FR.statusTooltipScanning
    this.item.backgroundColor = undefined
  }

  /**
   * Enrichissement IA en cours côté backend.
   *
   * État distinct de l'analyse : les findings déterministes sont déjà
   * affichés, le modèle les qualifie encore.
   */
  setEnriching(counts: SeverityCounts, fileName: string): void {
    const summary = describe(counts)
    this.item.text = `$(sync~spin) ${FR.statusEnriching}`
    this.item.tooltip = `${fileName}\n${summary || FR.statusTooltipOk}\n${
      FR.statusTooltipEnriching
    }`
    this.item.backgroundColor = undefined
  }

  /** L'enrichissement a échoué : les résultats des règles restent valables. */
  setEnrichmentFailed(counts: SeverityCounts, fileName: string, reason: string): void {
    this.setResult(counts, fileName)
    this.item.text = `$(warning) ${this.item.text.replace(/^\$\([^)]+\)\s*/, '')}`
    this.item.tooltip = `${fileName}\n${FR.statusTooltipEnrichmentFailed}\n${reason}`
  }

  setBackendUnavailable(): void {
    this.item.text = `$(debug-disconnect) ${FR.statusBackendDown}`
    this.item.tooltip = FR.backendUnavailable('')
    this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground')
  }

  /** Résultat d'un scan : « Sécurité : 1 critique, 2 élevées » ou « OK ». */
  setResult(counts: SeverityCounts, fileName: string): void {
    const summary = describe(counts)

    if (!summary) {
      this.item.text = `$(shield) ${FR.statusOk}`
      this.item.tooltip = `${FR.statusTooltipOk}\n${fileName}`
      this.item.backgroundColor = undefined
      return
    }

    this.item.text = `$(shield) Sécurité : ${summary}`
    this.item.tooltip = `${fileName}\n${summary}`
    this.item.backgroundColor = isAlarming(counts)
      ? new vscode.ThemeColor('statusBarItem.errorBackground')
      : new vscode.ThemeColor('statusBarItem.warningBackground')
  }

  dispose(): void {
    this.item.dispose()
    this.remote?.dispose()
    this.remote = undefined
    this.monitor?.dispose()
    this.monitor = undefined
  }
}
