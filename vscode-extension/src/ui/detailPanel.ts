/**
 * Fenêtre de détail d'un finding.
 *
 * Tout le contenu affiché vient du backend — titre, explication,
 * conséquences, recommandations, facteurs de risque. L'extension ne
 * rédige rien : elle met en forme et échappe. Un champ vide est annoncé
 * comme tel (« Non disponible. ») plutôt que comblé.
 *
 * Le panneau est réutilisé d'un finding à l'autre plutôt que d'en ouvrir
 * un par problème.
 *
 * Sécurité de la webview :
 *
 * - CSP stricte : `default-src 'none'`, script et style autorisés
 *   uniquement par nonce, jamais par `unsafe-inline` ;
 * - aucune ressource externe, aucun accès au système de fichiers
 *   (`localResourceRoots: []`) ;
 * - aucun secret, aucun jeton, aucune adresse de backend transmis ;
 * - tout contenu dynamique passe par `escapeHtml` : le code source de
 *   l'utilisateur, remonté dans `snippet`, n'est jamais interprété ;
 * - le script embarqué se limite à relayer deux clics vers des commandes
 *   existantes ; la webview ne modifie rien elle-même.
 */

import { randomBytes } from 'node:crypto'

import * as vscode from 'vscode'

import type { CodeFinding } from '../api/backendClient'
import { buildDetailHtml, type DetailHtmlOptions } from './detailHtml'
import { FR } from '../i18n/fr'

/** Nonce imprévisible, régénéré à chaque rendu : jamais de valeur constante. */
function nonce(): string {
  return randomBytes(16).toString('base64')
}

export class FindingDetailPanel {
  private static current: FindingDetailPanel | undefined

  private readonly panel: vscode.WebviewPanel
  private readonly disposables: vscode.Disposable[] = []
  private findingUid = ''

  private constructor() {
    this.panel = vscode.window.createWebviewPanel(
      'wazuhSecurityFinding',
      FR.detail.title,
      { viewColumn: vscode.ViewColumn.Beside, preserveFocus: true },
      {
        enableScripts: true,
        retainContextWhenHidden: false,
        // Aucune ressource locale n'est servie : la page est autonome.
        localResourceRoots: [],
        enableCommandUris: false,
        enableForms: false,
      }
    )

    // Les deux seules actions possibles depuis le panneau passent par les
    // commandes existantes : le panneau ne modifie rien lui-même. Toute
    // autre valeur reçue est ignorée sans être journalisée.
    this.panel.webview.onDidReceiveMessage(
      (message: { action?: unknown }) => {
        if (!this.findingUid) {
          return
        }
        if (message?.action === 'fix') {
          void vscode.commands.executeCommand('wazuhSecurity.applyFix', this.findingUid)
        } else if (message?.action === 'dismiss') {
          void vscode.commands.executeCommand(
            'wazuhSecurity.dismissFinding',
            this.findingUid
          )
        } else if (message?.action === 'aiFix') {
          // Phase 7 : une proposition, jamais une écriture. L'application
          // passe par l'aperçu puis par une confirmation modale.
          void vscode.commands.executeCommand(
            'wazuhSecurity.suggestFixWithAi',
            this.findingUid
          )
        } else if (message?.action === 'ai') {
          // Phase 6 : l'explication s'ouvre dans la fenêtre de
          // l'assistant. Le finding n'est pas modifié.
          void vscode.commands.executeCommand(
            'wazuhSecurity.analyzeWithAi',
            this.findingUid
          )
        }
      },
      undefined,
      this.disposables
    )

    this.panel.onDidDispose(() => this.dispose(), undefined, this.disposables)
  }

  /** Ouvre ou réutilise le panneau pour afficher ce finding. */
  static show(finding: CodeFinding, options: DetailHtmlOptions = {}): void {
    if (!FindingDetailPanel.current) {
      FindingDetailPanel.current = new FindingDetailPanel()
    }
    FindingDetailPanel.current.render(finding, options)
  }

  static disposeCurrent(): void {
    FindingDetailPanel.current?.panel.dispose()
  }

  private render(finding: CodeFinding, options: DetailHtmlOptions): void {
    this.findingUid = finding.finding_uid
    this.panel.title = finding.title || finding.category_label || FR.detail.title
    this.panel.webview.html = buildDetailHtml(finding, nonce(), options)
    this.panel.reveal(vscode.ViewColumn.Beside, true)
  }

  private dispose(): void {
    FindingDetailPanel.current = undefined
    for (const disposable of this.disposables) {
      disposable.dispose()
    }
    this.disposables.length = 0
  }

}
