/**
 * Fenêtre de l'assistant IA de sécurité (phase 6).
 *
 * Mince par construction : elle rend le modèle du contrôleur
 * (`ai/securityAiController.ts`) et relaie trois intentions de la page.
 * Tout ce qui décide — validation des messages, expurgation, traduction
 * des erreurs — vit dans des modules purs, testés sans VS Code.
 *
 * Sécurité de la webview, identique à la fiche de détail :
 *
 * - CSP stricte, style et script par nonce régénéré à chaque rendu ;
 * - aucune ressource locale (`localResourceRoots: []`), aucun lien de
 *   commande, aucune adresse de backend ni jeton transmis à la page ;
 * - chaque message reçu passe par `parsePanelMessage` : tout ce qui n'est
 *   pas une des trois actions connues est ignoré.
 */

import { randomBytes } from 'node:crypto'

import * as vscode from 'vscode'

import {
  SecurityAiController,
  parsePanelMessage,
  type SecurityAiControllerOptions,
} from '../ai/securityAiController'
import { FR } from '../i18n/fr'
import { buildAiPanelHtml } from './aiHtml'

function nonce(): string {
  return randomBytes(16).toString('base64')
}

export class SecurityAiPanel {
  private static current: SecurityAiPanel | undefined

  readonly controller: SecurityAiController
  private readonly panel: vscode.WebviewPanel
  private readonly disposables: vscode.Disposable[] = []
  private disposed = false

  private constructor(options: Omit<SecurityAiControllerOptions, 'onChange'>) {
    this.panel = vscode.window.createWebviewPanel(
      'wazuhSecurityAi',
      FR.assistant.panelTitle,
      { viewColumn: vscode.ViewColumn.Beside, preserveFocus: false },
      {
        enableScripts: true,
        // Conservé caché : une conversation en cours ne doit pas
        // disparaître parce que l'utilisateur a changé d'onglet.
        retainContextWhenHidden: true,
        localResourceRoots: [],
        enableCommandUris: false,
        enableForms: true,
      }
    )

    this.controller = new SecurityAiController({
      ...options,
      onChange: () => this.render(),
    })

    this.panel.webview.onDidReceiveMessage(
      (raw: unknown) => {
        const message = parsePanelMessage(raw)
        if (!message) {
          return
        }
        switch (message.action) {
          case 'ask':
            void this.controller.ask(message.question)
            break
          case 'reanalyze':
            void this.controller.reanalyze()
            break
          case 'summarize':
            void this.controller.summarize()
            break
          // Phase 7 : la page ne fait que demander. « Appliquer » ouvre la
          // confirmation native de l'éditeur ; aucune écriture ne part
          // d'ici.
          case 'applyFix':
            void vscode.commands.executeCommand('wazuhSecurity.applyAiFix')
            break
          case 'cancelFix':
            void vscode.commands.executeCommand('wazuhSecurity.cancelAiFix')
            break
          case 'showFixDiff':
            void vscode.commands.executeCommand('wazuhSecurity.showAiFixDiff')
            break
        }
      },
      undefined,
      this.disposables
    )

    this.panel.onDidDispose(() => this.dispose(), undefined, this.disposables)
    this.render()
  }

  /** Ouvre ou réutilise la fenêtre, et renvoie son contrôleur. */
  static open(options: Omit<SecurityAiControllerOptions, 'onChange'>): SecurityAiController {
    if (!SecurityAiPanel.current) {
      SecurityAiPanel.current = new SecurityAiPanel(options)
    } else {
      SecurityAiPanel.current.panel.reveal(vscode.ViewColumn.Beside, false)
    }
    return SecurityAiPanel.current.controller
  }

  static disposeCurrent(): void {
    SecurityAiPanel.current?.panel.dispose()
  }

  private render(): void {
    // Fenêtre fermée par l'utilisateur : le contrôleur lui survit — une
    // réponse IA en vol, un correctif en attente. Écrire dans une webview
    // détruite lève « Webview is disposed » et interromprait l'appelant,
    // jusqu'à l'application d'un correctif déjà confirmé.
    if (this.disposed) {
      return
    }
    const model = this.controller.model
    this.panel.title =
      model.view.kind === 'analysis' && model.view.findingTitle
        ? `IA — ${model.view.findingTitle}`
        : FR.assistant.panelTitle
    this.panel.webview.html = buildAiPanelHtml(model, nonce())
  }

  private dispose(): void {
    this.disposed = true
    SecurityAiPanel.current = undefined
    for (const disposable of this.disposables) {
      disposable.dispose()
    }
    this.disposables.length = 0
  }
}
