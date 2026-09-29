/**
 * Ouverture d'un finding depuis la vue « Security ».
 *
 * Trois gestes en un : ouvrir le fichier, y placer le curseur sur la zone
 * signalée, et présenter la fiche détaillée. Le chemin renvoyé par le
 * backend est relatif au workspace — c'est celui que l'extension lui a
 * envoyé — et il est résolu contre les dossiers réellement ouverts : rien
 * n'est ouvert hors du workspace, même si le backend annonce un chemin
 * étranger.
 */

import * as vscode from 'vscode'

import type { CodeFinding } from '../api/backendClient'
import { resolveFindingUri } from '../analysis/workspacePaths'
import { findingRange } from '../diagnostics/findingRange'
import { FR } from '../i18n/fr'
import type { FindingsStore } from '../state/findingsStore'
import { FindingDetailPanel } from './detailPanel'

/**
 * Ouvre le fichier, sélectionne la zone signalée, affiche le détail.
 *
 * Le fichier introuvable n'empêche pas la consultation : la fiche est
 * affichée quand même, avec l'extrait renvoyé par le backend.
 */
export async function revealFinding(
  store: FindingsStore,
  uid: string,
  log: (message: string) => void,
  /** Phase 6 : afficher « Analyser avec l'IA » pour ce finding ? */
  aiAvailable: (finding: CodeFinding) => boolean = () => false,
  /** Phase 7 : afficher « Suggest Fix with AI » ? */
  aiFixAvailable: () => boolean = () => false
): Promise<void> {
  const finding = store.get(uid)
  if (!finding) {
    void vscode.window.showWarningMessage(FR.actions.findingUnknown)
    return
  }

  await openInEditor(finding, log)
  FindingDetailPanel.show(finding, {
    aiAvailable: aiAvailable(finding),
    aiFixAvailable: aiFixAvailable(),
  })
}

/** Ouverture seule, sans fiche détaillée. */
export async function openInEditor(
  finding: CodeFinding,
  log: (message: string) => void
): Promise<vscode.TextEditor | undefined> {
  const uri = await resolveFindingUri(finding.file_path)
  if (!uri) {
    log(`${finding.file_path} introuvable dans le workspace — fiche affichée seule`)
    void vscode.window.showWarningMessage(FR.view.fileNotFound(finding.file_path))
    return undefined
  }

  let document: vscode.TextDocument
  try {
    document = await vscode.workspace.openTextDocument(uri)
  } catch (error) {
    log(
      `${finding.file_path} illisible : ${
        error instanceof Error ? error.message : String(error)
      }`
    )
    void vscode.window.showWarningMessage(FR.view.fileNotFound(finding.file_path))
    return undefined
  }

  const editor = await vscode.window.showTextDocument(document, {
    // `preview` : l'onglet est remplacé au finding suivant plutôt que
    // d'empiler une fenêtre par problème consulté.
    preview: true,
    preserveFocus: false,
    viewColumn: vscode.ViewColumn.One,
  })

  // La plage est bornée au document réel par `findingRange` : un fichier
  // modifié depuis l'analyse ne provoque jamais de position hors limites.
  const range = findingRange(document, finding)
  editor.selection = new vscode.Selection(range.start, range.end)
  editor.revealRange(range, vscode.TextEditorRevealType.InCenterIfOutsideViewport)

  return editor
}
