/**
 * Conversion d'un emplacement backend en `Range` VS Code.
 *
 * Extrait ici parce que deux consommateurs en dépendent et doivent
 * s'accorder au caractère près : le soulignement dans l'éditeur
 * (`DiagnosticsProvider`) et le positionnement du curseur depuis la vue
 * « Security » (`revealFinding`).
 *
 * Le backend numérote les lignes à partir de 1 (comme l'affichage) ;
 * l'API VS Code part de 0. La plage est bornée au document réel : un
 * fichier modifié depuis le scan ne doit jamais produire de position hors
 * limites.
 */

import * as vscode from 'vscode'

import type { CodeFinding } from '../api/backendClient'

export function findingRange(
  document: vscode.TextDocument,
  finding: CodeFinding
): vscode.Range {
  const lastLine = Math.max(0, document.lineCount - 1)
  const startLine = Math.min(Math.max(0, finding.location.line_start - 1), lastLine)
  const endLine = Math.min(Math.max(startLine, finding.location.line_end - 1), lastLine)

  const startText = document.lineAt(startLine).text
  const endText = document.lineAt(endLine).text

  const startColumn = Math.min(Math.max(0, finding.location.column_start), startText.length)
  let endColumn = Math.min(Math.max(0, finding.location.column_end), endText.length)

  // Une plage vide ne serait pas visible : on retient la ligne entière.
  if (startLine === endLine && endColumn <= startColumn) {
    endColumn = endText.length
  }

  return new vscode.Range(startLine, startColumn, endLine, endColumn)
}
