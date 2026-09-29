/**
 * Projection des sévérités sur l'énumération de VS Code.
 *
 * La table elle-même vit dans `severityLevels.ts`, sans dépendance à
 * `vscode`, pour rester vérifiable en test. Ce module n'en fait que la
 * traduction.
 */

import * as vscode from 'vscode'

import { levelFor } from './severityLevels'

export {
  SEVERITY_LEVELS,
  isNotifiable,
  levelFor,
  type BackendSeverity,
  type DiagnosticLevel,
} from './severityLevels'

/** Sévérité VS Code correspondante. */
export function toDiagnosticSeverity(severity: string): vscode.DiagnosticSeverity {
  return vscode.DiagnosticSeverity[levelFor(severity)]
}
