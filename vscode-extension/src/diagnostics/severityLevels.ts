/**
 * Correspondance entre la sévérité du backend et le niveau de diagnostic.
 *
 * Exprimée par des noms, pas par les constantes de `vscode` : la table
 * devient vérifiable sans éditeur. `severityMap.ts` n'a plus qu'à la
 * projeter sur l'énumération, en une ligne.
 *
 * Aucune catégorie n'est inventée : les quatre niveaux viennent du
 * backend (`app/ai/schemas.py`).
 */

export type BackendSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

/** Niveau de diagnostic, nommé. */
export type DiagnosticLevel = 'Error' | 'Warning' | 'Information'

/**
 * Projection des sévérités.
 *
 * CRITICAL et HIGH sont des erreurs : elles doivent teinter l'onglet et
 * remonter en tête du panneau Problèmes. MEDIUM avertit, LOW informe.
 */
export const SEVERITY_LEVELS: Readonly<Record<BackendSeverity, DiagnosticLevel>> = {
  CRITICAL: 'Error',
  HIGH: 'Error',
  MEDIUM: 'Warning',
  LOW: 'Information',
}

/** Niveau nommé. Une sévérité inconnue reste informative, jamais bloquante. */
export function levelFor(severity: string): DiagnosticLevel {
  return SEVERITY_LEVELS[severity as BackendSeverity] ?? 'Information'
}

/** Vrai pour les sévérités qui justifient une notification à l'écran. */
export function isNotifiable(severity: string): boolean {
  return severity === 'CRITICAL' || severity === 'HIGH'
}
