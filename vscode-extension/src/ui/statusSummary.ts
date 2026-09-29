/**
 * Résumé chiffré affiché dans la barre d'état.
 *
 * Extrait de `statusBar.ts` : c'est du texte calculé à partir de
 * compteurs, donc vérifiable sans éditeur — accords en nombre compris,
 * qui sont la source d'erreur habituelle.
 */

import type { SeverityCounts } from '../api/backendClient'

/**
 * « 1 critique, 2 élevées » — chaîne vide quand rien n'est ouvert.
 *
 * Les niveaux absents ne sont pas mentionnés : afficher « 0 faible »
 * allongerait la barre sans rien apprendre.
 */
export function describeCounts(counts: SeverityCounts): string {
  const parts: string[] = []

  if (counts.critical > 0) {
    parts.push(`${counts.critical} critique${counts.critical > 1 ? 's' : ''}`)
  }
  if (counts.high > 0) {
    parts.push(`${counts.high} élevée${counts.high > 1 ? 's' : ''}`)
  }
  if (counts.medium > 0) {
    parts.push(`${counts.medium} moyenne${counts.medium > 1 ? 's' : ''}`)
  }
  if (counts.low > 0) {
    parts.push(`${counts.low} faible${counts.low > 1 ? 's' : ''}`)
  }

  return parts.join(', ')
}

/** La barre doit-elle passer en rouge ? Réservé aux sévérités hautes. */
export function isAlarming(counts: SeverityCounts): boolean {
  return counts.critical > 0 || counts.high > 0
}
