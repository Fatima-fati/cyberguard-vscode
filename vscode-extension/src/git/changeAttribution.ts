/**
 * Attribution : ce problème vient-il du changement en cours ?
 *
 * C'est la pièce qui donne son sens à la phase 4. Sans elle, l'agent ne
 * sait dire que « ce fichier contient une faille » — ce qui était déjà
 * vrai hier, et ce qui ferait refuser un `push` pour un problème vieux de
 * deux ans qu'on n'a pas touché.
 *
 * Aucun nouveau finding n'est créé ici
 * ------------------------------------
 *
 * Ce module **classe** des `SecurityFinding` que les moteurs des phases
 * 2 et 3 ont produits. Il n'en fabrique aucun, n'en modifie aucun, et
 * n'ajoute aucun champ : l'attribution vit à côté du finding, dans
 * `AttributedFinding`. C'est ce qui permet à la vue, aux diagnostics et
 * aux bulles de continuer à travailler sur le type qu'ils connaissent.
 *
 * La règle, et son biais assumé
 * -----------------------------
 *
 * Un finding est dit **introduit** quand ses lignes croisent une ligne
 * que le changement ajoute. Sinon il est **préexistant**.
 *
 * En cas de doute — ligne inconnue, finding sans fichier, diff illisible
 * — le verdict est **préexistant**. Le biais est délibéré et va dans un
 * seul sens : se tromper vers « introduit » ferait bloquer des `push`
 * pour des problèmes que le développeur n'a pas causés, et la protection
 * serait désactivée dans la semaine. Se tromper vers « préexistant »
 * laisse passer un problème qui reste signalé par ailleurs, dans la vue
 * et dans « Problems ».
 *
 * Autrement dit : cette attribution décide de **ce qui interrompt**, pas
 * de ce qui est signalé. Rien n'est jamais masqué par elle.
 *
 * Aucune dépendance à `vscode` : ce module est testable en Node pur.
 */

import type { SecurityFinding, Severity } from '../security/securityTypes'
import { intersectsRanges, type ChangedLineIndex } from './diffParser'

export type FindingOrigin = 'introduced' | 'pre-existing'

/** Un finding, et ce que le diff en dit. Le finding n'est pas modifié. */
export interface AttributedFinding {
  readonly finding: SecurityFinding
  readonly origin: FindingOrigin
  /** Pourquoi ce verdict. Pour le journal et l'infobulle. */
  readonly reason: string
}

export interface AttributionResult {
  readonly introduced: readonly AttributedFinding[]
  readonly preExisting: readonly AttributedFinding[]
  /** Tous, dans l'ordre reçu. Évite un second parcours à l'appelant. */
  readonly all: readonly AttributedFinding[]
}

/**
 * Classe des findings selon le changement en cours.
 *
 * `findings` vient du registre existant — secrets, dépendances, code —
 * et n'est jamais muté.
 */
export function attributeFindings(
  findings: readonly SecurityFinding[],
  changed: ChangedLineIndex
): AttributionResult {
  const all: AttributedFinding[] = []
  const introduced: AttributedFinding[] = []
  const preExisting: AttributedFinding[] = []

  for (const finding of findings) {
    const attributed = attributeOne(finding, changed)
    all.push(attributed)
    if (attributed.origin === 'introduced') {
      introduced.push(attributed)
    } else {
      preExisting.push(attributed)
    }
  }

  return { introduced, preExisting, all }
}

/** Verdict pour un finding isolé. Exporté pour être testable seul. */
export function attributeOne(
  finding: SecurityFinding,
  changed: ChangedLineIndex
): AttributedFinding {
  const file = normalizePath(finding.file)

  if (!file) {
    // Un finding sans fichier — une statistique de projet, par exemple —
    // ne peut être rattaché à aucune ligne.
    return { finding, origin: 'pre-existing', reason: 'aucun fichier rattaché' }
  }

  if (changed.deletedFiles.has(file)) {
    // Le fichier n'existe plus : le problème part avec lui. Il n'est
    // sûrement pas « introduit » par sa propre suppression.
    return { finding, origin: 'pre-existing', reason: 'fichier supprimé' }
  }

  const ranges = changed.byPath.get(file)
  if (ranges === undefined) {
    return { finding, origin: 'pre-existing', reason: 'fichier non modifié' }
  }

  if (changed.addedFiles.has(file)) {
    // Fichier entièrement nouveau : tout ce qu'il porte est neuf, y
    // compris un finding dont on ne saurait pas situer la ligne.
    return { finding, origin: 'introduced', reason: 'fichier ajouté' }
  }

  const start = Math.max(1, finding.line_start || 0)
  const end = Math.max(start, finding.line_end || start)

  if (!finding.line_start || finding.line_start < 1) {
    // Finding au niveau du fichier — une dépendance vulnérable déclarée
    // dans un manifeste, par exemple — sur un fichier qui a bougé mais
    // pas été créé. On ne sait pas situer la ligne, donc on ne conclut
    // pas à « introduit ».
    return {
      finding,
      origin: 'pre-existing',
      reason: 'position inconnue dans un fichier modifié',
    }
  }

  if (intersectsRanges(ranges, start, end)) {
    return {
      finding,
      origin: 'introduced',
      reason: `ligne ${start} ajoutée par ce changement`,
    }
  }

  return {
    finding,
    origin: 'pre-existing',
    reason: 'lignes non touchées par ce changement',
  }
}

/**
 * Chemin de finding, ramené à la forme que le diff emploie.
 *
 * Les findings portent un chemin relatif à la racine du projet ; le diff
 * aussi. Restent les séparateurs — un finding produit sous Windows peut
 * porter des `\` — et un éventuel `./` de tête.
 */
function normalizePath(file: string | null | undefined): string {
  if (!file) {
    return ''
  }
  return file.trim().replace(/\\/g, '/').replace(/^\.\//, '')
}

// --------------------------------------------------------------------------
// Résumé
// --------------------------------------------------------------------------

/** Décompte par gravité. Même échelle que partout ailleurs. */
export interface SeverityTally {
  readonly critical: number
  readonly high: number
  readonly medium: number
  readonly low: number
  readonly total: number
}

/**
 * Bilan de sécurité d'un changement Git.
 *
 * Volumes et libellés seulement : aucune valeur de secret, aucune URL de
 * remote brute, aucun contenu de ligne.
 */
export interface GitSecuritySummary {
  /** Un dépôt est-il ouvert ? Faux = tout le reste est neutre. */
  readonly repository: boolean
  readonly branch: string | null
  /** Hôte du remote, jamais l'URL complète. */
  readonly remoteHost: string | null
  readonly changedFiles: number
  readonly addedLines: number
  readonly removedLines: number
  /** Le changement a-t-il dépassé le plafond d'analyse ? */
  readonly reduced: boolean
  /** Fichiers réellement analysés, quand le mode réduit s'applique. */
  readonly analyzedFiles: number
  readonly introduced: SeverityTally
  readonly preExisting: SeverityTally
  /** L'analyse a-t-elle abouti ? Faux après un délai ou une panne. */
  readonly conclusive: boolean
  /** Ce qui a empêché de conclure. Vide quand `conclusive`. */
  readonly message: string
  readonly analyzedAt: string
}

const EMPTY_TALLY: SeverityTally = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  total: 0,
}

export function tally(findings: readonly AttributedFinding[]): SeverityTally {
  let critical = 0
  let high = 0
  let medium = 0
  let low = 0

  for (const { finding } of findings) {
    switch (severityOf(finding)) {
      case 'CRITICAL':
        critical += 1
        break
      case 'HIGH':
        high += 1
        break
      case 'MEDIUM':
        medium += 1
        break
      default:
        low += 1
    }
  }

  return { critical, high, medium, low, total: findings.length }
}

/** Gravité du finding, ramenée à `LOW` si le backend en annonce une inconnue. */
export function severityOf(finding: SecurityFinding): Severity {
  const value = (finding.severity ?? '').toUpperCase()
  return value === 'CRITICAL' || value === 'HIGH' || value === 'MEDIUM'
    ? (value as Severity)
    : 'LOW'
}

/**
 * Résumé neutre.
 *
 * Utilisé quand aucun dépôt n'est ouvert, et comme base d'un résumé non
 * concluant. `conclusive: false` par défaut : un résumé vide ne doit
 * jamais se lire « aucun problème introduit ».
 */
export function emptySummary(
  overrides: Partial<GitSecuritySummary> = {}
): GitSecuritySummary {
  return {
    repository: false,
    branch: null,
    remoteHost: null,
    changedFiles: 0,
    addedLines: 0,
    removedLines: 0,
    reduced: false,
    analyzedFiles: 0,
    introduced: EMPTY_TALLY,
    preExisting: EMPTY_TALLY,
    conclusive: false,
    message: '',
    analyzedAt: new Date(0).toISOString(),
    ...overrides,
  }
}
