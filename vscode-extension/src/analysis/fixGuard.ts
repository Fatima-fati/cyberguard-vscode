/**
 * Contrôles préalables à l'application d'un correctif.
 *
 * Séparé de `quickFix.ts` pour deux raisons : ces règles décident si on
 * écrit ou non dans le fichier de quelqu'un, et elles doivent donc être
 * vérifiables sans lancer VS Code ; et elles sont appelées **deux fois**
 * — avant d'interroger le backend, puis juste avant d'écrire, parce que
 * le document a pu changer pendant l'aller-retour réseau et pendant que
 * la fenêtre de confirmation était ouverte.
 *
 * Aucune dépendance à `vscode`, aucun accès disque, aucune écriture :
 * ces fonctions observent un état et rendent un verdict.
 *
 * Principe directeur : **au moindre doute, on refuse.** Une correction
 * non appliquée est un désagrément ; une correction appliquée au mauvais
 * endroit écrase le travail du développeur.
 */

import type { CodeFixProposal } from '../api/backendClient'
import { FR } from '../i18n/fr'

/**
 * État du document observé au moment du contrôle.
 *
 * Volontairement réduit à des valeurs simples : c'est ce qui rend ces
 * règles testables sans éditeur.
 */
export interface DocumentState {
  /** Protocole de l'URI. Seul `file` est accepté : jamais de fichier distant. */
  scheme: string
  /**
   * Le fichier relève-t-il du workspace courant ?
   *
   * Vrai s'il appartient à un dossier ouvert — ou si aucun dossier n'est
   * ouvert, cas du fichier consulté isolément, que l'extension prend en
   * charge depuis la phase 1.
   */
  inWorkspace: boolean
  /** Nombre de lignes du document, tel qu'il est maintenant. */
  lineCount: number
  /** Texte de la ligne visée, ou `undefined` si elle n'existe plus. */
  currentLineText: string | undefined
  /** Empreinte du contenu actuel du document. */
  currentHash: string
  /** Empreinte du contenu au moment de l'analyse, si elle est connue. */
  analyzedHash: string | undefined
}

/** Ce qu'on doit savoir du finding pour décider. */
export interface FixTarget {
  status: string
  /** Ligne signalée, numérotée à partir de 1 comme côté backend. */
  line: number
}

export type FixVerdict =
  | { ok: true; line: number; replacement: string }
  | {
      ok: false
      /** Message déjà rédigé, affichable tel quel. */
      reason: string
      /**
       * Le refus vient-il d'une divergence entre le fichier et l'analyse ?
       *
       * L'appelant affiche alors le message de dérive, à l'exclusion de
       * tout autre.
       */
      fileChanged: boolean
    }

function refuse(reason: string, fileChanged = false): FixVerdict {
  return { ok: false, reason, fileChanged }
}

function drifted(): FixVerdict {
  return refuse(FR.fix.fileChanged, true)
}

/**
 * Contrôles qui ne dépendent pas de la proposition du backend.
 *
 * Appliqués **avant** la requête : inutile de déranger le serveur pour un
 * finding refermé ou un fichier qui a bougé.
 */
export function validateTarget(target: FixTarget, state: DocumentState): FixVerdict {
  // 1. Jamais un fichier distant, jamais un document virtuel : on n'écrit
  //    que dans un fichier local, par l'API de l'éditeur.
  if (state.scheme !== 'file') {
    return refuse(FR.fix.notLocalFile)
  }

  // 2. Le fichier doit relever du workspace courant.
  if (!state.inWorkspace) {
    return refuse(FR.fix.outsideWorkspace)
  }

  // 3. Un finding déjà corrigé ou écarté ne se corrige pas une seconde fois.
  if (target.status !== 'open') {
    return refuse(FR.fix.notOpen)
  }

  // 4. Le contenu doit être exactement celui qui a été analysé. Une
  //    modification ailleurs dans le fichier suffit à invalider les
  //    numéros de ligne du rapport.
  if (state.analyzedHash !== undefined && state.analyzedHash !== state.currentHash) {
    return drifted()
  }

  // 5. La ligne visée doit toujours exister.
  if (target.line < 1 || target.line > state.lineCount) {
    return drifted()
  }

  if (state.currentLineText === undefined) {
    return drifted()
  }

  return { ok: true, line: target.line, replacement: state.currentLineText }
}

/**
 * Contrôle complet, juste avant d'écrire.
 *
 * Reprend `validateTarget` — l'état a pu changer depuis le premier
 * passage — puis vérifie la proposition elle-même.
 */
export function validateFix(
  target: FixTarget,
  proposal: CodeFixProposal,
  state: DocumentState
): FixVerdict {
  const targetVerdict = validateTarget(target, state)
  if (!targetVerdict.ok) {
    return targetVerdict
  }

  // 6. Le backend a-t-il seulement un correctif à proposer ?
  if (!proposal.available || proposal.replacement_line === null) {
    return refuse(proposal.blockers[0] ?? FR.actions.fixUnavailable)
  }

  const replacement = proposal.replacement_line
  const currentLine = state.currentLineText ?? ''

  // 7. La ligne doit être, au caractère près, celle sur laquelle le
  //    correctif a été calculé. C'est ce contrôle qui rattrape une
  //    modification faite pendant que la fenêtre de confirmation était
  //    ouverte.
  if (proposal.original_line !== null && proposal.original_line !== currentLine) {
    return drifted()
  }

  // 8. Cohérence du remplacement : une ligne, et une seule. Un texte
  //    multiligne décalerait toute la numérotation du fichier et rendrait
  //    les autres findings faux.
  if (/[\r\n]/.test(replacement)) {
    return refuse(FR.fix.multiline)
  }

  // 9. Un remplacement identique n'est pas une correction.
  if (replacement === currentLine) {
    return refuse(FR.fix.noChange)
  }

  // 10. Une ligne non vide ne devient pas vide par « correction » : ce
  //     serait une suppression de code déguisée.
  if (replacement.trim() === '' && currentLine.trim() !== '') {
    return refuse(FR.fix.emptyReplacement)
  }

  return { ok: true, line: target.line, replacement }
}
