/**
 * Politique de vérification avant `push`.
 *
 * Trois modes, et un seul par défaut
 * ----------------------------------
 *
 *     off     aucune vérification
 *     warn    prévient, laisse passer          ← défaut
 *     block   demande une confirmation explicite
 *
 * `warn` est le défaut parce qu'un outil de sécurité qui bloque sans
 * qu'on le lui ait demandé est désinstallé, pas corrigé. `block` existe
 * pour les équipes qui le choisissent, jamais par surprise.
 *
 * Quatre règles, et ce qu'elles protègent
 * ---------------------------------------
 *
 * **1. Seul ce qui est introduit compte.** Un problème préexistant ne
 * bloque jamais : le développeur ne l'a pas causé, et l'en rendre
 * responsable au moment où il pousse autre chose est le plus sûr moyen de
 * faire désactiver la protection.
 *
 * **2. Seules les gravités hautes interrompent.** `CRITICAL` et `HIGH`.
 * Une interruption sur un `LOW` coûte plus d'attention qu'elle n'en
 * mérite, et dévalue les suivantes.
 *
 * **3. Le blocage a toujours une sortie.** `bypassAvailable` est vrai
 * chaque fois que la décision est `block`, sans exception possible dans
 * ce code. Une protection sans échappatoire empêche de pousser un
 * correctif urgent, et se contourne alors par la ligne de commande — donc
 * sans être vue.
 *
 * **4. L'échec est ouvert.** Délai dépassé, dépôt illisible, moteur en
 * panne : la décision est `allow`, marquée `degraded`. Un agent de
 * sécurité qui empêche de travailler quand il tombe en panne est un
 * agent qu'on retire.
 *
 * Aucune dépendance à `vscode` : ce module est testable en Node pur.
 */

import type { AttributedFinding, GitSecuritySummary } from './changeAttribution'
import { severityOf } from './changeAttribution'

/** Réglage utilisateur. */
export type PrePushMode = 'off' | 'warn' | 'block'

/** Ce que la vérification conclut. */
export type PrePushDecision =
  /** Rien à signaler, ou mode `off`, ou échec ouvert. */
  | 'allow'
  /** Des problèmes introduits, mais le `push` reste autorisé. */
  | 'warn'
  /** Confirmation explicite requise. Toujours contournable. */
  | 'block'

export interface PrePushVerdict {
  readonly decision: PrePushDecision
  readonly mode: PrePushMode
  /** Les findings qui motivent la décision. Vide si `allow`. */
  readonly triggering: readonly AttributedFinding[]
  /** Phrase destinée à l'utilisateur. Toujours présente. */
  readonly reason: string
  /**
   * Un contournement est-il proposé ?
   *
   * **Toujours vrai quand `decision === 'block'`.** Un test le vérifie,
   * parce que c'est la garantie la plus facile à perdre au fil des
   * retouches.
   */
  readonly bypassAvailable: boolean
  /** L'analyse a-t-elle échoué ouvert ? */
  readonly degraded: boolean
}

/** Gravités qui interrompent. Les autres sont signalées, jamais bloquantes. */
const BLOCKING_SEVERITIES: ReadonlySet<string> = new Set(['CRITICAL', 'HIGH'])

/** Ce finding introduit justifie-t-il d'interrompre ? */
export function isBlocking(attributed: AttributedFinding): boolean {
  return (
    attributed.origin === 'introduced' &&
    BLOCKING_SEVERITIES.has(severityOf(attributed.finding))
  )
}

export function normalizeMode(value: string | undefined | null): PrePushMode {
  const mode = (value ?? '').toLowerCase()
  // Une valeur inconnue retombe sur le défaut, jamais sur `block` : un
  // réglage mal orthographié ne doit pas durcir la protection à l'insu
  // de l'utilisateur.
  return mode === 'off' || mode === 'block' ? mode : 'warn'
}

export interface PrePushInput {
  readonly mode: PrePushMode
  readonly summary: GitSecuritySummary
  /** Findings attribués par `changeAttribution`. */
  readonly attributed: readonly AttributedFinding[]
}

/**
 * Décide ce qui doit se passer avant un `push`.
 *
 * Fonction pure : aucune boîte de dialogue, aucun minuteur, aucun accès
 * au dépôt. C'est ce qui rend la politique vérifiable sans éditeur — et
 * c'est ce qui compte, parce que ces règles décident si le travail de
 * quelqu'un est interrompu.
 */
export function decidePrePush(input: PrePushInput): PrePushVerdict {
  const { mode, summary } = input

  if (mode === 'off') {
    return {
      decision: 'allow',
      mode,
      triggering: [],
      reason: 'Vérification avant push désactivée.',
      bypassAvailable: false,
      degraded: false,
    }
  }

  // Échec ouvert. Testé **avant** le décompte : un résumé non concluant
  // porte des zéros qui ne signifient pas « rien trouvé ».
  if (!summary.conclusive) {
    return {
      decision: 'allow',
      mode,
      triggering: [],
      reason:
        summary.message ||
        "La vérification n'a pas abouti. Le push n'est pas retenu pour autant.",
      bypassAvailable: false,
      degraded: true,
    }
  }

  const triggering = input.attributed.filter(isBlocking)

  if (triggering.length === 0) {
    return {
      decision: 'allow',
      mode,
      triggering: [],
      reason: cleanReason(summary),
      bypassAvailable: false,
      degraded: false,
    }
  }

  const reason = describeTriggering(triggering, summary)

  if (mode === 'block') {
    return {
      decision: 'block',
      mode,
      triggering,
      reason,
      // Invariant du module : un blocage est toujours contournable.
      bypassAvailable: true,
      degraded: false,
    }
  }

  return {
    decision: 'warn',
    mode,
    triggering,
    reason,
    bypassAvailable: false,
    degraded: false,
  }
}

// --------------------------------------------------------------------------
// Formulations
// --------------------------------------------------------------------------

function cleanReason(summary: GitSecuritySummary): string {
  const scope = summary.reduced
    ? ` (${summary.analyzedFiles} fichier${summary.analyzedFiles > 1 ? 's' : ''} sur ${
        summary.changedFiles
      } analysé${summary.analyzedFiles > 1 ? 's' : ''})`
    : ''

  if (summary.preExisting.total > 0) {
    // La nuance est dite explicitement : « rien d'introduit » n'est pas
    // « rien à signaler », et taire la différence tromperait.
    return (
      `Aucun problème de gravité haute introduit par ce changement${scope}. ` +
      `${summary.preExisting.total} signalement${
        summary.preExisting.total > 1 ? 's' : ''
      } préexistant${summary.preExisting.total > 1 ? 's' : ''} reste${
        summary.preExisting.total > 1 ? 'nt' : ''
      } ouvert${summary.preExisting.total > 1 ? 's' : ''}.`
    )
  }

  return `Aucun problème introduit par ce changement${scope}.`
}

function describeTriggering(
  triggering: readonly AttributedFinding[],
  summary: GitSecuritySummary
): string {
  const critical = triggering.filter(
    (item) => severityOf(item.finding) === 'CRITICAL'
  ).length
  const high = triggering.length - critical

  const parts: string[] = []
  if (critical > 0) {
    parts.push(`${critical} critique${critical > 1 ? 's' : ''}`)
  }
  if (high > 0) {
    parts.push(`${high} élevé${high > 1 ? 's' : ''}`)
  }

  const head = `${triggering.length} problème${
    triggering.length > 1 ? 's' : ''
  } introduit${triggering.length > 1 ? 's' : ''} par ce changement (${parts.join(
    ', '
  )}).`

  return summary.reduced
    ? `${head} Analyse partielle : ${summary.analyzedFiles} fichier(s) sur ${summary.changedFiles}.`
    : head
}
