/**
 * Vérification avant `push` : la partie qui parle à l'utilisateur.
 *
 * La décision elle-même est prise par `prePushPolicy.ts`, qui est pure et
 * testable. Ce module n'ajoute que ce qui exige VS Code : la boîte de
 * dialogue, le choix des boutons, et le renvoi vers la vue.
 *
 * Aucun hook Git n'est installé
 * -----------------------------
 *
 * L'extension **n'écrit rien** dans `.git/hooks`, ni au démarrage, ni à
 * l'activation du mode `block`, ni sur proposition. Deux raisons :
 *
 * - un hook est un script exécuté par Git à chaque `push`, y compris
 *   quand VS Code est fermé. En écrire un sans demande explicite
 *   reviendrait à modifier le dépôt de l'utilisateur pour installer du
 *   code exécutable — exactement ce qu'un agent de sécurité ne doit pas
 *   faire ;
 * - un hook installé en silence donne le sentiment d'être protégé
 *   partout, alors qu'il ne l'est que sur ce poste et ce clone.
 *
 * La vérification est donc lancée **depuis l'éditeur**, par la commande
 * « Check Changes Before Push ». La limite est dite clairement à
 * l'utilisateur : un `push` fait depuis un terminal n'est pas intercepté.
 *
 * Le blocage a toujours une sortie
 * --------------------------------
 *
 * Quand la décision est `block`, la boîte propose « Pousser quand
 * même ». Ce n'est pas une faiblesse du dispositif, c'est ce qui le rend
 * utilisable : une protection sans échappatoire empêche de livrer un
 * correctif urgent, et se contourne alors par la ligne de commande —
 * donc sans laisser de trace. Le contournement, lui, est journalisé.
 */

import * as vscode from 'vscode'

import { FR } from '../i18n/fr'
import type { AttributedFinding } from './changeAttribution'
import type { GitSecurityService } from './gitSecurityService'
import { decidePrePush, type PrePushMode, type PrePushVerdict } from './prePushPolicy'

/** Ce que l'utilisateur a finalement décidé. */
export type PrePushOutcome =
  /** Rien ne s'y oppose, ou le mode laisse passer. */
  | 'allowed'
  /** Des problèmes ont été signalés, le push reste autorisé. */
  | 'warned'
  /** L'utilisateur a passé outre un blocage. Journalisé. */
  | 'bypassed'
  /** L'utilisateur a renoncé. */
  | 'cancelled'

export interface PrePushResult {
  readonly outcome: PrePushOutcome
  readonly verdict: PrePushVerdict
}

export interface PrePushCheckOptions {
  readonly service: GitSecurityService
  readonly mode: () => PrePushMode
  readonly budgetMs: () => number
  readonly log: (message: string) => void
  /** Ouvre le premier problème signalé. Réutilise la commande existante. */
  readonly reveal: (finding: AttributedFinding) => Promise<void>
}

/**
 * Lance la vérification et présente son résultat.
 *
 * Ne lève jamais : toute panne se traduit par un verdict `allow` marqué
 * `degraded`, conformément à l'échec ouvert.
 */
export async function runPrePushCheck(
  options: PrePushCheckOptions
): Promise<PrePushResult> {
  const mode = options.mode()

  if (mode === 'off') {
    const verdict = decidePrePush({
      mode,
      summary: options.service.summary(),
      attributed: [],
    })
    options.log(FR.git.disabled)
    return { outcome: 'allowed', verdict }
  }

  // Analyse fraîche : l'état du dépôt a pu changer depuis la dernière.
  // Le budget est celui du réglage — l'objectif reste sous trois secondes.
  const analysis = await options.service.analyze({ budgetMs: options.budgetMs() })

  const verdict = decidePrePush({
    mode,
    summary: analysis.summary,
    attributed: analysis.attributed,
  })

  if (verdict.degraded) {
    // L'échec ouvert est **dit**, pas tu : l'utilisateur doit savoir que
    // le feu vert n'en est pas un.
    void vscode.window.showWarningMessage(FR.git.prePushDegraded)
    options.log(`${FR.git.prePushTitle} — ${verdict.reason}`)
    return { outcome: 'allowed', verdict }
  }

  if (verdict.decision === 'allow') {
    void vscode.window.showInformationMessage(FR.git.prePushClean(verdict.reason))
    options.log(`${FR.git.prePushTitle} — ${verdict.reason}`)
    return { outcome: 'allowed', verdict }
  }

  const lead = verdict.triggering[0]

  if (verdict.decision === 'warn') {
    options.log(`${FR.git.prePushTitle} — ${verdict.reason}`)
    const choice = await vscode.window.showWarningMessage(
      FR.git.prePushWarn(verdict.reason),
      FR.git.prePushReview
    )
    if (choice === FR.git.prePushReview && lead) {
      await options.reveal(lead)
    }
    return { outcome: 'warned', verdict }
  }

  // --- Blocage --------------------------------------------------------
  //
  // Modale : c'est le seul endroit de l'extension qui interrompt
  // réellement, et cela doit se voir. Les deux issues sont explicites,
  // et « Pousser quand même » est toujours proposé.
  options.log(`${FR.git.prePushTitle} — ${verdict.reason}`)
  const choice = await vscode.window.showWarningMessage(
    FR.git.prePushBlock(verdict.reason),
    { modal: true, detail: describeTriggering(verdict.triggering) },
    FR.git.prePushReview,
    FR.git.prePushBypass
  )

  if (choice === FR.git.prePushReview) {
    if (lead) {
      await options.reveal(lead)
    }
    options.log(FR.git.prePushCancelled)
    return { outcome: 'cancelled', verdict }
  }

  if (choice === FR.git.prePushBypass) {
    // Tracé : un contournement est une décision de sécurité, et elle doit
    // laisser une trace consultable.
    options.log(FR.git.prePushBypassed(verdict.triggering.length))
    return { outcome: 'bypassed', verdict }
  }

  options.log(FR.git.prePushCancelled)
  return { outcome: 'cancelled', verdict }
}

/**
 * Détail affiché dans la modale.
 *
 * Titre, fichier et ligne — jamais la preuve : un secret détecté ne doit
 * pas apparaître dans une boîte de dialogue, qui est précisément ce qu'on
 * capture en copie d'écran pour demander de l'aide.
 */
function describeTriggering(triggering: readonly AttributedFinding[]): string {
  const lines = triggering.slice(0, 5).map(({ finding }) => {
    const where = finding.file
      ? `${finding.file}:${Math.max(1, finding.line_start)}`
      : '(projet)'
    return `• [${finding.severity}] ${finding.title} — ${where}`
  })

  if (triggering.length > lines.length) {
    lines.push(`• … ${triggering.length - lines.length} autre(s)`)
  }

  return lines.join('\n')
}
