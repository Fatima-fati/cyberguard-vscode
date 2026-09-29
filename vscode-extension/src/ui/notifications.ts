/**
 * Notifications de sécurité, dédupliquées.
 *
 * Ce module **remplace** la notification en ligne qui vivait dans
 * `scanController.ts` ; il n'en ajoute pas une seconde. Tout ce qui doit
 * atteindre l'utilisateur sous forme de bulle passe désormais par ici,
 * y compris l'échec d'une analyse IA.
 *
 * Le problème résolu : le même problème était annoncé plusieurs fois pour
 * des raisons qui n'intéressent pas le développeur — il sauvegarde sans
 * avoir touché à la ligne fautive, ou l'analyse IA repasse derrière les
 * règles sur le même code. Une bulle par sauvegarde, et l'extension
 * devient insupportable.
 *
 * Deux garde-fous, distincts, tous deux dans `notificationLedger.ts` :
 *
 * 1. **Empreinte** — un problème n'est annoncé qu'une fois.
 * 2. **Fenêtre de regroupement et délai minimal** — une analyse qui
 *    remonte douze problèmes produit une bulle, pas douze.
 *
 * Ce fichier ne garde que ce qui exige VS Code : les minuteurs, le choix
 * du canal d'affichage et le renvoi vers les commandes existantes.
 *
 * Aucun chiffre n'est inventé : la gravité et le titre viennent du
 * backend, le décompte est celui des problèmes réellement retenus.
 */

import * as path from 'node:path'

import * as vscode from 'vscode'

import type { CodeFinding } from '../api/backendClient'
import { FR } from '../i18n/fr'
import {
  COOLDOWN_MS,
  NotificationLedger,
  leadOf,
  severityOf,
} from '../state/notificationLedger'
import type { Severity } from '../state/findingsStore'

/** Réglages injectés — l'état de l'IA est décidé par le backend, pas ici. */
export interface NotificationCenterOptions {
  /**
   * Le backend annonce-t-il l'enrichissement IA actif ?
   *
   * Sert uniquement à masquer un bouton inutilisable. **Une IA
   * indisponible n'empêche jamais la notification elle-même** : la bulle
   * est affichée, simplement sans l'action « Analyze with AI ».
   */
  isAiEnabled: () => boolean
  log: (message: string) => void
}

export class NotificationCenter implements vscode.Disposable {
  private readonly ledger = new NotificationLedger()
  private queue: CodeFinding[] = []
  private timer: NodeJS.Timeout | undefined
  private disposed = false

  /** Instant du dernier avertissement d'échec IA, pour ne pas le répéter. */
  private lastAiFailureAt = 0

  private readonly isAiEnabled: () => boolean
  private readonly log: (message: string) => void

  constructor(options: NotificationCenterOptions) {
    this.isAiEnabled = options.isAiEnabled
    this.log = options.log
  }

  /**
   * Soumet des findings à notification.
   *
   * Ne notifie rien immédiatement : retient ceux qui méritent une bulle,
   * puis programme un affichage groupé. Appelable aussi souvent qu'on
   * veut — à chaque analyse, à chaque événement SSE.
   */
  consider(findings: readonly CodeFinding[]): void {
    if (this.disposed) {
      return
    }

    const fresh = this.ledger.admit(findings)
    if (fresh.length === 0) {
      return
    }

    this.queue.push(...fresh)
    this.schedule()
  }

  /**
   * Signale l'échec d'un enrichissement IA, au plus une fois par palier.
   *
   * Un balayage de workspace avec un modèle indisponible produirait sinon
   * un avertissement par fichier. L'échec ne remet rien en cause : les
   * findings des règles restent affichés, les diagnostics et la barre
   * d'état aussi.
   */
  reportEnrichmentFailure(reason: string): void {
    if (this.disposed) {
      return
    }

    const now = Date.now()
    if (now - this.lastAiFailureAt < COOLDOWN_MS) {
      this.log(`échec d'enrichissement IA répété, avertissement tu : ${reason}`)
      return
    }

    this.lastAiFailureAt = now
    void vscode.window.showWarningMessage(FR.ai.enrichmentFailed(reason))
  }

  /**
   * Oublie ce qui a été annoncé (commande « Clear Findings »).
   */
  reset(): void {
    this.ledger.reset()
    this.queue = []
    this.lastAiFailureAt = 0
    this.cancelTimer()
  }

  dispose(): void {
    this.disposed = true
    this.cancelTimer()
    this.queue = []
    this.ledger.reset()
  }

  // ---------------- Interne ----------------

  private cancelTimer(): void {
    if (this.timer) {
      clearTimeout(this.timer)
      this.timer = undefined
    }
  }

  /** Programme l'affichage : regroupement d'abord, délai minimal ensuite. */
  private schedule(): void {
    if (this.timer) {
      return
    }

    this.timer = setTimeout(() => {
      this.timer = undefined
      this.flush()
    }, this.ledger.delay(Date.now()))
  }

  /** Affiche une bulle pour le lot en attente. */
  private flush(): void {
    if (this.disposed || this.queue.length === 0) {
      return
    }

    const batch = this.queue
    this.queue = []
    this.ledger.markShown(Date.now())

    const lead = leadOf(batch)
    if (!lead) {
      return
    }

    const severity = severityOf(lead)
    const message = FR.notify.body(
      severity,
      lead.title || lead.category_label || lead.rule_id,
      path.basename(lead.file_path) || lead.file_path,
      lead.location?.line_start ?? 0,
      // Décompte réel des autres problèmes retenus, jamais une estimation.
      batch.length - 1
    )

    this.log(
      `notification ${severity} — ${lead.rule_id} ${lead.file_path}:${
        lead.location?.line_start ?? 0
      }${batch.length > 1 ? ` (+${batch.length - 1} autre(s))` : ''}`
    )

    void this.present(severity, message, lead)
  }

  /**
   * Choisit le canal natif correspondant à la gravité.
   *
   * LOW reste une information discrète, MEDIUM et HIGH des avertissements,
   * CRITICAL passe en erreur — le canal le plus visible dont dispose
   * VS Code. Le marqueur de tête distingue HIGH de MEDIUM, que l'API rend
   * autrement identiques.
   */
  private async present(
    severity: Severity,
    message: string,
    finding: CodeFinding
  ): Promise<void> {
    const actions: string[] = [FR.notify.viewIssue]

    // Bouton masqué quand le backend n'a pas l'IA : proposer une action
    // qui échouerait serait pire que de ne pas la proposer.
    if (this.isAiEnabled()) {
      actions.push(FR.notify.analyzeWithAi)
    }

    // Appelées sur `vscode.window`, jamais détachées : une référence de
    // méthode isolée perdrait son receveur.
    const choice =
      severity === 'CRITICAL'
        ? await vscode.window.showErrorMessage(message, ...actions)
        : severity === 'LOW'
          ? await vscode.window.showInformationMessage(message, ...actions)
          : await vscode.window.showWarningMessage(message, ...actions)

    if (choice === FR.notify.viewIssue) {
      // Ouvre le fichier, place le curseur sur la ligne, affiche la fiche :
      // la commande existante fait déjà les trois.
      await vscode.commands.executeCommand(
        'wazuhSecurity.openFinding',
        finding.finding_uid
      )
      return
    }

    if (choice === FR.notify.analyzeWithAi) {
      // L'analyse est faite par le backend. L'extension ne contacte aucun
      // fournisseur de modèle, ici comme ailleurs.
      await vscode.commands.executeCommand(
        'wazuhSecurity.analyzeWithAi',
        finding.finding_uid
      )
    }
  }
}
