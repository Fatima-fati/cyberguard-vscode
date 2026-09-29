/**
 * Mémoire des notifications déjà présentées.
 *
 * Séparé de `notifications.ts` pour la même raison que `fixGuard.ts` l'est
 * de `quickFix.ts` : ce sont ces règles qui décident si le développeur est
 * interrompu, et elles doivent être vérifiables sans lancer VS Code.
 *
 * Aucune dépendance à `vscode`, aucun minuteur, aucune horloge implicite :
 * l'instant courant est toujours reçu en paramètre, pour que le
 * comportement dans le temps soit testable.
 */

import { createHash } from 'node:crypto'

import type { CodeFinding } from '../api/backendClient'
import { SEVERITY_ORDER, type Severity } from './findingsStore'

/**
 * Attente avant l'affichage, pour regrouper une rafale.
 *
 * Les findings d'une analyse arrivent en un seul appel, mais ceux du flux
 * SSE tombent un par un : cette fenêtre les rassemble.
 */
export const GROUP_WINDOW_MS = 500

/** Délai minimal entre deux bulles, quelle que soit l'activité. */
export const COOLDOWN_MS = 15_000

const SEVERITY_RANK: Readonly<Record<Severity, number>> = {
  LOW: 0,
  MEDIUM: 1,
  HIGH: 2,
  CRITICAL: 3,
}

/** Gravité du finding, ramenée à LOW si le backend en annonce une inconnue. */
export function severityOf(finding: CodeFinding): Severity {
  return SEVERITY_ORDER.includes(finding.severity as Severity)
    ? (finding.severity as Severity)
    : 'LOW'
}

/**
 * Empreinte stable d'un problème.
 *
 * Décrit **le problème, pas son évaluation** : chemin, règle, ligne et
 * extrait. Ni la gravité, ni le score, ni `finding_uid` n'y entrent —
 * `finding_uid` est un UUID régénéré à chaque analyse, et la gravité
 * change précisément lors de l'enrichissement IA qu'on veut taire.
 *
 * Conséquences voulues : deux analyses du même code produisent la même
 * empreinte, avant comme après le passage du modèle ; modifier la ligne
 * fautive, la déplacer ou changer de règle en produit une différente, et
 * autorise donc une nouvelle notification.
 *
 * L'extrait est haché, jamais journalisé ni transmis.
 */
export function fingerprint(finding: CodeFinding): string {
  const parts = [
    finding.file_path ?? '',
    finding.rule_id ?? '',
    String(finding.location?.line_start ?? 0),
    finding.location?.snippet ?? '',
  ]

  // Chaque partie est préfixée de sa longueur : aucun jeu de valeurs ne
  // peut produire la même chaîne qu'un autre par simple concaténation,
  // quel que soit le contenu de l'extrait.
  return createHash('sha256')
    .update(parts.map((part) => `${part.length}:${part}`).join('|'), 'utf8')
    .digest('hex')
}

/**
 * Le finding le plus grave d'un lot.
 *
 * C'est celui que la bulle nomme ; les autres sont comptés. À gravité
 * égale, le score de risque du backend départage — jamais une valeur
 * calculée ici.
 */
export function leadOf(batch: readonly CodeFinding[]): CodeFinding | undefined {
  return [...batch].sort(
    (a, b) =>
      SEVERITY_RANK[severityOf(b)] - SEVERITY_RANK[severityOf(a)] ||
      (b.risk_score ?? 0) - (a.risk_score ?? 0)
  )[0]
}

export class NotificationLedger {
  /** Empreinte → gravité déjà annoncée, pour ne pas répéter. */
  private readonly announced = new Map<string, Severity>()
  private lastShownAt = 0

  /**
   * Retient les findings qui méritent une bulle, et les enregistre.
   *
   * L'enregistrement a lieu ici, pas à l'affichage : un même problème reçu
   * deux fois pendant la fenêtre de regroupement ne doit compter qu'une
   * fois, même si la bulle n'est pas encore apparue.
   */
  admit(findings: readonly CodeFinding[]): CodeFinding[] {
    const fresh: CodeFinding[] = []

    // Chaque retenue est enregistrée immédiatement, avant d'examiner la
    // suivante : deux exemplaires du même problème dans un seul lot — ce
    // que le flux SSE produit facilement — ne doivent compter qu'une fois.
    for (const finding of findings) {
      if (!this.shouldAnnounce(finding)) {
        continue
      }
      this.announced.set(fingerprint(finding), severityOf(finding))
      fresh.push(finding)
    }

    return fresh
  }

  /**
   * Ce finding mérite-t-il une bulle ?
   *
   * Non si : il est déjà corrigé ou écarté, ou son empreinte a déjà été
   * annoncée à une gravité au moins équivalente.
   *
   * Oui si l'analyse IA **aggrave** le diagnostic : passer de MEDIUM à
   * CRITICAL sur le même code est une information neuve, pas une
   * répétition. Le cas inverse — le modèle confirme à l'identique, ou
   * revoit à la baisse — reste silencieux.
   */
  shouldAnnounce(finding: CodeFinding): boolean {
    if (!finding || finding.status !== 'open') {
      return false
    }

    const previous = this.announced.get(fingerprint(finding))
    if (previous === undefined) {
      return true
    }

    return SEVERITY_RANK[severityOf(finding)] > SEVERITY_RANK[previous]
  }

  /**
   * Combien de temps attendre avant d'afficher.
   *
   * Au minimum la fenêtre de regroupement ; davantage si la bulle
   * précédente est trop récente.
   */
  delay(now: number): number {
    return Math.max(GROUP_WINDOW_MS, COOLDOWN_MS - (now - this.lastShownAt))
  }

  /** Enregistre l'instant d'affichage, qui ouvre le délai suivant. */
  markShown(now: number): void {
    this.lastShownAt = now
  }

  /**
   * Oublie tout (commande « Clear Findings »).
   *
   * L'utilisateur repart d'une vue vide : il doit pouvoir être prévenu à
   * nouveau des problèmes qu'il vient d'effacer de l'affichage.
   */
  reset(): void {
    this.announced.clear()
    this.lastShownAt = 0
  }

  /** Nombre d'empreintes retenues. Utile aux tests et au diagnostic. */
  get size(): number {
    return this.announced.size
  }
}
