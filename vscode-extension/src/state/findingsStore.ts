/**
 * Registre des findings alimentant la vue « Security ».
 *
 * Ce module ne dédouble ni le scanner, ni le flux SSE, ni la base : il
 * conserve en mémoire les findings **déjà produits** par `/api/code/*`,
 * pour que la vue puisse les regrouper et les compter sans réinterroger
 * le backend à chaque affichage.
 *
 * Trois sources l'alimentent, toutes existantes :
 *
 * - la réponse HTTP de `/api/code/scan` (`replaceFile`) ;
 * - l'événement SSE `code_finding` (`upsertIfTracked`) ;
 * - `GET /api/code/findings` lors d'un rafraîchissement (`merge`).
 *
 * Aucune dépendance à `vscode` : ce module est testable en Node pur.
 * Rien n'est persisté — ni `globalState`, ni `workspaceState`, ni disque.
 */

import type { CodeFinding } from '../api/backendClient'
import { isProjectFinding } from '../security/findingAdapter'

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

/** Ordre d'affichage : du plus grave au moins grave, jamais alphabétique. */
export const SEVERITY_ORDER: readonly Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

const SEVERITY_RANK: Readonly<Record<Severity, number>> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
}

/** Compteurs du bandeau « Risk Overview ». */
export interface RiskOverview {
  critical: number
  high: number
  medium: number
  low: number
  total: number
}

export interface SeverityGroup {
  severity: Severity
  findings: CodeFinding[]
}

/** Se désabonne. Appelée à la libération de la vue. */
export type Unsubscribe = () => void

/**
 * Un finding est « visible » tant qu'il est ouvert.
 *
 * Corrigé ou écarté, il disparaît de la vue mais reste consultable côté
 * backend : l'extension n'efface jamais un historique.
 */
function isVisible(finding: CodeFinding): boolean {
  return finding.status === 'open'
}

function severityOf(finding: CodeFinding): Severity {
  return SEVERITY_ORDER.includes(finding.severity as Severity)
    ? (finding.severity as Severity)
    : 'LOW'
}

/**
 * Tri stable : gravité, puis score décroissant, puis fichier et ligne.
 *
 * Le développeur doit trouver en haut de liste ce qu'il doit traiter en
 * premier, et retrouver la liste dans le même ordre d'un scan à l'autre.
 */
function compare(a: CodeFinding, b: CodeFinding): number {
  const bySeverity = SEVERITY_RANK[severityOf(a)] - SEVERITY_RANK[severityOf(b)]
  if (bySeverity !== 0) {
    return bySeverity
  }

  const byScore = (b.risk_score ?? 0) - (a.risk_score ?? 0)
  if (byScore !== 0) {
    return byScore
  }

  const byPath = a.file_path.localeCompare(b.file_path)
  if (byPath !== 0) {
    return byPath
  }

  return (a.location?.line_start ?? 0) - (b.location?.line_start ?? 0)
}

/**
 * Ne retient, pour chaque fichier, que les findings de sa dernière analyse.
 *
 * `GET /api/code/findings` rend l'**historique** : un fichier analysé
 * trois fois y figure trois fois, et les findings des analyses précédentes
 * restent `open` tant que personne ne s'est prononcé dessus. Les reprendre
 * tels quels afficherait le même problème plusieurs fois, et ferait
 * réapparaître des problèmes déjà corrigés.
 *
 * Le tri se fait sur `created_at`, comparé en tant que chaîne : les dates
 * ISO-8601 produites par le backend se classent correctement ainsi.
 *
 * À égalité de date entre deux analyses d'un même fichier, la première
 * rencontrée l'emporte — situation qui suppose deux analyses dans la même
 * seconde, et dont l'une ou l'autre issue est acceptable.
 */
export function latestScanPerFile(findings: readonly CodeFinding[]): CodeFinding[] {
  const newest = new Map<string, { scanUid: string; stamp: string }>()

  for (const finding of findings) {
    const stamp = finding.created_at ?? ''
    const current = newest.get(finding.file_path)
    if (!current || stamp > current.stamp) {
      newest.set(finding.file_path, { scanUid: finding.scan_uid, stamp })
    }
  }

  return findings.filter(
    (finding) => newest.get(finding.file_path)?.scanUid === finding.scan_uid
  )
}

export class FindingsStore {
  /** Indexé par `finding_uid` : le backend en garantit l'unicité. */
  private readonly byUid = new Map<string, CodeFinding>()
  private readonly listeners = new Set<() => void>()

  /** S'abonne aux changements. Retourne la fonction de désabonnement. */
  onChange(listener: () => void): Unsubscribe {
    this.listeners.add(listener)
    return () => {
      this.listeners.delete(listener)
    }
  }

  /**
   * Remplace les findings d'un fichier par ceux du dernier scan.
   *
   * Un remplacement, pas une fusion : un problème corrigé entre deux
   * analyses doit disparaître de la vue.
   *
   * **Les findings de sécurité projet sont épargnés.** Analyser
   * `config.py` ne dit rien du secret qui y a été repéré par le balayage
   * du projet : les effacer ferait disparaître un signalement que
   * personne n'a corrigé, au moment précis où l'utilisateur travaille sur
   * le fichier concerné. Les deux familles cohabitent dans le même
   * registre et se remplacent séparément.
   */
  replaceFile(filePath: string, findings: readonly CodeFinding[]): void {
    let changed = false

    for (const [uid, finding] of this.byUid) {
      if (finding.file_path === filePath && !isProjectFinding(finding)) {
        this.byUid.delete(uid)
        changed = true
      }
    }

    for (const finding of findings) {
      this.byUid.set(finding.finding_uid, finding)
      changed = true
    }

    if (changed) {
      this.emit()
    }
  }

  /**
   * Remplace l'intégralité des findings de sécurité projet.
   *
   * Portée volontairement globale, et non par fichier : un balayage de
   * projet couvre tout le dossier d'un coup. Un secret supprimé d'un
   * fichier qui n'apparaît plus dans le nouveau lot doit disparaître de
   * la vue, ce qu'un remplacement fichier par fichier ne ferait pas.
   *
   * Les findings d'analyse de fichier ne sont pas touchés.
   */
  replaceProjectFindings(findings: readonly CodeFinding[]): void {
    let changed = false

    for (const [uid, finding] of this.byUid) {
      if (isProjectFinding(finding)) {
        this.byUid.delete(uid)
        changed = true
      }
    }

    for (const finding of findings) {
      if (!finding?.finding_uid) {
        continue
      }
      this.byUid.set(finding.finding_uid, finding)
      changed = true
    }

    if (changed) {
      this.emit()
    }
  }

  /** Findings de sécurité projet actuellement affichés. */
  projectFindings(): CodeFinding[] {
    return this.all().filter(isProjectFinding)
  }

  /**
   * Applique une mise à jour venue du flux temps réel.
   *
   * **Seuls les findings rattachables à ce workspace sont acceptés** : le
   * flux `/api/stream` est partagé (interface web, autre poste), et la vue
   * ne doit jamais afficher le code d'un autre. Un finding est rattachable
   * s'il est déjà connu, ou s'il porte sur un fichier déjà analysé ici.
   *
   * Retourne `false` quand l'événement a été ignoré.
   */
  upsertIfTracked(finding: CodeFinding): boolean {
    if (!finding || !finding.finding_uid) {
      return false
    }

    if (!this.byUid.has(finding.finding_uid) && !this.tracksFile(finding.file_path)) {
      return false
    }

    this.byUid.set(finding.finding_uid, finding)
    this.emit()
    return true
  }

  /** Insère ou remplace sans condition (résultat d'une requête explicite). */
  upsert(finding: CodeFinding): void {
    if (!finding || !finding.finding_uid) {
      return
    }
    this.byUid.set(finding.finding_uid, finding)
    this.emit()
  }

  /**
   * Fusionne un lot venu de `GET /api/code/findings`.
   *
   * Retourne le nombre de findings encore inconnus de la vue.
   */
  merge(findings: readonly CodeFinding[]): number {
    let added = 0

    for (const finding of findings) {
      if (!finding || !finding.finding_uid) {
        continue
      }
      if (!this.byUid.has(finding.finding_uid)) {
        added += 1
      }
      this.byUid.set(finding.finding_uid, finding)
    }

    if (findings.length > 0) {
      this.emit()
    }

    return added
  }

  /** Ce fichier a-t-il déjà produit des findings ici ? */
  tracksFile(filePath: string | undefined): boolean {
    if (!filePath) {
      return false
    }
    for (const finding of this.byUid.values()) {
      if (finding.file_path === filePath) {
        return true
      }
    }
    return false
  }

  /**
   * Oublie un fichier (document fermé, fichier exclu).
   *
   * Les findings de sécurité projet sont conservés : ils décrivent le
   * dossier, pas la session d'édition. Fermer un onglet ne corrige pas un
   * secret.
   */
  removeFile(filePath: string): void {
    let changed = false
    for (const [uid, finding] of this.byUid) {
      if (finding.file_path === filePath && !isProjectFinding(finding)) {
        this.byUid.delete(uid)
        changed = true
      }
    }
    if (changed) {
      this.emit()
    }
  }

  /** Vide la vue. Le backend, lui, conserve tout son historique. */
  clear(): void {
    if (this.byUid.size === 0) {
      return
    }
    this.byUid.clear()
    this.emit()
  }

  /** Retrouve un finding, même corrigé ou écarté (fenêtre de détail). */
  get(uid: string): CodeFinding | undefined {
    return this.byUid.get(uid)
  }

  /** Findings ouverts, triés. */
  all(): CodeFinding[] {
    return [...this.byUid.values()].filter(isVisible).sort(compare)
  }

  /** Chemins distincts encore représentés dans la vue. */
  files(): string[] {
    return [...new Set(this.all().map((finding) => finding.file_path))].sort()
  }

  /** Compteurs du bandeau, findings ouverts uniquement. */
  overview(): RiskOverview {
    const overview: RiskOverview = { critical: 0, high: 0, medium: 0, low: 0, total: 0 }

    for (const finding of this.byUid.values()) {
      if (!isVisible(finding)) {
        continue
      }

      switch (severityOf(finding)) {
        case 'CRITICAL':
          overview.critical += 1
          break
        case 'HIGH':
          overview.high += 1
          break
        case 'MEDIUM':
          overview.medium += 1
          break
        default:
          overview.low += 1
      }

      overview.total += 1
    }

    return overview
  }

  /** Findings ouverts regroupés par gravité. Les groupes vides sont omis. */
  grouped(): SeverityGroup[] {
    const groups = new Map<Severity, CodeFinding[]>()

    for (const finding of this.all()) {
      const severity = severityOf(finding)
      const bucket = groups.get(severity)
      if (bucket) {
        bucket.push(finding)
      } else {
        groups.set(severity, [finding])
      }
    }

    return SEVERITY_ORDER.filter((severity) => groups.has(severity)).map((severity) => ({
      severity,
      findings: groups.get(severity) ?? [],
    }))
  }

  private emit(): void {
    // Copie de la liste : un abonné peut se désabonner pendant la diffusion.
    for (const listener of [...this.listeners]) {
      try {
        listener()
      } catch {
        // Un abonné défaillant ne doit pas priver les autres de l'événement.
      }
    }
  }
}
