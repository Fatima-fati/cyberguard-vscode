/**
 * Projection d'un `SecurityFinding` sur la forme attendue par la vue.
 *
 * Le problème résolu
 * ------------------
 *
 * La vue « Security », les diagnostics, les notifications, le tri par
 * gravité, le badge et la fenêtre de détail sont écrits pour `CodeFinding`.
 * Introduire un second type à travers toute cette chaîne aurait demandé de
 * doubler chaque point de passage — et chaque doublon est une occasion de
 * diverger.
 *
 * Un secret détecté et une dépendance vulnérable **sont** des signalements
 * de sécurité avec un titre, une gravité, un fichier et une ligne. Ils
 * remplissent donc la même forme, et l'utilisateur voit une seule liste
 * triée par gravité, comme la spécification le demande :
 *
 *     Security
 *     ├── Critical (2)
 *     │   ├── Secret detected
 *     │   └── Vulnerable dependency
 *     └── High (4)
 *
 * Ce qui distingue les deux familles dans le registre
 * ---------------------------------------------------
 *
 * `detection_engine` est **absent** des findings d'analyse de fichier et
 * **présent** sur ceux-ci. Cette seule différence permet au registre de
 * remplacer les uns sans effacer les autres : analyser `config.py` ne doit
 * pas faire disparaître le secret qui y a été repéré, et inversement.
 *
 * Ce qui n'est jamais inventé ici
 * -------------------------------
 *
 * Aucun champ n'est fabriqué : le titre, la gravité, la confiance et la
 * recommandation viennent du backend. `risk_score` est dérivé de la
 * gravité par une table fixe — il sert au tri secondaire de la vue, et
 * n'est jamais présenté comme une mesure.
 *
 * Aucune dépendance à `vscode` : ce module est testable en Node pur.
 */

import type { CodeFinding } from '../api/backendClient'
import type { SecurityFinding, Severity } from './securityTypes'

/**
 * Score attribué à chaque gravité, pour le tri secondaire de la vue.
 *
 * Ce n'est **pas** une mesure de risque : rien n'a été calculé. La vue
 * trie par gravité puis par score, et sans valeur les findings de même
 * gravité se réordonneraient à chaque rafraîchissement. Les paliers
 * reprennent ceux de `app.ai.schemas.RISK_THRESHOLDS`, pour que l'échelle
 * affichée reste cohérente avec celle des findings de code.
 */
const SCORE_BY_SEVERITY: Readonly<Record<Severity, number>> = {
  CRITICAL: 90,
  HIGH: 70,
  MEDIUM: 45,
  LOW: 20,
}

/** Confiance affichée en fraction, comme pour les findings de code. */
const CONFIDENCE_VALUE: Readonly<Record<string, number>> = {
  HIGH: 0.9,
  MEDIUM: 0.6,
  LOW: 0.3,
}

/**
 * Catégorie de vulnérabilité correspondante, pour les libellés partagés.
 *
 * Un secret écrit en dur **est** la catégorie `hardcoded_secret` du moteur
 * de règles : réutiliser le même identifiant évite deux vocabulaires pour
 * un seul concept.
 */
const CATEGORY_MAP: Readonly<Record<string, string>> = {
  SECRET: 'hardcoded_secret',
  DEPENDENCY: 'vulnerable_dependency',
  CONFIGURATION: 'insecure_configuration',
  CODE: 'unknown',
  API: 'insecure_api',
  GIT: 'unknown',
}

/** Traduit un finding de sécurité projet en entrée de la vue. */
export function toViewFinding(finding: SecurityFinding): CodeFinding {
  const severity = finding.severity
  const references = finding.references ?? []

  return {
    finding_uid: finding.id,
    // Les findings projet n'appartiennent à aucun scan de fichier. Une
    // valeur stable par catégorie suffit au dédoublonnage de la vue.
    scan_uid: `project:${finding.category}`,
    rule_id: finding.detection_engine || finding.category,
    category: CATEGORY_MAP[finding.category] ?? 'unknown',
    category_label: finding.category_label,
    // Les références documentaires renseignent la colonne CWE quand elles
    // en portent une ; sinon le champ reste vide plutôt que rempli au
    // hasard.
    cwe: references.find((item) => item.startsWith('CWE-')) ?? null,
    owasp: null,
    severity,
    severity_label: finding.severity_label,
    risk_score: SCORE_BY_SEVERITY[severity] ?? 0,
    risk_band: severity,
    confidence: CONFIDENCE_VALUE[finding.confidence] ?? 0.5,
    source: 'rule',
    source_label: finding.detection_engine,
    title: finding.title,
    explanation: finding.description,
    why_dangerous: finding.description,
    potential_impact: [],
    recommendations: finding.remediation ? [finding.remediation] : [],
    risk_factors: [],
    location: {
      line_start: Math.max(1, finding.line_start),
      line_end: Math.max(1, finding.line_end || finding.line_start),
      column_start: 0,
      column_end: 0,
      // La preuve est **déjà expurgée** par le moteur puis par le backend.
      // C'est la seule chose qui puisse figurer ici : l'extrait réel du
      // fichier révélerait le secret dans la fenêtre de détail.
      snippet: finding.evidence,
    },
    file_path: finding.file ?? '',
    fix_available: false,
    fix_summary: '',
    status: finding.status,
    status_label: finding.status_label,
    created_at: finding.created_at,
    // Marque d'origine : c'est elle qui permet au registre de distinguer
    // ces findings de ceux d'une analyse de fichier.
    detection_engine: finding.detection_engine || finding.category,
  }
}

/** Traduit un lot, en écartant les entrées inexploitables. */
export function toViewFindings(
  findings: readonly SecurityFinding[]
): CodeFinding[] {
  return findings
    .filter((finding) => finding && finding.id)
    .map((finding) => toViewFinding(finding))
}

/**
 * Ce finding vient-il de la sécurité projet plutôt que d'une analyse de
 * fichier ?
 *
 * Prédicat unique, utilisé par le registre et par les vues : dupliquer le
 * test `detection_engine !== undefined` à chaque point d'appel finirait
 * par produire deux définitions divergentes de « finding projet ».
 */
export function isProjectFinding(finding: CodeFinding): boolean {
  return typeof finding.detection_engine === 'string' && finding.detection_engine.length > 0
}
