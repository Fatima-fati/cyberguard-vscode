/**
 * Texte affiché au survol d'un diagnostic.
 *
 * Répond aux quatre questions du développeur : ce qui ne va pas, pourquoi
 * c'est dangereux, ce que ça peut coûter, et quoi faire. Tout vient du
 * backend — l'extension met en forme, elle ne rédige pas.
 *
 * Extrait de `provider.ts` : c'est de la mise en forme de texte, donc
 * vérifiable sans éditeur.
 */

import type { CodeFinding } from '../api/backendClient'
import { FR } from '../i18n/fr'

/**
 * Message affiché au survol.
 *
 * Répond aux quatre questions du développeur : ce qui ne va pas,
 * pourquoi c'est dangereux, ce que ça peut coûter, et quoi faire.
 */
export function buildDiagnosticMessage(finding: CodeFinding): string {
  const lines: string[] = [
    finding.title || finding.category_label,
    '',
    `${FR.diagnostic.severity} : ${finding.severity_label} · ${finding.category_label}`,
  ]

  const references = [finding.cwe, finding.owasp].filter(Boolean)
  if (references.length > 0) {
    lines.push(references.join(' · '))
  }

  if (finding.explanation) {
    lines.push('', finding.explanation)
  }

  if (finding.why_dangerous) {
    lines.push('', `${FR.diagnostic.why} : ${finding.why_dangerous}`)
  }

  if (finding.potential_impact.length > 0) {
    lines.push('', `${FR.diagnostic.impact} :`)
    lines.push(...finding.potential_impact.map((item) => `  • ${item}`))
  }

  if (finding.recommendations.length > 0) {
    lines.push('', `${FR.diagnostic.recommendation} :`)
    lines.push(...finding.recommendations.map((item) => `  • ${item}`))
  }

  lines.push(
    '',
    `${FR.diagnostic.detectedBy} : ${finding.source_label} ${finding.rule_id} ` +
      `(score ${finding.risk_score}/100${
        finding.source === 'ia'
          ? `, confiance ${Math.round(finding.confidence * 100)} %`
          : ''
      })`
  )

  return lines.join('\n')
}
