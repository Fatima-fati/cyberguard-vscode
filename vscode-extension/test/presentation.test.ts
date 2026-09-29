/**
 * Tests de la mise en forme : gravités, barre d'état, survol.
 *
 * Trois surfaces que l'utilisateur lit en permanence, et dont le calcul
 * ne dépend pas de l'API VS Code — seulement sa projection finale, qui
 * tient en une ligne dans chaque module.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import type { CodeFinding, SeverityCounts } from '../src/api/backendClient'
import { buildDiagnosticMessage } from '../src/diagnostics/hoverMessage'
import {
  SEVERITY_LEVELS,
  isNotifiable,
  levelFor,
} from '../src/diagnostics/severityLevels'
import { describeCounts, isAlarming } from '../src/ui/statusSummary'

function counts(overrides: Partial<SeverityCounts> = {}): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0, ...overrides }
}

function finding(overrides: Partial<CodeFinding> = {}): CodeFinding {
  return {
    finding_uid: 'uid-1',
    scan_uid: 'scan-1',
    rule_id: 'PY-SQLI-001',
    category: 'injection',
    category_label: 'Injection',
    cwe: 'CWE-89',
    owasp: 'A03:2021',
    severity: 'CRITICAL',
    severity_label: 'Critique',
    risk_score: 92,
    risk_band: 'critique',
    confidence: 0.9,
    source: 'rule',
    source_label: 'Règle déterministe',
    title: 'SQL Injection',
    explanation: 'La valeur est concaténée sans échappement.',
    why_dangerous: 'Un attaquant peut lire toute la table.',
    potential_impact: ['Exfiltration de la base'],
    recommendations: ['Utiliser une requête paramétrée'],
    risk_factors: [],
    location: {
      line_start: 10,
      line_end: 10,
      column_start: 0,
      column_end: 20,
      snippet: '',
    },
    file_path: 'src/users.py',
    fix_available: false,
    fix_summary: '',
    status: 'open',
    status_label: 'Ouvert',
    created_at: '2026-01-01T00:00:00Z',
    ...overrides,
  }
}

describe('Correspondance des sévérités', () => {
  it('projette les quatre niveaux du backend', () => {
    assert.deepEqual(SEVERITY_LEVELS, {
      CRITICAL: 'Error',
      HIGH: 'Error',
      MEDIUM: 'Warning',
      LOW: 'Information',
    })
  })

  it('traite CRITICAL et HIGH comme des erreurs', () => {
    assert.equal(levelFor('CRITICAL'), 'Error')
    assert.equal(levelFor('HIGH'), 'Error')
  })

  it('distingue MEDIUM de LOW', () => {
    assert.equal(levelFor('MEDIUM'), 'Warning')
    assert.equal(levelFor('LOW'), 'Information')
  })

  it('reste informatif sur une sévérité inconnue', () => {
    // Un backend plus récent ne doit jamais faire virer un fichier au
    // rouge par accident.
    assert.equal(levelFor('CATASTROPHIC'), 'Information')
    assert.equal(levelFor(''), 'Information')
  })

  it('ne notifie que les deux sévérités hautes', () => {
    assert.equal(isNotifiable('CRITICAL'), true)
    assert.equal(isNotifiable('HIGH'), true)
    assert.equal(isNotifiable('MEDIUM'), false)
    assert.equal(isNotifiable('LOW'), false)
  })
})

describe('Résumé de la barre d’état', () => {
  it('reste vide quand rien n’est ouvert', () => {
    assert.equal(describeCounts(counts()), '')
  })

  it('accorde le singulier et le pluriel', () => {
    assert.equal(describeCounts(counts({ critical: 1 })), '1 critique')
    assert.equal(describeCounts(counts({ critical: 2 })), '2 critiques')
    assert.equal(describeCounts(counts({ high: 1 })), '1 élevée')
    assert.equal(describeCounts(counts({ high: 3 })), '3 élevées')
    assert.equal(describeCounts(counts({ medium: 1 })), '1 moyenne')
    assert.equal(describeCounts(counts({ medium: 2 })), '2 moyennes')
    assert.equal(describeCounts(counts({ low: 1 })), '1 faible')
    assert.equal(describeCounts(counts({ low: 4 })), '4 faibles')
  })

  it('ordonne du plus grave au moins grave', () => {
    assert.equal(
      describeCounts(counts({ critical: 1, high: 2, medium: 3, low: 4 })),
      '1 critique, 2 élevées, 3 moyennes, 4 faibles'
    )
  })

  it('tait les niveaux absents', () => {
    // « 0 faible » allongerait la barre sans rien apprendre.
    assert.equal(describeCounts(counts({ critical: 1, low: 2 })), '1 critique, 2 faibles')
    assert.ok(!describeCounts(counts({ critical: 1 })).includes('0'))
  })

  it('ne s’alarme que sur les sévérités hautes', () => {
    assert.equal(isAlarming(counts({ critical: 1 })), true)
    assert.equal(isAlarming(counts({ high: 1 })), true)
    assert.equal(isAlarming(counts({ medium: 9, low: 9 })), false)
    assert.equal(isAlarming(counts()), false)
  })
})

describe('Message de survol', () => {
  it('répond aux quatre questions du développeur', () => {
    const message = buildDiagnosticMessage(finding())

    assert.match(message, /SQL Injection/)
    assert.match(message, /Critique/)
    assert.match(message, /concaténée sans échappement/)
    assert.match(message, /lire toute la table/)
    assert.match(message, /Exfiltration de la base/)
    assert.match(message, /Utiliser une requête paramétrée/)
  })

  it('cite les références CWE et OWASP quand elles existent', () => {
    assert.match(buildDiagnosticMessage(finding()), /CWE-89 · A03:2021/)
  })

  it('omet la ligne de références quand le backend n’en donne aucune', () => {
    const message = buildDiagnosticMessage(finding({ cwe: null, owasp: null }))
    assert.ok(!message.includes('CWE'))
    assert.ok(!message.includes('OWASP'))
  })

  it('nomme la règle et son score, sans rien inventer', () => {
    const message = buildDiagnosticMessage(finding())
    assert.match(message, /PY-SQLI-001/)
    assert.match(message, /score 92\/100/)
  })

  it('n’affiche la confiance que pour un verdict du modèle', () => {
    // Pour une règle déterministe, la confiance n'apporte rien.
    assert.ok(!buildDiagnosticMessage(finding({ source: 'rule' })).includes('confiance'))

    const parIa = buildDiagnosticMessage(
      finding({ source: 'ia', source_label: 'Analyse IA', confidence: 0.83 })
    )
    assert.match(parIa, /confiance 83 %/)
  })

  it('reste lisible quand les sections facultatives sont vides', () => {
    const message = buildDiagnosticMessage(
      finding({
        explanation: '',
        why_dangerous: '',
        potential_impact: [],
        recommendations: [],
      })
    )

    assert.match(message, /SQL Injection/)
    // Aucun titre de section orphelin.
    assert.ok(!message.includes('Recommandation :'))
    assert.ok(!message.includes('Conséquences possibles :'))
  })

  it('replie sur la catégorie quand le titre manque', () => {
    assert.match(buildDiagnosticMessage(finding({ title: '' })), /^Injection/)
  })
})
