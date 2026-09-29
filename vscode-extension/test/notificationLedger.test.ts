/**
 * Tests de la déduplication des notifications.
 *
 * Ce sont ces règles qui décident si le développeur est interrompu :
 * elles se vérifient sans éditeur, sans minuteur réel et sans backend.
 * L'instant courant est toujours fourni par le test, jamais lu de
 * l'horloge.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import type { CodeFinding } from '../src/api/backendClient'
import { FR } from '../src/i18n/fr'
import {
  COOLDOWN_MS,
  GROUP_WINDOW_MS,
  NotificationLedger,
  fingerprint,
  leadOf,
  severityOf,
} from '../src/state/notificationLedger'

const SNIPPET = 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)'

function finding(overrides: Partial<CodeFinding> = {}): CodeFinding {
  return {
    finding_uid: 'uid-1',
    scan_uid: 'scan-1',
    rule_id: 'PY-SQLI-001',
    category: 'injection',
    category_label: 'Injection',
    cwe: 'CWE-89',
    owasp: 'A03:2021',
    severity: 'HIGH',
    severity_label: 'Élevée',
    risk_score: 70,
    risk_band: 'élevé',
    confidence: 0.9,
    source: 'rule',
    source_label: 'Règle déterministe',
    title: 'SQL Injection',
    explanation: '',
    why_dangerous: '',
    potential_impact: [],
    recommendations: [],
    risk_factors: [],
    location: {
      line_start: 10,
      line_end: 10,
      column_start: 0,
      column_end: 20,
      snippet: SNIPPET,
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

describe('fingerprint — ce qui identifie un problème', () => {
  it('est stable pour deux analyses du même code', () => {
    // Le scan renvoie un `finding_uid` neuf à chaque fois : l'empreinte,
    // elle, ne doit pas bouger.
    const first = finding({ finding_uid: 'uuid-a', scan_uid: 's1' })
    const second = finding({ finding_uid: 'uuid-b', scan_uid: 's2' })

    assert.equal(fingerprint(first), fingerprint(second))
  })

  it("ignore l'évaluation : gravité, score et confiance", () => {
    // C'est exactement ce que l'enrichissement IA modifie. S'il entrait
    // dans l'empreinte, chaque passage du modèle re-notifierait.
    const rule = finding({ severity: 'MEDIUM', risk_score: 45, confidence: 0.6 })
    const enriched = finding({
      severity: 'CRITICAL',
      risk_score: 95,
      confidence: 0.98,
      source: 'ia',
      source_label: 'Analyse IA',
    })

    assert.equal(fingerprint(rule), fingerprint(enriched))
  })

  it('change quand le fichier change', () => {
    assert.notEqual(
      fingerprint(finding()),
      fingerprint(finding({ file_path: 'src/autre.py' }))
    )
  })

  it('change quand la règle change', () => {
    assert.notEqual(
      fingerprint(finding()),
      fingerprint(finding({ rule_id: 'PY-CMDI-002' }))
    )
  })

  it('change quand la ligne se déplace', () => {
    assert.notEqual(
      fingerprint(finding()),
      fingerprint(
        finding({
          location: {
            line_start: 42,
            line_end: 42,
            column_start: 0,
            column_end: 20,
            snippet: SNIPPET,
          },
        })
      )
    )
  })

  it('change quand le code de la ligne est modifié', () => {
    assert.notEqual(
      fingerprint(finding()),
      fingerprint(
        finding({
          location: {
            line_start: 10,
            line_end: 10,
            column_start: 0,
            column_end: 20,
            snippet: 'cursor.execute("SELECT ...", (user_id,))',
          },
        })
      )
    )
  })

  it('ne confond pas deux découpages différents des mêmes champs', () => {
    // Sans préfixe de longueur, « ab | c » et « a | bc » se confondraient.
    const a = finding({ file_path: 'ab', rule_id: 'c' })
    const b = finding({ file_path: 'a', rule_id: 'bc' })

    assert.notEqual(fingerprint(a), fingerprint(b))
  })
})

describe('NotificationLedger — première annonce et répétitions', () => {
  it('annonce un problème inédit', () => {
    const ledger = new NotificationLedger()
    assert.equal(ledger.admit([finding()]).length, 1)
  })

  it('ne réannonce pas le même problème resauvegardé sans changement', () => {
    const ledger = new NotificationLedger()
    ledger.admit([finding({ finding_uid: 'uuid-a' })])

    // Nouvelle analyse, contenu identique : rien de neuf à signaler.
    const second = ledger.admit([finding({ finding_uid: 'uuid-b' })])

    assert.deepEqual(second, [])
  })

  it("reste muet quand l'IA confirme le diagnostic à l'identique", () => {
    const ledger = new NotificationLedger()
    ledger.admit([finding({ severity: 'HIGH' })])

    const sse = ledger.admit([
      finding({ severity: 'HIGH', source: 'ia', risk_score: 88 }),
    ])

    assert.deepEqual(sse, [])
  })

  it("reste muet quand l'IA revoit la gravité à la baisse", () => {
    const ledger = new NotificationLedger()
    ledger.admit([finding({ severity: 'HIGH' })])

    const sse = ledger.admit([finding({ severity: 'LOW', source: 'ia' })])

    assert.deepEqual(sse, [])
  })

  it("réannonce quand l'IA aggrave le diagnostic", () => {
    // Passer de MEDIUM à CRITICAL sur le même code est une information
    // neuve, pas une répétition.
    const ledger = new NotificationLedger()
    ledger.admit([finding({ severity: 'MEDIUM' })])

    const sse = ledger.admit([finding({ severity: 'CRITICAL', source: 'ia' })])

    assert.equal(sse.length, 1)
    assert.equal(sse[0]?.severity, 'CRITICAL')
  })

  it("n'aggrave qu'une fois : le palier atteint fait référence", () => {
    const ledger = new NotificationLedger()
    ledger.admit([finding({ severity: 'MEDIUM' })])
    ledger.admit([finding({ severity: 'CRITICAL' })])

    assert.deepEqual(ledger.admit([finding({ severity: 'CRITICAL' })]), [])
    assert.deepEqual(ledger.admit([finding({ severity: 'HIGH' })]), [])
  })

  it('annonce de nouveau un problème dont le code a changé', () => {
    const ledger = new NotificationLedger()
    ledger.admit([finding()])

    const moved = finding({
      location: {
        line_start: 12,
        line_end: 12,
        column_start: 0,
        column_end: 20,
        snippet: SNIPPET,
      },
    })

    assert.equal(ledger.admit([moved]).length, 1)
  })

  it("n'annonce jamais un finding corrigé ou écarté", () => {
    const ledger = new NotificationLedger()

    assert.deepEqual(ledger.admit([finding({ status: 'dismissed' })]), [])
    assert.deepEqual(ledger.admit([finding({ status: 'fixed' })]), [])
    assert.equal(ledger.size, 0)
  })

  it('ne retient pas deux fois le même problème dans un même lot', () => {
    // Cas du flux SSE qui répète un finding pendant la fenêtre de
    // regroupement : une seule entrée doit survivre.
    const ledger = new NotificationLedger()

    const admitted = ledger.admit([
      finding({ finding_uid: 'a' }),
      finding({ finding_uid: 'b' }),
    ])

    assert.equal(admitted.length, 1)
    assert.equal(ledger.size, 1)
  })

  it('distingue plusieurs problèmes d’un même fichier', () => {
    const ledger = new NotificationLedger()

    const admitted = ledger.admit([
      finding({ finding_uid: 'a', rule_id: 'PY-SQLI-001' }),
      finding({ finding_uid: 'b', rule_id: 'PY-SECRET-003' }),
    ])

    assert.equal(admitted.length, 2)
  })

  it('repart de zéro après un vidage de la vue', () => {
    const ledger = new NotificationLedger()
    ledger.admit([finding()])
    ledger.reset()

    assert.equal(ledger.size, 0)
    assert.equal(ledger.admit([finding()]).length, 1)
  })
})

describe('NotificationLedger — cadence', () => {
  it('regroupe une rafale avant le premier affichage', () => {
    const ledger = new NotificationLedger()
    assert.equal(ledger.delay(1_000_000), GROUP_WINDOW_MS)
  })

  it('impose le délai minimal après une bulle récente', () => {
    const ledger = new NotificationLedger()
    const now = 1_000_000
    ledger.markShown(now)

    // Immédiatement après : il faut attendre le cooldown entier.
    assert.equal(ledger.delay(now), COOLDOWN_MS)
    // À mi-parcours : le reste du cooldown.
    assert.equal(ledger.delay(now + COOLDOWN_MS / 2), COOLDOWN_MS / 2)
  })

  it('retombe à la fenêtre de regroupement une fois le délai écoulé', () => {
    const ledger = new NotificationLedger()
    const now = 1_000_000
    ledger.markShown(now)

    assert.equal(ledger.delay(now + COOLDOWN_MS), GROUP_WINDOW_MS)
    assert.equal(ledger.delay(now + COOLDOWN_MS * 10), GROUP_WINDOW_MS)
  })

  it('ne rend jamais un délai négatif', () => {
    const ledger = new NotificationLedger()
    ledger.markShown(0)
    assert.ok(ledger.delay(Number.MAX_SAFE_INTEGER) >= GROUP_WINDOW_MS)
  })
})

describe('leadOf — le problème que la bulle nomme', () => {
  it('retient le plus grave du lot', () => {
    const lead = leadOf([
      finding({ finding_uid: 'a', severity: 'LOW' }),
      finding({ finding_uid: 'b', severity: 'CRITICAL' }),
      finding({ finding_uid: 'c', severity: 'MEDIUM' }),
    ])

    assert.equal(lead?.finding_uid, 'b')
  })

  it('départage par le score du backend à gravité égale', () => {
    const lead = leadOf([
      finding({ finding_uid: 'a', severity: 'HIGH', risk_score: 60 }),
      finding({ finding_uid: 'b', severity: 'HIGH', risk_score: 85 }),
    ])

    assert.equal(lead?.finding_uid, 'b')
  })

  it('rend undefined sur un lot vide', () => {
    assert.equal(leadOf([]), undefined)
  })

  it('traite une gravité inconnue comme LOW', () => {
    assert.equal(severityOf(finding({ severity: 'UNKNOWN' as never })), 'LOW')
  })
})

describe('Corps de la notification', () => {
  it('contient les quatre éléments imposés', () => {
    const message = FR.notify.body('HIGH', 'SQL Injection', 'users.py', 10, 0)

    assert.match(message, /Security vulnerability detected/)
    assert.match(message, /^SQL Injection$/m)
    assert.match(message, /^users\.py:10$/m)
    assert.match(message, /^Severity: HIGH$/m)
  })

  it('ne mentionne aucun score', () => {
    // « Ne pas afficher de score fictif » : le plus simple est de n'en
    // afficher aucun.
    const message = FR.notify.body('CRITICAL', 'Hardcoded Secret', 'config.py', 22, 0)
    assert.ok(!/\/100|score/i.test(message))
  })

  it('marque visuellement HIGH et CRITICAL', () => {
    // L'API ne distingue pas MEDIUM de HIGH : les deux sont des
    // avertissements. Le marqueur de tête fait la différence.
    const low = FR.notify.body('LOW', 't', 'f.py', 1, 0)
    const medium = FR.notify.body('MEDIUM', 't', 'f.py', 1, 0)
    const high = FR.notify.body('HIGH', 't', 'f.py', 1, 0)
    const critical = FR.notify.body('CRITICAL', 't', 'f.py', 1, 0)

    assert.ok(low.startsWith('Security'))
    assert.ok(medium.startsWith('Security'))
    assert.ok(!high.startsWith('Security'))
    assert.ok(!critical.startsWith('Security'))
    assert.notEqual(high[0], critical[0])
  })

  it('compte les autres problèmes du lot, sans les inventer', () => {
    assert.ok(!/autre/.test(FR.notify.body('LOW', 't', 'f.py', 1, 0)))
    assert.match(FR.notify.body('LOW', 't', 'f.py', 1, 1), /\+ 1 autre /)
    assert.match(FR.notify.body('LOW', 't', 'f.py', 1, 4), /\+ 4 autres /)
  })

  it('nomme les deux actions attendues', () => {
    assert.equal(FR.notify.viewIssue, 'View Issue')
    assert.equal(FR.notify.analyzeWithAi, 'Analyze with AI')
  })
})
