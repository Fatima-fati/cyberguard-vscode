/**
 * Tests du registre alimentant la vue « Security ».
 *
 * Aucune dépendance à `vscode` : ce que l'on vérifie ici, c'est le
 * comportement du modèle — compteurs, regroupement, ordre, et surtout le
 * refus des findings qui ne concernent pas ce workspace.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import type { CodeFinding } from '../src/api/backendClient'
import { FindingsStore, latestScanPerFile } from '../src/state/findingsStore'

/** Finding minimal conforme au contrat backend. */
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
    risk_score: 90,
    risk_band: 'critique',
    confidence: 0.9,
    source: 'rule',
    source_label: 'Règle déterministe',
    title: 'SQL Injection',
    explanation: '',
    why_dangerous: '',
    potential_impact: [],
    recommendations: [],
    risk_factors: [],
    location: { line_start: 10, line_end: 10, column_start: 0, column_end: 20, snippet: '' },
    file_path: 'users.py',
    fix_available: false,
    fix_summary: '',
    status: 'open',
    status_label: 'Ouvert',
    created_at: '2026-01-01T00:00:00Z',
    ...overrides,
  }
}

describe('FindingsStore — compteurs', () => {
  it('compte par gravité et donne un total', () => {
    const store = new FindingsStore()
    store.merge([
      finding({ finding_uid: 'a', severity: 'CRITICAL' }),
      finding({ finding_uid: 'b', severity: 'HIGH' }),
      finding({ finding_uid: 'c', severity: 'HIGH' }),
      finding({ finding_uid: 'd', severity: 'MEDIUM' }),
      finding({ finding_uid: 'e', severity: 'LOW' }),
    ])

    assert.deepEqual(store.overview(), {
      critical: 1,
      high: 2,
      medium: 1,
      low: 1,
      total: 5,
    })
  })

  it('exclut les findings corrigés ou écartés', () => {
    const store = new FindingsStore()
    store.merge([
      finding({ finding_uid: 'a', severity: 'CRITICAL' }),
      finding({ finding_uid: 'b', severity: 'HIGH', status: 'dismissed' }),
      finding({ finding_uid: 'c', severity: 'HIGH', status: 'fixed' }),
    ])

    assert.deepEqual(store.overview(), {
      critical: 1,
      high: 0,
      medium: 0,
      low: 0,
      total: 1,
    })
    assert.equal(store.all().length, 1)
    // Écarté n'est pas oublié : la fiche reste consultable.
    assert.ok(store.get('b'))
  })

  it('remet les compteurs à zéro sur une vue vide', () => {
    const store = new FindingsStore()
    assert.deepEqual(store.overview(), {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      total: 0,
    })
    assert.deepEqual(store.grouped(), [])
  })
})

describe('FindingsStore — regroupement et ordre', () => {
  it('regroupe par gravité, du plus grave au moins grave', () => {
    const store = new FindingsStore()
    store.merge([
      finding({ finding_uid: 'a', severity: 'LOW' }),
      finding({ finding_uid: 'b', severity: 'CRITICAL' }),
      finding({ finding_uid: 'c', severity: 'MEDIUM' }),
      finding({ finding_uid: 'd', severity: 'HIGH' }),
    ])

    assert.deepEqual(
      store.grouped().map((group) => group.severity),
      ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    )
  })

  it('omet les gravités sans finding', () => {
    const store = new FindingsStore()
    store.merge([finding({ finding_uid: 'a', severity: 'MEDIUM' })])

    assert.deepEqual(
      store.grouped().map((group) => group.severity),
      ['MEDIUM']
    )
  })

  it('classe par score décroissant à gravité égale, puis fichier et ligne', () => {
    const store = new FindingsStore()
    store.merge([
      finding({ finding_uid: 'a', severity: 'HIGH', risk_score: 60, file_path: 'b.py' }),
      finding({ finding_uid: 'b', severity: 'HIGH', risk_score: 80, file_path: 'z.py' }),
      finding({
        finding_uid: 'c',
        severity: 'HIGH',
        risk_score: 60,
        file_path: 'a.py',
        location: {
          line_start: 5,
          line_end: 5,
          column_start: 0,
          column_end: 1,
          snippet: '',
        },
      }),
    ])

    assert.deepEqual(
      store.all().map((item) => item.finding_uid),
      ['b', 'c', 'a']
    )
  })
})

describe('FindingsStore — mise à jour', () => {
  it("remplace les findings d'un fichier plutôt que de les cumuler", () => {
    const store = new FindingsStore()
    store.replaceFile('users.py', [
      finding({ finding_uid: 'a' }),
      finding({ finding_uid: 'b', severity: 'LOW' }),
    ])
    assert.equal(store.overview().total, 2)

    // Deuxième scan : un seul problème subsiste.
    store.replaceFile('users.py', [finding({ finding_uid: 'a' })])
    assert.equal(store.overview().total, 1)
    assert.equal(store.get('b'), undefined)
  })

  it('ne touche pas aux autres fichiers', () => {
    const store = new FindingsStore()
    store.replaceFile('users.py', [finding({ finding_uid: 'a', file_path: 'users.py' })])
    store.replaceFile('config.py', [finding({ finding_uid: 'b', file_path: 'config.py' })])

    store.replaceFile('users.py', [])

    assert.deepEqual(store.files(), ['config.py'])
    assert.equal(store.overview().total, 1)
  })

  it('compte les findings encore inconnus lors d’une fusion', () => {
    const store = new FindingsStore()
    assert.equal(store.merge([finding({ finding_uid: 'a' })]), 1)
    // Le même identifiant est une mise à jour, pas un ajout.
    assert.equal(store.merge([finding({ finding_uid: 'a', risk_score: 95 })]), 0)
    assert.equal(store.get('a')?.risk_score, 95)
  })

  it('vide la vue sans perdre la capacité à en reconstruire une', () => {
    const store = new FindingsStore()
    store.merge([finding({ finding_uid: 'a' })])
    store.clear()

    assert.equal(store.overview().total, 0)
    assert.equal(store.get('a'), undefined)

    store.merge([finding({ finding_uid: 'a' })])
    assert.equal(store.overview().total, 1)
  })

  it('oublie un fichier à la demande', () => {
    const store = new FindingsStore()
    store.merge([
      finding({ finding_uid: 'a', file_path: 'users.py' }),
      finding({ finding_uid: 'b', file_path: 'config.py' }),
    ])

    store.removeFile('users.py')

    assert.deepEqual(store.files(), ['config.py'])
  })
})

describe('FindingsStore — événements SSE', () => {
  it('accepte la version enrichie d’un finding déjà connu', () => {
    const store = new FindingsStore()
    store.replaceFile('users.py', [finding({ finding_uid: 'a', risk_score: 70 })])

    const accepted = store.upsertIfTracked(
      finding({ finding_uid: 'a', risk_score: 95, source: 'ia', source_label: 'Analyse IA' })
    )

    assert.equal(accepted, true)
    assert.equal(store.get('a')?.risk_score, 95)
    assert.equal(store.get('a')?.source, 'ia')
    // Une mise à jour, pas un doublon.
    assert.equal(store.overview().total, 1)
  })

  it('accepte un finding inédit sur un fichier déjà analysé ici', () => {
    const store = new FindingsStore()
    store.replaceFile('users.py', [finding({ finding_uid: 'a', file_path: 'users.py' })])

    const accepted = store.upsertIfTracked(
      finding({ finding_uid: 'ia-1', file_path: 'users.py', source: 'ia' })
    )

    assert.equal(accepted, true)
    assert.equal(store.overview().total, 2)
  })

  it("refuse un finding portant sur un fichier jamais analysé ici", () => {
    // Le flux /api/stream est partagé avec l'interface web : la vue ne
    // doit jamais afficher le code d'un autre poste.
    const store = new FindingsStore()
    store.replaceFile('users.py', [finding({ finding_uid: 'a', file_path: 'users.py' })])

    const accepted = store.upsertIfTracked(
      finding({ finding_uid: 'etranger', file_path: '/autre/projet/app.py' })
    )

    assert.equal(accepted, false)
    assert.equal(store.overview().total, 1)
    assert.equal(store.get('etranger'), undefined)
  })

  it('retire de la vue un finding écarté par l’IA', () => {
    const store = new FindingsStore()
    store.replaceFile('users.py', [finding({ finding_uid: 'a' })])

    store.upsertIfTracked(
      finding({ finding_uid: 'a', status: 'dismissed', status_label: 'Écarté' })
    )

    assert.equal(store.overview().total, 0)
    assert.equal(store.all().length, 0)
  })

  it('ignore une charge utile sans identifiant', () => {
    const store = new FindingsStore()
    assert.equal(store.upsertIfTracked({} as CodeFinding), false)
    assert.equal(store.overview().total, 0)
  })
})

describe('FindingsStore — abonnements', () => {
  it('prévient les abonnés à chaque changement', () => {
    const store = new FindingsStore()
    let calls = 0
    store.onChange(() => {
      calls += 1
    })

    store.merge([finding({ finding_uid: 'a' })])
    store.upsert(finding({ finding_uid: 'b' }))
    store.clear()

    assert.equal(calls, 3)
  })

  it('ne prévient pas pour un vidage déjà vide', () => {
    const store = new FindingsStore()
    let calls = 0
    store.onChange(() => {
      calls += 1
    })

    store.clear()

    assert.equal(calls, 0)
  })

  it('cesse de prévenir après désabonnement', () => {
    const store = new FindingsStore()
    let calls = 0
    const unsubscribe = store.onChange(() => {
      calls += 1
    })

    store.merge([finding({ finding_uid: 'a' })])
    unsubscribe()
    store.merge([finding({ finding_uid: 'b' })])

    assert.equal(calls, 1)
  })

  it('continue de prévenir les autres abonnés si l’un échoue', () => {
    const store = new FindingsStore()
    let reached = false
    store.onChange(() => {
      throw new Error('abonné défaillant')
    })
    store.onChange(() => {
      reached = true
    })

    store.merge([finding({ finding_uid: 'a' })])

    assert.equal(reached, true)
  })
})

describe('latestScanPerFile — dédoublonnage de l’historique', () => {
  it('ne garde que la dernière analyse d’un fichier', () => {
    // `GET /api/code/findings` rend l'historique : le même fichier y
    // figure une fois par analyse, et les findings anciens restent
    // « open » tant que personne ne s'est prononcé.
    const kept = latestScanPerFile([
      finding({
        finding_uid: 'vieux',
        scan_uid: 'scan-1',
        created_at: '2026-01-01T10:00:00Z',
      }),
      finding({
        finding_uid: 'recent',
        scan_uid: 'scan-2',
        created_at: '2026-01-02T10:00:00Z',
      }),
    ])

    assert.deepEqual(
      kept.map((item) => item.finding_uid),
      ['recent']
    )
  })

  it('garde tous les findings de la dernière analyse', () => {
    const kept = latestScanPerFile([
      finding({ finding_uid: 'a', scan_uid: 's1', created_at: '2026-01-01T10:00:00Z' }),
      finding({ finding_uid: 'b', scan_uid: 's2', created_at: '2026-01-02T10:00:00Z' }),
      finding({ finding_uid: 'c', scan_uid: 's2', created_at: '2026-01-02T10:00:00Z' }),
    ])

    assert.deepEqual(
      kept.map((item) => item.finding_uid).sort(),
      ['b', 'c']
    )
  })

  it('traite chaque fichier indépendamment', () => {
    const kept = latestScanPerFile([
      finding({
        finding_uid: 'u1',
        file_path: 'users.py',
        scan_uid: 's1',
        created_at: '2026-01-01T10:00:00Z',
      }),
      finding({
        finding_uid: 'u2',
        file_path: 'users.py',
        scan_uid: 's2',
        created_at: '2026-01-05T10:00:00Z',
      }),
      finding({
        finding_uid: 'c1',
        file_path: 'config.py',
        scan_uid: 's3',
        created_at: '2026-01-02T10:00:00Z',
      }),
    ])

    assert.deepEqual(
      kept.map((item) => item.finding_uid).sort(),
      ['c1', 'u2']
    )
  })

  it('supporte un ordre d’arrivée quelconque', () => {
    // La route renvoie l'historique trié par date décroissante ; on ne
    // s'appuie pas dessus.
    const recent = finding({
      finding_uid: 'recent',
      scan_uid: 's2',
      created_at: '2026-01-02T10:00:00Z',
    })
    const old = finding({
      finding_uid: 'vieux',
      scan_uid: 's1',
      created_at: '2026-01-01T10:00:00Z',
    })

    assert.deepEqual(
      latestScanPerFile([recent, old]).map((item) => item.finding_uid),
      ['recent']
    )
    assert.deepEqual(
      latestScanPerFile([old, recent]).map((item) => item.finding_uid),
      ['recent']
    )
  })

  it('rend une liste vide pour une entrée vide', () => {
    assert.deepEqual(latestScanPerFile([]), [])
  })

  it('empêche les doublons à la reprise dans le store', () => {
    // Bout à bout : sans le filtre, le même problème apparaîtrait deux
    // fois dans la vue Security.
    const history = [
      finding({
        finding_uid: 'vieux',
        scan_uid: 's1',
        created_at: '2026-01-01T10:00:00Z',
      }),
      finding({
        finding_uid: 'recent',
        scan_uid: 's2',
        created_at: '2026-01-02T10:00:00Z',
      }),
    ]

    const store = new FindingsStore()
    store.merge(latestScanPerFile(history))

    assert.equal(store.overview().total, 1)
  })
})
