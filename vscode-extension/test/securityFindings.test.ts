/**
 * Tests de l'unification des findings dans la vue « Security ».
 *
 * Trois garanties vérifiées ici :
 *
 *     COHABITATION   un secret repéré dans `config.py` et un finding
 *                    d'analyse du même fichier vivent dans le même
 *                    registre sans s'effacer l'un l'autre
 *     ISOLATION      une analyse de fichier ne fait pas disparaître un
 *                    signalement de sécurité projet, et réciproquement
 *     EXPURGATION    ce que la vue affiche d'un secret reste une preuve
 *                    masquée, jamais la valeur
 *
 * La deuxième garantie est celle qui se casserait le plus silencieusement :
 * `replaceFile` efface par chemin, et un secret porte un chemin lui aussi.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import type { CodeFinding } from '../src/api/backendClient'
import {
  isProjectFinding,
  toViewFinding,
  toViewFindings,
} from '../src/security/findingAdapter'
import { FindingsStore } from '../src/state/findingsStore'
import type { SecurityFinding } from '../src/security/securityTypes'

// --------------------------------------------------------------------------
// Fabriques
// --------------------------------------------------------------------------

function securityFinding(
  overrides: Partial<SecurityFinding> = {}
): SecurityFinding {
  return {
    id: 'sec-1',
    project_uid: 'proj-a',
    category: 'SECRET',
    severity: 'CRITICAL',
    severity_label: 'CRITIQUE',
    confidence: 'HIGH',
    confidence_label: 'ÉLEVÉE',
    category_label: 'Secret exposé',
    title: "Clé d'API OpenAI écrite en dur",
    description: 'Une clé apparaît dans le code source.',
    file: 'backend/config.py',
    line_start: 24,
    line_end: 24,
    evidence: 'OpenAI API key detected: sk-proj-********',
    remediation: 'Révoquez immédiatement cette clé.',
    references: ['CWE-798'],
    detection_engine: 'secret-scanner',
    status: 'open',
    status_label: 'Ouvert',
    created_at: '2026-09-28T10:00:00Z',
    ...overrides,
  }
}

/** Finding d'analyse de fichier : **sans** `detection_engine`. */
function codeFinding(overrides: Partial<CodeFinding> = {}): CodeFinding {
  return {
    finding_uid: 'code-1',
    scan_uid: 'scan-1',
    rule_id: 'py.sql_injection',
    category: 'sql_injection',
    category_label: 'SQL injection',
    cwe: 'CWE-89',
    owasp: null,
    severity: 'HIGH',
    severity_label: 'ÉLEVÉE',
    risk_score: 70,
    risk_band: 'HIGH',
    confidence: 0.8,
    source: 'rule',
    source_label: 'Règle de détection',
    title: 'Requête SQL construite par concaténation',
    explanation: '',
    why_dangerous: '',
    potential_impact: [],
    recommendations: [],
    risk_factors: [],
    location: { line_start: 10, line_end: 10, column_start: 0, column_end: 0, snippet: '' },
    file_path: 'backend/config.py',
    fix_available: false,
    fix_summary: '',
    status: 'open',
    status_label: 'Ouvert',
    created_at: '2026-09-28T11:00:00Z',
    ...overrides,
  }
}

// --------------------------------------------------------------------------
// Adaptation
// --------------------------------------------------------------------------

describe('findings de sécurité — projection sur la vue', () => {
  it('conserve l’essentiel sans rien inventer', () => {
    const view = toViewFinding(securityFinding())

    assert.equal(view.finding_uid, 'sec-1')
    assert.equal(view.severity, 'CRITICAL')
    assert.equal(view.title, "Clé d'API OpenAI écrite en dur")
    assert.equal(view.file_path, 'backend/config.py')
    assert.equal(view.location.line_start, 24)
    assert.equal(view.cwe, 'CWE-798')
    // La recommandation du backend devient la recommandation affichée :
    // l'extension ne rédige pas la sienne.
    assert.deepEqual(view.recommendations, ['Révoquez immédiatement cette clé.'])
  })

  it('n’expose que la preuve expurgée en guise d’extrait', () => {
    const view = toViewFinding(securityFinding())

    // L'extrait réel du fichier n'est pas disponible : il n'a jamais
    // quitté le moteur de détection. C'est une limite voulue — un extrait
    // afficherait le secret dans la fenêtre de détail.
    assert.equal(view.location.snippet, 'OpenAI API key detected: sk-proj-********')
    assert.ok(view.location.snippet.includes('********'))
  })

  it('ne propose jamais de correction automatique pour un secret', () => {
    // Retirer une clé du code demande de la révoquer d'abord : aucune
    // correction mécanique ne peut faire ce travail-là.
    assert.equal(toViewFinding(securityFinding()).fix_available, false)
  })

  it('marque l’origine, ce qui distingue les deux familles', () => {
    assert.equal(isProjectFinding(toViewFinding(securityFinding())), true)
    assert.equal(isProjectFinding(codeFinding()), false)
  })

  it('projette une dépendance vulnérable comme un finding de la vue', () => {
    const view = toViewFinding(
      securityFinding({
        id: 'dep-1',
        category: 'DEPENDENCY',
        category_label: 'Dépendance vulnérable',
        title: 'express 4.17.1 — GHSA-xxxx',
        file: 'package.json',
        line_start: 0,
        line_end: 0,
        detection_engine: 'osv',
        severity: 'HIGH',
      })
    )

    assert.equal(view.category, 'vulnerable_dependency')
    assert.equal(view.file_path, 'package.json')
    // Le backend ne donne pas de ligne pour une dépendance : la vue
    // retient 1 plutôt que 0, qui n'est pas une ligne valide.
    assert.equal(view.location.line_start, 1)
    assert.equal(view.source_label, 'osv')
  })

  it('écarte une entrée sans identifiant plutôt que de l’afficher de travers', () => {
    const findings = toViewFindings([
      securityFinding(),
      securityFinding({ id: '' }),
    ])
    assert.equal(findings.length, 1)
  })
})

// --------------------------------------------------------------------------
// Cohabitation dans le registre
// --------------------------------------------------------------------------

describe('registre — cohabitation des deux familles', () => {
  it('une analyse de fichier n’efface pas le secret repéré dans ce fichier', () => {
    const store = new FindingsStore()

    store.replaceProjectFindings(toViewFindings([securityFinding()]))
    assert.equal(store.all().length, 1)

    // Le fichier est analysé : ses findings de code sont remplacés. Le
    // secret, lui, décrit le même fichier mais vient d'un autre moteur et
    // n'a pas été réexaminé. L'effacer ferait disparaître un signalement
    // que personne n'a corrigé.
    store.replaceFile('backend/config.py', [codeFinding()])

    const uids = store.all().map((finding) => finding.finding_uid).sort()
    assert.deepEqual(uids, ['code-1', 'sec-1'])
  })

  it('un nouveau balayage de projet n’efface pas les findings d’analyse', () => {
    const store = new FindingsStore()

    store.replaceFile('backend/config.py', [codeFinding()])
    store.replaceProjectFindings(toViewFindings([securityFinding()]))
    store.replaceProjectFindings(
      toViewFindings([securityFinding({ id: 'sec-2', line_start: 30 })])
    )

    const uids = store.all().map((finding) => finding.finding_uid).sort()
    // Le secret précédent a disparu — il n'était plus dans le lot —, le
    // finding d'analyse est intact.
    assert.deepEqual(uids, ['code-1', 'sec-2'])
  })

  it('fermer un fichier ne fait pas disparaître son secret', () => {
    const store = new FindingsStore()

    store.replaceProjectFindings(toViewFindings([securityFinding()]))
    store.replaceFile('backend/config.py', [codeFinding()])

    // `removeFile` suit la fermeture d'un onglet. Fermer un onglet ne
    // corrige pas un secret.
    store.removeFile('backend/config.py')

    const uids = store.all().map((finding) => finding.finding_uid)
    assert.deepEqual(uids, ['sec-1'])
  })

  it('un balayage sans résultat retire les secrets précédents', () => {
    const store = new FindingsStore()

    store.replaceProjectFindings(toViewFindings([securityFinding()]))
    store.replaceProjectFindings([])

    // Le secret a été corrigé entre deux balayages : le laisser affiché
    // serait faux.
    assert.equal(store.projectFindings().length, 0)
  })

  it('« Clear Findings » vide les deux familles', () => {
    const store = new FindingsStore()

    store.replaceFile('backend/config.py', [codeFinding()])
    store.replaceProjectFindings(toViewFindings([securityFinding()]))
    store.clear()

    assert.equal(store.all().length, 0)
  })
})

// --------------------------------------------------------------------------
// Comptage et tri
// --------------------------------------------------------------------------

describe('registre — comptage et tri unifiés', () => {
  it('les deux familles alimentent les mêmes compteurs', () => {
    const store = new FindingsStore()

    store.replaceProjectFindings(
      toViewFindings([
        securityFinding({ id: 's1', severity: 'CRITICAL' }),
        securityFinding({
          id: 'd1',
          category: 'DEPENDENCY',
          severity: 'HIGH',
          file: 'package.json',
          detection_engine: 'osv',
        }),
      ])
    )
    store.replaceFile('backend/app.py', [
      codeFinding({ finding_uid: 'c1', file_path: 'backend/app.py' }),
    ])

    const overview = store.overview()
    assert.equal(overview.critical, 1)
    assert.equal(overview.high, 2)
    assert.equal(overview.total, 3)
  })

  it('le regroupement par gravité mélange les familles, comme la vue l’attend', () => {
    const store = new FindingsStore()

    store.replaceProjectFindings(
      toViewFindings([
        securityFinding({ id: 's1', severity: 'CRITICAL' }),
        securityFinding({
          id: 'd1',
          category: 'DEPENDENCY',
          severity: 'CRITICAL',
          title: 'lodash 4.17.20 — CVE-0000',
          file: 'package.json',
          detection_engine: 'osv',
        }),
      ])
    )

    const groups = store.grouped()
    const critical = groups.find((group) => group.severity === 'CRITICAL')

    // Exactement la forme demandée : Critical (2) contenant un secret et
    // une dépendance vulnérable.
    assert.equal(critical?.findings.length, 2)
  })

  it('expose les findings de sécurité projet séparément quand c’est utile', () => {
    const store = new FindingsStore()

    store.replaceFile('backend/app.py', [
      codeFinding({ finding_uid: 'c1', file_path: 'backend/app.py' }),
    ])
    store.replaceProjectFindings(toViewFindings([securityFinding()]))

    assert.deepEqual(
      store.projectFindings().map((finding) => finding.finding_uid),
      ['sec-1']
    )
  })
})

// --------------------------------------------------------------------------
// Isolation entre projets
// --------------------------------------------------------------------------

describe('registre — isolation entre projets', () => {
  it('changer de projet remplace les findings sans en mélanger deux', () => {
    const store = new FindingsStore()

    store.replaceProjectFindings(
      toViewFindings([securityFinding({ id: 'a1', project_uid: 'proj-a' })])
    )
    // Ouvrir un autre dossier : le balayage du nouveau projet remplace
    // l'intégralité des findings de sécurité. Deux projets partageant
    // `config.py` ne doivent jamais se mélanger dans la vue.
    store.replaceProjectFindings(
      toViewFindings([securityFinding({ id: 'b1', project_uid: 'proj-b' })])
    )

    assert.deepEqual(
      store.projectFindings().map((finding) => finding.finding_uid),
      ['b1']
    )
  })

  it('aucune valeur de secret n’atteint la vue, quelle que soit la famille', () => {
    const store = new FindingsStore()

    store.replaceProjectFindings(
      toViewFindings([
        securityFinding(),
        securityFinding({
          id: 'd1',
          category: 'DEPENDENCY',
          evidence: 'npm · express@4.17.1 déclarée dans package.json',
          detection_engine: 'osv',
        }),
      ])
    )

    const serialized = JSON.stringify(store.all())
    // La forme complète d'une clé OpenAI ne doit apparaître nulle part :
    // ni dans le titre, ni dans l'extrait, ni dans une recommandation.
    assert.ok(!/sk-proj-[A-Za-z0-9]{10,}/.test(serialized))
  })
})
