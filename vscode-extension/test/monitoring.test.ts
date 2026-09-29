/**
 * Tests de l'analyse incrémentale et de son intégration.
 *
 * Quatre questions, et ce sont celles qui décident si la phase 3 tient :
 *
 *     INCRÉMENTAL   un fichier modifié remplace **sa** contribution, et
 *                   le lot soumis reste complet — sinon le backend
 *                   effacerait les constats de tous les autres fichiers
 *     SILENCE       une sauvegarde qui ne change rien ne produit rien :
 *                   ni soumission, ni bulle
 *     CLOISONNEMENT le registre décrit **un** projet, et ne survit pas au
 *                   changement de dossier ouvert
 *     RÉGRESSION    les accumulateurs de la phase 2 rendent exactement ce
 *                   qu'ils rendaient avant
 *
 * La première est la plus facile à casser en silence : la réconciliation
 * du backend supprime ce qui ne lui est pas resoumis, et un registre
 * incomplet ne se voit pas — jusqu'au jour où un secret disparaît de la
 * vue sans avoir été corrigé.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import Module from 'node:module'

import type { CodeFinding } from '../src/api/backendClient'
import { toViewFindings } from '../src/security/findingAdapter'
import { FindingsStore } from '../src/state/findingsStore'
import { NotificationLedger } from '../src/state/notificationLedger'
import { SecretScanAccumulator } from '../src/security/secretScanner'
import { DependencyInventoryAccumulator } from '../src/security/dependencyInventory'
import { SecurityBaseline } from '../src/monitor/securityBaseline'
import { ApiScanAccumulator } from '../src/apisec/apiScanner'
import type {
  ApiFindingSubmission,
  DependencyRecord,
  SecretFindingSubmission,
  SecurityFinding,
} from '../src/security/securityTypes'

// --------------------------------------------------------------------------
// Fabriques
// --------------------------------------------------------------------------

function secret(
  overrides: Partial<SecretFindingSubmission> = {}
): SecretFindingSubmission {
  return {
    rule_id: 'openai-api-key',
    file_path: 'src/config.py',
    line: 12,
    column: 10,
    secret_type: 'openai_api_key',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    // Déjà expurgée par le moteur : c'est la seule forme qui circule.
    evidence_redacted: 'sk-proj-********',
    title: "Clé d'API OpenAI écrite en dur",
    description: 'Une clé apparaît dans le code source.',
    remediation: 'Révoquez cette clé.',
    references: ['CWE-798'],
    ...overrides,
  }
}

function dependency(overrides: Partial<DependencyRecord> = {}): DependencyRecord {
  return {
    name: 'express',
    ecosystem: 'npm',
    version: '4.17.1',
    direct: true,
    manifest: 'package.json',
    source: 'manifest',
    ...overrides,
  }
}

function securityFinding(overrides: Partial<SecurityFinding> = {}): SecurityFinding {
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
    file: 'src/config.py',
    line_start: 12,
    line_end: 12,
    evidence: 'sk-proj-********',
    remediation: 'Révoquez cette clé.',
    references: ['CWE-798'],
    detection_engine: 'secret-scanner',
    status: 'open',
    status_label: 'Ouvert',
    created_at: '2026-09-28T10:00:00Z',
    ...overrides,
  }
}

/** Registre amorcé comme le ferait une découverte complète. */
function established(): SecurityBaseline {
  const baseline = new SecurityBaseline()
  baseline.adopt({
    scannedPaths: new Set(['src/config.py', 'src/app.py', 'README.md']),
    secretsByFile: new Map([['src/config.py', [secret()]]]),
    dependenciesByManifest: new Map([['package.json', [dependency()]]]),
    apiByFile: new Map(),
    endpointsDetected: 0,
    skippedFiles: 4,
    truncated: false,
  })
  return baseline
}

// --------------------------------------------------------------------------
// Analyse incrémentale : secrets
// --------------------------------------------------------------------------

describe('SecurityBaseline — analyse incrémentale d’un secret', () => {
  it('refuse de soumettre tant qu’aucun parcours n’a eu lieu', () => {
    const baseline = new SecurityBaseline()

    // Un lot reconstitué depuis un registre vide annoncerait « ce projet
    // n'a plus aucun secret », et la réconciliation du backend
    // supprimerait tout ce qu'il savait.
    assert.equal(baseline.isEstablished, false)
    assert.equal(established().isEstablished, true)
  })

  it('remplace la contribution d’un seul fichier sans toucher aux autres', () => {
    const baseline = established()
    baseline.setFileSecrets('src/other.py', [
      secret({ file_path: 'src/other.py', line: 3, rule_id: 'aws-access-key' }),
    ])

    const scan = baseline.secretScan()
    const paths = scan.findings.map((finding) => finding.file_path).sort()

    // Le lot reste **complet** : le fichier d'origine est toujours là.
    assert.deepEqual(paths, ['src/config.py', 'src/other.py'])
  })

  it('fait disparaître un secret corrigé', () => {
    const baseline = established()

    const changed = baseline.setFileSecrets('src/config.py', [])
    assert.equal(changed, true, 'la correction est un changement d’état')

    const scan = baseline.secretScan()
    assert.equal(scan.findings.length, 0)
    // Le fichier reste suivi : il a bien été analysé, il ne porte plus rien.
    assert.equal(scan.scannedFiles, 3)
  })

  it('ne signale aucun changement quand les constats sont identiques', () => {
    const baseline = established()

    // Une sauvegarde qui ne touche pas la ligne fautive : le trajet
    // réseau serait pure perte, et le backend recevrait un lot qu'il a
    // déjà.
    assert.equal(baseline.setFileSecrets('src/config.py', [secret()]), false)
  })

  it('signale un changement quand le secret se déplace', () => {
    const baseline = established()

    // Même secret, autre ligne : l'empreinte backend changera, donc le
    // finding sera recréé. C'est un changement réel.
    assert.equal(baseline.setFileSecrets('src/config.py', [secret({ line: 40 })]), true)
  })

  it('compte un fichier neuf comme un changement, même sans constat', () => {
    const baseline = established()

    // Un fichier créé puis analysé sans rien trouver fait bouger
    // `scanned_files`, et donc les statistiques affichées.
    assert.equal(baseline.setFileSecrets('src/neuf.py', []), true)
    assert.equal(baseline.secretScan().scannedFiles, 4)
  })

  it('retire un fichier supprimé', () => {
    const baseline = established()

    assert.equal(baseline.removeFile('src/config.py'), true)
    assert.equal(baseline.secretScan().findings.length, 0)
    assert.equal(baseline.tracksFile('src/config.py'), false)
    // Une seconde suppression n'est plus un changement.
    assert.equal(baseline.removeFile('src/config.py'), false)
  })

  it('trie le lot par gravité, comme la découverte complète', () => {
    const baseline = established()
    baseline.setFileSecrets('a.py', [
      secret({ file_path: 'a.py', severity: 'LOW', secret_type: 'generic' }),
    ])
    baseline.setFileSecrets('b.py', [
      secret({ file_path: 'b.py', severity: 'HIGH', secret_type: 'aws' }),
    ])

    const severities = baseline.secretScan().findings.map((f) => f.severity)
    assert.deepEqual(severities, ['CRITICAL', 'HIGH', 'LOW'])
  })

  it('conserve les compteurs du parcours de référence', () => {
    const scan = established().secretScan()

    // `skipped_files` décrit ce que la découverte n'a pas lu — binaires,
    // fichiers sensibles. La surveillance ne le réinvente pas.
    assert.equal(scan.skippedFiles, 4)
    assert.equal(scan.truncated, false)
  })
})

// --------------------------------------------------------------------------
// Analyse incrémentale : dépendances
// --------------------------------------------------------------------------

describe('SecurityBaseline — analyse incrémentale d’un manifeste', () => {
  it('remplace les dépendances d’un manifeste sans perdre les autres', () => {
    const baseline = established()
    baseline.setManifest('backend/requirements.txt', [
      dependency({
        name: 'fastapi',
        ecosystem: 'pypi',
        version: '0.100.0',
        manifest: 'backend/requirements.txt',
      }),
    ])

    const inventory = baseline.inventory()
    assert.equal(inventory.manifestsRead, 2)
    assert.deepEqual(
      inventory.dependencies.map((item) => item.name).sort(),
      ['express', 'fastapi']
    )
  })

  it('détecte une dépendance ajoutée', () => {
    const baseline = established()

    const changed = baseline.setManifest('package.json', [
      dependency(),
      dependency({ name: 'lodash', version: '4.17.20' }),
    ])

    assert.equal(changed, true)
    assert.equal(baseline.inventory().dependencies.length, 2)
  })

  it('détecte une montée de version', () => {
    const baseline = established()

    assert.equal(
      baseline.setManifest('package.json', [dependency({ version: '4.21.0' })]),
      true
    )
  })

  it('ne signale rien quand le manifeste est réécrit à l’identique', () => {
    const baseline = established()

    // Un `npm install` qui ne change aucune version ne doit pas
    // réinterroger la base publique de vulnérabilités.
    assert.equal(baseline.setManifest('package.json', [dependency()]), false)
  })

  it('retire un manifeste supprimé', () => {
    const baseline = established()

    assert.equal(baseline.removeManifest('package.json'), true)
    assert.equal(baseline.inventory().dependencies.length, 0)
    assert.equal(baseline.inventory().manifestsRead, 0)
    assert.equal(baseline.removeManifest('package.json'), false)
  })
})

// --------------------------------------------------------------------------
// Analyse incrémentale : sécurité d'API (phase 5)
// --------------------------------------------------------------------------

describe('SecurityBaseline — analyse incrémentale d’API', () => {
  function apiFinding(
    overrides: Partial<ApiFindingSubmission> = {}
  ): ApiFindingSubmission {
    return {
      rule_id: 'API-AUTH-001',
      file_path: 'src/api.py',
      line: 10,
      issue_type: 'unauthenticated_endpoint',
      endpoint: '/items',
      http_method: 'POST',
      framework: 'fastapi',
      severity: 'HIGH',
      confidence: 'MEDIUM',
      evidence: '@app.post("/items")',
      title: 'Endpoint sans authentification apparente',
      description: '',
      remediation: '',
      references: ['CWE-306'],
      ...overrides,
    }
  }

  /** Registre amorcé avec une contribution d'API. */
  function withApi(): SecurityBaseline {
    const baseline = new SecurityBaseline()
    baseline.adopt({
      scannedPaths: new Set(['src/api.py', 'src/health.py']),
      secretsByFile: new Map(),
      dependenciesByManifest: new Map(),
      apiByFile: new Map([['src/api.py', [apiFinding()]]]),
      endpointsDetected: 2,
      skippedFiles: 0,
      truncated: false,
    })
    return baseline
  }

  it('remplace la contribution d’un seul fichier sans toucher aux autres', () => {
    const baseline = withApi()
    baseline.setFileApiFindings(
      'src/admin.py',
      [apiFinding({ file_path: 'src/admin.py', endpoint: '/admin/purge' })],
      1
    )

    const paths = baseline.apiScan().findings.map((f) => f.file_path).sort()
    // Le lot reste **complet** : la réconciliation du backend supprime ce
    // qui ne lui est pas resoumis.
    assert.deepEqual(paths, ['src/admin.py', 'src/api.py'])
  })

  it('ne signale aucun changement quand les constats sont identiques', () => {
    const baseline = withApi()

    // Une sauvegarde qui ne touche pas la route : le trajet réseau serait
    // pure perte, et le backend recevrait un lot qu'il a déjà.
    assert.equal(
      baseline.setFileApiFindings('src/api.py', [apiFinding()], 1),
      false
    )
  })

  it('signale un changement quand la route se déplace', () => {
    const baseline = withApi()

    assert.equal(
      baseline.setFileApiFindings('src/api.py', [apiFinding({ line: 42 })], 1),
      true
    )
  })

  it('fait disparaître un problème corrigé', () => {
    const baseline = withApi()

    assert.equal(baseline.setFileApiFindings('src/api.py', [], 1), true)
    assert.equal(baseline.apiScan().findings.length, 0)
  })

  it('retire un fichier supprimé', () => {
    const baseline = withApi()

    assert.equal(baseline.removeApiFile('src/api.py'), true)
    assert.equal(baseline.apiScan().findings.length, 0)
    assert.equal(baseline.removeApiFile('src/api.py'), false)
  })

  it('conserve le décompte de routes du parcours de référence', () => {
    // Ce chiffre dit la couverture. Le remettre à zéro parce qu'un seul
    // fichier a changé ferait afficher « aucune route reconnue » à un
    // projet qui en expose vingt.
    assert.equal(withApi().apiScan().endpointsDetected, 2)
  })

  it('oublie l’API au changement de dossier ouvert', () => {
    const baseline = withApi()
    baseline.clear()

    assert.equal(baseline.isEstablished, false)
    assert.equal(baseline.apiScan().findings.length, 0)
    assert.equal(baseline.apiScan().endpointsDetected, 0)
  })

  it('copie les collections adoptées plutôt que de les référencer', () => {
    const apiByFile = new Map([['src/api.py', [apiFinding()]]])
    const baseline = new SecurityBaseline()
    baseline.adopt({
      scannedPaths: new Set(['src/api.py']),
      secretsByFile: new Map(),
      dependenciesByManifest: new Map(),
      apiByFile,
      endpointsDetected: 1,
      skippedFiles: 0,
      truncated: false,
    })

    apiByFile.clear()
    assert.equal(baseline.apiScan().findings.length, 1)
  })

  it('un registre reconstitué depuis l’accumulateur rend le même lot', () => {
    const accumulator = new ApiScanAccumulator()
    accumulator.consider(
      'src/api.py',
      ['@app.post("/items")', 'async def create(i: Item): pass'].join('\n')
    )

    const detail = accumulator.perFile()
    const baseline = new SecurityBaseline()
    baseline.adopt({
      scannedPaths: detail.scannedPaths,
      secretsByFile: new Map(),
      dependenciesByManifest: new Map(),
      apiByFile: detail.apiByFile,
      endpointsDetected: detail.endpointsDetected,
      skippedFiles: 0,
      truncated: detail.truncated,
    })

    // Sans aucune modification, le premier lot reconstitué doit être
    // identique à celui qu'une découverte complète aurait soumis.
    const direct = accumulator.result()
    const reconstituted = baseline.apiScan()
    assert.equal(reconstituted.findings.length, direct.findings.length)
    assert.equal(reconstituted.endpointsDetected, direct.endpointsDetected)
    assert.deepEqual(
      reconstituted.findings.map((f) => `${f.file_path}:${f.line}:${f.rule_id}`),
      direct.findings.map((f) => `${f.file_path}:${f.line}:${f.rule_id}`)
    )
  })
})

// --------------------------------------------------------------------------
// Cloisonnement
// --------------------------------------------------------------------------

describe('SecurityBaseline — cloisonnement des projets', () => {
  it('oublie tout au changement de dossier ouvert', () => {
    const baseline = established()
    baseline.clear()

    // Conserver le registre ferait soumettre les constats du projet
    // précédent sous l'identifiant du suivant.
    assert.equal(baseline.isEstablished, false)
    assert.equal(baseline.trackedFiles, 0)
    assert.equal(baseline.trackedManifests, 0)
    assert.equal(baseline.secretScan().findings.length, 0)
  })

  it('remplace entièrement l’état lors d’une nouvelle adoption', () => {
    const baseline = established()

    baseline.adopt({
      scannedPaths: new Set(['autre/main.go']),
      secretsByFile: new Map(),
      dependenciesByManifest: new Map([['autre/go.mod', []]]),
      apiByFile: new Map(),
      endpointsDetected: 0,
      skippedFiles: 0,
      truncated: false,
    })

    assert.equal(baseline.tracksFile('src/config.py'), false)
    assert.equal(baseline.tracksManifest('package.json'), false)
    assert.equal(baseline.trackedFiles, 1)
  })

  it('copie les collections adoptées plutôt que de les référencer', () => {
    const secretsByFile = new Map([['src/config.py', [secret()]]])
    const baseline = new SecurityBaseline()
    baseline.adopt({
      scannedPaths: new Set(['src/config.py']),
      secretsByFile,
      dependenciesByManifest: new Map(),
      apiByFile: new Map(),
      endpointsDetected: 0,
      skippedFiles: 0,
      truncated: false,
    })

    // L'accumulateur d'origine est jetable ; le muter après coup ne doit
    // pas modifier le registre du surveillant.
    secretsByFile.clear()
    assert.equal(baseline.secretScan().findings.length, 1)
  })
})

// --------------------------------------------------------------------------
// Notifications
// --------------------------------------------------------------------------

describe('Surveillance — aucune bulle répétée à chaque sauvegarde', () => {
  /**
   * Le surveillant republie **tous** les findings du projet à chaque
   * cycle : c'est ce qui garantit qu'une soumission de secrets seule ne
   * fasse pas disparaître les dépendances vulnérables de la vue.
   *
   * La conséquence à vérifier : le registre de notifications doit taire
   * tout ce qu'il a déjà annoncé, sinon chaque sauvegarde rejouerait la
   * bulle de chaque finding du projet.
   */
  function cycle(ledger: NotificationLedger, findings: SecurityFinding[]): CodeFinding[] {
    return ledger.admit(toViewFindings(findings))
  }

  it('annonce un finding une fois, puis se tait', () => {
    const ledger = new NotificationLedger()
    const project = [securityFinding()]

    assert.equal(cycle(ledger, project).length, 1, 'première découverte')
    assert.equal(cycle(ledger, project).length, 0, 'deuxième sauvegarde')
    assert.equal(cycle(ledger, project).length, 0, 'dixième sauvegarde')
  })

  it('n’annonce que le nouveau finding d’un lot déjà connu', () => {
    const ledger = new NotificationLedger()
    const known = securityFinding()

    cycle(ledger, [known])

    const fresh = cycle(ledger, [
      known,
      securityFinding({
        id: 'sec-2',
        file: 'src/db.py',
        line_start: 7,
        line_end: 7,
        evidence: 'postgres://********',
        title: 'Identifiants de base de données en dur',
      }),
    ])

    assert.equal(fresh.length, 1)
    assert.equal(fresh[0]?.file_path, 'src/db.py')
  })

  it('réannonce un problème dont la gravité augmente', () => {
    const ledger = new NotificationLedger()
    const medium = securityFinding({ severity: 'MEDIUM', severity_label: 'Moyenne' })

    cycle(ledger, [medium])

    // Même fichier, même ligne, même moteur : c'est le même problème,
    // mais requalifié plus haut. C'est une information neuve.
    const escalated = cycle(ledger, [
      securityFinding({ severity: 'CRITICAL', severity_label: 'CRITIQUE' }),
    ])
    assert.equal(escalated.length, 1)
  })

  it('reste muet quand la gravité redescend', () => {
    const ledger = new NotificationLedger()

    cycle(ledger, [securityFinding({ severity: 'CRITICAL' })])
    const lowered = cycle(ledger, [
      securityFinding({ severity: 'MEDIUM', severity_label: 'Moyenne' }),
    ])

    assert.equal(lowered.length, 0)
  })

  it('n’annonce jamais un finding écarté comme faux positif', () => {
    const ledger = new NotificationLedger()

    const dismissed = cycle(ledger, [
      securityFinding({ status: 'dismissed', status_label: 'Écarté' }),
    ])
    assert.equal(dismissed.length, 0)
  })

  it('annonce à nouveau un secret déplacé', () => {
    const ledger = new NotificationLedger()

    cycle(ledger, [securityFinding({ line_start: 12, line_end: 12 })])

    // Ligne différente : le backend recrée le finding, et l'utilisateur
    // doit être prévenu — la décision qu'il avait prise portait sur ce
    // qui était là, pas sur ce qui y est maintenant.
    const moved = cycle(ledger, [
      securityFinding({ id: 'sec-9', line_start: 40, line_end: 40 }),
    ])
    assert.equal(moved.length, 1)
  })
})

// --------------------------------------------------------------------------
// Intégration à l'architecture de findings existante
// --------------------------------------------------------------------------

describe('Surveillance — un seul registre de findings', () => {
  it('republie les findings projet sans effacer ceux d’une analyse de fichier', () => {
    const store = new FindingsStore()

    // Une analyse de code a rempli la vue pour `src/config.py`…
    store.replaceFile('src/config.py', [
      {
        finding_uid: 'code-1',
        scan_uid: 'scan-1',
        rule_id: 'PY-SQLI-001',
        category: 'injection',
        category_label: 'Injection',
        cwe: 'CWE-89',
        owasp: null,
        severity: 'HIGH',
        severity_label: 'Élevée',
        risk_score: 70,
        risk_band: 'élevé',
        confidence: 0.9,
        source: 'rule',
        source_label: 'Règle',
        title: 'Injection SQL',
        explanation: '',
        why_dangerous: '',
        potential_impact: [],
        recommendations: [],
        risk_factors: [],
        location: { line_start: 30, line_end: 30, column_start: 0, column_end: 5, snippet: 'x' },
        file_path: 'src/config.py',
        fix_available: false,
        fix_summary: '',
        status: 'open',
        status_label: 'Ouvert',
        created_at: '2026-09-28T10:00:00Z',
      },
    ])

    // …et un cycle de surveillance republie les findings de sécurité
    // projet, qui portent sur le **même** fichier.
    store.replaceProjectFindings(toViewFindings([securityFinding()]))

    const files = store.files()
    assert.equal(store.all().length, 2, 'les deux familles cohabitent')
    assert.equal(files.includes('src/config.py'), true)
  })

  it('remplace les findings projet d’un cycle à l’autre sans les empiler', () => {
    const store = new FindingsStore()

    store.replaceProjectFindings(toViewFindings([securityFinding()]))
    store.replaceProjectFindings(toViewFindings([securityFinding()]))

    // Deux cycles de surveillance sur un projet inchangé : un seul
    // finding affiché, pas deux.
    assert.equal(store.projectFindings().length, 1)
  })

  it('fait disparaître de la vue un secret corrigé', () => {
    const store = new FindingsStore()

    store.replaceProjectFindings(toViewFindings([securityFinding()]))
    assert.equal(store.projectFindings().length, 1)

    // Le backend ne renvoie plus rien : le problème est corrigé.
    store.replaceProjectFindings([])
    assert.equal(store.projectFindings().length, 0)
  })
})

// --------------------------------------------------------------------------
// Régression : la phase 2 ne bouge pas
// --------------------------------------------------------------------------

describe('Régression — les accumulateurs de la phase 2 sont inchangés', () => {
  it('`SecretScanAccumulator.result()` rend exactement ce qu’il rendait', () => {
    const accumulator = new SecretScanAccumulator()
    accumulator.consider('src/config.py', 'KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz012345"')
    accumulator.consider('README.md', 'aucun secret ici')
    accumulator.skip()

    const result = accumulator.result()
    assert.equal(result.scannedFiles, 2)
    assert.equal(result.skippedFiles, 1)
    assert.equal(result.truncated, false)
    assert.equal(Array.isArray(result.findings), true)
  })

  it('`perFile()` décrit le même parcours que `result()`', () => {
    const accumulator = new SecretScanAccumulator()
    accumulator.consider('src/config.py', 'KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz012345"')
    accumulator.consider('README.md', 'rien')
    accumulator.skip()

    const result = accumulator.result()
    const detail = accumulator.perFile()

    // Le détail par fichier est un ajout, pas une seconde source : les
    // deux doivent décrire le même parcours, sinon le registre de la
    // surveillance partirait d'un état que le backend n'a jamais reçu.
    assert.equal(detail.scannedPaths.size, result.scannedFiles)
    assert.equal(detail.skippedFiles, result.skippedFiles)
    assert.equal(detail.truncated, result.truncated)

    const flattened = [...detail.secretsByFile.values()].flat()
    assert.equal(flattened.length, result.findings.length)
  })

  it('`perFile()` ne retient que les fichiers réellement porteurs', () => {
    const accumulator = new SecretScanAccumulator()
    accumulator.consider('README.md', 'rien du tout')

    const detail = accumulator.perFile()
    assert.equal(detail.scannedPaths.has('README.md'), true, 'le fichier est suivi')
    assert.equal(detail.secretsByFile.has('README.md'), false, 'sans constat')
  })

  it('`DependencyInventoryAccumulator.result()` est inchangé', () => {
    const accumulator = new DependencyInventoryAccumulator()
    accumulator.consider(
      'package.json',
      'package.json',
      JSON.stringify({ dependencies: { express: '4.17.1', lodash: '4.17.20' } })
    )

    const result = accumulator.result()
    assert.equal(result.manifestsRead, 1)
    assert.equal(result.dependencies.length, 2)
    assert.equal(result.truncated, false)
  })

  it('`perManifest()` décrit le même inventaire que `result()`', () => {
    const accumulator = new DependencyInventoryAccumulator()
    accumulator.consider(
      'package.json',
      'package.json',
      JSON.stringify({ dependencies: { express: '4.17.1' } })
    )
    accumulator.consider(
      'requirements.txt',
      'backend/requirements.txt',
      'fastapi==0.100.0\nuvicorn==0.23.0\n'
    )

    const result = accumulator.result()
    const detail = accumulator.perManifest()

    assert.equal(detail.dependenciesByManifest.size, result.manifestsRead)
    const flattened = [...detail.dependenciesByManifest.values()].flat()
    assert.equal(flattened.length, result.dependencies.length)
  })

  it('enregistre un manifeste lu même sans dépendance déclarée', () => {
    const accumulator = new DependencyInventoryAccumulator()
    accumulator.consider('package.json', 'package.json', JSON.stringify({ name: 'vide' }))

    // « Lu, rien dedans » et « jamais ouvert » ne sont pas la même chose :
    // le surveillant a besoin de distinguer les deux pour savoir s'il
    // doit resoumettre un inventaire quand ce manifeste change.
    const detail = accumulator.perManifest()
    assert.equal(detail.dependenciesByManifest.has('package.json'), true)
    assert.deepEqual(detail.dependenciesByManifest.get('package.json'), [])
  })

  it('un registre reconstitué depuis les accumulateurs rend le même lot', () => {
    const secrets = new SecretScanAccumulator()
    secrets.consider('src/config.py', 'KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz012345"')
    secrets.consider('README.md', 'rien')

    const inventory = new DependencyInventoryAccumulator()
    inventory.consider(
      'package.json',
      'package.json',
      JSON.stringify({ dependencies: { express: '4.17.1' } })
    )

    const detail = secrets.perFile()
    const manifests = inventory.perManifest()

    const baseline = new SecurityBaseline()
    baseline.adopt({
      scannedPaths: detail.scannedPaths,
      secretsByFile: detail.secretsByFile,
      dependenciesByManifest: manifests.dependenciesByManifest,
      apiByFile: new Map(),
      endpointsDetected: 0,
      skippedFiles: detail.skippedFiles,
      truncated: detail.truncated || manifests.truncated,
    })

    // Sans aucune modification, le premier lot reconstitué doit être
    // identique à celui qu'une découverte complète aurait soumis — sinon
    // la première sauvegarde déclencherait une réconciliation parasite.
    const reconstituted = baseline.secretScan()
    const direct = secrets.result()

    assert.equal(reconstituted.findings.length, direct.findings.length)
    assert.equal(reconstituted.scannedFiles, direct.scannedFiles)
    assert.equal(reconstituted.skippedFiles, direct.skippedFiles)
    assert.deepEqual(
      reconstituted.findings.map((f) => `${f.file_path}:${f.line}`),
      direct.findings.map((f) => `${f.file_path}:${f.line}`)
    )

    assert.deepEqual(
      baseline.inventory().dependencies.map((d) => d.name),
      inventory.result().dependencies.map((d) => d.name)
    )
  })
})

describe('surveillance — fichier supprimé', () => {
  /**
   * Régression : la surveillance ne relance aucune analyse de code sur un
   * fichier supprimé, et n'effaçait rien non plus. Ses diagnostics et ses
   * findings de code restaient affichés pour un fichier disparu.
   *
   * `scanController.ts` dépend de `vscode` : il reçoit un double minimal.
   */
  it('oublie diagnostics et findings de code, garde les findings projet', () => {
    const fakeVscode = { workspace: { workspaceFolders: undefined } }
    const loader = Module as unknown as {
      _load: (request: string, parent: unknown, isMain: boolean) => unknown
    }
    const original = loader._load
    loader._load = function (request, parent, isMain) {
      return request === 'vscode' ? fakeVscode : original.call(this, request, parent, isMain)
    }
    try {
      // Chargé après le double : `import` serait évalué avant lui.
      const { ScanController } = require('../src/analysis/scanController') as typeof import('../src/analysis/scanController')
      const store = new FindingsStore()
      const code = {
        ...toViewFindings([securityFinding({ file: 'app/burst.py' })])[0]!,
        finding_uid: 'code-1',
        scan_uid: 'scan-1',
        detection_engine: undefined,
      } as CodeFinding
      const project = toViewFindings([securityFinding({ id: 'projet-1', file: 'app/burst.py' })])[0]!
      store.merge([code, project])

      const cleared: string[] = []
      const controller = new ScanController({
        diagnostics: { clear: (uri: { toString(): string }) => cleared.push(uri.toString()) },
        store,
      } as unknown as ConstructorParameters<typeof ScanController>[0])

      controller.forgetDeleted(
        { toString: () => 'file:///c%3A/p/app/burst.py' } as never,
        'app/burst.py'
      )

      assert.deepEqual(cleared, ['file:///c%3A/p/app/burst.py', 'file:///c%3A/p/app/burst.py'])
      assert.equal(store.get('code-1'), undefined)
      assert.ok(store.get(project.finding_uid), 'le finding projet suit son propre chemin')
    } finally {
      loader._load = original
    }
  })
})
