/**
 * Tests de la posture de sécurité et du contrôle CI/CD, côté extension
 * (phase 8).
 *
 *     AFFICHAGE     « non analysé » ne s'écrit jamais « 0 » ; un domaine
 *                   partiel le dit ; aucun score.
 *     GIT           le bilan local l'emporte sur le « indisponible » du
 *                   backend, sans inventer de zéro.
 *     CI            arguments stricts ; le verdict vient du backend ; codes
 *                   de sortie 0 / 1 / 2 ; une panne en mode block ne passe
 *                   jamais pour « conforme ».
 *     CODE          les fichiers sensibles ne sont jamais lus ni envoyés ;
 *                   le plafond est annoncé.
 *     SÛRETÉ        le rapport d'erreur ne porte ni dossier, ni adresse,
 *                   ni jeton.
 */

import assert from 'node:assert/strict'
import { afterEach, describe, it } from 'node:test'

import { BackendClient, type CodeScanResult, type ScanPayload } from '../src/api/backendClient'
import { GitignoreMatcher } from '../src/analysis/documentFilter'
import {
  errorReport,
  parseCiArgs,
  runCiCheck,
  type CiDependencies,
  type CiOptions,
  type CiReport,
} from '../src/cli/ciRunner'
import type { GitSecuritySummary } from '../src/git/changeAttribution'
import {
  normalizeCiMode,
  type CiCheckResult,
  type CiPolicyRequest,
  type PostureArea,
  type SecurityPosture,
} from '../src/posture/postureTypes'
import { areaValue, postureGroups, type PostureGroup } from '../src/posture/postureView'

// --------------------------------------------------------------------------
// Fabriques
// --------------------------------------------------------------------------

const ZERO = { total: 0, critical: 0, high: 0, medium: 0, low: 0 }

function area(overrides: Partial<PostureArea> & Pick<PostureArea, 'area'>): PostureArea {
  return {
    state: 'not_analyzed',
    coverage: 'not_analyzed',
    findings: null,
    last_scan: null,
    metrics: {},
    warnings: [],
    ...overrides,
  }
}

function posture(overrides: Partial<SecurityPosture> = {}): SecurityPosture {
  return {
    project_uid: 'projet-a',
    project_name: 'App',
    generated_at: '2026-09-29T10:00:00Z',
    analysis: 'not_analyzed',
    findings: { ...ZERO },
    areas: [
      area({ area: 'secrets' }),
      area({ area: 'dependencies' }),
      area({ area: 'code' }),
      area({ area: 'api' }),
      area({ area: 'git', state: 'unavailable', coverage: 'unavailable', warnings: ['locale'] }),
    ],
    coverage: {
      context_available: false,
      files_discovered: 0,
      files_indexed: 0,
      index_truncated: false,
      sensitive_files: 0,
      unsupported_languages: [],
      vulnerability_provider: '',
      vulnerability_provider_status: 'disabled',
      vulnerability_check_conclusive: false,
      vulnerability_message: '',
      last_discovery: null,
    },
    history: {
      available: false,
      message: 'Historique insuffisant : les findings résolus ne sont pas conservés.',
      oldest_open_finding: null,
      newest_open_finding: null,
    },
    ai_generated: false,
    requires_ai: false,
    requires_wazuh: false,
    ...overrides,
  }
}

function ciResult(overrides: Partial<CiCheckResult> = {}): CiCheckResult {
  return {
    schema_version: '1.0',
    project: { project_uid: 'projet-a', project_name: 'App' },
    generated_at: '2026-09-29T10:00:00Z',
    policy: { mode: 'warn', fail_on: [], warn_on: [] },
    status: 'passed',
    exit_decision: 'pass',
    exit_code: 0,
    analysis: 'complete',
    counts: { ...ZERO },
    counts_by_area: {},
    conditions: [],
    reasons: [],
    incomplete_areas: [],
    unsupported_languages: [],
    vulnerability_provider_status: 'available',
    vulnerability_check_conclusive: true,
    blocking_findings: [],
    requires_ai: false,
    requires_wazuh: false,
    ...overrides,
  }
}

function group(groups: PostureGroup[], id: string): PostureGroup {
  const found = groups.find((item) => item.id === id)
  assert.ok(found, `groupe ${id} absent`)
  return found
}

function row(groups: PostureGroup[], id: string) {
  for (const item of groups) {
    const found = item.children.find((child) => child.id === id)
    if (found) {
      return found
    }
  }
  assert.fail(`ligne ${id} absente`)
}

// --------------------------------------------------------------------------
// Affichage de la posture
// --------------------------------------------------------------------------

describe('posture — « non analysé » contre « zéro finding »', () => {
  it('un domaine jamais analysé n’affiche pas de nombre', () => {
    assert.equal(areaValue(area({ area: 'secrets' })), 'Non analysé')
    assert.equal(areaValue(area({ area: 'secrets', state: 'unavailable', coverage: 'unavailable' })), 'Indisponible')
  })

  it('un domaine analysé sans finding le dit, en toutes lettres', () => {
    const value = areaValue(
      area({ area: 'secrets', state: 'no_findings', coverage: 'complete', findings: { ...ZERO } })
    )
    assert.equal(value, 'Aucun finding')
  })

  it('un domaine partiel l’annonce à côté du nombre', () => {
    const value = areaValue(
      area({
        area: 'dependencies',
        state: 'findings',
        coverage: 'partial',
        findings: { ...ZERO, total: 1, high: 1 },
      })
    )
    assert.equal(value, '1 finding(s) · partiel')
  })

  it('un projet jamais analysé n’affiche aucun zéro de gravité', () => {
    const groups = postureGroups({ posture: posture() })

    assert.equal(group(groups, 'posture:overall').value, 'Non analysé')
    for (const key of ['critical', 'high', 'medium', 'low']) {
      assert.equal(row(groups, `posture:findings:${key}`).value, 'Non analysé', key)
    }
    for (const name of ['secrets', 'dependencies', 'code', 'api']) {
      assert.equal(row(groups, `posture:area:${name}`).value, 'Non analysé', name)
    }
  })

  it('un projet analysé affiche ses décomptes par gravité', () => {
    const groups = postureGroups({
      posture: posture({
        analysis: 'partial',
        findings: { total: 7, critical: 0, high: 2, medium: 4, low: 1 },
      }),
    })

    assert.equal(group(groups, 'posture:overall').value, 'Analyse partielle')
    assert.equal(row(groups, 'posture:findings:critical').value, '0')
    assert.equal(row(groups, 'posture:findings:high').value, '2')
    assert.equal(row(groups, 'posture:findings:medium').value, '4')
    assert.equal(row(groups, 'posture:findings:low').value, '1')
    assert.equal(row(groups, 'posture:findings:high').color, 'charts.orange')
  })

  it('aucune ligne n’affiche un score ni une note', () => {
    const groups = postureGroups({ posture: posture({ analysis: 'complete' }), ci: ciResult() })
    const text = JSON.stringify(groups)
    // Aucune valeur de score, sous aucune forme (« sans score » est permis).
    assert.ok(!/score\s*[:=]?\s*\d|\d+\s*\/\s*100|\bgrade\b|\bnote\s*:/i.test(text))
    // « Analyse complète » n'est jamais présenté comme « sûr ».
    assert.ok(!/sûr|sécurisé|safe/i.test(group(groups, 'posture:overall').value))
  })
})

describe('posture — couverture', () => {
  it('annonce un index tronqué, les fichiers sensibles et les langages sans règles', () => {
    const groups = postureGroups({
      posture: posture({
        analysis: 'partial',
        coverage: {
          ...posture().coverage,
          context_available: true,
          files_discovered: 5000,
          files_indexed: 2000,
          index_truncated: true,
          sensitive_files: 3,
          unsupported_languages: ['go'],
        },
      }),
    })

    assert.match(row(groups, 'posture:coverage:files').value, /2000 sur 5000 — index tronqué/)
    assert.equal(row(groups, 'posture:coverage:sensitive').value, '3')
    assert.equal(row(groups, 'posture:coverage:languages').value, 'go')
    assert.equal(row(groups, 'posture:coverage:languages').color, 'charts.yellow')
  })

  it('un fournisseur de vulnérabilités muet est signalé', () => {
    const groups = postureGroups({
      posture: posture({
        coverage: {
          ...posture().coverage,
          vulnerability_provider: 'osv',
          vulnerability_provider_status: 'unavailable',
          vulnerability_message: 'Base de vulnérabilités injoignable.',
        },
      }),
    })
    const provider = row(groups, 'posture:coverage:provider')
    assert.equal(provider.value, 'osv · unavailable')
    assert.equal(provider.color, 'charts.yellow')
    assert.equal(provider.tooltip, 'Base de vulnérabilités injoignable.')
  })

  it('sans contexte, les fichiers indexés disent « non analysé »', () => {
    const groups = postureGroups({ posture: posture() })
    assert.equal(row(groups, 'posture:coverage:files').value, 'Non analysé')
  })

  it('l’historique insuffisant est dit, jamais inventé', () => {
    const groups = postureGroups({ posture: posture() })
    const history = row(groups, 'posture:history')
    assert.equal(history.value, 'Historique insuffisant')
    assert.match(history.tooltip ?? '', /ne sont pas conservés/)
  })

  it('l’état de la surveillance est affiché', () => {
    const groups = postureGroups({ posture: posture(), monitoring: 'ANALYZING' })
    assert.equal(row(groups, 'posture:monitoring').value, 'Analyse en cours')
    assert.equal(
      row(postureGroups({ posture: posture(), monitoring: 'off' }), 'posture:monitoring').value,
      'Désactivée'
    )
  })

  it('une posture illisible le dit, sans autre section', () => {
    const groups = postureGroups({ error: 'le serveur ne répond pas' })
    assert.equal(groups.length, 1)
    assert.match(groups[0]?.value ?? '', /Posture indisponible : le serveur ne répond pas/)
  })

  it('sans posture ni erreur, aucune section', () => {
    assert.deepEqual(postureGroups({}), [])
  })
})

describe('posture — domaine Git', () => {
  const summary = (overrides: Partial<GitSecuritySummary> = {}): GitSecuritySummary => ({
    repository: true,
    branch: 'main',
    remoteHost: 'github.com',
    changedFiles: 2,
    addedLines: 10,
    removedLines: 1,
    reduced: false,
    analyzedFiles: 2,
    introduced: { ...ZERO },
    preExisting: { ...ZERO },
    conclusive: true,
    message: '',
    analyzedAt: '2026-09-29T10:00:00Z',
    ...overrides,
  })

  it('sans bilan local, reprend l’état du backend', () => {
    assert.equal(row(postureGroups({ posture: posture() }), 'posture:area:git').value, 'Indisponible')
  })

  it('un bilan non concluant s’écrit « non vérifié », pas « 0 »', () => {
    const git = row(postureGroups({ posture: posture(), git: summary({ conclusive: false, message: 'délai' }) }), 'posture:area:git')
    assert.equal(git.value, 'Non vérifié')
  })

  it('les problèmes introduits par le changement sont comptés', () => {
    const git = row(
      postureGroups({ posture: posture(), git: summary({ introduced: { ...ZERO, total: 2, high: 1 } }) }),
      'posture:area:git'
    )
    assert.equal(git.value, '2 introduit(s) par le changement')
    assert.equal(git.color, 'charts.red')
  })

  it('aucun dépôt ouvert est dit tel quel', () => {
    const git = row(postureGroups({ posture: posture(), git: summary({ repository: false }) }), 'posture:area:git')
    assert.equal(git.value, 'Aucun dépôt ouvert')
  })
})

describe('posture — section CI/CD', () => {
  it('affiche la politique, le statut et les raisons', () => {
    const groups = postureGroups({
      posture: posture(),
      ci: ciResult({
        policy: { mode: 'block', fail_on: ['critical_findings'], warn_on: [] },
        status: 'blocked',
        exit_decision: 'fail',
        exit_code: 1,
        reasons: [{ code: 'critical_findings', action: 'block', message: '1 finding(s) CRITICAL ouvert(s).' }],
      }),
    })
    const ci = group(groups, 'posture:ci')
    assert.equal(ci.value, 'Bloquant')
    assert.equal(ci.expanded, true)
    assert.equal(ci.children[0]?.label, 'Politique : block')
    assert.equal(ci.children[1]?.value, '1 finding(s) CRITICAL ouvert(s).')
  })

  it('un contrôle indisponible ne se lit pas « conforme »', () => {
    const ci = group(postureGroups({ posture: posture() }), 'posture:ci')
    assert.equal(ci.value, 'Contrôle CI indisponible')
  })

  it('un mode inconnu retombe sur warn, jamais sur block', () => {
    assert.equal(normalizeCiMode('blok'), 'warn')
    assert.equal(normalizeCiMode(undefined), 'warn')
    assert.equal(normalizeCiMode('block'), 'block')
    assert.equal(normalizeCiMode('off'), 'off')
  })
})

describe('posture — types sans champ de contenu ni de score', () => {
  const FORBIDDEN = new Set([
    'score', 'security_score', 'grade', 'rating', 'risk_score',
    'evidence', 'content', 'file_content', 'snippet', 'root_hash', 'workspace_path', 'token',
  ])
  const samples: Record<string, object> = {
    SecurityPosture: posture(),
    PostureArea: area({ area: 'secrets' }),
    PostureCoverage: posture().coverage,
    CiCheckResult: ciResult(),
  }
  for (const [name, sample] of Object.entries(samples)) {
    it(`${name} ne porte aucun champ interdit`, () => {
      for (const field of Object.keys(sample)) {
        assert.ok(!FORBIDDEN.has(field), `${name}.${field}`)
      }
    })
  }
})

// --------------------------------------------------------------------------
// Client HTTP
// --------------------------------------------------------------------------

describe('BackendClient — posture et CI', () => {
  const realFetch = globalThis.fetch
  afterEach(() => {
    ;(globalThis as { fetch: unknown }).fetch = realFetch
  })

  it('lit la posture et demande le contrôle CI sur leurs routes', async () => {
    const seen: { url: string; method?: string; body?: string }[] = []
    ;(globalThis as { fetch: unknown }).fetch = async (input: unknown, init?: RequestInit) => {
      seen.push({ url: String(input), method: init?.method, body: init?.body as string | undefined })
      return new Response(JSON.stringify(String(input).includes('ci-check') ? ciResult() : posture()), { status: 200 })
    }
    const client = new BackendClient({ baseUrl: 'http://127.0.0.1:8000' })

    await client.getPosture('projet a')
    await client.ciCheck('projet a', { mode: 'block' })

    assert.equal(seen[0]?.url, 'http://127.0.0.1:8000/api/project/projet%20a/posture')
    assert.equal(seen[0]?.method, 'GET')
    assert.equal(seen[1]?.url, 'http://127.0.0.1:8000/api/project/projet%20a/ci-check')
    assert.equal(seen[1]?.method, 'POST')
    assert.deepEqual(JSON.parse(seen[1]?.body ?? '{}'), { mode: 'block' })
  })
})

// --------------------------------------------------------------------------
// Arguments de la ligne de commande
// --------------------------------------------------------------------------

describe('CI — arguments', () => {
  const parse = (argv: string[], env: Record<string, string> = {}) => parseCiArgs(argv, env, '/depot')

  it('a des défauts sûrs', () => {
    const parsed = parse([])
    assert.equal(parsed.ok, true)
    if (!parsed.ok) return
    assert.equal(parsed.options.root, '/depot')
    assert.equal(parsed.options.backendUrl, 'http://127.0.0.1:8000')
    assert.equal(parsed.options.allowRemoteBackend, false)
    // Aucune politique imposée : celle du backend s'applique (warn).
    assert.equal(parsed.options.mode, undefined)
    assert.equal(parsed.options.scan, true)
    assert.equal(parsed.options.code, true)
  })

  it('lit politique, conditions et options', () => {
    const parsed = parse([
      '--root', 'app', '--policy', 'block', '--fail-on', 'critical_findings,secrets_present',
      '--warn-on', 'unsupported_languages', '--output', 'r.json', '--no-code',
      '--no-vulnerability-check', '--max-code-files', '5',
    ])
    assert.equal(parsed.ok, true)
    if (!parsed.ok) return
    assert.equal(parsed.options.mode, 'block')
    assert.deepEqual(parsed.options.failOn, ['critical_findings', 'secrets_present'])
    assert.deepEqual(parsed.options.warnOn, ['unsupported_languages'])
    assert.equal(parsed.options.code, false)
    assert.equal(parsed.options.vulnerabilityCheck, false)
    assert.equal(parsed.options.maxCodeFiles, 5)
  })

  it('lit le jeton et l’adresse depuis l’environnement', () => {
    const parsed = parse([], {
      WAZUH_SECURITY_TOKEN: 'jeton',
      WAZUH_SECURITY_BACKEND_URL: 'http://127.0.0.1:9000',
      WAZUH_SECURITY_CI_POLICY: 'panique',
    })
    assert.equal(parsed.ok, true)
    if (!parsed.ok) return
    assert.equal(parsed.options.token, 'jeton')
    assert.equal(parsed.options.backendUrl, 'http://127.0.0.1:9000')
    // Une valeur inconnue en environnement retombe sur warn.
    assert.equal(parsed.options.mode, 'warn')
  })

  it('refuse l’inconnu au lieu de le deviner', () => {
    for (const argv of [
      ['--policy', 'panique'],
      ['--fail-on', 'tout'],
      ['--bogus'],
      ['--root'],
      ['--max-code-files', '-3'],
    ]) {
      assert.equal(parse(argv).ok, false, argv.join(' '))
    }
    const help = parse(['--help'])
    assert.equal(!help.ok && help.help, true)
  })
})

// --------------------------------------------------------------------------
// Déroulé du contrôle
// --------------------------------------------------------------------------

function options(overrides: Partial<CiOptions> = {}): CiOptions {
  return {
    root: '/depot',
    backendUrl: 'http://127.0.0.1:8000',
    allowRemoteBackend: false,
    token: 'jeton-tres-secret',
    tokenFile: undefined,
    mode: undefined,
    failOn: undefined,
    warnOn: undefined,
    output: undefined,
    scan: true,
    code: true,
    vulnerabilityCheck: true,
    maxCodeFiles: 300,
    ...overrides,
  }
}

class FakeCiBackend {
  healthResult: { project_security_enabled?: boolean } | Error = { project_security_enabled: true }
  result: CiCheckResult = ciResult()
  ciError: Error | undefined
  scanned: ScanPayload[] = []
  policies: CiPolicyRequest[] = []
  checkedProjects: string[] = []

  async health() {
    if (this.healthResult instanceof Error) throw this.healthResult
    return this.healthResult
  }

  async scan(payload: ScanPayload): Promise<CodeScanResult> {
    this.scanned.push(payload)
    return {} as CodeScanResult
  }

  async ciCheck(projectUid: string, policy: CiPolicyRequest): Promise<CiCheckResult> {
    if (this.ciError) throw this.ciError
    this.checkedProjects.push(projectUid)
    this.policies.push(policy)
    return this.result
  }
}

function deps(backend: FakeCiBackend, overrides: Partial<CiDependencies> = {}): CiDependencies {
  const files: Record<string, string> = {
    'src/app.py': 'def hello():\n    return 1\n',
    'src/util.ts': 'export const x = 1\n',
    '.env': 'SECRET=valeur',
    'config/id_rsa': '-----BEGIN',
    'README.md': '# Doc',
  }
  return {
    backend,
    discover: async () => ({
      ok: true,
      projectUid: 'projet-a',
      message: 'Contexte établi.',
      indexedFiles: Object.keys(files).map((path) => ({ path, size: files[path]?.length ?? 0 })),
    }),
    identify: async () => 'projet-a',
    readText: async (_root, relative) => files[relative],
    gitignore: () => GitignoreMatcher.empty(),
    log: () => undefined,
    ...overrides,
  }
}

describe('CI — déroulé', () => {
  it('le verdict et le code de sortie viennent du backend', async () => {
    for (const [result, exit] of [
      [ciResult({ status: 'passed', exit_code: 0 }), 0],
      [ciResult({ status: 'warning', exit_code: 0 }), 0],
      [ciResult({ status: 'off', exit_code: 0 }), 0],
      [ciResult({ status: 'blocked', exit_decision: 'fail', exit_code: 1 }), 1],
    ] as const) {
      const backend = new FakeCiBackend()
      backend.result = result
      const run = await runCiCheck(options(), deps(backend))
      assert.equal(run.exitCode, exit, result.status)
      assert.equal((run.report as CiReport).result.status, result.status)
    }
  })

  it('transmet la politique demandée, et rien quand aucune ne l’est', async () => {
    const backend = new FakeCiBackend()
    await runCiCheck(options(), deps(backend))
    await runCiCheck(options({ mode: 'block', failOn: ['secrets_present'] }), deps(backend))

    assert.deepEqual(backend.policies[0], {})
    assert.deepEqual(backend.policies[1], { mode: 'block', fail_on: ['secrets_present'] })
  })

  it('n’envoie à l’analyse de code que des sources couvertes, jamais un fichier sensible', async () => {
    const backend = new FakeCiBackend()
    const run = await runCiCheck(options(), deps(backend))

    const sent = backend.scanned.map((payload) => payload.file_path).sort()
    assert.deepEqual(sent, ['src/app.py', 'src/util.ts'])
    assert.ok(backend.scanned.every((payload) => payload.project_uid === 'projet-a'))
    assert.ok(backend.scanned.every((payload) => payload.ai_enrichment === false))
    assert.equal((run.report as CiReport).scan.code_files_submitted, 2)
  })

  it('un fichier sensible n’est même pas lu', async () => {
    const backend = new FakeCiBackend()
    const read: string[] = []
    await runCiCheck(
      options(),
      deps(backend, {
        readText: async (_root, relative) => {
          read.push(relative)
          return 'x = 1\n'
        },
      })
    )
    assert.ok(!read.includes('.env'))
    assert.ok(!read.includes('config/id_rsa'))
  })

  it('le plafond de l’analyse de code est annoncé', async () => {
    const backend = new FakeCiBackend()
    const run = await runCiCheck(options({ maxCodeFiles: 1 }), deps(backend))
    const report = run.report as CiReport

    assert.equal(backend.scanned.length, 1)
    assert.equal(report.scan.code_truncated, true)
  })

  it('--no-code et --no-scan n’envoient aucun fichier', async () => {
    const backend = new FakeCiBackend()
    let discovered = false
    await runCiCheck(options({ code: false }), deps(backend))
    await runCiCheck(
      options({ scan: false }),
      deps(backend, {
        discover: async () => {
          discovered = true
          throw new Error('ne doit pas être appelé')
        },
      })
    )
    assert.equal(backend.scanned.length, 0)
    assert.equal(discovered, false)
    assert.deepEqual(backend.checkedProjects, ['projet-a', 'projet-a'])
  })

  it('un backend injoignable ne bloque pas en mode warn, mais bloque en mode block', async () => {
    for (const [mode, exit] of [[undefined, 0], ['warn', 0], ['off', 0], ['block', 2]] as const) {
      const backend = new FakeCiBackend()
      backend.healthResult = new Error('le serveur ne répond pas')
      const run = await runCiCheck(options({ mode }), deps(backend))
      assert.equal(run.exitCode, exit, String(mode))
      assert.equal(run.report.exit_code, exit)
      assert.equal((run.report as { status: string }).status, 'error')
    }
  })

  it('un backend sans sécurité projet est une erreur explicite', async () => {
    const backend = new FakeCiBackend()
    backend.healthResult = { project_security_enabled: false }
    const run = await runCiCheck(options({ mode: 'block' }), deps(backend))
    assert.equal(run.exitCode, 2)
  })

  it('une découverte ou un contrôle en échec devient un rapport, jamais une exception', async () => {
    const failingDiscovery = await runCiCheck(
      options(),
      deps(new FakeCiBackend(), {
        discover: async () => ({ ok: false, projectUid: undefined, message: 'Backend injoignable.', indexedFiles: [] }),
      })
    )
    assert.equal((failingDiscovery.report as { status: string }).status, 'error')

    const backend = new FakeCiBackend()
    backend.ciError = new Error('HTTP 500')
    const failingCheck = await runCiCheck(options({ mode: 'block' }), deps(backend))
    assert.equal(failingCheck.exitCode, 2)
  })

  it('le rapport d’erreur ne porte ni dossier, ni adresse, ni jeton', () => {
    const run = errorReport('block', 'backend', 'Backend injoignable.')
    const raw = JSON.stringify(run.report)
    assert.ok(!raw.includes('/depot'))
    assert.ok(!raw.includes('127.0.0.1'))
    assert.ok(!raw.includes('jeton-tres-secret'))
    assert.equal((run.report as { requires_ai: boolean }).requires_ai, false)
  })

  it('le rapport complet ne recopie ni le jeton ni le dossier', async () => {
    const backend = new FakeCiBackend()
    const run = await runCiCheck(options(), deps(backend))
    const raw = JSON.stringify(run.report)
    assert.ok(!raw.includes('jeton-tres-secret'))
    assert.ok(!raw.includes('/depot'))
    assert.equal(JSON.parse(raw).schema_version, '1.0')
  })

  it('le contrôle ne dépend ni de l’IA ni de Wazuh', async () => {
    const backend = new FakeCiBackend()
    const run = await runCiCheck(options(), deps(backend))
    const report = run.report as CiReport
    assert.equal(report.result.requires_ai, false)
    assert.equal(report.result.requires_wazuh, false)
    assert.ok(backend.scanned.every((payload) => payload.ai_enrichment === false))
  })
})
