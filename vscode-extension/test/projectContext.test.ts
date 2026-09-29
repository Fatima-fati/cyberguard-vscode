/**
 * Tests du service de contexte de projet.
 *
 * Le client backend et le système de fichiers sont doublés : la séquence
 * complète — enregistrement, parcours, soumission — est exercée sans
 * serveur et sans disque.
 *
 * Ce qui est vérifié ici, et pas ailleurs :
 *
 *     l'ordre des trois échanges       découvrir avant d'indexer
 *     le cloisonnement des projets     A et B ne se mélangent pas
 *     ce qui franchit la frontière     l'empreinte, jamais le chemin
 *     les échecs                       backend éteint, annulation
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { BackendError } from '../src/api/backendClient'
import type { BackendClient } from '../src/api/backendClient'
import { ProjectContextService } from '../src/project/projectContext'
import { runStartup, type StartupSteps } from '../src/project/startup'
import { rootHashOf } from '../src/project/projectIdentity'
import type {
  DirectoryEntry,
  DiscoveryFileSystem,
} from '../src/project/projectDiscovery'
import type {
  LocalProjectView,
  ProjectDiscoverSubmission,
  ProjectIndexSubmission,
  ProjectRegistration,
  ProjectSecurityContext,
} from '../src/project/projectTypes'

// --------------------------------------------------------------------------
// Doubles
// --------------------------------------------------------------------------

/** Système de fichiers minimal : une table plate de chemins. */
class FlatFs implements DiscoveryFileSystem {
  constructor(private readonly files: Record<string, string>) {}

  private norm(p: string): string {
    return p.replace(/\\/g, '/').replace(/\/+$/, '')
  }

  async readDirectory(directory: string): Promise<DirectoryEntry[]> {
    const prefix = `${this.norm(directory)}/`
    const names = new Map<string, DirectoryEntry>()

    for (const path of Object.keys(this.files)) {
      if (!path.startsWith(prefix)) {
        continue
      }
      const [head, ...tail] = path.slice(prefix.length).split('/')
      if (!head || names.has(head)) {
        continue
      }
      names.set(head, {
        name: head,
        isDirectory: tail.length > 0,
        isFile: tail.length === 0,
        isSymbolicLink: false,
      })
    }
    return [...names.values()]
  }

  async stat(file: string) {
    const content = this.files[this.norm(file)]
    if (content === undefined) {
      throw new Error('ENOENT')
    }
    return { size: content.length, mtimeMs: 1_700_000_000_000 }
  }

  async readFile(file: string): Promise<string> {
    const content = this.files[this.norm(file)]
    if (content === undefined) {
      throw new Error('ENOENT')
    }
    return content
  }
}

/** Contexte de réponse, avec des valeurs neutres par défaut. */
function contextFor(
  projectUid: string,
  overrides: Partial<ProjectSecurityContext> = {}
): ProjectSecurityContext {
  return {
    project_uid: projectUid,
    project_name: 'MonApplication',
    root_hash: 'a'.repeat(64),
    status: 'ready',
    project_types: ['Backend'],
    primary_language: 'python',
    languages: [
      { language: 'python', file_count: 1, share: 100, analysis_supported: true },
    ],
    frameworks: [],
    file_statistics: {
      discovered: 1,
      indexed: 1,
      source: 1,
      manifests: 0,
      configuration: 0,
      tests: 0,
      sensitive: 0,
      truncated: false,
    },
    manifests: [],
    important_files: [],
    configuration_files: [],
    security_sensitive_files: [],
    git_repository_detected: false,
    git_remote_host: null,
    // Statistiques de securite (phase 2) : valeurs neutres. Un contexte
    // fraichement decouvert n'a encore rien balaye, et `last_scan: null`
    // dit « jamais analyse » plutot que « aucun secret ».
    secret_statistics: {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      files_with_secrets: 0,
      scanned_files: 0,
      truncated: false,
      engine: '',
      last_scan: null,
    },
    api_statistics: {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      endpoints_detected: 0,
      unauthenticated_endpoints: 0,
      files_with_findings: 0,
      scanned_files: 0,
      truncated: false,
      engine: '',
      last_scan: null,
    },
    dependency_statistics: {
      total: 0,
      direct: 0,
      transitive: 0,
      vulnerable: 0,
      unverified: 0,
      manifests_read: 0,
      truncated: false,
      last_inventory: null,
    },
    dependency_ecosystems: [],
    vulnerability_statistics: {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      packages_affected: 0,
      packages_checked: 0,
      packages_unverified: 0,
      provider: 'osv',
      provider_status: 'disabled',
      provider_status_label: 'Verification desactivee',
      message: 'Verification des vulnerabilites desactivee.',
      conclusive: false,
      last_check: null,
    },
    warnings: [],
    last_discovery: '2026-09-27T22:03:00Z',
    discovery_version: '1.0.0',
    ...overrides,
  }
}

interface RecordedCalls {
  discover: ProjectDiscoverSubmission[]
  index: { projectUid: string; submission: ProjectIndexSubmission }[]
}

/**
 * Client doublé.
 *
 * Seules les trois méthodes de projet sont fournies ; le reste du client
 * n'est pas sollicité par ce service, et le déclarer inutilement
 * masquerait un appel imprévu.
 */
function fakeClient(options: {
  calls: RecordedCalls
  registration?: ProjectRegistration
  context?: ProjectSecurityContext
  discoverError?: unknown
  indexError?: unknown
}): BackendClient {
  const projectUid = options.registration?.project_uid ?? 'uid-1'

  return {
    async discoverProject(submission: ProjectDiscoverSubmission) {
      options.calls.discover.push(submission)
      if (options.discoverError) {
        throw options.discoverError
      }
      return (
        options.registration ?? {
          project_uid: projectUid,
          project_name: submission.project_name,
          root_hash: submission.root_hash,
          status: 'discovery' as const,
          known: false,
          last_discovery: null,
        }
      )
    },
    async submitProjectIndex(uid: string, submission: ProjectIndexSubmission) {
      options.calls.index.push({ projectUid: uid, submission })
      if (options.indexError) {
        throw options.indexError
      }
      return options.context ?? contextFor(uid)
    },
  } as unknown as BackendClient
}

const ROOT = '/home/dev/MonApplication'

function build(options: {
  files?: Record<string, string>
  registration?: ProjectRegistration
  context?: ProjectSecurityContext
  discoverError?: unknown
  indexError?: unknown
  maxFiles?: number
}) {
  const calls: RecordedCalls = { discover: [], index: [] }
  const traces: string[] = []

  const service = new ProjectContextService({
    client: fakeClient({
      calls,
      ...(options.registration ? { registration: options.registration } : {}),
      ...(options.context ? { context: options.context } : {}),
      ...(options.discoverError ? { discoverError: options.discoverError } : {}),
      ...(options.indexError ? { indexError: options.indexError } : {}),
    }),
    log: (message) => traces.push(message),
    fileSystem: new FlatFs(options.files ?? { [`${ROOT}/src/app.py`]: 'print(1)' }),
    ...(options.maxFiles !== undefined ? { maxFiles: options.maxFiles } : {}),
  })

  return { service, calls, traces }
}

// --------------------------------------------------------------------------
// Séquence nominale
// --------------------------------------------------------------------------

describe('ProjectContextService — découverte', () => {
  it('enregistre, parcourt, puis soumet — dans cet ordre', async () => {
    const { service, calls } = build({})

    const outcome = await service.discover({ workspacePath: ROOT })

    assert.equal(outcome.ok, true)
    assert.equal(calls.discover.length, 1)
    assert.equal(calls.index.length, 1)
    // L'enregistrement précède l'index : sans `project_uid`, l'index
    // n'aurait nulle part où aller, et parcourir un monorepo pour
    // découvrir ensuite que le backend est éteint serait du travail perdu.
    assert.equal(calls.index[0]!.projectUid, 'uid-1')
  })

  it('transmet l’empreinte de la racine, jamais le chemin', async () => {
    const { service, calls } = build({})
    await service.discover({ workspacePath: ROOT })

    const sent = calls.discover[0]!
    assert.equal(sent.root_hash, rootHashOf(ROOT))
    assert.match(sent.root_hash, /^[0-9a-f]{64}$/)

    // Vérification sur l'intégralité de ce qui a été envoyé, les deux
    // requêtes comprises : le chemin absolu révélerait le nom de
    // l'utilisateur et l'arborescence de son poste.
    const serialise = JSON.stringify(calls)
    assert.ok(!serialise.includes('/home/dev'), 'chemin absolu transmis')
    assert.ok(!serialise.includes('home'), 'fragment de chemin transmis')
  })

  it('transmet le nom du dossier, pas son chemin', async () => {
    const { service, calls } = build({})
    await service.discover({ workspacePath: ROOT })
    assert.equal(calls.discover[0]!.project_name, 'MonApplication')
  })

  it('expose le contexte reçu', async () => {
    const { service } = build({})
    await service.discover({ workspacePath: ROOT })

    const view = service.current()
    assert.ok(view)
    assert.equal(view.status, 'ready')
    assert.equal(view.projectName, 'MonApplication')
    assert.equal(view.context?.project_uid, 'uid-1')
    assert.ok(view.lastDiscovery instanceof Date)
    assert.equal(view.error, undefined)
  })

  it('conserve le chemin local côté extension seulement', async () => {
    // Le §14 de la commande demandait `workspacePath` dans le modèle ; il y
    // est, côté extension, et il ne franchit jamais la frontière HTTP.
    const { service, calls } = build({})
    await service.discover({ workspacePath: ROOT })

    assert.equal(service.current()?.workspacePath, ROOT)
    assert.ok(!JSON.stringify(calls).includes(ROOT))
  })

  it('fournit l’identifiant de projet pour les analyses et le flux', async () => {
    const { service } = build({})
    assert.equal(service.projectUid(), undefined)

    await service.discover({ workspacePath: ROOT })
    assert.equal(service.projectUid(), 'uid-1')
  })

  it('soumet un index de métadonnées, sans contenu', async () => {
    const { service, calls } = build({
      files: {
        [`${ROOT}/src/app.py`]: 'mot_de_passe = "en-clair"',
        [`${ROOT}/.env`]: 'OPENAI_API_KEY=sk-secret-reel',
      },
    })

    await service.discover({ workspacePath: ROOT })
    const submission = calls.index[0]!.submission

    const serialise = JSON.stringify(submission)
    assert.ok(!serialise.includes('sk-secret-reel'), 'valeur de secret transmise')
    assert.ok(!serialise.includes('en-clair'), 'contenu de source transmis')

    // Le `.env` est bien annoncé — c'est ce que la découverte doit
    // constater — mais sans empreinte, donc sans avoir été lu.
    const env = submission.files.find((entry) => entry.path === '.env')
    assert.ok(env)
    assert.equal(env.content_hash, null)
  })

  it('transmet la version de découverte', async () => {
    const { service, calls } = build({})
    await service.discover({ workspacePath: ROOT })
    assert.equal(calls.discover[0]!.discovery_version, '1.0.0')
    assert.equal(calls.index[0]!.submission.discovery_version, '1.0.0')
  })
})

// --------------------------------------------------------------------------
// Cloisonnement
// --------------------------------------------------------------------------

describe('ProjectContextService — cloisonnement', () => {
  it('deux dossiers produisent deux empreintes distinctes', async () => {
    const a = build({ files: { '/home/dev/client-a/backend/app.py': 'x' } })
    const b = build({ files: { '/home/dev/client-b/backend/app.py': 'x' } })

    await a.service.discover({ workspacePath: '/home/dev/client-a/backend' })
    await b.service.discover({ workspacePath: '/home/dev/client-b/backend' })

    // Les deux dossiers s'appellent « backend » : c'est exactement le cas
    // que `folders[0].name` confondait.
    assert.equal(a.calls.discover[0]!.project_name, 'backend')
    assert.equal(b.calls.discover[0]!.project_name, 'backend')
    assert.notEqual(a.calls.discover[0]!.root_hash, b.calls.discover[0]!.root_hash)
  })

  it('changer de dossier oublie le contexte précédent', async () => {
    const { service } = build({})
    await service.discover({ workspacePath: ROOT })
    assert.ok(service.current())

    service.clear()
    // Afficher le contexte d'un projet sous le nom d'un autre serait pire
    // que de n'afficher rien.
    assert.equal(service.current(), undefined)
    assert.equal(service.projectUid(), undefined)
  })
})

// --------------------------------------------------------------------------
// Concurrence et annulation
// --------------------------------------------------------------------------

describe('ProjectContextService — concurrence', () => {
  it('refuse une seconde découverte simultanée', async () => {
    const { service, calls } = build({})

    const first = service.discover({ workspacePath: ROOT })
    const second = await service.discover({ workspacePath: ROOT })

    // Refusé, pas mis en file : deux parcours concurrents doubleraient le
    // coût pour un résultat identique.
    assert.equal(second.ok, false)
    assert.match(second.message, /en cours/)

    await first
    assert.equal(calls.discover.length, 1)
  })

  it('accepte une nouvelle découverte après la précédente', async () => {
    const { service, calls } = build({})
    await service.discover({ workspacePath: ROOT })
    await service.discover({ workspacePath: ROOT })
    assert.equal(calls.discover.length, 2)
  })

  it('n’est plus « en cours » après un échec', async () => {
    const { service } = build({ discoverError: new BackendError('panne', 500) })
    await service.discover({ workspacePath: ROOT })
    assert.equal(service.isRunning, false)
  })
})

describe('ProjectContextService — annulation', () => {
  it('ne soumet aucun index partiel', async () => {
    const files: Record<string, string> = {}
    for (let n = 0; n < 50; n += 1) {
      files[`${ROOT}/src/f${n}.py`] = 'x'
    }

    const { service, calls } = build({ files })
    const outcome = await service.discover({
      workspacePath: ROOT,
      isCancelled: () => true,
    })

    assert.equal(outcome.cancelled, true)
    assert.equal(outcome.ok, false)
    // Un index partiel décrirait un projet qui n'existe pas.
    assert.equal(calls.index.length, 0)
  })
})

// --------------------------------------------------------------------------
// Échecs
// --------------------------------------------------------------------------

describe('ProjectContextService — échecs', () => {
  it('distingue un backend injoignable', async () => {
    // De loin la cause la plus fréquente, et sa correction ne ressemble à
    // aucune autre : le message doit dire de démarrer le backend.
    const { service } = build({ discoverError: new BackendError('injoignable', 0) })
    const outcome = await service.discover({ workspacePath: ROOT })

    assert.equal(outcome.ok, false)
    assert.match(outcome.message, /Backend indisponible/)
    assert.match(outcome.message, /Démarrez/)
    assert.equal(service.current()?.status, 'error')
  })

  it('rapporte une erreur d’authentification de façon actionnable', async () => {
    const { service } = build({
      discoverError: new BackendError('Le backend a refusé', 401),
    })
    const outcome = await service.discover({ workspacePath: ROOT })
    assert.equal(outcome.ok, false)
    assert.equal(service.current()?.status, 'error')
  })

  it('conserve le contexte précédent quand un rafraîchissement échoue', async () => {
    const { service } = build({})
    await service.discover({ workspacePath: ROOT })
    const before = service.current()?.context
    assert.ok(before)

    // Second service, même racine, mais le backend tombe.
    const broken = new ProjectContextService({
      client: fakeClient({
        calls: { discover: [], index: [] },
        discoverError: new BackendError('injoignable', 0),
      }),
      log: () => undefined,
      fileSystem: new FlatFs({ [`${ROOT}/src/app.py`]: 'x' }),
    })
    await broken.discover({ workspacePath: ROOT })
    assert.equal(broken.current()?.status, 'error')

    // Le premier service garde ce qu'il savait : un échec de
    // rafraîchissement n'efface pas une connaissance acquise.
    assert.deepEqual(service.current()?.context, before)
  })

  it('n’expose aucune trace d’exécution à l’utilisateur', async () => {
    const error = new Error('boum')
    error.stack = 'Error: boum\n    at secret.ts:42'
    const { service } = build({ indexError: error })

    const outcome = await service.discover({ workspacePath: ROOT })
    assert.ok(!outcome.message.includes('secret.ts'), outcome.message)
    assert.ok(!outcome.message.includes('at '), outcome.message)
  })
})

// --------------------------------------------------------------------------
// Avertissements
// --------------------------------------------------------------------------

describe('ProjectContextService — avertissements', () => {
  it('remonte les avertissements du contexte', async () => {
    const { service } = build({
      context: contextFor('uid-1', {
        warnings: ['Index tronqué à 10 fichiers'],
      }),
    })

    const outcome = await service.discover({ workspacePath: ROOT })
    assert.equal(outcome.ok, true)
    assert.deepEqual(outcome.warnings, ['Index tronqué à 10 fichiers'])
    // Le message signale qu'il y a des avertissements plutôt que de les
    // taire : une troncature silencieuse serait un mensonge de couverture.
    assert.match(outcome.message, /avertissement/)
  })

  it('annonce un succès sans avertissement de façon lisible', async () => {
    const { service } = build({})
    const outcome = await service.discover({ workspacePath: ROOT })
    assert.match(outcome.message, /MonApplication/)
    assert.match(outcome.message, /indexé/)
  })

  it('signale les fichiers sensibles dans le compte rendu', async () => {
    const { service } = build({
      context: contextFor('uid-1', {
        file_statistics: {
          ...contextFor('uid-1').file_statistics,
          sensitive: 3,
        },
      }),
    })
    const outcome = await service.discover({ workspacePath: ROOT })
    assert.match(outcome.message, /3 fichiers sensibles/)
  })
})

// --------------------------------------------------------------------------
// Journalisation
// --------------------------------------------------------------------------

describe('ProjectContextService — journalisation', () => {
  it('trace par identifiant, jamais par chemin de poste', async () => {
    const { service, traces } = build({})
    await service.discover({ workspacePath: ROOT })

    assert.ok(traces.length > 0)
    for (const trace of traces) {
      // Une trace copiée dans un rapport de bug ne doit pas révéler
      // l'arborescence du poste.
      assert.ok(!trace.includes('/home/dev'), trace)
    }
    // L'identifiant court permet de corréler les traces entre elles.
    assert.ok(
      traces.some((trace) => trace.includes(rootHashOf(ROOT).slice(0, 12))),
      traces.join(' | ')
    )
  })

  it('ne journalise jamais le chemin d’un fichier sensible', async () => {
    const { service, traces } = build({
      context: contextFor('uid-1', {
        security_sensitive_files: [
          {
            path: 'backend/.env',
            kind: 'sensitive',
            type: 'environment-secrets',
            reason: 'peut contenir des identifiants',
          },
        ],
      }),
    })

    await service.discover({ workspacePath: ROOT })
    for (const trace of traces) {
      assert.ok(!trace.includes('backend/.env'), trace)
    }
  })

  it('ne journalise aucun contenu de fichier', async () => {
    const { service, traces } = build({
      files: { [`${ROOT}/src/app.py`]: 'cle = "sk-secret-reel"' },
    })
    await service.discover({ workspacePath: ROOT })
    for (const trace of traces) {
      assert.ok(!trace.includes('sk-secret-reel'), trace)
    }
  })
})

// --------------------------------------------------------------------------
// Observateurs
// --------------------------------------------------------------------------

describe('ProjectContextService — observateurs', () => {
  it('notifie à chaque changement d’état', async () => {
    const { service } = build({})
    const seen: (LocalProjectView | undefined)[] = []
    service.onChange((view) => seen.push(view))

    await service.discover({ workspacePath: ROOT })

    // Au moins « découverte en cours » puis « prêt ».
    assert.ok(seen.length >= 2, `${seen.length} notification(s)`)
    assert.equal(seen[seen.length - 1]?.status, 'ready')
  })

  it('un observateur défaillant n’empêche pas les autres', async () => {
    const { service } = build({})
    let reached = false

    service.onChange(() => {
      throw new Error('vue en cours de démontage')
    })
    service.onChange(() => {
      reached = true
    })

    await service.discover({ workspacePath: ROOT })
    assert.equal(reached, true)
  })

  it('le désabonnement est effectif', async () => {
    const { service } = build({})
    let calls = 0
    const unsubscribe = service.onChange(() => {
      calls += 1
    })

    unsubscribe()
    await service.discover({ workspacePath: ROOT })
    assert.equal(calls, 0)
  })
})

describe('démarrage — ordre imposé', () => {
  /**
   * Régression : contrôle du backend et découverte partaient de front. La
   * découverte ne voyait pas encore la sécurité projet (aucun parcours de
   * référence : surveillance des secrets en attente toute la session), et
   * la reprise de l'historique partait sans `project_uid` (findings de
   * tous les projets du backend).
   */
  function steps(overrides: Partial<StartupSteps> = {}) {
    const order: string[] = []
    let uid: string | undefined
    const value: StartupSteps = {
      folderOpen: true,
      discoverOnStartup: true,
      syncOnStartup: true,
      checkBackend: async (sync) => {
        await new Promise((resolve) => setTimeout(resolve, 5))
        order.push(`backend(sync=${sync})`)
      },
      discover: async () => {
        order.push('discover')
        uid = 'projet-a'
      },
      projectUid: () => uid,
      syncHistory: async () => {
        order.push(`history(${uid})`)
      },
      ...overrides,
    }
    return { order, value }
  }

  it('backend, puis découverte, puis historique filtré par projet', async () => {
    const { order, value } = steps()
    await runStartup(value)
    assert.deepEqual(order, ['backend(sync=false)', 'discover', 'history(projet-a)'])
  })

  it('sans identifiant de projet, aucune reprise non filtrée', async () => {
    const { order, value } = steps({ discoverOnStartup: false })
    await runStartup(value)
    assert.deepEqual(order, ['backend(sync=false)'])
  })

  it('découverte en échec : aucune reprise', async () => {
    const { order, value } = steps({ discover: async () => { order.push('discover') } })
    await runStartup(value)
    assert.deepEqual(order, ['backend(sync=false)', 'discover'])
  })

  it('aucun dossier ouvert : reprise faite par le contrôle du backend, comme avant', async () => {
    const { order, value } = steps({ folderOpen: false })
    await runStartup(value)
    assert.deepEqual(order, ['backend(sync=true)'])
  })

  it('la reprise au démarrage désactivée est respectée', async () => {
    const { order, value } = steps({ syncOnStartup: false })
    await runStartup(value)
    assert.deepEqual(order, ['backend(sync=false)', 'discover'])
  })
})
