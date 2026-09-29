/**
 * Tests du client HTTP.
 *
 * `fetch` est remplacé par un bouchon : aucun appel réseau, aucun backend
 * requis, aucune clé OpenAI. Ce que l'on vérifie ici, c'est le contrat —
 * codes HTTP traduits en français, annulation, absence de trace
 * d'exécution brute.
 */

import assert from 'node:assert/strict'
import { afterEach, describe, it } from 'node:test'

import {
  BackendClient,
  BackendError,
  ScanCancelledError,
  type CodeScanResult,
} from '../src/api/backendClient'

const realFetch = globalThis.fetch

type FetchStub = (input: unknown, init?: RequestInit) => Promise<Response>

/** Remplace `fetch` le temps d'un test. */
function stubFetch(stub: FetchStub): void {
  ;(globalThis as { fetch: unknown }).fetch = stub
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const SCAN_RESULT: Partial<CodeScanResult> = {
  scan_uid: 'abc',
  file_path: 'src/users.py',
  findings: [],
  findings_count: 0,
  analysis_status: 'analyzed',
  cached: false,
}

afterEach(() => {
  ;(globalThis as { fetch: unknown }).fetch = realFetch
})

describe('BackendClient', () => {
  it("n'appelle que les routes /api/code/*", async () => {
    const urls: string[] = []
    stubFetch(async (input) => {
      urls.push(String(input))
      return jsonResponse({ status: 'ok' })
    })

    const client = new BackendClient({ baseUrl: 'http://127.0.0.1:8000/' })
    await client.health()

    assert.deepEqual(urls, ['http://127.0.0.1:8000/api/code/health'])
  })

  it('envoie le document et son empreinte au scan', async () => {
    let payload: Record<string, unknown> = {}
    stubFetch(async (_input, init) => {
      payload = JSON.parse(String(init?.body))
      return jsonResponse(SCAN_RESULT)
    })

    const client = new BackendClient({ baseUrl: 'http://127.0.0.1:8000' })
    await client.scan({
      file_path: 'src/users.py',
      language: 'python',
      content: 'x = 1\n',
      content_hash: 'deadbeef',
      workspace: 'projet',
      project_uid: null,
      ai_enrichment: false,
    })

    assert.equal(payload.file_path, 'src/users.py')
    // Le langage part tel que le filtre l'a résolu, sans transformation.
    assert.equal(payload.language, 'python')
    assert.equal(payload.content_hash, 'deadbeef')
    // Le workspace transmis est un identifiant, pas un chemin absolu.
    assert.equal(payload.workspace, 'projet')
    assert.equal(payload.ai_enrichment, false)
  })

  it('transmet la ligne courante à la proposition de correctif', async () => {
    let url = ''
    stubFetch(async (input) => {
      url = String(input)
      return jsonResponse({ finding_uid: 'f1', available: false, blockers: [] })
    })

    const client = new BackendClient({ baseUrl: 'http://127.0.0.1:8000' })
    await client.proposeFix('f1', 'requests.get(url, verify=False)')

    assert.match(url, /\/api\/code\/findings\/f1\/fix\?current_line=/)
    assert.match(url, /verify%3DFalse/)
  })

  it('enregistre une décision sur un finding', async () => {
    let body: Record<string, unknown> = {}
    stubFetch(async (_input, init) => {
      body = JSON.parse(String(init?.body))
      return jsonResponse({ finding_uid: 'f1', status: 'dismissed' })
    })

    const client = new BackendClient({ baseUrl: 'http://127.0.0.1:8000' })
    await client.decideFinding('f1', { status: 'dismissed', reason: 'faux positif' })

    assert.equal(body.status, 'dismissed')
    assert.equal(body.reason, 'faux positif')
  })

  // --- Traduction des codes HTTP ------------------------------------------

  const cases: Array<[number, RegExp]> = [
    [400, /refusée par le serveur/],
    [404, /introuvable/],
    [408, /délai imparti/],
    [422, /empreinte incorrecte/],
    [500, /erreur interne/],
    [502, /a répondu une erreur/],
    [503, /désactivée côté serveur/],
  ]

  for (const [status, pattern] of cases) {
    it(`traduit le code HTTP ${status} en message français`, async () => {
      stubFetch(async () => jsonResponse({ detail: { error: 'technique' } }, status))

      const client = new BackendClient({ baseUrl: 'http://127.0.0.1:8000' })
      await assert.rejects(
        () => client.health(),
        (error: unknown) => {
          assert.ok(error instanceof BackendError)
          assert.equal(error.status, status)
          assert.match(error.message, pattern)
          // Le détail technique reste séparé du message affiché.
          assert.ok(!error.message.includes('Error:'))
          return true
        }
      )
    })
  }

  it('signale un backend injoignable sans exposer la trace', async () => {
    stubFetch(async () => {
      throw new TypeError('fetch failed: ECONNREFUSED 127.0.0.1:8000')
    })

    const client = new BackendClient({ baseUrl: 'http://127.0.0.1:8000' })
    await assert.rejects(
      () => client.health(),
      (error: unknown) => {
        assert.ok(error instanceof BackendError)
        assert.equal(error.status, 0)
        assert.match(error.message, /ne répond pas/)
        assert.ok(!error.message.includes('ECONNREFUSED'))
        // La trace reste disponible pour le canal de sortie.
        assert.match(String(error.detail), /ECONNREFUSED/)
        return true
      }
    )
  })

  it('signale une réponse illisible', async () => {
    stubFetch(
      async () => new Response('<html>erreur</html>', { status: 200 })
    )

    const client = new BackendClient({ baseUrl: 'http://127.0.0.1:8000' })
    await assert.rejects(
      () => client.health(),
      (error: unknown) => {
        assert.ok(error instanceof BackendError)
        assert.match(error.message, /illisible/)
        return true
      }
    )
  })

  it('distingue une annulation d’une panne', async () => {
    const controller = new AbortController()
    stubFetch(async (_input, init) => {
      controller.abort()
      // Comme le vrai `fetch` : rejet dès que le signal est déclenché.
      throw Object.assign(new Error('aborted'), {
        name: 'AbortError',
        signal: init?.signal,
      })
    })

    const client = new BackendClient({ baseUrl: 'http://127.0.0.1:8000' })
    await assert.rejects(
      () =>
        client.scan(
          {
            file_path: 'a.py',
            language: 'python',
            content: 'x = 1\n',
            content_hash: 'h',
            workspace: null,
            project_uid: null,
            ai_enrichment: false,
          },
          controller.signal
        ),
      (error: unknown) => {
        assert.ok(error instanceof ScanCancelledError)
        assert.match(error.message, /annulée/)
        return true
      }
    )
  })

  it("extrait le message métier d'une erreur de validation FastAPI", async () => {
    stubFetch(async () =>
      jsonResponse(
        { detail: [{ msg: "Value error, L'empreinte annoncee ne correspond pas" }] },
        422
      )
    )

    const client = new BackendClient({ baseUrl: 'http://127.0.0.1:8000' })
    await assert.rejects(
      () => client.health(),
      (error: unknown) => {
        assert.ok(error instanceof BackendError)
        assert.match(String(error.detail), /empreinte annoncee/)
        assert.ok(!String(error.detail).startsWith('Value error'))
        return true
      }
    )
  })

  it('interroge /api/code/findings avec les filtres demandés', async () => {
    const urls: string[] = []
    stubFetch(async (input) => {
      urls.push(String(input))
      return jsonResponse([])
    })

    const client = new BackendClient({ baseUrl: 'http://127.0.0.1:8000' })
    await client.listFindings({ status: 'open', limit: 500 })

    assert.equal(urls.length, 1)
    const url = new URL(String(urls[0]))
    assert.equal(url.pathname, '/api/code/findings')
    assert.equal(url.searchParams.get('status'), 'open')
    assert.equal(url.searchParams.get('limit'), '500')
    // Les filtres non renseignés ne sont pas envoyés vides.
    assert.equal(url.searchParams.get('severity'), null)
    assert.equal(url.searchParams.get('file_path'), null)
  })

  it("n'ajoute aucun paramètre quand aucun filtre n'est demandé", async () => {
    const urls: string[] = []
    stubFetch(async (input) => {
      urls.push(String(input))
      return jsonResponse([])
    })

    const client = new BackendClient({ baseUrl: 'http://127.0.0.1:8000' })
    await client.listFindings()

    assert.deepEqual(urls, ['http://127.0.0.1:8000/api/code/findings'])
  })

  it("ignore une réponse de findings qui n'est pas une liste", async () => {
    // Un backend d'une autre version ne doit pas faire échouer la vue :
    // mieux vaut n'afficher aucun finding qu'en afficher de travers.
    stubFetch(async () => jsonResponse({ items: [] }))

    const client = new BackendClient({ baseUrl: 'http://127.0.0.1:8000' })
    assert.deepEqual(await client.listFindings(), [])
  })

  it('transmet la ligne courante intacte, caractères réservés compris', async () => {
    // Le backend s'en sert pour refuser si la ligne a bougé depuis
    // l'analyse : elle doit arriver intacte, y compris ses caractères
    // réservés.
    const urls: string[] = []
    const inits: (RequestInit | undefined)[] = []
    stubFetch(async (input, init) => {
      urls.push(String(input))
      inits.push(init)
      return jsonResponse({ finding_uid: 'uid-1', available: false })
    })

    const client = new BackendClient({ baseUrl: 'http://127.0.0.1:8000' })
    const line = 'cursor.execute("SELECT * FROM t WHERE a = " + b)  # &?=/'
    await client.proposeFix('uid-1', line)

    const url = new URL(String(urls[0]))
    assert.equal(url.pathname, '/api/code/findings/uid-1/fix')
    assert.equal(url.searchParams.get('current_line'), line)
    assert.equal(inits[0]?.method, 'POST')
  })

  it('omet current_line quand la ligne n’est pas fournie', async () => {
    const urls: string[] = []
    stubFetch(async (input) => {
      urls.push(String(input))
      return jsonResponse({ finding_uid: 'uid-1', available: false })
    })

    const client = new BackendClient({ baseUrl: 'http://127.0.0.1:8000' })
    await client.proposeFix('uid-1')

    assert.deepEqual(urls, ['http://127.0.0.1:8000/api/code/findings/uid-1/fix'])
  })

  it('envoie la décision complète de l’éditeur, actor compris', async () => {
    const inits: (RequestInit | undefined)[] = []
    const urls: string[] = []
    stubFetch(async (input, init) => {
      urls.push(String(input))
      inits.push(init)
      return jsonResponse({ finding_uid: 'uid-1', status: 'dismissed' })
    })

    const client = new BackendClient({ baseUrl: 'http://127.0.0.1:8000' })
    await client.decideFinding('uid-1', {
      status: 'dismissed',
      reason: 'Requête paramétrée par un décorateur',
      actor: 'vscode',
    })

    assert.equal(urls[0], 'http://127.0.0.1:8000/api/code/findings/uid-1/decision')
    assert.equal(inits[0]?.method, 'POST')
    assert.deepEqual(JSON.parse(String(inits[0]?.body)), {
      status: 'dismissed',
      reason: 'Requête paramétrée par un décorateur',
      actor: 'vscode',
    })
  })

  it('échappe un identifiant de finding inattendu', async () => {
    // Aucun identifiant ne doit pouvoir s'échapper du segment de chemin.
    const urls: string[] = []
    stubFetch(async (input) => {
      urls.push(String(input))
      return jsonResponse({ finding_uid: 'x', status: 'fixed' })
    })

    const client = new BackendClient({ baseUrl: 'http://127.0.0.1:8000' })
    await client.decideFinding('../../admin?x=1', { status: 'fixed' })

    assert.equal(
      urls[0],
      'http://127.0.0.1:8000/api/code/findings/..%2F..%2Fadmin%3Fx%3D1/decision'
    )
  })

  it('relit une analyse par son scan_uid', async () => {
    // Repli du flux temps réel : aucun contenu de fichier n'est renvoyé,
    // le backend répond depuis ce qu'il a déjà en base.
    const urls: string[] = []
    const inits: (RequestInit | undefined)[] = []
    stubFetch(async (input, init) => {
      urls.push(String(input))
      inits.push(init)
      return jsonResponse(SCAN_RESULT)
    })

    const client = new BackendClient({ baseUrl: 'http://127.0.0.1:8000' })
    const result = await client.getScan('abc123')

    assert.deepEqual(urls, ['http://127.0.0.1:8000/api/code/scans/abc123'])
    assert.equal(inits[0]?.method, 'GET')
    assert.equal(inits[0]?.body, undefined)
    assert.equal(result.scan_uid, 'abc')
  })

  it('signale proprement une analyse introuvable', async () => {
    stubFetch(async () => jsonResponse({ detail: { error: 'Analyse introuvable' } }, 404))

    const client = new BackendClient({ baseUrl: 'http://127.0.0.1:8000' })
    await assert.rejects(
      () => client.getScan('inconnu'),
      (error: unknown) => {
        assert.ok(error instanceof BackendError)
        assert.equal(error.status, 404)
        return true
      }
    )
  })

  it('respecte le changement d’adresse du backend', async () => {
    const urls: string[] = []
    stubFetch(async (input) => {
      urls.push(String(input))
      return jsonResponse({ status: 'ok' })
    })

    const client = new BackendClient({ baseUrl: 'http://127.0.0.1:8000' })
    client.setBaseUrl('http://192.168.1.10:9000/')
    await client.health()

    assert.equal(client.url, 'http://192.168.1.10:9000')
    assert.equal(urls[0], 'http://192.168.1.10:9000/api/code/health')
  })
})

describe('BackendClient — trace de diagnostic', () => {
  it('trace la méthode, l’URL et le code HTTP de chaque appel', async () => {
    stubFetch(async () => jsonResponse(SCAN_RESULT))

    const traces: string[] = []
    const client = new BackendClient({
      baseUrl: 'http://127.0.0.1:8000',
      onTrace: (message) => traces.push(message),
    })
    await client.scan({
      file_path: 'test.py',
      language: 'python',
      content: 'x = 1\n',
      content_hash: 'deadbeef',
      workspace: 'projet',
      project_uid: null,
      ai_enrichment: false,
    })

    assert.equal(traces.length, 2)
    assert.match(traces[0] ?? '', /POST http:\/\/127\.0\.0\.1:8000\/api\/code\/scan/)
    assert.match(traces[1] ?? '', /HTTP 200/)
    assert.match(traces[1] ?? '', /POST http:\/\/127\.0\.0\.1:8000\/api\/code\/scan/)
  })

  it('trace aussi un backend injoignable, plutôt que de se taire', async () => {
    stubFetch(async () => {
      throw new Error('ECONNREFUSED')
    })

    const traces: string[] = []
    const client = new BackendClient({
      baseUrl: 'http://127.0.0.1:8000',
      onTrace: (message) => traces.push(message),
    })

    await assert.rejects(() => client.health())
    assert.equal(traces.length, 2)
    assert.match(traces[1] ?? '', /aucune réponse/)
    assert.match(traces[1] ?? '', /ECONNREFUSED/)
  })

  it('ne fait jamais passer le contenu analysé dans la trace', async () => {
    stubFetch(async () => jsonResponse(SCAN_RESULT))

    const secret = 'password = "hunter2"\n'
    const traces: string[] = []
    const client = new BackendClient({
      baseUrl: 'http://127.0.0.1:8000',
      onTrace: (message) => traces.push(message),
    })
    await client.scan({
      file_path: 'test.py',
      language: 'python',
      content: secret,
      content_hash: 'deadbeef',
      workspace: 'projet',
      project_uid: null,
      ai_enrichment: false,
    })

    for (const trace of traces) {
      assert.ok(!trace.includes('hunter2'), `contenu divulgué : ${trace}`)
      assert.ok(!trace.includes('password'), `contenu divulgué : ${trace}`)
    }
  })

  it('reste utilisable sans trace configurée', async () => {
    stubFetch(async () => jsonResponse({ status: 'ok' }))
    const client = new BackendClient({ baseUrl: 'http://127.0.0.1:8000' })

    await client.health()
  })
})

// --------------------------------------------------------------------------
// Authentification (phase 0)
// --------------------------------------------------------------------------

describe('BackendClient — authentification', () => {
  it('joint le jeton à chaque requête', async () => {
    const headers: (Record<string, string> | undefined)[] = []
    stubFetch(async (_input, init) => {
      headers.push(init?.headers as Record<string, string> | undefined)
      return jsonResponse({ status: 'ok' })
    })

    const client = new BackendClient({
      baseUrl: 'http://127.0.0.1:8000',
      authHeader: async () => ({ Authorization: 'Bearer jeton-de-test' }),
    })
    await client.health()

    assert.equal(headers.length, 1)
    assert.equal(headers[0]?.Authorization, 'Bearer jeton-de-test')
  })

  it('conserve les en-têtes propres à la requête', async () => {
    // Le jeton s'ajoute, il ne remplace pas : un POST doit garder son
    // `Content-Type`, sinon le backend refuserait le corps JSON.
    const headers: Record<string, string>[] = []
    stubFetch(async (_input, init) => {
      headers.push(init?.headers as Record<string, string>)
      return jsonResponse(SCAN_RESULT)
    })

    const client = new BackendClient({
      baseUrl: 'http://127.0.0.1:8000',
      authHeader: async () => ({ Authorization: 'Bearer jeton' }),
    })
    await client.scan({
      file_path: 'a.py',
      language: 'python',
      content: 'x',
      content_hash: 'h',
      workspace: null,
      project_uid: null,
      ai_enrichment: false,
    })

    assert.equal(headers[0]!['Content-Type'], 'application/json')
    assert.equal(headers[0]!.Authorization, 'Bearer jeton')
  })

  it('part sans jeton quand aucun n’est disponible', async () => {
    // Le backend répondra 401 avec un message explicite : mieux qu'un échec
    // côté client, qui ne dirait pas si le backend tourne.
    const headers: Record<string, string>[] = []
    stubFetch(async (_input, init) => {
      headers.push((init?.headers ?? {}) as Record<string, string>)
      return jsonResponse({ status: 'ok' })
    })

    const client = new BackendClient({
      baseUrl: 'http://127.0.0.1:8000',
      authHeader: async () => undefined,
    })
    await client.health()

    assert.equal(headers[0]!.Authorization, undefined)
  })

  it('traduit un 401 en message actionnable', async () => {
    stubFetch(async () => jsonResponse({ detail: 'refusé' }, 401))

    const client = new BackendClient({ baseUrl: 'http://127.0.0.1:8000' })
    await assert.rejects(
      () => client.health(),
      (error: unknown) => {
        assert.ok(error instanceof BackendError)
        assert.equal(error.status, 401)
        // Un « erreur inattendue » laisserait l'utilisateur sans piste alors
        // que la cause et le remède sont connus.
        assert.match(error.message, /authentification/i)
        return true
      }
    )
  })
})

describe('BackendClient — reprise après 401', () => {
  it('relit le jeton et réessaie une fois', async () => {
    // Cas concret : le backend redémarre et régénère son jeton. Sans cette
    // reprise, l'extension resterait muette jusqu'au redémarrage de
    // l'éditeur.
    const presented: (string | undefined)[] = []
    let current = 'jeton-perime'

    stubFetch(async (_input, init) => {
      const header = (init?.headers as Record<string, string>)?.Authorization
      presented.push(header)
      if (header === 'Bearer jeton-neuf') {
        return jsonResponse({ status: 'ok' })
      }
      return jsonResponse({ detail: 'refusé' }, 401)
    })

    const client = new BackendClient({
      baseUrl: 'http://127.0.0.1:8000',
      authHeader: async () => ({ Authorization: `Bearer ${current}` }),
      onUnauthorized: async () => {
        current = 'jeton-neuf'
        return true
      },
    })

    const health = await client.health()
    assert.equal(health.status, 'ok')
    assert.deepEqual(presented, ['Bearer jeton-perime', 'Bearer jeton-neuf'])
  })

  it('ne réessaie qu’une seule fois', async () => {
    // Insister accumulerait des refus dans les journaux du backend sans
    // aucune chance de succès.
    let attempts = 0
    stubFetch(async () => {
      attempts += 1
      return jsonResponse({ detail: 'refusé' }, 401)
    })

    const client = new BackendClient({
      baseUrl: 'http://127.0.0.1:8000',
      authHeader: async () => ({ Authorization: 'Bearer jeton' }),
      onUnauthorized: async () => true,
    })

    await assert.rejects(() => client.health())
    assert.equal(attempts, 2)
  })

  it('ne réessaie pas si aucun nouveau jeton n’a été trouvé', async () => {
    let attempts = 0
    stubFetch(async () => {
      attempts += 1
      return jsonResponse({ detail: 'refusé' }, 401)
    })

    const client = new BackendClient({
      baseUrl: 'http://127.0.0.1:8000',
      authHeader: async () => ({ Authorization: 'Bearer jeton' }),
      onUnauthorized: async () => false,
    })

    await assert.rejects(() => client.health())
    assert.equal(attempts, 1)
  })

  it('ne réessaie pas sur un autre code d’erreur', async () => {
    let attempts = 0
    stubFetch(async () => {
      attempts += 1
      return jsonResponse({ detail: 'panne' }, 500)
    })

    const client = new BackendClient({
      baseUrl: 'http://127.0.0.1:8000',
      onUnauthorized: async () => true,
    })

    await assert.rejects(() => client.health())
    assert.equal(attempts, 1)
  })

  it('ne journalise jamais le jeton', async () => {
    const traces: string[] = []
    stubFetch(async () => jsonResponse({ detail: 'refusé' }, 401))

    const client = new BackendClient({
      baseUrl: 'http://127.0.0.1:8000',
      authHeader: async () => ({ Authorization: 'Bearer jeton-tres-secret' }),
      onUnauthorized: async () => true,
      onTrace: (message) => traces.push(message),
    })

    await assert.rejects(() => client.health())
    assert.ok(traces.length > 0)
    for (const trace of traces) {
      assert.ok(!trace.includes('jeton-tres-secret'), trace)
    }
  })
})

// --------------------------------------------------------------------------
// Routes de projet (phase 1)
// --------------------------------------------------------------------------

describe('BackendClient — routes de projet', () => {
  it('enregistre un projet', async () => {
    const seen: { url: string; body: unknown }[] = []
    stubFetch(async (input, init) => {
      seen.push({ url: String(input), body: JSON.parse(String(init?.body)) })
      return jsonResponse({ project_uid: 'uid-1', known: false })
    })

    const client = new BackendClient({ baseUrl: 'http://127.0.0.1:8000' })
    await client.discoverProject({
      root_hash: 'a'.repeat(64),
      project_name: 'App',
      discovery_version: '1.0.0',
    })

    assert.equal(seen[0]!.url, 'http://127.0.0.1:8000/api/project/discover')
    assert.deepEqual(seen[0]!.body, {
      root_hash: 'a'.repeat(64),
      project_name: 'App',
      discovery_version: '1.0.0',
    })
  })

  it('soumet l’index sur la route du projet', async () => {
    const urls: string[] = []
    stubFetch(async (input) => {
      urls.push(String(input))
      return jsonResponse({ project_uid: 'uid-1' })
    })

    const client = new BackendClient({ baseUrl: 'http://127.0.0.1:8000' })
    await client.submitProjectIndex('uid-1', {
      files: [],
      manifests: [],
      git: { detected: false, remote_host: null },
      discovered_count: 0,
      truncated: false,
      warnings: [],
      discovery_version: '1.0.0',
    })

    assert.deepEqual(urls, ['http://127.0.0.1:8000/api/project/uid-1/index'])
  })

  it('échappe l’identifiant dans l’URL', async () => {
    // L'identifiant vient du backend, mais l'échapper coûte une fonction et
    // ferme la question une fois pour toutes.
    const urls: string[] = []
    stubFetch(async (input) => {
      urls.push(String(input))
      return jsonResponse({ project_uid: 'x' })
    })

    const client = new BackendClient({ baseUrl: 'http://127.0.0.1:8000' })
    await client.getProjectContext('a/../b')
    assert.deepEqual(urls, ['http://127.0.0.1:8000/api/project/a%2F..%2Fb/context'])
  })

  it('filtre les findings par projet', async () => {
    const urls: string[] = []
    stubFetch(async (input) => {
      urls.push(String(input))
      return jsonResponse([])
    })

    const client = new BackendClient({ baseUrl: 'http://127.0.0.1:8000' })
    await client.listFindings({ status: 'open', project_uid: 'uid-1' })

    assert.match(urls[0]!, /project_uid=uid-1/)
    assert.doesNotMatch(urls[0]!, /current_only/)
  })

  it('demande le seul dernier scan de chaque fichier quand on le lui dit', async () => {
    const urls: string[] = []
    stubFetch(async (input) => {
      urls.push(String(input))
      return jsonResponse([])
    })

    const client = new BackendClient({ baseUrl: 'http://127.0.0.1:8000' })
    await client.listFindings({ status: 'open', project_uid: 'uid-1', current_only: true })

    assert.match(urls[0]!, /project_uid=uid-1/)
    assert.match(urls[0]!, /current_only=true/)
  })
})
