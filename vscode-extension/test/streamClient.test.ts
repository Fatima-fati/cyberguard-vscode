/**
 * Tests du client SSE.
 *
 * `fetch` et le minuteur sont injectés : aucune connexion réseau, aucune
 * attente réelle. La reconnexion est déclenchée à la main, ce qui rend
 * vérifiable une séquence qui prendrait une minute en temps réel.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  StreamClient,
  retryDelay,
  type Scheduled,
  type StreamEvent,
} from '../src/api/streamClient'

/** Minuteur contrôlé par le test : rien ne part tout seul. */
class FakeScheduler {
  readonly delays: number[] = []
  private pending: (() => void) | undefined
  private cancelled = false

  readonly schedule = (callback: () => void, delayMs: number): Scheduled => {
    this.delays.push(delayMs)
    this.pending = callback
    this.cancelled = false
    return {
      cancel: () => {
        this.cancelled = true
        this.pending = undefined
      },
    }
  }

  get wasCancelled(): boolean {
    return this.cancelled
  }

  get hasPending(): boolean {
    return this.pending !== undefined
  }

  /** Déclenche la reconnexion en attente. */
  async fire(): Promise<void> {
    const callback = this.pending
    this.pending = undefined
    callback?.()
    // Laisse la boucle de connexion se dérouler.
    await new Promise((resolve) => setImmediate(resolve))
  }
}

/** Réponse SSE servant les blocs fournis, puis se terminant. */
function sseResponse(blocks: readonly string[]): Response {
  const encoder = new TextEncoder()
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const block of blocks) {
        controller.enqueue(encoder.encode(block))
      }
      controller.close()
    },
  })

  return new Response(body, {
    status: 200,
    headers: { 'Content-Type': 'text/event-stream' },
  })
}

interface Harness {
  client: StreamClient
  events: StreamEvent[]
  logs: string[]
  scheduler: FakeScheduler
  calls: () => number
}

function harness(
  responder: (call: number) => Promise<Response>,
  events: readonly string[] = ['code_finding']
): Harness {
  const received: StreamEvent[] = []
  const logs: string[] = []
  const scheduler = new FakeScheduler()
  let calls = 0

  const client = new StreamClient({
    baseUrl: 'http://127.0.0.1:8000',
    events,
    onEvent: (event) => received.push(event),
    onLog: (message) => logs.push(message),
    fetchImpl: async () => {
      calls += 1
      return responder(calls)
    },
    scheduler: scheduler.schedule,
  })

  return { client, events: received, logs, scheduler, calls: () => calls }
}

/** Laisse la boucle de connexion aller jusqu'au bout du flux. */
async function settle(): Promise<void> {
  for (let index = 0; index < 5; index += 1) {
    await new Promise((resolve) => setImmediate(resolve))
  }
}

const FINDING_BLOCK =
  'event: code_finding\ndata: {"finding_uid":"f1","scan_uid":"s1","file_path":"users.py"}\n\n'

describe('retryDelay — temporisation progressive', () => {
  it('suit la séquence 1, 2, 4, 8, 16 puis plafonne à 30 s', () => {
    assert.deepEqual(
      [1, 2, 3, 4, 5, 6, 7].map(retryDelay),
      [1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000]
    )
  })

  it('ne déborde jamais sur une coupure très longue', () => {
    assert.equal(retryDelay(1_000), 30_000)
    assert.ok(Number.isFinite(retryDelay(Number.MAX_SAFE_INTEGER)))
  })

  it('reste défensif sur une tentative invalide', () => {
    assert.equal(retryDelay(0), 1_000)
    assert.equal(retryDelay(-5), 1_000)
  })
})

describe('StreamClient — réception', () => {
  it('livre un événement valide, décodé', async () => {
    const test = harness(async () => sseResponse([FINDING_BLOCK]))
    test.client.start()
    await settle()

    assert.equal(test.events.length, 1)
    assert.equal(test.events[0]?.event, 'code_finding')
    const data = test.events[0]?.data as Record<string, unknown>
    assert.equal(data.finding_uid, 'f1')
    assert.equal(data.scan_uid, 's1')

    test.client.dispose()
  })

  it('ignore un événement d’un autre type', async () => {
    // Les alertes Wazuh et les notifications IA passent sur le même flux.
    const test = harness(async () =>
      sseResponse([
        'event: alert\ndata: {"id":1}\n\n',
        'event: ai_notification\ndata: {"x":2}\n\n',
        'event: code_scan\ndata: {"scan_uid":"s1"}\n\n',
        FINDING_BLOCK,
      ])
    )
    test.client.start()
    await settle()

    assert.equal(test.events.length, 1)
    assert.equal(test.events[0]?.event, 'code_finding')

    test.client.dispose()
  })

  it('survit à une charge utile JSON invalide', async () => {
    const test = harness(async () =>
      sseResponse([
        'event: code_finding\ndata: {ceci n\'est pas du json\n\n',
        FINDING_BLOCK,
      ])
    )
    test.client.start()
    await settle()

    // Le bloc illisible est écarté, le suivant passe.
    assert.equal(test.events.length, 1)
    assert.equal((test.events[0]?.data as Record<string, unknown>).finding_uid, 'f1')

    test.client.dispose()
  })

  it('ignore les commentaires de maintien en vie', async () => {
    const test = harness(async () =>
      sseResponse([': heartbeat\n\n', FINDING_BLOCK])
    )
    test.client.start()
    await settle()

    assert.equal(test.events.length, 1)
    test.client.dispose()
  })

  it('accepte un bloc découpé en plusieurs morceaux réseau', async () => {
    const test = harness(async () =>
      sseResponse([
        'event: code_fin',
        'ding\ndata: {"finding_uid":"f1",',
        '"scan_uid":"s1"}\n\n',
      ])
    )
    test.client.start()
    await settle()

    assert.equal(test.events.length, 1)
    assert.equal((test.events[0]?.data as Record<string, unknown>).scan_uid, 's1')

    test.client.dispose()
  })

  it('tolère des fins de ligne \\r\\n', async () => {
    const test = harness(async () =>
      sseResponse([
        'event: code_finding\r\ndata: {"finding_uid":"f1"}\r\n\r\n',
      ])
    )
    test.client.start()
    await settle()

    assert.equal(test.events.length, 1)
    test.client.dispose()
  })

  it('ne laisse pas un consommateur défaillant casser le flux', async () => {
    const logs: string[] = []
    const scheduler = new FakeScheduler()
    let delivered = 0

    const client = new StreamClient({
      baseUrl: 'http://127.0.0.1:8000',
      events: ['code_finding'],
      onEvent: () => {
        delivered += 1
        throw new Error('consommateur défaillant')
      },
      onLog: (message) => logs.push(message),
      fetchImpl: async () => sseResponse([FINDING_BLOCK, FINDING_BLOCK]),
      scheduler: scheduler.schedule,
    })

    client.start()
    await settle()

    assert.equal(delivered, 2)
    client.dispose()
  })
})

describe('StreamClient — reconnexion', () => {
  it('reprogramme une connexion après une coupure', async () => {
    const test = harness(async () => {
      throw new Error('ECONNREFUSED')
    })

    test.client.start()
    await settle()

    assert.equal(test.calls(), 1)
    assert.deepEqual(test.scheduler.delays, [1_000])

    test.client.dispose()
  })

  it('espace les tentatives successives', async () => {
    const test = harness(async () => {
      throw new Error('ECONNREFUSED')
    })

    test.client.start()
    await settle()

    for (let index = 0; index < 5; index += 1) {
      await test.scheduler.fire()
      await settle()
    }

    assert.deepEqual(
      test.scheduler.delays,
      [1_000, 2_000, 4_000, 8_000, 16_000, 30_000]
    )
    assert.equal(test.calls(), 6)

    test.client.dispose()
  })

  it('repart d’une seconde après une connexion réussie', async () => {
    // Deux échecs, puis une connexion qui aboutit : le compteur retombe.
    const test = harness(async (call) => {
      if (call <= 2) {
        throw new Error('ECONNREFUSED')
      }
      return sseResponse([FINDING_BLOCK])
    })

    test.client.start()
    await settle()
    await test.scheduler.fire()
    await settle()
    await test.scheduler.fire()
    await settle()

    assert.deepEqual(test.scheduler.delays, [1_000, 2_000, 1_000])
    assert.equal(test.events.length, 1)

    test.client.dispose()
  })

  it('traite une réponse HTTP en erreur comme une coupure', async () => {
    const test = harness(async () => new Response('non', { status: 503 }))

    test.client.start()
    await settle()

    assert.deepEqual(test.scheduler.delays, [1_000])
    assert.equal(test.events.length, 0)

    test.client.dispose()
  })

  it('ne prévient jamais l’utilisateur, seulement le canal de sortie', async () => {
    const test = harness(async () => {
      throw new Error('ECONNREFUSED')
    })

    test.client.start()
    await settle()

    // Le seul canal est `onLog`. Aucune API de notification n'est
    // joignable depuis ce module : il n'importe pas `vscode`.
    assert.ok(test.logs.some((line) => /reconnexion/i.test(line)))

    test.client.dispose()
  })
})

describe('StreamClient — connexion unique', () => {
  it('ignore un second start()', async () => {
    const test = harness(async () => sseResponse([]))

    test.client.start()
    test.client.start()
    test.client.start()
    await settle()

    assert.equal(test.calls(), 1)
    test.client.dispose()
  })

  it('ne double pas la connexion quand la reconnexion se déclenche', async () => {
    const test = harness(async () => {
      throw new Error('ECONNREFUSED')
    })

    test.client.start()
    await settle()

    // `start()` pendant qu'une reconnexion est programmée ne relance rien.
    test.client.start()
    await settle()

    assert.equal(test.calls(), 1)
    test.client.dispose()
  })
})

describe('StreamClient — fermeture', () => {
  it('annule le minuteur de reconnexion', async () => {
    const test = harness(async () => {
      throw new Error('ECONNREFUSED')
    })

    test.client.start()
    await settle()
    assert.ok(test.scheduler.hasPending)

    test.client.dispose()

    assert.ok(test.scheduler.wasCancelled)
    assert.ok(!test.scheduler.hasPending)
  })

  it('ne se reconnecte plus après fermeture', async () => {
    const test = harness(async () => {
      throw new Error('ECONNREFUSED')
    })

    test.client.start()
    await settle()
    const before = test.calls()

    test.client.dispose()
    await settle()

    // Même en forçant le minuteur, plus rien ne repart.
    await test.scheduler.fire()
    await settle()

    assert.equal(test.calls(), before)
  })

  it('supporte plusieurs fermetures de suite', () => {
    const test = harness(async () => sseResponse([]))
    test.client.start()

    test.client.dispose()
    test.client.dispose()
    test.client.stop()

    assert.equal(test.client.connected, false)
  })

  it('peut être redémarré après fermeture', async () => {
    const test = harness(async () => sseResponse([FINDING_BLOCK]))

    test.client.start()
    await settle()
    test.client.stop()

    test.client.start()
    await settle()

    assert.equal(test.calls(), 2)
    assert.equal(test.events.length, 2)

    test.client.dispose()
  })
})

describe('StreamClient — journalisation', () => {
  it('ne journalise jamais la charge utile d’un événement', async () => {
    // Le flux transporte des extraits de code, et pourrait transporter un
    // secret détecté. Rien de tout cela ne doit finir dans un journal.
    const secret = 'AKIAIOSFODNN7EXAMPLE'
    const test = harness(async () =>
      sseResponse([
        `event: code_finding\ndata: {"finding_uid":"f1","snippet":"aws_key = '${secret}'"}\n\n`,
      ])
    )

    test.client.start()
    await settle()

    assert.equal(test.events.length, 1)
    const joined = test.logs.join('\n')
    assert.ok(!joined.includes(secret))
    assert.ok(!joined.includes('aws_key'))

    test.client.dispose()
  })

  it('ne journalise pas non plus une charge utile illisible', async () => {
    const secret = 'ghp_secretTokenValue123'
    const test = harness(async () =>
      sseResponse([`event: code_finding\ndata: {cassé ${secret}\n\n`])
    )

    test.client.start()
    await settle()

    const joined = test.logs.join('\n')
    assert.ok(!joined.includes(secret))
    // L'incident est bien signalé, mais sans son contenu.
    assert.ok(joined.includes('illisible'))

    test.client.dispose()
  })
})

// --------------------------------------------------------------------------
// Authentification et cloisonnement (phase 0)
// --------------------------------------------------------------------------

describe('StreamClient — authentification', () => {
  it('joint le jeton à la connexion', async () => {
    // Le flux porte des extraits du code analysé : ouvert sans contrôle, il
    // les livrait à n'importe quel processus local.
    const headers: Record<string, string>[] = []
    const scheduler = new FakeScheduler()

    const client = new StreamClient({
      baseUrl: 'http://127.0.0.1:8000',
      events: ['code_finding'],
      onEvent: () => undefined,
      scheduler: scheduler.schedule,
      authHeader: async () => ({ Authorization: 'Bearer jeton-de-test' }),
      fetchImpl: async (_input, init) => {
        headers.push((init?.headers ?? {}) as Record<string, string>)
        return new Response(null, { status: 500 })
      },
    })

    client.start()
    await settle()
    client.dispose()

    assert.equal(headers.length, 1)
    assert.equal(headers[0]!.Authorization, 'Bearer jeton-de-test')
    // L'en-tête SSE d'origine est conservé.
    assert.equal(headers[0]!.Accept, 'text/event-stream')
  })

  it('résout le jeton à chaque tentative, pas une fois pour toutes', async () => {
    // Le backend a pu redémarrer pendant la coupure avec un nouveau jeton.
    // Une valeur capturée au démarrage condamnerait le flux jusqu'au
    // redémarrage de l'éditeur.
    const presented: (string | undefined)[] = []
    const scheduler = new FakeScheduler()
    let current = 'jeton-1'

    const client = new StreamClient({
      baseUrl: 'http://127.0.0.1:8000',
      events: ['code_finding'],
      onEvent: () => undefined,
      scheduler: scheduler.schedule,
      authHeader: async () => ({ Authorization: `Bearer ${current}` }),
      fetchImpl: async (_input, init) => {
        presented.push((init?.headers as Record<string, string>)?.Authorization)
        return new Response(null, { status: 500 })
      },
    })

    client.start()
    await settle()

    current = 'jeton-2'
    scheduler.fire()
    await settle()
    client.dispose()

    assert.deepEqual(presented, ['Bearer jeton-1', 'Bearer jeton-2'])
  })

  it('se connecte sans en-tête quand aucun jeton n’est disponible', async () => {
    const headers: Record<string, string>[] = []
    const scheduler = new FakeScheduler()

    const client = new StreamClient({
      baseUrl: 'http://127.0.0.1:8000',
      events: ['code_finding'],
      onEvent: () => undefined,
      scheduler: scheduler.schedule,
      authHeader: async () => undefined,
      fetchImpl: async (_input, init) => {
        headers.push((init?.headers ?? {}) as Record<string, string>)
        return new Response(null, { status: 500 })
      },
    })

    client.start()
    await settle()
    client.dispose()

    assert.equal(headers[0]!.Authorization, undefined)
  })

  it('trace un refus d’authentification de façon distincte', async () => {
    // Sans cette trace, la temporisation progressive rendrait un jeton
    // périmé indiscernable d'un backend éteint — deux causes qui se
    // corrigent différemment.
    const traces: string[] = []
    const scheduler = new FakeScheduler()

    const client = new StreamClient({
      baseUrl: 'http://127.0.0.1:8000',
      events: ['code_finding'],
      onEvent: () => undefined,
      onLog: (message) => traces.push(message),
      scheduler: scheduler.schedule,
      fetchImpl: async () => new Response(null, { status: 401 }),
    })

    client.start()
    await settle()
    client.dispose()

    assert.ok(
      traces.some((trace) => /authentification/i.test(trace)),
      traces.join(' | ')
    )
  })

  it('ne journalise jamais le jeton', async () => {
    const traces: string[] = []
    const scheduler = new FakeScheduler()

    const client = new StreamClient({
      baseUrl: 'http://127.0.0.1:8000',
      events: ['code_finding'],
      onEvent: () => undefined,
      onLog: (message) => traces.push(message),
      scheduler: scheduler.schedule,
      authHeader: async () => ({ Authorization: 'Bearer jeton-tres-secret' }),
      fetchImpl: async () => new Response(null, { status: 401 }),
    })

    client.start()
    await settle()
    client.dispose()

    for (const trace of traces) {
      assert.ok(!trace.includes('jeton-tres-secret'), trace)
    }
  })
})

describe('StreamClient — portée par projet', () => {
  it('déclare le projet dans l’URL', async () => {
    const urls: string[] = []
    const scheduler = new FakeScheduler()

    const client = new StreamClient({
      baseUrl: 'http://127.0.0.1:8000',
      events: ['code_finding'],
      onEvent: () => undefined,
      scheduler: scheduler.schedule,
      projectUid: () => 'uid-1',
      fetchImpl: async (input) => {
        urls.push(String(input))
        return new Response(null, { status: 500 })
      },
    })

    client.start()
    await settle()
    client.dispose()

    assert.deepEqual(urls, ['http://127.0.0.1:8000/api/stream?project_uid=uid-1'])
  })

  it('n’ajoute rien quand aucun projet n’est établi', async () => {
    // Le flux reste utilisable pour un fichier ouvert hors de tout dossier ;
    // il ne recevra simplement aucun `code_finding`, ce qui est le
    // comportement voulu du cloisonnement.
    const urls: string[] = []
    const scheduler = new FakeScheduler()

    const client = new StreamClient({
      baseUrl: 'http://127.0.0.1:8000',
      events: ['code_finding'],
      onEvent: () => undefined,
      scheduler: scheduler.schedule,
      projectUid: () => undefined,
      fetchImpl: async (input) => {
        urls.push(String(input))
        return new Response(null, { status: 500 })
      },
    })

    client.start()
    await settle()
    client.dispose()

    assert.deepEqual(urls, ['http://127.0.0.1:8000/api/stream'])
  })

  it('résout le projet à chaque connexion', async () => {
    // Le dossier ouvert peut changer pendant une coupure : réutiliser
    // l'ancien identifiant abonnerait le flux au projet précédent.
    const urls: string[] = []
    const scheduler = new FakeScheduler()
    let current: string | undefined = 'uid-a'

    const client = new StreamClient({
      baseUrl: 'http://127.0.0.1:8000',
      events: ['code_finding'],
      onEvent: () => undefined,
      scheduler: scheduler.schedule,
      projectUid: () => current,
      fetchImpl: async (input) => {
        urls.push(String(input))
        return new Response(null, { status: 500 })
      },
    })

    client.start()
    await settle()

    current = 'uid-b'
    scheduler.fire()
    await settle()
    client.dispose()

    assert.match(urls[0]!, /project_uid=uid-a/)
    assert.match(urls[1]!, /project_uid=uid-b/)
  })

  it('échappe l’identifiant de projet', async () => {
    const urls: string[] = []
    const scheduler = new FakeScheduler()

    const client = new StreamClient({
      baseUrl: 'http://127.0.0.1:8000',
      events: ['code_finding'],
      onEvent: () => undefined,
      scheduler: scheduler.schedule,
      projectUid: () => 'a&b=c',
      fetchImpl: async (input) => {
        urls.push(String(input))
        return new Response(null, { status: 500 })
      },
    })

    client.start()
    await settle()
    client.dispose()

    assert.deepEqual(urls, ['http://127.0.0.1:8000/api/stream?project_uid=a%26b%3Dc'])
  })
})
