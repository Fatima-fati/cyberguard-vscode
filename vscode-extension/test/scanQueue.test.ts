/**
 * Tests de la file d'analyses de la surveillance continue.
 *
 * C'est cette file qui décide si l'éditeur reste utilisable pendant qu'un
 * `git checkout` remue deux cents fichiers. Ses règles se vérifient sans
 * VS Code, sans backend et — surtout — **sans minuteur réel** : les
 * minuteurs sont injectés, et le test les fait avancer lui-même. Attendre
 * réellement 1 200 ms produirait des tests lents et intermittents.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import type { RequiredAnalyses } from '../src/monitor/changeClassification'
import {
  DEFAULT_DEBOUNCE_MS,
  ScanQueue,
  type MonitorState,
  type QueueTimers,
  type ScanJob,
} from '../src/monitor/scanQueue'

// --------------------------------------------------------------------------
// Horloge de test
// --------------------------------------------------------------------------

/**
 * Minuteurs pilotés à la main.
 *
 * `advance(ms)` déclenche tout ce qui était dû. Le test contrôle ainsi
 * exactement quand l'anti-rebond expire, et peut vérifier qu'il n'a
 * **pas** expiré une milliseconde plus tôt.
 */
class FakeTimers implements QueueTimers {
  private now = 0
  private sequence = 0
  private readonly scheduled = new Map<
    number,
    { dueAt: number; callback: () => void }
  >()

  setTimeout(callback: () => void, delayMs: number): unknown {
    const handle = (this.sequence += 1)
    this.scheduled.set(handle, { dueAt: this.now + delayMs, callback })
    return handle
  }

  clearTimeout(handle: unknown): void {
    this.scheduled.delete(handle as number)
  }

  advance(ms: number): void {
    this.now += ms
    // Copie avant parcours : un rappel peut reprogrammer un minuteur, et
    // muter la table pendant qu'on l'itère produirait un comportement
    // dépendant de l'ordre d'insertion.
    for (const [handle, entry] of [...this.scheduled]) {
      if (entry.dueAt <= this.now) {
        this.scheduled.delete(handle)
        entry.callback()
      }
    }
  }

  get pendingTimers(): number {
    return this.scheduled.size
  }
}

/** Laisse tourner les microtâches : la file ne s'attend jamais elle-même. */
async function settle(times = 4): Promise<void> {
  for (let index = 0; index < times; index += 1) {
    await Promise.resolve()
  }
}

const CODE: RequiredAnalyses = { code: true, secrets: true, dependencies: false }
const SECRETS: RequiredAnalyses = { code: false, secrets: true, dependencies: false }
const DEPENDENCIES: RequiredAnalyses = {
  code: false,
  secrets: true,
  dependencies: true,
}

function job(path: string, overrides: Partial<ScanJob> = {}): ScanJob {
  return { path, analyses: CODE, removed: false, ...overrides }
}

/** Fabrique une file et la trace : travaux exécutés, états, abandons. */
function harness(
  options: {
    debounceMs?: number
    maxConcurrent?: number
    maxQueued?: number
    run?: (job: ScanJob, signal: AbortSignal) => Promise<void>
  } = {}
) {
  const timers = new FakeTimers()
  const executed: ScanJob[] = []
  const states: MonitorState[] = []
  const dropped: string[] = []
  const errors: { path: string; error: unknown }[] = []

  const queue = new ScanQueue({
    timers,
    debounceMs: options.debounceMs ?? DEFAULT_DEBOUNCE_MS,
    ...(options.maxConcurrent !== undefined
      ? { maxConcurrent: options.maxConcurrent }
      : {}),
    ...(options.maxQueued !== undefined ? { maxQueued: options.maxQueued } : {}),
    run: async (item, signal) => {
      executed.push(item)
      if (options.run) {
        await options.run(item, signal)
      }
    },
    onStateChange: (state) => states.push(state),
    onDropped: (path) => dropped.push(path),
    onError: (path, error) => errors.push({ path, error }),
  })

  return { queue, timers, executed, states, dropped, errors }
}

// --------------------------------------------------------------------------
// Anti-rebond
// --------------------------------------------------------------------------

describe('ScanQueue — anti-rebond des sauvegardes rapprochées', () => {
  it("n'exécute rien avant l'échéance", async () => {
    const { queue, timers, executed } = harness({ debounceMs: 1_000 })

    queue.submit(job('src/app.py'))
    timers.advance(999)
    await settle()

    assert.equal(executed.length, 0, 'aucune analyse ne doit partir trop tôt')
    queue.dispose()
  })

  it('regroupe dix sauvegardes en une seule analyse', async () => {
    const { queue, timers, executed } = harness({ debounceMs: 1_000 })

    // Dix `Ctrl+S` en rafale, chacun avant l'expiration du précédent.
    for (let index = 0; index < 10; index += 1) {
      queue.submit(job('src/app.py'))
      timers.advance(100)
    }

    timers.advance(1_000)
    await settle()

    assert.equal(executed.length, 1, 'une rafale ne doit produire qu’un travail')
    assert.equal(executed[0]?.path, 'src/app.py')
    queue.dispose()
  })

  it('reprogramme le délai à chaque nouvelle sauvegarde', async () => {
    const { queue, timers, executed } = harness({ debounceMs: 1_000 })

    queue.submit(job('src/app.py'))
    timers.advance(900)
    // Une sauvegarde de plus : le compte repart de zéro, il ne reste pas
    // 100 ms à courir.
    queue.submit(job('src/app.py'))
    timers.advance(900)
    await settle()

    assert.equal(executed.length, 0)

    timers.advance(200)
    await settle()
    assert.equal(executed.length, 1)
    queue.dispose()
  })
})

// --------------------------------------------------------------------------
// Dédoublonnage
// --------------------------------------------------------------------------

describe('ScanQueue — aucun travail en double', () => {
  it('ne retient qu’une entrée par chemin', () => {
    const { queue, timers } = harness({ debounceMs: 1_000 })

    queue.submit(job('src/app.py'))
    queue.submit(job('src/app.py'))
    queue.submit(job('src/app.py'))

    assert.equal(queue.pendingCount, 1, 'trois soumissions, une seule entrée')
    timers.advance(1_000)
    assert.equal(queue.readyCount + queue.runningCount <= 1, true)
    queue.dispose()
  })

  it('fusionne les analyses demandées plutôt que d’empiler des travaux', async () => {
    const { queue, timers, executed } = harness({ debounceMs: 1_000 })

    // Le même `package.json` vu deux fois : une fois pour ses secrets,
    // une fois pour ses dépendances. Un seul travail doit porter les deux.
    queue.submit(job('package.json', { analyses: SECRETS }))
    queue.submit(job('package.json', { analyses: DEPENDENCIES }))

    timers.advance(1_000)
    await settle()

    assert.equal(executed.length, 1)
    assert.deepEqual(executed[0]?.analyses, {
      code: false,
      secrets: true,
      dependencies: true,
    })
    queue.dispose()
  })

  it('ne perd pas la suppression la plus récente', async () => {
    const { queue, timers, executed } = harness({ debounceMs: 1_000 })

    queue.submit(job('src/old.py', { removed: false }))
    queue.submit(job('src/old.py', { removed: true }))

    timers.advance(1_000)
    await settle()

    assert.equal(executed.length, 1)
    assert.equal(executed[0]?.removed, true, 'l’état le plus récent gagne')
    queue.dispose()
  })

  it('remet en attente un chemin resoumis alors qu’il était prêt', async () => {
    let release: (() => void) | undefined
    const { queue, timers, executed } = harness({
      debounceMs: 1_000,
      maxConcurrent: 1,
      run: () => new Promise<void>((resolve) => (release = resolve)),
    })

    // `a` occupe l'unique place ; `b` devient prêt et attend son tour.
    queue.submit(job('a.py'))
    timers.advance(1_000)
    await settle()
    queue.submit(job('b.py', { analyses: SECRETS }))
    timers.advance(1_000)
    await settle()

    assert.equal(queue.readyCount, 1, 'b attend une place')

    // `b` resoumis pendant qu'il patiente : toujours un seul travail.
    queue.submit(job('b.py', { analyses: CODE }))
    assert.equal(queue.readyCount + queue.pendingCount, 1)

    timers.advance(1_000)
    release?.()
    await settle(8)

    const forB = executed.filter((item) => item.path === 'b.py')
    assert.equal(forB.length, 1, 'b n’est analysé qu’une fois')
    assert.deepEqual(forB[0]?.analyses, {
      code: true,
      secrets: true,
      dependencies: false,
    })
    queue.dispose()
  })
})

// --------------------------------------------------------------------------
// Une seule analyse par fichier
// --------------------------------------------------------------------------

describe('ScanQueue — une seule analyse par fichier à la fois', () => {
  it('annule le travail en vol quand le fichier change encore', async () => {
    const aborted: string[] = []
    let release: (() => void) | undefined

    const { queue, timers } = harness({
      debounceMs: 500,
      run: (item, signal) =>
        new Promise<void>((resolve) => {
          signal.addEventListener('abort', () => aborted.push(item.path))
          release = resolve
        }),
    })

    queue.submit(job('src/app.py'))
    timers.advance(500)
    await settle()
    assert.equal(queue.runningCount, 1)

    // Nouvelle sauvegarde : l'analyse en vol porte sur un contenu périmé.
    queue.submit(job('src/app.py'))
    await settle()

    assert.deepEqual(aborted, ['src/app.py'])
    release?.()
    queue.dispose()
  })

  it('ne démarre jamais deux travaux pour le même chemin', async () => {
    const running: string[] = []
    let concurrentForSamePath = 0
    const releases: (() => void)[] = []

    const { queue, timers } = harness({
      debounceMs: 100,
      maxConcurrent: 4,
      run: (item) =>
        new Promise<void>((resolve) => {
          if (running.includes(item.path)) {
            concurrentForSamePath += 1
          }
          running.push(item.path)
          releases.push(() => {
            running.splice(running.indexOf(item.path), 1)
            resolve()
          })
        }),
    })

    queue.submit(job('a.py'))
    timers.advance(100)
    await settle()
    queue.submit(job('b.py'))
    timers.advance(100)
    await settle()

    assert.equal(concurrentForSamePath, 0)
    assert.equal(queue.runningCount, 2)
    for (const release of releases) {
      release()
    }
    queue.dispose()
  })
})

// --------------------------------------------------------------------------
// Concurrence et contre-pression
// --------------------------------------------------------------------------

describe('ScanQueue — concurrence bornée', () => {
  it('ne dépasse jamais la limite de travaux simultanés', async () => {
    let peak = 0
    const releases: (() => void)[] = []

    const { queue, timers } = harness({
      debounceMs: 100,
      maxConcurrent: 2,
      run: () =>
        new Promise<void>((resolve) => {
          releases.push(resolve)
        }),
    })

    for (const name of ['a', 'b', 'c', 'd', 'e']) {
      queue.submit(job(`${name}.py`))
    }
    timers.advance(100)
    await settle(8)
    peak = Math.max(peak, queue.runningCount)

    assert.equal(peak, 2, 'deux travaux au plus')
    assert.equal(queue.readyCount, 3, 'les autres attendent')

    // Une place se libère : exactement un travail démarre.
    releases.shift()?.()
    await settle(8)
    assert.equal(queue.runningCount, 2)
    assert.equal(queue.readyCount, 2)

    for (const release of releases) {
      release()
    }
    queue.dispose()
  })
})

describe('ScanQueue — contre-pression', () => {
  it('abandonne les travaux ordinaires les plus anciens au-delà du plafond', () => {
    const { queue, dropped } = harness({ debounceMs: 1_000, maxQueued: 3 })

    queue.submit(job('a.py'))
    queue.submit(job('b.py'))
    queue.submit(job('c.py'))
    queue.submit(job('d.py'))

    assert.equal(queue.pendingCount, 3, 'la file reste sous son plafond')
    assert.deepEqual(dropped, ['a.py'], 'le plus ancien part en premier')
    assert.equal(queue.droppedCount, 1)
    queue.dispose()
  })

  it("n'abandonne jamais le fichier que l'utilisateur vient d'éditer", () => {
    const { queue, dropped } = harness({ debounceMs: 1_000, maxQueued: 2 })

    queue.submit(job('edited.py', { priority: 'high' }))
    queue.submit(job('background-1.py'))
    queue.submit(job('background-2.py'))

    assert.equal(dropped.includes('edited.py'), false)
    assert.deepEqual(dropped, ['background-1.py'])
    queue.dispose()
  })

  it('journalise chaque abandon plutôt que de perdre un travail en silence', () => {
    const { queue, dropped } = harness({ debounceMs: 1_000, maxQueued: 1 })

    queue.submit(job('a.py'))
    queue.submit(job('b.py'))
    queue.submit(job('c.py'))

    // Une file de sécurité qui perd des travaux sans le dire ferait croire
    // à une surveillance complète qui n'a pas eu lieu.
    assert.equal(dropped.length, queue.droppedCount)
    assert.equal(queue.droppedCount, 2)
    queue.dispose()
  })
})

// --------------------------------------------------------------------------
// Priorité
// --------------------------------------------------------------------------

describe('ScanQueue — priorité au fichier édité', () => {
  /**
   * File dont les travaux ne se terminent jamais d'eux-mêmes.
   *
   * L'ordre d'attente n'est observable que si la place d'exécution reste
   * occupée : avec une exécution instantanée, la file se viderait avant
   * qu'on puisse la lire.
   */
  function blocked() {
    const releases: (() => void)[] = []
    const harnessed = harness({
      debounceMs: 100,
      maxConcurrent: 1,
      run: () => new Promise<void>((resolve) => releases.push(resolve)),
    })
    return { ...harnessed, releases }
  }

  it('fait passer le fichier prioritaire devant la rafale de fond', async () => {
    const { queue, timers, releases } = blocked()

    // Un `git checkout` remplit la file…
    for (let index = 0; index < 5; index += 1) {
      queue.submit(job(`vendor-${index}.py`))
    }
    // …et l'utilisateur sauvegarde le fichier qu'il a sous les yeux.
    queue.submit(job('edited.py', { priority: 'high' }))
    timers.advance(100)
    await settle(8)

    // Le premier arrivé occupe la place d'exécution ; le prioritaire est
    // en tête de ce qui reste, et non en sixième position.
    assert.equal(queue.runningCount, 1)
    assert.equal(queue.readyOrder[0], 'edited.py')

    for (const release of releases) {
      release()
    }
    queue.dispose()
  })

  it('conserve l’ordre d’arrivée à l’intérieur d’une même priorité', async () => {
    const { queue, timers, releases } = blocked()

    queue.submit(job('first.py', { priority: 'high' }))
    queue.submit(job('second.py', { priority: 'high' }))
    queue.submit(job('third.py', { priority: 'high' }))
    timers.advance(100)
    await settle(8)

    assert.deepEqual([...queue.readyOrder], ['second.py', 'third.py'])

    for (const release of releases) {
      release()
    }
    queue.dispose()
  })

  it('ne redescend jamais une priorité déjà accordée', async () => {
    const { queue, timers, releases } = blocked()

    queue.submit(job('busy.py'))
    timers.advance(100)
    await settle(8)

    queue.submit(job('edited.py', { priority: 'high' }))
    // Un événement de fond resoumet le même chemin en `normal` : il reste
    // prioritaire, parce que l'utilisateur l'a touché.
    queue.submit(job('edited.py', { priority: 'normal' }))
    queue.submit(job('other.py'))
    timers.advance(100)
    await settle(8)

    assert.equal(queue.readyOrder[0], 'edited.py')

    for (const release of releases) {
      release()
    }
    queue.dispose()
  })
})

// --------------------------------------------------------------------------
// Annulation
// --------------------------------------------------------------------------

describe('ScanQueue — annulation', () => {
  it('retire un chemin en attente', () => {
    const { queue } = harness({ debounceMs: 1_000 })

    queue.submit(job('src/app.py'))
    assert.equal(queue.pendingCount, 1)

    queue.cancel('src/app.py')
    assert.equal(queue.pendingCount, 0)
    assert.equal(queue.isIdle, true)
    queue.dispose()
  })

  it('interrompt un travail en cours par son signal', async () => {
    let seen: AbortSignal | undefined
    let release: (() => void) | undefined

    const { queue, timers } = harness({
      debounceMs: 100,
      run: (_item, signal) =>
        new Promise<void>((resolve) => {
          seen = signal
          release = resolve
        }),
    })

    queue.submit(job('src/app.py'))
    timers.advance(100)
    await settle()

    assert.equal(seen?.aborted, false)
    queue.cancel('src/app.py')
    assert.equal(seen?.aborted, true)

    release?.()
    queue.dispose()
  })

  it('ne compte pas une annulation comme une erreur', async () => {
    const { queue, timers, errors, states } = harness({
      debounceMs: 100,
      run: (_item, signal) =>
        new Promise<void>((_resolve, reject) => {
          signal.addEventListener('abort', () => {
            const error = new Error('aborted')
            error.name = 'AbortError'
            reject(error)
          })
        }),
    })

    queue.submit(job('src/app.py'))
    timers.advance(100)
    await settle()
    queue.cancel('src/app.py')
    await settle(8)

    assert.deepEqual(errors, [], 'une annulation est un déroulement normal')
    assert.equal(states.includes('ERROR'), false)
    queue.dispose()
  })

  it('`cancelAll` vide les trois emplacements', async () => {
    const releases: (() => void)[] = []
    const { queue, timers } = harness({
      debounceMs: 100,
      maxConcurrent: 1,
      run: () => new Promise<void>((resolve) => releases.push(resolve)),
    })

    queue.submit(job('running.py'))
    timers.advance(100)
    await settle()
    queue.submit(job('ready.py'))
    timers.advance(100)
    await settle()
    queue.submit(job('pending.py'))

    assert.equal(queue.runningCount, 1)
    assert.equal(queue.readyCount, 1)
    assert.equal(queue.pendingCount, 1)

    queue.cancelAll()
    assert.equal(queue.pendingCount, 0)
    assert.equal(queue.readyCount, 0)

    for (const release of releases) {
      release()
    }
    await settle(8)
    assert.equal(queue.isIdle, true)
    queue.dispose()
  })

  it('n’accepte plus rien après `dispose`', () => {
    const { queue, timers } = harness({ debounceMs: 100 })
    queue.dispose()

    queue.submit(job('src/app.py'))
    assert.equal(queue.pendingCount, 0)
    assert.equal(timers.pendingTimers, 0, 'aucun minuteur ne survit')
  })
})

// --------------------------------------------------------------------------
// État affiché
// --------------------------------------------------------------------------

describe('ScanQueue — état READY / ANALYZING / ERROR', () => {
  it('part de READY et passe à ANALYZING dès qu’un travail est retenu', async () => {
    const { queue, timers, states } = harness({ debounceMs: 100 })

    assert.equal(queue.currentState, 'READY')

    queue.submit(job('src/app.py'))
    assert.equal(queue.currentState, 'ANALYZING')

    timers.advance(100)
    await settle(8)
    assert.equal(queue.currentState, 'READY')
    assert.deepEqual(states, ['ANALYZING', 'READY'])
    queue.dispose()
  })

  it('ne clignote pas pendant une rafale', async () => {
    const { queue, timers, states } = harness({ debounceMs: 100 })

    for (let index = 0; index < 20; index += 1) {
      queue.submit(job(`file-${index}.py`))
    }
    timers.advance(100)
    await settle(16)

    // Une transition à l'entrée, une au retour au calme. Pas quarante.
    assert.deepEqual(states, ['ANALYZING', 'READY'])
    queue.dispose()
  })

  it('passe en ERROR quand un travail échoue, et le signale', async () => {
    const { queue, timers, errors } = harness({
      debounceMs: 100,
      run: async () => {
        throw new Error('backend injoignable')
      },
    })

    queue.submit(job('src/app.py'))
    timers.advance(100)
    await settle(8)

    assert.equal(queue.currentState, 'ERROR')
    assert.equal(errors.length, 1)
    assert.equal(errors[0]?.path, 'src/app.py')
    queue.dispose()
  })

  it('revient à READY dès qu’un travail aboutit', async () => {
    let shouldFail = true
    const { queue, timers } = harness({
      debounceMs: 100,
      run: async () => {
        if (shouldFail) {
          throw new Error('panne passagère')
        }
      },
    })

    queue.submit(job('a.py'))
    timers.advance(100)
    await settle(8)
    assert.equal(queue.currentState, 'ERROR')

    shouldFail = false
    queue.submit(job('b.py'))
    timers.advance(100)
    await settle(8)

    assert.equal(queue.currentState, 'READY', 'une réussite efface l’erreur')
    queue.dispose()
  })
})

// --------------------------------------------------------------------------
// Non-blocage
// --------------------------------------------------------------------------

describe('ScanQueue — ne bloque jamais l’appelant', () => {
  it('`submit` rend la main avant toute exécution', () => {
    let started = false
    const { queue, timers } = harness({
      debounceMs: 0,
      run: async () => {
        started = true
      },
    })

    queue.submit(job('src/app.py'))
    // Même avec un anti-rebond nul, rien n'a tourné pendant `submit` :
    // l'exécution passe par un minuteur, donc par la boucle d'événements.
    assert.equal(started, false)

    timers.advance(0)
    assert.equal(started, true)
    queue.dispose()
  })
})
