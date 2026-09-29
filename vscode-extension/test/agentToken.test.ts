/**
 * Tests de la résolution du jeton d'authentification.
 *
 * Réserve de secrets et système de fichiers sont injectés : aucun accès au
 * trousseau réel, aucune lecture du profil de l'utilisateur, et surtout
 * aucun risque d'écraser le jeton de sa machine.
 *
 * Ce qui est vérifié en priorité : **le jeton n'apparaît dans aucune
 * trace.** Le journal est le support qui fuit le plus facilement — il est
 * collé dans des rapports de bug et partagé sans relecture.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { AgentToken, defaultTokenPath, type SecretVault } from '../src/api/agentToken'

const JETON = 'jeton-de-test-aBcDeF123456'

/** Réserve en mémoire, avec la trace des appels. */
class FakeVault implements SecretVault {
  private readonly values = new Map<string, string>()
  readonly stored: string[] = []
  readonly deleted: string[] = []
  failing = false

  constructor(initial?: Record<string, string>) {
    for (const [key, value] of Object.entries(initial ?? {})) {
      this.values.set(key, value)
    }
  }

  async get(key: string): Promise<string | undefined> {
    if (this.failing) {
      throw new Error('trousseau indisponible')
    }
    return this.values.get(key)
  }

  async store(key: string, value: string): Promise<void> {
    if (this.failing) {
      throw new Error('trousseau indisponible')
    }
    this.values.set(key, value)
    this.stored.push(key)
  }

  async delete(key: string): Promise<void> {
    if (this.failing) {
      throw new Error('trousseau indisponible')
    }
    this.values.delete(key)
    this.deleted.push(key)
  }

  has(key: string): boolean {
    return this.values.has(key)
  }
}

/** Lecteur de fichier scripté. */
function fileReader(content: string | Error): (file: string) => Promise<string> {
  return async () => {
    if (content instanceof Error) {
      throw content
    }
    return content
  }
}

function missingFile(): Error {
  const error = new Error('fichier absent') as Error & { code: string }
  error.code = 'ENOENT'
  return error
}

describe('AgentToken — résolution', () => {
  it('lit le jeton de la réserve en priorité', async () => {
    const vault = new FakeVault({ 'wazuhSecurity.agentToken': JETON })
    let fileRead = false

    const token = new AgentToken({
      vault,
      tokenPath: '/inexistant',
      readFile: async () => {
        fileRead = true
        return 'autre-valeur'
      },
    })

    const { token: value, origin } = await token.resolve()
    assert.equal(value, JETON)
    assert.equal(origin, 'secretStorage')
    // Le fichier n'est pas lu quand la réserve répond : un accès disque de
    // moins sur le chemin courant.
    assert.equal(fileRead, false)
  })

  it('se rabat sur le fichier du backend', async () => {
    const vault = new FakeVault()
    const token = new AgentToken({
      vault,
      tokenPath: '/tmp/jeton',
      readFile: fileReader(JETON),
    })

    const { token: value, origin } = await token.resolve()
    assert.equal(value, JETON)
    assert.equal(origin, 'tokenFile')
  })

  it('met le jeton du fichier en réserve pour les sessions suivantes', async () => {
    // Le trousseau du système protège mieux qu'un fichier du profil.
    const vault = new FakeVault()
    const token = new AgentToken({
      vault,
      tokenPath: '/tmp/jeton',
      readFile: fileReader(JETON),
    })

    await token.resolve()
    assert.deepEqual(vault.stored, ['wazuhSecurity.agentToken'])
    assert.equal(vault.has('wazuhSecurity.agentToken'), true)
  })

  it('ignore les blancs autour du jeton', async () => {
    const token = new AgentToken({
      vault: new FakeVault(),
      tokenPath: '/tmp/jeton',
      readFile: fileReader(`  ${JETON}\n`),
    })
    assert.equal((await token.resolve()).token, JETON)
  })

  it('retourne `undefined` quand aucun jeton n’existe', async () => {
    // Situation normale : le backend n'a jamais démarré sur cette machine.
    // L'appelant doit expliquer, pas échouer en silence.
    const token = new AgentToken({
      vault: new FakeVault(),
      tokenPath: '/tmp/jeton',
      readFile: fileReader(missingFile()),
    })

    const { token: value, origin } = await token.resolve()
    assert.equal(value, undefined)
    assert.equal(origin, 'none')
  })

  it('traite un fichier vide comme une absence de jeton', async () => {
    const token = new AgentToken({
      vault: new FakeVault(),
      tokenPath: '/tmp/jeton',
      readFile: fileReader('   \n'),
    })
    assert.equal((await token.resolve()).token, undefined)
  })

  it('met le résultat en mémoire pour la session', async () => {
    let reads = 0
    const token = new AgentToken({
      vault: new FakeVault(),
      tokenPath: '/tmp/jeton',
      readFile: async () => {
        reads += 1
        return JETON
      },
    })

    await token.resolve()
    await token.resolve()
    await token.resolve()
    assert.equal(reads, 1)
  })
})

describe('AgentToken — reprise après 401', () => {
  it('oublie la réserve et relit le fichier', async () => {
    // Le cas concret : le backend redémarre et régénère son jeton. Sans
    // cette reprise, l'extension resterait muette jusqu'au redémarrage de
    // l'éditeur.
    const vault = new FakeVault({ 'wazuhSecurity.agentToken': 'jeton-perime' })
    const token = new AgentToken({
      vault,
      tokenPath: '/tmp/jeton',
      readFile: fileReader('jeton-neuf'),
    })

    assert.equal((await token.resolve()).token, 'jeton-perime')

    const { token: refreshed, origin } = await token.refresh()
    assert.equal(refreshed, 'jeton-neuf')
    assert.equal(origin, 'tokenFile')
    assert.deepEqual(vault.deleted, ['wazuhSecurity.agentToken'])
  })

  it('retourne `undefined` si le fichier a disparu', async () => {
    const token = new AgentToken({
      vault: new FakeVault({ 'wazuhSecurity.agentToken': JETON }),
      tokenPath: '/tmp/jeton',
      readFile: fileReader(missingFile()),
    })

    await token.resolve()
    assert.equal((await token.refresh()).token, undefined)
  })
})

describe('AgentToken — en-tête', () => {
  it('produit un en-tête Bearer', async () => {
    const token = new AgentToken({
      vault: new FakeVault({ 'wazuhSecurity.agentToken': JETON }),
      tokenPath: '/tmp/jeton',
      readFile: fileReader(missingFile()),
    })

    assert.deepEqual(await token.authorizationHeader(), {
      Authorization: `Bearer ${JETON}`,
    })
  })

  it('ne produit aucun en-tête sans jeton', async () => {
    // `undefined` plutôt qu'un en-tête vide : un `Bearer ` sans valeur
    // serait refusé de la même façon, mais brouillerait le diagnostic.
    const token = new AgentToken({
      vault: new FakeVault(),
      tokenPath: '/tmp/jeton',
      readFile: fileReader(missingFile()),
    })
    assert.equal(await token.authorizationHeader(), undefined)
  })
})

describe('AgentToken — tolérance aux pannes', () => {
  it('un trousseau indisponible n’empêche pas d’utiliser le fichier', async () => {
    // Session sans interface graphique, par exemple : ce n'est pas une
    // panne, et l'extension doit rester utilisable.
    const vault = new FakeVault()
    vault.failing = true

    const token = new AgentToken({
      vault,
      tokenPath: '/tmp/jeton',
      readFile: fileReader(JETON),
    })

    assert.equal((await token.resolve()).token, JETON)
  })
})

describe('AgentToken — non-divulgation', () => {
  it('ne journalise jamais la valeur du jeton', async () => {
    const traces: string[] = []
    const token = new AgentToken({
      vault: new FakeVault(),
      tokenPath: '/tmp/jeton',
      readFile: fileReader(JETON),
      onLog: (message) => traces.push(message),
    })

    await token.resolve()
    await token.refresh()

    assert.ok(traces.length > 0, 'la résolution doit laisser une trace')
    for (const trace of traces) {
      assert.ok(!trace.includes(JETON), `jeton présent dans : ${trace}`)
    }
  })

  it('ne journalise pas non plus un jeton absent ou illisible', async () => {
    const traces: string[] = []
    const token = new AgentToken({
      vault: new FakeVault({ 'wazuhSecurity.agentToken': 'secret-en-reserve' }),
      tokenPath: '/tmp/jeton',
      readFile: fileReader(missingFile()),
      onLog: (message) => traces.push(message),
    })

    await token.resolve()
    await token.refresh()

    for (const trace of traces) {
      assert.ok(!trace.includes('secret-en-reserve'), trace)
    }
  })

  it('trace le code d’erreur système, pas un contenu de fichier', async () => {
    const traces: string[] = []
    const token = new AgentToken({
      vault: new FakeVault(),
      tokenPath: '/tmp/jeton',
      readFile: fileReader(missingFile()),
      onLog: (message) => traces.push(message),
    })

    await token.resolve()
    // `ENOENT` suffit au diagnostic et ne peut rien contenir de sensible.
    assert.ok(traces.some((trace) => trace.includes('ENOENT')), traces.join(' | '))
  })
})

describe('defaultTokenPath', () => {
  it('range le jeton hors du dépôt', () => {
    // Un secret placé dans le projet finit commité ou partagé avec le
    // dossier.
    const path = defaultTokenPath().replace(/\\/g, '/')
    assert.match(path, /\.wazuh-security\/agent-token$/)
    assert.ok(!path.includes('VsCode-extension'), path)
  })

  it('ne contient aucun chemin utilisateur codé en dur', () => {
    // Un chemin absolu spécifique à une machine ne survivrait à aucun autre
    // poste. Il doit être dérivé du profil.
    const path = defaultTokenPath()
    assert.ok(path.length > '/.wazuh-security/agent-token'.length)
  })
})
