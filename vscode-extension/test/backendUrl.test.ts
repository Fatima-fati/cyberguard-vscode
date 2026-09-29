/**
 * Tests de la validation de l'adresse du backend.
 *
 * L'enjeu est précis : `backendUrl` décide où part le contenu intégral de
 * chaque fichier analysé. C'est le seul chemin d'exfiltration du code de
 * l'utilisateur, et l'audit le désigne comme la vulnérabilité la plus
 * concrète de l'extension (§20.3).
 *
 * Ces tests couvrent donc autant les adresses acceptées que celles
 * refusées — et surtout : **aucun refus ne doit se transformer en
 * acceptation silencieuse.**
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  DEFAULT_BACKEND_URL,
  isLocalHost,
  shouldAdvertiseBackend,
  validateBackendUrl,
} from '../src/api/backendUrl'

describe('validateBackendUrl — adresses locales', () => {
  const locales = [
    'http://127.0.0.1:8000',
    'http://127.0.0.1',
    'http://localhost:8000',
    'http://localhost',
    'https://127.0.0.1:8443',
    'http://[::1]:8000',
    // Boucle locale sur certaines distributions.
    'http://127.0.1.1:8000',
  ]

  for (const url of locales) {
    it(`accepte ${url}`, () => {
      const verdict = validateBackendUrl(url)
      assert.equal(verdict.ok, true)
      if (verdict.ok) {
        assert.equal(verdict.local, true)
      }
    })
  }

  it('accepte l’adresse par défaut', () => {
    const verdict = validateBackendUrl(DEFAULT_BACKEND_URL)
    assert.equal(verdict.ok, true)
  })

  it('normalise la sortie', () => {
    // Slash final retiré, casse de l'hôte uniformisée : la valeur retournée
    // est utilisable telle quelle, sans retouche par l'appelant.
    const verdict = validateBackendUrl('http://LOCALHOST:8000/')
    assert.equal(verdict.ok, true)
    if (verdict.ok) {
      assert.equal(verdict.url, 'http://localhost:8000')
    }
  })

  it('tolère les espaces autour de l’adresse', () => {
    const verdict = validateBackendUrl('  http://127.0.0.1:8000  ')
    assert.equal(verdict.ok, true)
  })
})

describe('validateBackendUrl — refus', () => {
  it('refuse une chaîne vide', () => {
    const verdict = validateBackendUrl('')
    assert.equal(verdict.ok, false)
    if (!verdict.ok) {
      assert.equal(verdict.reason, 'empty')
      // Le message dit quoi faire, pas seulement ce qui a échoué.
      assert.match(verdict.message, /backendUrl/)
    }
  })

  it('refuse une chaîne d’espaces', () => {
    const verdict = validateBackendUrl('   ')
    assert.equal(verdict.ok, false)
    if (!verdict.ok) {
      assert.equal(verdict.reason, 'empty')
    }
  })

  const malformees = ['pas-une-url', '127.0.0.1:8000', '://127.0.0.1', 'http:/']

  for (const url of malformees) {
    it(`refuse l’adresse malformée « ${url} »`, () => {
      const verdict = validateBackendUrl(url, { allowRemote: true })
      assert.equal(verdict.ok, false)
      if (!verdict.ok) {
        assert.ok(
          verdict.reason === 'malformed' || verdict.reason === 'noHost',
          `raison inattendue : ${verdict.reason}`
        )
      }
    })
  }

  const protocoles = [
    'file:///etc/passwd',
    'ftp://127.0.0.1',
    'ws://127.0.0.1:8000',
    'wss://127.0.0.1:8000',
    'javascript:alert(1)',
    'data:text/plain,bonjour',
  ]

  for (const url of protocoles) {
    it(`refuse le protocole de « ${url} »`, () => {
      const verdict = validateBackendUrl(url, { allowRemote: true })
      assert.equal(verdict.ok, false)
    })
  }

  it('refuse des identifiants dans l’adresse', () => {
    // Ils partiraient dans chaque requête et finiraient dans les journaux
    // des intermédiaires. Le backend s'authentifie par en-tête.
    const verdict = validateBackendUrl('http://admin:motdepasse@127.0.0.1:8000')
    assert.equal(verdict.ok, false)
    if (!verdict.ok) {
      assert.equal(verdict.reason, 'credentials')
      // Le message ne répète évidemment pas le mot de passe reçu.
      assert.ok(!verdict.message.includes('motdepasse'))
    }
  })

  it('refuse un identifiant seul, sans mot de passe', () => {
    const verdict = validateBackendUrl('http://admin@127.0.0.1:8000')
    assert.equal(verdict.ok, false)
    if (!verdict.ok) {
      assert.equal(verdict.reason, 'credentials')
    }
  })

  it('refuse un chemin de base', () => {
    // Un chemin changerait la cible de toutes les routes construites
    // ailleurs, et permettrait un détournement discret.
    const verdict = validateBackendUrl('http://127.0.0.1:8000/api')
    assert.equal(verdict.ok, false)
    if (!verdict.ok) {
      assert.equal(verdict.reason, 'notAnOrigin')
    }
  })

  it('neutralise une remontée de chemin par normalisation', () => {
    // `new URL()` réduit `/../..` à `/` avant que la règle « origine seule »
    // ne s'applique : l'adresse est donc acceptée, mais la valeur retournée
    // est l'origine propre. C'est le résultat voulu — ce qui compte est
    // qu'aucun reste de chemin ne subsiste dans l'adresse utilisée.
    const verdict = validateBackendUrl('http://127.0.0.1:8000/../..')
    assert.equal(verdict.ok, true)
    if (verdict.ok) {
      assert.equal(verdict.url, 'http://127.0.0.1:8000')
      assert.ok(!verdict.url.includes('..'))
    }
  })

  it('refuse un chemin qui survit à la normalisation', () => {
    // `/api/../autre` se réduit à `/autre`, qui reste un chemin : refusé.
    const verdict = validateBackendUrl('http://127.0.0.1:8000/api/../autre')
    assert.equal(verdict.ok, false)
    if (!verdict.ok) {
      assert.equal(verdict.reason, 'notAnOrigin')
    }
  })

  it('refuse une requête ou un fragment', () => {
    for (const url of ['http://127.0.0.1:8000?x=1', 'http://127.0.0.1:8000#y']) {
      assert.equal(validateBackendUrl(url).ok, false, url)
    }
  })
})

describe('validateBackendUrl — backends distants', () => {
  const distants = [
    'https://attaquant.example',
    'http://192.168.1.50:8000',
    'https://backend.entreprise.local',
    'http://10.0.0.5:8000',
    // `0.0.0.0` est une adresse d'écoute, pas de destination : la traiter
    // comme locale validerait une URL qui peut joindre autre chose.
    'http://0.0.0.0:8000',
  ]

  for (const url of distants) {
    it(`refuse ${url} par défaut`, () => {
      const verdict = validateBackendUrl(url)
      assert.equal(verdict.ok, false)
      if (!verdict.ok) {
        assert.equal(verdict.reason, 'remoteNotAllowed')
      }
    })
  }

  it('c’est le scénario du dépôt malveillant qui est fermé ici', () => {
    // Un `.vscode/settings.json` pointant vers un serveur tiers est la
    // situation décrite par l'audit §20.3. Même si le réglage `machine`
    // était contourné, la validation refuse.
    const verdict = validateBackendUrl('https://attaquant.example')
    assert.equal(verdict.ok, false)
    if (!verdict.ok) {
      // Le message nomme l'hôte et dit ce qui se passerait.
      assert.match(verdict.message, /attaquant\.example/)
      assert.match(verdict.message, /machine/)
    }
  })

  for (const url of distants) {
    it(`accepte ${url} avec un accord explicite`, () => {
      const verdict = validateBackendUrl(url, { allowRemote: true })
      assert.equal(verdict.ok, true)
      if (verdict.ok) {
        assert.equal(verdict.local, false)
      }
    })
  }

  it('un accord explicite ne lève aucune autre règle', () => {
    // `allowRemote` autorise un hôte distant, rien de plus : protocole et
    // identifiants restent refusés.
    assert.equal(
      validateBackendUrl('file:///etc/passwd', { allowRemote: true }).ok,
      false
    )
    assert.equal(
      validateBackendUrl('https://u:p@distant.example', { allowRemote: true }).ok,
      false
    )
    assert.equal(
      validateBackendUrl('https://distant.example/api', { allowRemote: true }).ok,
      false
    )
  })

  it('exige `true`, pas une valeur vaguement vraie', () => {
    // Comparaison stricte : une valeur venue d'un réglage mal typé ne doit
    // pas ouvrir la porte.
    const verdict = validateBackendUrl('https://distant.example', {
      allowRemote: undefined,
    })
    assert.equal(verdict.ok, false)
  })
})

describe('isLocalHost', () => {
  const locaux = ['127.0.0.1', '127.0.1.1', '127.255.255.255', 'localhost',
    'LOCALHOST', '::1', '[::1]']
  for (const host of locaux) {
    it(`${host} est local`, () => assert.equal(isLocalHost(host), true))
  }

  const distants = ['0.0.0.0', '192.168.1.1', '10.0.0.1', 'example.com',
    '128.0.0.1', '::2', '2001:db8::1']
  for (const host of distants) {
    it(`${host} n’est pas local`, () => assert.equal(isLocalHost(host), false))
  }

  it('ne résout aucun nom', () => {
    // Un nom qui résout aujourd'hui vers 127.0.0.1 peut résoudre demain
    // ailleurs. La vérification reste textuelle, donc stable et hors ligne.
    assert.equal(isLocalHost('localhost.attaquant.example'), false)
    assert.equal(isLocalHost('127.0.0.1.attaquant.example'), false)
  })
})

describe('shouldAdvertiseBackend', () => {
  it('ne signale pas un backend local', () => {
    // Le cas normal n'a pas besoin d'être annoncé : une marque permanente
    // affichée tout le temps finit par ne plus être vue.
    assert.equal(
      shouldAdvertiseBackend(validateBackendUrl('http://127.0.0.1:8000')),
      false
    )
  })

  it('signale un backend distant', () => {
    assert.equal(
      shouldAdvertiseBackend(
        validateBackendUrl('https://distant.example', { allowRemote: true })
      ),
      true
    )
  })

  it('ne signale rien pour une adresse refusée', () => {
    // Un refus se traite par un message d'erreur, pas par une marque
    // permanente : il n'y a pas de backend à annoncer.
    assert.equal(shouldAdvertiseBackend(validateBackendUrl('')), false)
  })
})
