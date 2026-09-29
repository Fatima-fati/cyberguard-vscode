/**
 * Tests du classement des fichiers surveillés, et du cache d'empreintes.
 *
 * Deux garanties, et elles se cassent dans des directions opposées :
 *
 *     TROP LARGE   un `.env` lu « pour vérifier », un `node_modules`
 *                  parcouru, une image envoyée au backend
 *     TROP ÉTROIT  un `docker-compose.yml` jamais relu, un secret
 *                  introduit dans un fichier qu'on avait décidé
 *                  d'ignorer — un angle mort de sécurité
 *
 * Le second est le plus grave, et c'est pourquoi le classement par défaut
 * d'un fichier texte inconnu est « cherche des secrets », pas « ignore ».
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  classifyChange,
  crossesExcludedDirectory,
  mergeAnalyses,
  requiresWork,
} from '../src/monitor/changeClassification'
import {
  SignatureCache,
  demandsAnalysis,
  type FileSignature,
} from '../src/monitor/fileSignature'

// --------------------------------------------------------------------------
// Exclusions
// --------------------------------------------------------------------------

describe('classifyChange — dossiers exclus par la découverte', () => {
  const excluded = [
    'node_modules/react/index.js',
    'dist/bundle.js',
    'build/output.js',
    'coverage/lcov-report/index.html',
    '.venv/lib/site.py',
    'venv/lib/site.py',
    'src/__pycache__/app.cpython-312.pyc',
    'out/extension.js',
    'out-test/analysis.test.cjs',
    '.git/COMMIT_EDITMSG',
    'vendor/autoload.php',
    'target/classes/App.class',
    '.next/server/page.js',
    'deep/nested/node_modules/pkg/index.js',
  ]

  for (const path of excluded) {
    it(`ignore ${path}`, () => {
      const verdict = classifyChange(path)
      assert.equal(verdict.kind, 'ignored', path)
      assert.equal(requiresWork(verdict), false)
    })
  }

  it('ne confond pas un fichier nommé « build » avec un dossier de build', () => {
    // `crossesExcludedDirectory` ne regarde que les segments de dossier :
    // un script nommé `build` à la racine est un fichier ordinaire.
    assert.equal(crossesExcludedDirectory('build'), false)
    assert.equal(crossesExcludedDirectory('scripts/build'), false)
    assert.equal(crossesExcludedDirectory('build/app.js'), true)
  })

  it('respecte le .gitignore fourni', () => {
    const ignore = { ignores: (path: string) => path.startsWith('generated/') }

    assert.equal(classifyChange('generated/api.ts', { ignore }).kind, 'ignored')
    assert.equal(classifyChange('src/api.ts', { ignore }).kind, 'code')
  })

  it('refuse tout chemin qui sort du dossier ouvert', () => {
    // Cloisonnement : la surveillance ne déborde jamais du workspace,
    // même si l'éditeur signale le changement.
    assert.equal(classifyChange('../ailleurs/app.py').kind, 'ignored')
    assert.equal(classifyChange('').kind, 'ignored')
  })
})

// --------------------------------------------------------------------------
// Fichiers jamais lus
// --------------------------------------------------------------------------

describe('classifyChange — fichiers sensibles, jamais lus', () => {
  const sensitive = [
    '.env',
    '.env.production',
    'backend/.env',
    'certs/server.pem',
    'certs/server.key',
    'keys/id_rsa',
    '.npmrc',
    'credentials.json',
    'config/secrets.yml',
  ]

  for (const path of sensitive) {
    it(`ne lit jamais ${path}`, () => {
      const verdict = classifyChange(path)
      assert.equal(verdict.kind, 'sensitive', path)
      assert.equal(verdict.readable, false, 'le contenu ne doit jamais être ouvert')
      assert.equal(requiresWork(verdict), false, 'aucune analyse de contenu')
    })
  }

  it('classe le fichier sensible AVANT le manifeste', () => {
    // `credentials.json` ressemble à un manifeste JSON. S'il était classé
    // comme tel, il serait lu — c'est exactement l'ordre de contrôle que
    // la phase 1 impose, et il vaut ici aussi.
    assert.equal(classifyChange('credentials.json').kind, 'sensitive')
    assert.equal(classifyChange('secrets.json').kind, 'sensitive')
  })

  it('laisse passer un modèle vide de valeurs', () => {
    // Un `.env.example` a précisément pour intérêt de ne rien contenir.
    assert.equal(classifyChange('.env.example').readable, true)
    assert.equal(classifyChange('.env.sample').readable, true)
  })
})

describe('classifyChange — binaires', () => {
  for (const path of [
    'resources/shield.png',
    'docs/manuel.pdf',
    'lib/native.dll',
    'data/app.sqlite3',
    'fonts/Inter.woff2',
  ]) {
    it(`ne lit pas ${path}`, () => {
      const verdict = classifyChange(path)
      assert.equal(verdict.kind, 'binary', path)
      assert.equal(verdict.readable, false)
      assert.equal(requiresWork(verdict), false, 'pas de scan lourd')
    })
  }
})

// --------------------------------------------------------------------------
// Ce qui déclenche quoi
// --------------------------------------------------------------------------

describe('classifyChange — le bon moteur pour le bon fichier', () => {
  it('un fichier de code déclenche l’analyse de code ET la recherche de secrets', () => {
    const verdict = classifyChange('src/users.py')

    assert.equal(verdict.kind, 'code')
    assert.equal(verdict.language, 'python')
    assert.deepEqual(verdict.analyses, {
      code: true,
      secrets: true,
      dependencies: false,
    })
  })

  const languages: [string, string][] = [
    ['src/app.py', 'python'],
    ['src/app.js', 'javascript'],
    ['src/app.jsx', 'javascript'],
    ['src/app.mjs', 'javascript'],
    ['src/app.ts', 'typescript'],
    ['src/app.tsx', 'typescript'],
    ['src/App.php', 'php'],
    ['src/App.java', 'java'],
  ]

  for (const [path, language] of languages) {
    it(`reconnaît ${path} comme ${language}`, () => {
      assert.equal(classifyChange(path).language, language)
    })
  }

  it('un manifeste déclenche l’inventaire des dépendances', () => {
    const verdict = classifyChange('package.json')

    assert.equal(verdict.kind, 'dependency')
    assert.equal(verdict.analyses.dependencies, true)
    // Un jeton peut se glisser dans un script npm : le manifeste passe
    // aussi par la recherche de secrets, comme lors d'une découverte.
    assert.equal(verdict.analyses.secrets, true)
    assert.equal(verdict.analyses.code, false, 'aucune analyse de code lourde')
  })

  for (const manifest of [
    'requirements.txt',
    'package-lock.json',
    'pyproject.toml',
    'composer.json',
    'go.mod',
    'Gemfile',
    'pom.xml',
  ]) {
    it(`reconnaît ${manifest} comme manifeste`, () => {
      assert.equal(classifyChange(manifest).kind, 'dependency', manifest)
    })
  }

  it('un fichier texte inconnu ne déclenche que la recherche de secrets', () => {
    const verdict = classifyChange('docker-compose.yml')

    assert.equal(verdict.kind, 'text')
    assert.deepEqual(verdict.analyses, {
      code: false,
      secrets: true,
      dependencies: false,
    })
  })

  it('un README ne déclenche aucun scan lourd', () => {
    const verdict = classifyChange('README.md')

    assert.equal(verdict.analyses.code, false)
    assert.equal(verdict.analyses.dependencies, false)
    // Quelques expressions régulières en local : ce n'est pas un scan
    // lourd, et s'en abstenir créerait un angle mort — un secret collé
    // dans un fichier de documentation reste un secret.
    assert.equal(verdict.analyses.secrets, true)
  })

  it('normalise les séparateurs Windows', () => {
    assert.equal(classifyChange('src\\users.py').kind, 'code')
    assert.equal(classifyChange('node_modules\\pkg\\index.js').kind, 'ignored')
  })
})

describe('mergeAnalyses', () => {
  it('fait l’union de deux demandes', () => {
    const merged = mergeAnalyses(
      { code: true, secrets: false, dependencies: false },
      { code: false, secrets: true, dependencies: true }
    )
    assert.deepEqual(merged, { code: true, secrets: true, dependencies: true })
  })

  it('n’enlève jamais une analyse déjà demandée', () => {
    const merged = mergeAnalyses(
      { code: true, secrets: true, dependencies: true },
      { code: false, secrets: false, dependencies: false }
    )
    assert.deepEqual(merged, { code: true, secrets: true, dependencies: true })
  })
})

// --------------------------------------------------------------------------
// Cache d'empreintes
// --------------------------------------------------------------------------

function signature(overrides: Partial<FileSignature> = {}): FileSignature {
  return { size: 1_024, mtimeMs: 1_000, hash: 'abc123', ...overrides }
}

describe('SignatureCache — éviter les analyses inutiles', () => {
  it('considère comme neuf un fichier jamais vu', () => {
    const cache = new SignatureCache()
    assert.equal(cache.compare('src/app.py', signature()), 'new')
    assert.equal(demandsAnalysis('new'), true)
  })

  it('conclut « inchangé » quand taille et date sont identiques', () => {
    const cache = new SignatureCache()
    cache.remember('src/app.py', signature())

    // Le cas le moins cher : aucune lecture n'a même été nécessaire.
    assert.equal(cache.compare('src/app.py', signature()), 'unchanged')
    assert.equal(demandsAnalysis('unchanged'), false)
  })

  it('conclut « changé » dès que la taille diffère', () => {
    const cache = new SignatureCache()
    cache.remember('src/app.py', signature({ size: 1_024 }))

    assert.equal(cache.compare('src/app.py', signature({ size: 1_025 })), 'changed')
  })

  it('reconnaît une sauvegarde sans modification', () => {
    const cache = new SignatureCache()
    cache.remember('src/app.py', signature({ mtimeMs: 1_000 }))

    // `Ctrl+S` sans avoir rien tapé : la date bouge, pas le contenu.
    const verdict = cache.compare('src/app.py', signature({ mtimeMs: 2_000 }))
    assert.equal(verdict, 'touched')
    assert.equal(demandsAnalysis(verdict), false, 'aucune analyse ne doit partir')
  })

  it('conclut « changé » quand l’empreinte diffère', () => {
    const cache = new SignatureCache()
    cache.remember('src/app.py', signature({ hash: 'abc123' }))

    assert.equal(
      cache.compare('src/app.py', signature({ mtimeMs: 2_000, hash: 'def456' })),
      'changed'
    )
  })

  it('ne suppose rien quand une empreinte manque', () => {
    const cache = new SignatureCache()
    cache.remember('big.log', signature({ hash: null }))

    // Un fichier manqué à tort est un angle mort de sécurité ; un fichier
    // réanalysé à tort coûte une requête. On choisit la requête.
    assert.equal(
      cache.compare('big.log', signature({ mtimeMs: 2_000, hash: null })),
      'changed'
    )
    assert.equal(
      cache.compare('big.log', signature({ mtimeMs: 2_000, hash: 'abc123' })),
      'changed'
    )
  })

  it('rafraîchit la date après une réécriture à l’identique', () => {
    const cache = new SignatureCache()
    cache.remember('src/app.py', signature({ mtimeMs: 1_000 }))

    cache.refreshTimestamp('src/app.py', 2_000)

    // Sans ce rafraîchissement, chaque sauvegarde suivante relancerait la
    // comparaison d'empreinte, donc une lecture complète du fichier.
    assert.equal(cache.compare('src/app.py', signature({ mtimeMs: 2_000 })), 'unchanged')
  })

  it('oublie un fichier supprimé', () => {
    const cache = new SignatureCache()
    cache.remember('src/gone.py', signature())

    cache.forget('src/gone.py')
    assert.equal(cache.has('src/gone.py'), false)
    assert.equal(cache.compare('src/gone.py', signature()), 'new')
  })

  it('reprend l’index d’une découverte sans relire le disque', () => {
    const cache = new SignatureCache()

    cache.adopt([
      {
        path: 'src/app.py',
        size: 2_048,
        mtime: '2026-09-28T10:00:00.000Z',
        content_hash: 'hash-app',
      },
      { path: 'logo.png', size: 9_000, mtime: '2026-09-28T10:00:00.000Z', content_hash: null },
    ])

    assert.equal(cache.size, 2)
    assert.equal(
      cache.compare('src/app.py', {
        size: 2_048,
        mtimeMs: Date.parse('2026-09-28T10:00:00.000Z'),
        hash: 'hash-app',
      }),
      'unchanged'
    )
  })

  it('remplace l’index plutôt que de le compléter', () => {
    const cache = new SignatureCache()
    cache.remember('supprime.py', signature())

    cache.adopt([
      { path: 'src/app.py', size: 1, mtime: '2026-09-28T10:00:00.000Z', content_hash: 'x' },
    ])

    // Un fichier disparu de l'index a disparu du projet. Le laisser le
    // rendrait indéfiniment « inchangé », donc jamais réanalysé.
    assert.equal(cache.has('supprime.py'), false)
    assert.equal(cache.size, 1)
  })

  it('accepte une date absente sans se tromper de verdict', () => {
    const cache = new SignatureCache()
    cache.adopt([{ path: 'src/app.py', size: 10, mtime: null, content_hash: 'h' }])

    // Date inconnue : la comparaison retombe sur l'empreinte.
    assert.equal(
      cache.compare('src/app.py', { size: 10, mtimeMs: 5_000, hash: 'h' }),
      'touched'
    )
    assert.equal(
      cache.compare('src/app.py', { size: 10, mtimeMs: 5_000, hash: 'autre' }),
      'changed'
    )
  })

  it('oublie tout au changement de dossier ouvert', () => {
    const cache = new SignatureCache()
    cache.remember('a.py', signature())
    cache.remember('b.py', signature())

    cache.clear()
    assert.equal(cache.size, 0)
  })
})
