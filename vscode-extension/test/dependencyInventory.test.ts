/**
 * Tests de l'inventaire des dépendances.
 *
 * Deux garanties, de nature différente :
 *
 *     LECTURE SEULE   aucun gestionnaire de paquets n'est lancé. Le module
 *                     n'a aucun moyen d'en lancer un — il ne reçoit que du
 *                     texte — et ces tests le vérifient en ne lui donnant
 *                     jamais rien d'autre.
 *
 *     HONNÊTETÉ       une contrainte de version (`^1.2.0`) n'est pas une
 *                     version. Elle produit une chaîne vide, qui se propage
 *                     jusqu'au bout comme « non vérifiable » plutôt que
 *                     d'être devinée.
 *
 * Les manifestes utilisés ici sont réduits à ce qu'ils doivent prouver,
 * mais respectent la forme réelle de chaque écosystème.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  DependencyInventoryAccumulator,
  exactVersion,
  manifestKind,
  parseDependencies,
} from '../src/security/dependencyInventory'
import type { DependencyRecord } from '../src/security/securityTypes'

/** Retrouve une dépendance par son nom. */
function find(
  records: readonly DependencyRecord[],
  name: string
): DependencyRecord | undefined {
  return records.find((record) => record.name === name)
}

// --------------------------------------------------------------------------
// Reconnaissance des fichiers
// --------------------------------------------------------------------------

describe('inventaire — fichiers reconnus', () => {
  const expected: readonly [string, string, string][] = [
    ['package.json', 'npm', 'manifest'],
    ['package-lock.json', 'npm', 'lockfile'],
    ['yarn.lock', 'npm', 'lockfile'],
    ['pnpm-lock.yaml', 'npm', 'lockfile'],
    ['requirements.txt', 'pypi', 'manifest'],
    ['requirements-dev.txt', 'pypi', 'manifest'],
    ['pyproject.toml', 'pypi', 'manifest'],
    ['poetry.lock', 'pypi', 'lockfile'],
    ['pom.xml', 'maven', 'manifest'],
    ['build.gradle', 'maven', 'manifest'],
    ['build.gradle.kts', 'maven', 'manifest'],
    ['composer.json', 'composer', 'manifest'],
    ['composer.lock', 'composer', 'lockfile'],
    ['go.mod', 'go', 'manifest'],
    ['go.sum', 'go', 'lockfile'],
    ['Gemfile', 'rubygems', 'manifest'],
    ['Gemfile.lock', 'rubygems', 'lockfile'],
  ]

  for (const [fileName, ecosystem, source] of expected) {
    it(`reconnaît ${fileName} (${ecosystem}, ${source})`, () => {
      const kind = manifestKind(fileName)
      assert.ok(kind, `${fileName} non reconnu`)
      assert.equal(kind.ecosystem, ecosystem)
      assert.equal(kind.source, source)
    })
  }

  it('accepte les variantes de requirements', () => {
    assert.ok(manifestKind('requirements-prod.txt'))
    assert.ok(manifestKind('requirements.test.txt'))
  })

  it('ignore ce qui n’est pas un manifeste', () => {
    assert.equal(manifestKind('README.md'), undefined)
    assert.equal(manifestKind('app.py'), undefined)
  })
})

// --------------------------------------------------------------------------
// Versions
// --------------------------------------------------------------------------

describe('inventaire — versions exactes contre contraintes', () => {
  it('retient une version figée', () => {
    assert.equal(exactVersion('1.2.3'), '1.2.3')
    assert.equal(exactVersion('v1.2.3'), '1.2.3')
    assert.equal(exactVersion('==1.2.3'), '1.2.3')
    assert.equal(exactVersion('4.18.2-beta.1'), '4.18.2-beta.1')
  })

  it('refuse une contrainte plutôt que de deviner', () => {
    // Inventer une version plausible à partir d'un intervalle produirait
    // une réponse — vulnérable ou saine — qui ne décrirait aucun artefact
    // réellement installé.
    for (const constraint of ['^1.2.0', '~1.2', '>=1.0,<2.0', '*', 'latest', '~>2.0']) {
      assert.equal(exactVersion(constraint), '', `« ${constraint} » accepté à tort`)
    }
  })
})

// --------------------------------------------------------------------------
// Node.js
// --------------------------------------------------------------------------

describe('inventaire — Node.js', () => {
  it('lit package.json, dépendances de développement comprises', () => {
    const raw = JSON.stringify({
      dependencies: { express: '^4.18.0', lodash: '4.17.21' },
      devDependencies: { typescript: '~5.4.5' },
    })

    const records = parseDependencies('package.json', 'package.json', raw)

    // Les dépendances de développement comptent : une vulnérabilité dans
    // un outil de build est exploitable en intégration continue.
    assert.equal(records.length, 3)
    assert.equal(find(records, 'express')?.version, '')
    assert.equal(find(records, 'lodash')?.version, '4.17.21')
    assert.equal(find(records, 'typescript')?.direct, true)
    assert.equal(find(records, 'express')?.ecosystem, 'npm')
  })

  it('lit package-lock.json v2 et distingue direct de transitif', () => {
    const raw = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'app' },
        'node_modules/express': { version: '4.18.2' },
        'node_modules/express/node_modules/cookie': { version: '0.5.0' },
      },
    })

    const records = parseDependencies('package-lock.json', 'package-lock.json', raw)

    assert.equal(find(records, 'express')?.version, '4.18.2')
    assert.equal(find(records, 'express')?.direct, true)
    assert.equal(find(records, 'cookie')?.direct, false)
    assert.equal(find(records, 'express')?.source, 'lockfile')
  })

  it('lit yarn.lock, formats v1 et berry', () => {
    const v1 = ['"express@^4.18.0":', '  version "4.18.2"', ''].join('\n')
    const berry = ['"lodash@npm:^4.17.0":', '  version: 4.17.21', ''].join('\n')

    assert.equal(
      find(parseDependencies('yarn.lock', 'yarn.lock', v1), 'express')?.version,
      '4.18.2'
    )
    assert.equal(
      find(parseDependencies('yarn.lock', 'yarn.lock', berry), 'lodash')?.version,
      '4.17.21'
    )
  })

  it('lit pnpm-lock.yaml', () => {
    const raw = ['lockfileVersion: 6.0', 'packages:', '  /express/4.18.2:', '    dev: false', ''].join('\n')

    const records = parseDependencies('pnpm-lock.yaml', 'pnpm-lock.yaml', raw)
    assert.equal(find(records, 'express')?.version, '4.18.2')
  })
})

// --------------------------------------------------------------------------
// Python
// --------------------------------------------------------------------------

describe('inventaire — Python', () => {
  it('lit requirements.txt et écarte les lignes d’option', () => {
    const raw = [
      '# commentaire',
      'fastapi==0.141.1',
      'uvicorn[standard]>=0.52',
      '--index-url https://utilisateur:motdepasse@depot.example/simple',
      '-r autres.txt',
      'httpx == 0.28.1',
    ].join('\n')

    const records = parseDependencies('requirements.txt', 'requirements.txt', raw)

    assert.equal(find(records, 'fastapi')?.version, '0.141.1')
    // Une contrainte reste une contrainte : version vide.
    assert.equal(find(records, 'uvicorn')?.version, '')
    // La ligne `--index-url` peut porter des identifiants de dépôt privé.
    // Elle n'est pas lue, et rien de ce qu'elle contient n'entre dans
    // l'inventaire.
    const serialized = JSON.stringify(records)
    assert.ok(!serialized.includes('motdepasse'))
    assert.ok(!serialized.includes('depot.example'))
  })

  it('lit pyproject.toml en format PEP 621', () => {
    const raw = [
      '[project]',
      'name = "demo"',
      'dependencies = ["fastapi>=0.100", "pydantic==2.13.4"]',
    ].join('\n')

    const records = parseDependencies('pyproject.toml', 'pyproject.toml', raw)

    assert.equal(find(records, 'fastapi')?.version, '')
    assert.equal(find(records, 'pydantic')?.version, '2.13.4')
  })

  it('lit pyproject.toml en format Poetry', () => {
    const raw = [
      '[tool.poetry.dependencies]',
      'python = "^3.11"',
      'fastapi = "0.141.1"',
      'httpx = { version = "0.28.1", extras = ["http2"] }',
    ].join('\n')

    const records = parseDependencies('pyproject.toml', 'pyproject.toml', raw)

    // `python` n'est pas un paquet : l'inventorier ferait apparaître une
    // « dépendance » qu'aucune base ne connaît.
    assert.equal(find(records, 'python'), undefined)
    assert.equal(find(records, 'fastapi')?.version, '0.141.1')
    assert.equal(find(records, 'httpx')?.version, '0.28.1')
  })

  it('lit poetry.lock', () => {
    const raw = [
      '[[package]]',
      'name = "fastapi"',
      'version = "0.141.1"',
      '',
      '[[package]]',
      'name = "starlette"',
      'version = "0.41.0"',
    ].join('\n')

    const records = parseDependencies('poetry.lock', 'poetry.lock', raw)

    assert.equal(records.length, 2)
    assert.equal(find(records, 'starlette')?.version, '0.41.0')
    assert.equal(find(records, 'starlette')?.source, 'lockfile')
  })
})

// --------------------------------------------------------------------------
// Java
// --------------------------------------------------------------------------

describe('inventaire — Java', () => {
  it('lit pom.xml sous la forme groupId:artifactId', () => {
    const raw = [
      '<project>',
      '  <dependencies>',
      '    <dependency>',
      '      <groupId>org.springframework.boot</groupId>',
      '      <artifactId>spring-boot-starter-web</artifactId>',
      '      <version>3.2.0</version>',
      '    </dependency>',
      '    <dependency>',
      '      <groupId>com.example</groupId>',
      '      <artifactId>lib</artifactId>',
      '      <version>${lib.version}</version>',
      '    </dependency>',
      '  </dependencies>',
      '</project>',
    ].join('\n')

    const records = parseDependencies('pom.xml', 'pom.xml', raw)

    assert.equal(
      find(records, 'org.springframework.boot:spring-boot-starter-web')?.version,
      '3.2.0'
    )
    // Une version portée par une propriété n'est pas résolue : la
    // résoudre demanderait de suivre l'héritage des POM parents,
    // éventuellement distants. La dépendance est donc non vérifiable, et
    // le dit.
    assert.equal(find(records, 'com.example:lib')?.version, '')
  })

  it('lit build.gradle et build.gradle.kts', () => {
    const groovy = "implementation 'org.apache.commons:commons-lang3:3.14.0'"
    const kotlin = 'implementation("com.google.guava:guava:32.1.2-jre")'

    assert.equal(
      find(
        parseDependencies('build.gradle', 'build.gradle', groovy),
        'org.apache.commons:commons-lang3'
      )?.version,
      '3.14.0'
    )
    assert.equal(
      find(
        parseDependencies('build.gradle.kts', 'build.gradle.kts', kotlin),
        'com.google.guava:guava'
      )?.version,
      '32.1.2-jre'
    )
  })
})

// --------------------------------------------------------------------------
// PHP, Go, Ruby
// --------------------------------------------------------------------------

describe('inventaire — PHP', () => {
  it('lit composer.json et écarte les contraintes de plateforme', () => {
    const raw = JSON.stringify({
      require: { php: '^8.1', 'ext-json': '*', 'laravel/framework': '^10.0' },
      'require-dev': { 'phpunit/phpunit': '10.5.0' },
    })

    const records = parseDependencies('composer.json', 'composer.json', raw)

    // `php` et `ext-json` ne sont pas des paquets.
    assert.equal(find(records, 'php'), undefined)
    assert.equal(find(records, 'ext-json'), undefined)
    assert.equal(find(records, 'laravel/framework')?.version, '')
    assert.equal(find(records, 'phpunit/phpunit')?.version, '10.5.0')
  })

  it('lit composer.lock', () => {
    const raw = JSON.stringify({
      packages: [{ name: 'laravel/framework', version: 'v10.43.0' }],
      'packages-dev': [{ name: 'phpunit/phpunit', version: '10.5.11' }],
    })

    const records = parseDependencies('composer.lock', 'composer.lock', raw)

    assert.equal(find(records, 'laravel/framework')?.version, '10.43.0')
    assert.equal(find(records, 'laravel/framework')?.direct, true)
    assert.equal(find(records, 'phpunit/phpunit')?.direct, false)
  })
})

describe('inventaire — Go', () => {
  it('lit go.mod et distingue les dépendances indirectes', () => {
    const raw = [
      'module example.com/app',
      '',
      'go 1.22',
      '',
      'require (',
      '\tgithub.com/gin-gonic/gin v1.9.1',
      '\tgithub.com/stretchr/testify v1.8.4 // indirect',
      ')',
    ].join('\n')

    const records = parseDependencies('go.mod', 'go.mod', raw)

    assert.equal(find(records, 'github.com/gin-gonic/gin')?.version, '1.9.1')
    assert.equal(find(records, 'github.com/gin-gonic/gin')?.direct, true)
    // `// indirect` est l'une des rares déclarations d'indirection données
    // par le manifeste lui-même.
    assert.equal(find(records, 'github.com/stretchr/testify')?.direct, false)
  })

  it('retire le suffixe de version majeure d’un module Go', () => {
    const raw = 'require github.com/gofiber/fiber/v2 v2.52.0'
    const records = parseDependencies('go.mod', 'go.mod', raw)
    assert.ok(find(records, 'github.com/gofiber/fiber'))
  })

  it('lit go.sum en écartant les doublons de go.mod', () => {
    const raw = [
      'github.com/gin-gonic/gin v1.9.1 h1:abcdef=',
      'github.com/gin-gonic/gin v1.9.1/go.mod h1:ghijkl=',
    ].join('\n')

    const records = parseDependencies('go.sum', 'go.sum', raw)

    // Deux lignes pour un module : la déduplication les ramène à une.
    assert.equal(records.length, 1)
    assert.equal(records[0]?.version, '1.9.1')
  })
})

describe('inventaire — Ruby', () => {
  it('lit Gemfile', () => {
    const raw = ["gem 'rails', '7.1.3'", "gem 'puma', '~> 6.4'"].join('\n')
    const records = parseDependencies('Gemfile', 'Gemfile', raw)

    assert.equal(find(records, 'rails')?.version, '7.1.3')
    assert.equal(find(records, 'puma')?.version, '')
  })

  it('lit Gemfile.lock', () => {
    const raw = [
      'GEM',
      '  remote: https://rubygems.org/',
      '  specs:',
      '    rails (7.1.3)',
      '      actioncable (= 7.1.3)',
      '    puma (6.4.2)',
      '',
      'PLATFORMS',
      '  ruby',
    ].join('\n')

    const records = parseDependencies('Gemfile.lock', 'Gemfile.lock', raw)

    assert.equal(find(records, 'rails')?.version, '7.1.3')
    assert.equal(find(records, 'puma')?.version, '6.4.2')
    // Six espaces : une contrainte d'un autre gem, pas un gem installé.
    assert.equal(find(records, 'actioncable'), undefined)
  })
})

// --------------------------------------------------------------------------
// Robustesse
// --------------------------------------------------------------------------

describe('inventaire — robustesse', () => {
  it('un manifeste mal formé produit une liste vide, jamais une exception', () => {
    // Un `composer.json` en cours d'édition ne doit pas faire échouer
    // l'inventaire du projet entier.
    assert.deepEqual(parseDependencies('package.json', 'package.json', '{ oops'), [])
    assert.deepEqual(parseDependencies('composer.lock', 'composer.lock', 'nope'), [])
    assert.deepEqual(parseDependencies('pom.xml', 'pom.xml', '<project>'), [])
  })

  it('un fichier non reconnu ne produit rien', () => {
    assert.deepEqual(parseDependencies('README.md', 'README.md', '# titre'), [])
  })

  it('écarte les noms impossibles', () => {
    const raw = JSON.stringify({ dependencies: { 'nom avec espace': '1.0.0' } })
    assert.deepEqual(parseDependencies('package.json', 'package.json', raw), [])
  })
})

// --------------------------------------------------------------------------
// Accumulateur
// --------------------------------------------------------------------------

describe('inventaire — accumulateur de projet', () => {
  it('agrège plusieurs manifestes et compte ceux qui ont été lus', () => {
    const accumulator = new DependencyInventoryAccumulator()

    accumulator.consider(
      'package.json',
      'package.json',
      JSON.stringify({ dependencies: { express: '4.18.2' } })
    )
    accumulator.consider('requirements.txt', 'backend/requirements.txt', 'fastapi==0.141.1')
    accumulator.consider('README.md', 'README.md', '# ignoré')

    const result = accumulator.result()
    assert.equal(result.manifestsRead, 2)
    assert.equal(result.dependencies.length, 2)
    assert.equal(result.truncated, false)
  })

  it('annonce la troncature quand le plafond est atteint', () => {
    const accumulator = new DependencyInventoryAccumulator(1)
    accumulator.consider(
      'package.json',
      'package.json',
      JSON.stringify({ dependencies: { a: '1.0.0', b: '2.0.0', c: '3.0.0' } })
    )

    const result = accumulator.result()
    assert.equal(result.dependencies.length, 1)
    assert.equal(result.truncated, true)
  })

  it('conserve le chemin du manifeste d’origine', () => {
    const accumulator = new DependencyInventoryAccumulator()
    accumulator.consider(
      'package.json',
      'apps/web/package.json',
      JSON.stringify({ dependencies: { react: '18.2.0' } })
    )

    const [record] = accumulator.result().dependencies
    // Le chemin sert à pointer le fichier dans l'éditeur : sans lui, un
    // monorepo ne dirait pas lequel de ses paquets est concerné.
    assert.equal(record?.manifest, 'apps/web/package.json')
  })
})
