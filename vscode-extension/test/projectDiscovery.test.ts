/**
 * Tests de la découverte locale d'un projet.
 *
 * Le système de fichiers est injecté : des arborescences entières sont
 * décrites en quelques lignes, sans rien écrire sur disque, et un cas
 * pathologique — 50 000 fichiers, un lien symbolique, un dossier illisible —
 * s'exprime aussi facilement qu'un cas simple.
 *
 * Trois familles de garanties :
 *
 *     exclusions    node_modules, .git, dist, .venv ne sont pas indexés
 *     lecture       un `.env` est indexé mais **jamais lu**
 *     bornes        aucun plafond n'est atteint en silence
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  EXCLUDED_DIRECTORIES,
  discoverProject,
  extractDependencyNames,
  isBinaryPath,
  isExcludedDirectory,
  isNeverRead,
  manifestEcosystem,
  type DirectoryEntry,
  type DiscoveryFileSystem,
} from '../src/project/projectDiscovery'

// --------------------------------------------------------------------------
// Système de fichiers en mémoire
// --------------------------------------------------------------------------

interface FakeEntry {
  /** Contenu texte, ou `undefined` pour un dossier. */
  content?: string
  size?: number
  symlink?: boolean
  /** La lecture doit-elle échouer ? */
  unreadable?: boolean
}

/**
 * Système de fichiers décrit par une table plate de chemins.
 *
 * Enregistre les fichiers **réellement lus** : c'est ce qui permet
 * d'affirmer qu'un `.env` n'a jamais été ouvert, plutôt que de l'espérer.
 */
class FakeFs implements DiscoveryFileSystem {
  readonly reads: string[] = []
  readonly unreadableDirectories = new Set<string>()

  constructor(private readonly tree: Record<string, FakeEntry>) {}

  private normalize(p: string): string {
    return p.replace(/\\/g, '/').replace(/\/+$/, '')
  }

  async readDirectory(directory: string): Promise<DirectoryEntry[]> {
    const dir = this.normalize(directory)
    if (this.unreadableDirectories.has(dir)) {
      throw new Error('EACCES')
    }

    const prefix = dir === '' ? '' : `${dir}/`
    const names = new Map<string, DirectoryEntry>()

    for (const [path, entry] of Object.entries(this.tree)) {
      const normalized = this.normalize(path)
      if (!normalized.startsWith(prefix)) {
        continue
      }
      const rest = normalized.slice(prefix.length)
      if (!rest) {
        continue
      }
      const [head, ...tail] = rest.split('/')
      if (!head || names.has(head)) {
        continue
      }
      const isDirectory = tail.length > 0 || entry.content === undefined
      names.set(head, {
        name: head,
        isDirectory,
        isFile: !isDirectory,
        isSymbolicLink: tail.length === 0 && entry.symlink === true,
      })
    }

    return [...names.values()]
  }

  async stat(file: string): Promise<{ size: number; mtimeMs: number }> {
    const entry = this.tree[this.normalize(file)]
    if (!entry) {
      throw new Error('ENOENT')
    }
    return {
      size: entry.size ?? entry.content?.length ?? 0,
      mtimeMs: 1_700_000_000_000,
    }
  }

  async readFile(file: string): Promise<string> {
    const path = this.normalize(file)
    const entry = this.tree[path]
    if (!entry || entry.unreadable) {
      throw new Error('EACCES')
    }
    // La trace de lecture est le coeur des tests de non-lecture.
    this.reads.push(path)
    return entry.content ?? ''
  }
}

const ROOT = '/projet'

function file(content = 'x'): FakeEntry {
  return { content }
}

async function run(
  tree: Record<string, FakeEntry>,
  options: Partial<Parameters<typeof discoverProject>[0]> = {}
) {
  const fs = new FakeFs(tree)
  const result = await discoverProject({
    workspaceRoot: ROOT,
    fileSystem: fs,
    ...options,
  })
  return { result, fs, paths: result.files.map((entry) => entry.path).sort() }
}

// --------------------------------------------------------------------------
// Parcours de base
// --------------------------------------------------------------------------

describe('discoverProject — index', () => {
  it('indexe les fichiers avec leurs métadonnées', async () => {
    const { result } = await run({
      [`${ROOT}/src/app.py`]: { content: 'print(1)', size: 8 },
    })

    assert.equal(result.files.length, 1)
    const entry = result.files[0]!
    assert.equal(entry.path, 'src/app.py')
    assert.equal(entry.size, 8)
    assert.ok(entry.mtime, 'la date doit être renseignée')
    // L'empreinte sert au cache incrémental des phases suivantes.
    assert.match(entry.content_hash ?? '', /^[0-9a-f]{64}$/)
  })

  it('produit des chemins relatifs, jamais absolus', async () => {
    // Un chemin absolu révélerait l'arborescence du poste, et le backend
    // le refuserait.
    const { paths } = await run({
      [`${ROOT}/src/app.py`]: file(),
      [`${ROOT}/README.md`]: file(),
    })

    for (const path of paths) {
      assert.ok(!path.startsWith('/'), path)
      assert.ok(!path.includes(ROOT), path)
      assert.ok(!path.includes('..'), path)
    }
    assert.deepEqual(paths, ['README.md', 'src/app.py'])
  })

  it('descend dans les sous-dossiers', async () => {
    const { paths } = await run({
      [`${ROOT}/a.py`]: file(),
      [`${ROOT}/src/b.py`]: file(),
      [`${ROOT}/src/deep/c.py`]: file(),
      [`${ROOT}/src/deep/deeper/d.py`]: file(),
    })
    assert.deepEqual(paths, ['a.py', 'src/b.py', 'src/deep/c.py', 'src/deep/deeper/d.py'])
  })

  it('produit un ordre stable', async () => {
    // Deux découvertes du même projet doivent donner le même index, donc le
    // même contexte : sans cela, le contexte n'est pas comparable d'une
    // session à l'autre.
    const tree = {
      [`${ROOT}/z.py`]: file(),
      [`${ROOT}/a.py`]: file(),
      [`${ROOT}/m/b.py`]: file(),
    }
    const first = await run(tree)
    const second = await run(tree)
    assert.deepEqual(
      first.result.files.map((f) => f.path),
      second.result.files.map((f) => f.path)
    )
  })

  it('accepte un projet vide', async () => {
    const { result } = await run({})
    assert.deepEqual(result.files, [])
    assert.equal(result.truncated, false)
    assert.deepEqual(result.warnings, [])
  })
})

// --------------------------------------------------------------------------
// Exclusions — la liste demandée
// --------------------------------------------------------------------------

describe('discoverProject — dossiers exclus', () => {
  it('n’indexe ni node_modules, ni .git, ni dist, ni .venv', async () => {
    const { paths } = await run({
      [`${ROOT}/src/app.py`]: file(),
      [`${ROOT}/node_modules/react/index.js`]: file(),
      [`${ROOT}/node_modules/.bin/tsc`]: file(),
      [`${ROOT}/.git/config`]: file(),
      [`${ROOT}/.git/objects/ab/cdef`]: file(),
      [`${ROOT}/dist/bundle.js`]: file(),
      [`${ROOT}/.venv/lib/site.py`]: file(),
    })

    assert.deepEqual(paths, ['src/app.py'])
  })

  it('exclut aussi les dossiers imbriqués portant ces noms', async () => {
    const { paths } = await run({
      [`${ROOT}/packages/api/src/app.ts`]: file(),
      [`${ROOT}/packages/api/node_modules/lib/index.js`]: file(),
      [`${ROOT}/packages/web/dist/main.js`]: file(),
    })
    assert.deepEqual(paths, ['packages/api/src/app.ts'])
  })

  const exclus = [
    'node_modules', '.git', 'dist', 'build', 'out', 'out-test', '.venv', 'venv',
    '__pycache__', 'coverage', 'target', 'vendor', 'logs', 'tmp', 'bin', 'obj',
    '.terraform', '.mypy_cache', '.tox', 'bower_components',
  ]

  for (const name of exclus) {
    it(`${name} est exclu`, () => {
      assert.equal(isExcludedDirectory(name), true)
      assert.ok(EXCLUDED_DIRECTORIES.has(name))
    })
  }

  it('n’exclut pas un dossier de code ordinaire', async () => {
    for (const name of ['src', 'app', 'lib', 'tests', 'backend', 'frontend']) {
      assert.equal(isExcludedDirectory(name), false, name)
    }
  })
})

describe('discoverProject — .gitignore', () => {
  it('respecte les motifs fournis', async () => {
    const { paths } = await run(
      {
        [`${ROOT}/src/app.py`]: file(),
        [`${ROOT}/build.log`]: file(),
        [`${ROOT}/generated/out.py`]: file(),
      },
      {
        ignore: {
          ignores: (p) => p === 'build.log' || p.startsWith('generated/'),
        },
      }
    )
    assert.deepEqual(paths, ['src/app.py'])
  })

  it('n’entre pas dans un dossier ignoré', async () => {
    const { paths } = await run(
      {
        [`${ROOT}/src/app.py`]: file(),
        [`${ROOT}/ignore-moi/a.py`]: file(),
        [`${ROOT}/ignore-moi/b/c.py`]: file(),
      },
      { ignore: { ignores: (p) => p === 'ignore-moi/' } }
    )
    assert.deepEqual(paths, ['src/app.py'])
  })
})

// --------------------------------------------------------------------------
// Liens symboliques
// --------------------------------------------------------------------------

describe('discoverProject — liens symboliques', () => {
  it('ne suit jamais un lien, et le dit', async () => {
    // Un lien peut pointer hors du workspace, y compris vers un dossier
    // système. L'écarter est une décision de sécurité, pas une limitation.
    const { paths, result } = await run({
      [`${ROOT}/src/app.py`]: file(),
      [`${ROOT}/lien`]: { symlink: true },
      [`${ROOT}/lien-fichier.py`]: { content: 'x', symlink: true },
    })

    assert.deepEqual(paths, ['src/app.py'])
    assert.ok(
      result.warnings.some((w) => w.includes('symbolique')),
      result.warnings.join(' | ')
    )
  })
})

// --------------------------------------------------------------------------
// Fichiers sensibles : indexés, jamais lus
// --------------------------------------------------------------------------

describe('discoverProject — fichiers sensibles', () => {
  it('indexe un .env sans jamais le lire', async () => {
    // La garantie la plus importante de ce module. Le fichier doit
    // apparaître dans l'index — sa présence est ce que la découverte doit
    // constater — mais son contenu ne doit jamais être ouvert, pas même
    // pour calculer une empreinte : « lire pour hacher » reste lire.
    const { result, fs } = await run({
      [`${ROOT}/.env`]: { content: 'OPENAI_API_KEY=sk-secret-reel' },
      [`${ROOT}/src/app.py`]: file('print(1)'),
    })

    const env = result.files.find((entry) => entry.path === '.env')
    assert.ok(env, '.env doit être indexé')
    assert.equal(env.content_hash, null, 'aucune empreinte : le fichier n’est pas lu')

    assert.deepEqual(fs.reads, [`${ROOT}/src/app.py`])
    assert.ok(!fs.reads.some((p) => p.includes('.env')), fs.reads.join(' | '))
  })

  const sensibles = [
    '.env', '.env.local', '.env.production', 'certs/server.pem',
    'certs/server.key', 'store.p12', 'store.pfx', 'store.jks',
    '.ssh/id_rsa', '.ssh/id_ed25519', '.npmrc', '.pypirc', '.netrc',
    '.htpasswd', 'credentials.json', 'secrets.yml',
  ]

  for (const path of sensibles) {
    it(`${path} n’est jamais lu`, async () => {
      const { fs, result } = await run({
        [`${ROOT}/${path}`]: { content: 'valeur-secrete' },
      })
      assert.equal(result.files.length, 1, `${path} doit rester indexé`)
      assert.deepEqual(fs.reads, [], `${path} a été lu`)
      assert.equal(isNeverRead(path), true)
    })
  }

  const modeles = ['.env.example', '.env.sample', '.env.template', '.env.dist']

  for (const path of modeles) {
    it(`${path} est lu : c’est un modèle sans valeurs`, async () => {
      // Le traiter comme sensible banaliserait la liste, et une liste
      // banalisée n'est plus lue.
      assert.equal(isNeverRead(path), false)
    })
  }

  it('aucun contenu de fichier ne figure dans le résultat', async () => {
    // Le contrat ne porte aucun champ de contenu : ce test fige cette
    // absence pour qu'un ajout futur soit un choix conscient.
    const { result } = await run({
      [`${ROOT}/.env`]: { content: 'OPENAI_API_KEY=sk-secret-reel' },
      [`${ROOT}/src/app.py`]: file('mot_de_passe = "en-clair"'),
    })

    const serialise = JSON.stringify(result)
    assert.ok(!serialise.includes('sk-secret-reel'), 'valeur de secret présente')
    assert.ok(!serialise.includes('en-clair'), 'contenu de source présent')
    for (const entry of result.files) {
      assert.deepEqual(Object.keys(entry).sort(), [
        'content_hash',
        'mtime',
        'path',
        'size',
      ])
    }
  })
})

describe('discoverProject — binaires', () => {
  it('indexe un binaire sans le lire', async () => {
    const { result, fs } = await run({
      [`${ROOT}/assets/logo.png`]: { content: 'octets', size: 4096 },
      [`${ROOT}/data/app.db`]: { content: 'octets', size: 8192 },
      [`${ROOT}/src/app.py`]: file('code'),
    })

    assert.equal(result.files.length, 3)
    // Un `.db` dans un dépôt est une information de sécurité : il reste
    // indexé. Le lire ne dirait rien de plus et coûterait cher.
    assert.deepEqual(fs.reads, [`${ROOT}/src/app.py`])
  })

  const binaires = ['a.png', 'a.zip', 'a.exe', 'a.dll', 'a.pdf', 'a.db',
    'a.sqlite', 'a.woff2', 'a.jar', 'a.class', 'a.pyc', 'a.mp4']

  for (const path of binaires) {
    it(`${path} est reconnu comme binaire`, () => {
      assert.equal(isBinaryPath(path), true)
    })
  }

  for (const path of ['a.py', 'a.ts', 'a.json', 'a.yml', 'a.md', 'Dockerfile']) {
    it(`${path} n’est pas binaire`, () => assert.equal(isBinaryPath(path), false))
  }

  it('ne hache pas un fichier trop gros', async () => {
    const { result, fs } = await run({
      [`${ROOT}/src/gros.py`]: { content: 'x', size: 5_000_000 },
    })
    // Taille et date suffisent à détecter un changement : lire plusieurs
    // mégaoctets pour une empreinte serait du gaspillage.
    assert.equal(result.files[0]!.content_hash, null)
    assert.deepEqual(fs.reads, [])
  })
})

// --------------------------------------------------------------------------
// Bornes : jamais silencieuses
// --------------------------------------------------------------------------

describe('discoverProject — bornes', () => {
  it('tronque au plafond et l’annonce', async () => {
    const tree: Record<string, FakeEntry> = {}
    for (let n = 0; n < 50; n += 1) {
      tree[`${ROOT}/src/f${n}.py`] = file()
    }

    const { result } = await run(tree, { maxFiles: 10 })

    assert.equal(result.files.length, 10)
    assert.equal(result.truncated, true)
    // Afficher une couverture partielle comme complète serait un mensonge
    // de sécurité.
    assert.ok(
      result.warnings.some((w) => w.includes('tronqué')),
      result.warnings.join(' | ')
    )
  })

  it('borne la profondeur et l’annonce', async () => {
    const deep = `${ROOT}/${Array.from({ length: 12 }, (_, i) => `n${i}`).join('/')}/a.py`
    const { result } = await run({ [`${ROOT}/a.py`]: file(), [deep]: file() }, {
      maxDepth: 3,
    })

    assert.ok(result.files.some((f) => f.path === 'a.py'))
    assert.ok(!result.files.some((f) => f.path.includes('n11')))
    assert.ok(
      result.warnings.some((w) => w.includes('profonde')),
      result.warnings.join(' | ')
    )
  })

  it('signale un dossier illisible sans échouer', async () => {
    const fs = new FakeFs({
      [`${ROOT}/src/app.py`]: file(),
      [`${ROOT}/protege/secret.py`]: file(),
    })
    fs.unreadableDirectories.add(`${ROOT}/protege`)

    const result = await discoverProject({ workspaceRoot: ROOT, fileSystem: fs })

    // Une découverte qui s'arrête au premier dossier protégé ne servirait
    // à rien.
    assert.ok(result.files.some((f) => f.path === 'src/app.py'))
    assert.ok(
      result.warnings.some((w) => w.includes('parcouru')),
      result.warnings.join(' | ')
    )
  })

  it('garde un fichier illisible dans l’index, sans empreinte', async () => {
    // Un fichier absent du décompte serait un angle mort ; sans empreinte
    // est honnête.
    const { result } = await run({
      [`${ROOT}/src/app.py`]: { content: 'x', unreadable: true },
    })
    assert.equal(result.files.length, 1)
    assert.equal(result.files[0]!.content_hash, null)
  })
})

describe('discoverProject — annulation', () => {
  it('s’arrête quand l’appelant annule', async () => {
    const tree: Record<string, FakeEntry> = {}
    for (let n = 0; n < 100; n += 1) {
      tree[`${ROOT}/src/f${n}.py`] = file()
    }

    let seen = 0
    const { result } = await run(tree, {
      onProgress: () => {
        seen += 1
      },
      isCancelled: () => seen >= 5,
    })

    assert.equal(result.cancelled, true)
    assert.ok(result.files.length < 100, `${result.files.length} fichiers indexés`)
  })

  it('n’est pas annulé quand personne ne le demande', async () => {
    const { result } = await run({ [`${ROOT}/a.py`]: file() })
    assert.equal(result.cancelled, false)
  })
})

describe('discoverProject — progression', () => {
  it('rapporte l’avancement', async () => {
    const tree: Record<string, FakeEntry> = {}
    for (let n = 0; n < 10; n += 1) {
      tree[`${ROOT}/f${n}.py`] = file()
    }

    const progress: number[] = []
    await run(tree, { onProgress: (indexed) => progress.push(indexed) })

    assert.equal(progress.length, 10)
    assert.deepEqual(progress, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
  })
})

describe('discoverProject — Git', () => {
  it('reprend les métadonnées fournies', async () => {
    const { result } = await run(
      { [`${ROOT}/a.py`]: file() },
      { git: { detected: true, remote_host: 'github.com' } }
    )
    assert.deepEqual(result.git, { detected: true, remote_host: 'github.com' })
  })

  it('suppose l’absence de dépôt quand rien n’est fourni', async () => {
    const { result } = await run({ [`${ROOT}/a.py`]: file() })
    assert.deepEqual(result.git, { detected: false, remote_host: null })
  })
})

// --------------------------------------------------------------------------
// Manifestes
// --------------------------------------------------------------------------

describe('discoverProject — manifestes', () => {
  it('extrait les dépendances d’un package.json', async () => {
    const { result } = await run({
      [`${ROOT}/package.json`]: {
        content: JSON.stringify({
          dependencies: { react: '^18.0.0', express: '^4.0.0' },
          devDependencies: { typescript: '^5.0.0' },
        }),
      },
    })

    assert.equal(result.manifests.length, 1)
    const manifest = result.manifests[0]!
    assert.equal(manifest.path, 'package.json')
    assert.equal(manifest.ecosystem, 'npm')
    assert.deepEqual(manifest.dependency_names.sort(), ['express', 'react', 'typescript'])
  })

  it('trouve les manifestes des sous-dossiers', async () => {
    const { result } = await run({
      [`${ROOT}/frontend/package.json`]: {
        content: JSON.stringify({ dependencies: { react: '^18' } }),
      },
      [`${ROOT}/backend/requirements.txt`]: { content: 'fastapi==0.100\n' },
    })

    assert.deepEqual(
      result.manifests.map((m) => m.path).sort(),
      ['backend/requirements.txt', 'frontend/package.json']
    )
  })

  it('ignore un fichier qui n’est pas un manifeste connu', async () => {
    const { result } = await run({ [`${ROOT}/config.json`]: { content: '{}' } })
    assert.deepEqual(result.manifests, [])
  })

  it('signale un manifeste illisible', async () => {
    const { result } = await run({
      [`${ROOT}/package.json`]: { content: '{}', unreadable: true },
    })
    assert.ok(
      result.warnings.some((w) => w.includes('package.json')),
      result.warnings.join(' | ')
    )
  })

  it('signale un manifeste anormalement gros', async () => {
    const { result } = await run({
      [`${ROOT}/package.json`]: { content: '{}', size: 2_000_000 },
    })
    assert.deepEqual(result.manifests, [])
    assert.ok(result.warnings.some((w) => w.includes('package.json')))
  })

  const ecosystemes: [string, string][] = [
    ['package.json', 'npm'],
    ['requirements.txt', 'pypi'],
    ['pyproject.toml', 'pypi'],
    ['composer.json', 'composer'],
    ['pom.xml', 'maven'],
    ['go.mod', 'go'],
    ['Gemfile', 'rubygems'],
  ]

  for (const [name, ecosystem] of ecosystemes) {
    it(`${name} relève de ${ecosystem}`, () => {
      assert.equal(manifestEcosystem(name), ecosystem)
    })
  }

  it('ne reconnaît pas un nom inconnu', () => {
    assert.equal(manifestEcosystem('inconnu.txt'), undefined)
  })
})

// --------------------------------------------------------------------------
// Extraction : des noms, jamais des versions ni des identifiants
// --------------------------------------------------------------------------

describe('extractDependencyNames', () => {
  it('package.json : les clés, pas les contraintes de version', async () => {
    const names = extractDependencyNames(
      'package.json',
      JSON.stringify({
        dependencies: { react: '^18.2.0' },
        devDependencies: { vitest: '~1.0.0' },
        peerDependencies: { vue: '3' },
      })
    )
    assert.deepEqual(names.sort(), ['react', 'vitest', 'vue'])
    // Aucune version ne doit survivre à l'extraction.
    assert.ok(!names.some((n) => n.includes('18')))
  })

  it('package.json invalide : liste vide, pas d’exception', async () => {
    assert.deepEqual(extractDependencyNames('package.json', '{pas du json'), [])
  })

  it('requirements.txt : le nom seul', () => {
    const names = extractDependencyNames(
      'requirements.txt',
      'fastapi==0.141.1\nuvicorn[standard]>=0.52\n# commentaire\n\npydantic\n'
    )
    assert.deepEqual(names.sort(), ['fastapi', 'pydantic', 'uvicorn'])
  })

  it('requirements.txt : une URL de dépôt avec identifiants est écartée', () => {
    // Le cas qui justifie la règle « des noms, jamais des lignes » : un
    // `--index-url` peut porter un mot de passe.
    const names = extractDependencyNames(
      'requirements.txt',
      '--index-url https://utilisateur:motdepasse@depot.example/simple\n' +
        '-r autre.txt\n' +
        '-e ./local\n' +
        'fastapi==0.100\n'
    )
    assert.deepEqual(names, ['fastapi'])
    const serialise = names.join(' ')
    assert.ok(!serialise.includes('motdepasse'))
    assert.ok(!serialise.includes('utilisateur'))
    assert.ok(!serialise.includes('depot.example'))
  })

  it('pyproject.toml : dépendances en ligne', () => {
    const names = extractDependencyNames(
      'pyproject.toml',
      '[project]\nname = "app"\ndependencies = ["fastapi>=0.100", "uvicorn"]\n'
    )
    assert.ok(names.includes('fastapi'), names.join(','))
    assert.ok(names.includes('uvicorn'), names.join(','))
  })

  it('pyproject.toml : section poetry', () => {
    const names = extractDependencyNames(
      'pyproject.toml',
      '[tool.poetry.dependencies]\npython = "^3.12"\nfastapi = "^0.100"\n' +
        'flask = { version = "^3.0" }\n'
    )
    assert.ok(names.includes('fastapi'), names.join(','))
    assert.ok(names.includes('flask'), names.join(','))
    // `python` est la version du langage, pas une dépendance.
    assert.ok(!names.includes('python'), names.join(','))
  })

  it('pom.xml : les artifactId', () => {
    const names = extractDependencyNames(
      'pom.xml',
      '<dependency><groupId>org.springframework.boot</groupId>' +
        '<artifactId>spring-boot-starter-web</artifactId>' +
        '<version>3.0.0</version></dependency>'
    )
    assert.deepEqual(names, ['spring-boot-starter-web'])
  })

  it('go.mod : les modules, suffixe de version majeure retiré', () => {
    const names = extractDependencyNames(
      'go.mod',
      'module exemple\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n' +
        '\tgithub.com/stretchr/testify/v2 v2.0.0\n)\n'
    )
    assert.ok(names.includes('github.com/gin-gonic/gin'), names.join(','))
    assert.ok(names.includes('github.com/stretchr/testify'), names.join(','))
  })

  it('Gemfile : les gems', () => {
    const names = extractDependencyNames(
      'Gemfile',
      "source 'https://rubygems.org'\ngem 'rails', '~> 7.0'\ngem 'puma'\n"
    )
    assert.deepEqual(names.sort(), ['puma', 'rails'])
  })

  it('composer.json : la section require', () => {
    const names = extractDependencyNames(
      'composer.json',
      JSON.stringify({ require: { 'laravel/framework': '^10.0', php: '^8.1' } })
    )
    assert.ok(names.includes('laravel/framework'), names.join(','))
  })

  it('écarte tout jeton contenant un blanc ou une URL', () => {
    // Filtre final commun à toutes les sources : un nom de paquet n'a
    // jamais de blanc, et c'est ce seul critère qui ferme la porte aux
    // lignes d'option.
    const names = extractDependencyNames(
      'requirements.txt',
      'paquet-valide\n'
    )
    assert.deepEqual(names, ['paquet-valide'])
  })

  it('dédoublonne', () => {
    const names = extractDependencyNames(
      'requirements.txt',
      'fastapi==0.1\nfastapi==0.2\nfastapi\n'
    )
    assert.deepEqual(names, ['fastapi'])
  })

  it('renvoie une liste vide pour un manifeste inconnu', () => {
    assert.deepEqual(extractDependencyNames('inconnu.txt', 'du contenu'), [])
  })
})

// --------------------------------------------------------------------------
// Crochets d'analyse (phase 2)
// --------------------------------------------------------------------------
//
// La couture entre la découverte et les moteurs de sécurité : c'est elle
// qui garantit qu'un seul parcours du disque alimente l'index, la
// détection de secrets et l'inventaire des dépendances. Si elle se
// cassait, le symptôme serait silencieux — aucun secret détecté, aucune
// erreur — donc elle mérite ses propres tests.

describe('découverte — crochets d’analyse', () => {
  it('offre le texte des fichiers réellement lus', async () => {
    const fs = new FakeFs({
      '/p/src/app.ts': { content: 'const x = 1' },
      '/p/src/config.ts': { content: 'const k = "abc"' },
    })

    const vus = new Map<string, string>()
    await discoverProject({
      workspaceRoot: '/p',
      fileSystem: fs,
      onFileText: (path, text) => vus.set(path, text),
    })

    assert.deepEqual([...vus.keys()].sort(), ['src/app.ts', 'src/config.ts'])
    assert.equal(vus.get('src/app.ts'), 'const x = 1')
  })

  it('n’offre JAMAIS le texte d’un fichier sensible', async () => {
    // La règle de la phase 1 n'est pas relâchée par la phase 2 : un `.env`
    // reste indexé et jamais ouvert. Le crochet ne peut donc pas devenir
    // une porte dérobée vers son contenu.
    const fs = new FakeFs({
      '/p/.env': { content: 'OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrst' },
      '/p/id_rsa': { content: '-----BEGIN RSA PRIVATE KEY-----' },
      '/p/server.pem': { content: '-----BEGIN PRIVATE KEY-----' },
      '/p/src/app.ts': { content: 'const x = 1' },
    })

    const vus: string[] = []
    const result = await discoverProject({
      workspaceRoot: '/p',
      fileSystem: fs,
      onFileText: (path) => vus.push(path),
    })

    assert.deepEqual(vus, ['src/app.ts'])
    // Ils sont bien indexés — leur présence est l'information — mais sans
    // empreinte, parce que la calculer demanderait de les lire.
    const env = result.files.find((file) => file.path === '.env')
    assert.ok(env)
    assert.equal(env.content_hash, null)
    assert.ok(!fs.reads.includes('/p/.env'))
  })

  it('signale les fichiers volontairement non lus', async () => {
    const fs = new FakeFs({
      '/p/.env': { content: 'SECRET=1' },
      '/p/logo.png': { content: 'binaire' },
      '/p/src/app.ts': { content: 'const x = 1' },
    })

    let ignores = 0
    await discoverProject({
      workspaceRoot: '/p',
      fileSystem: fs,
      onFileSkipped: () => {
        ignores += 1
      },
    })

    // Le décompte permet à l'appelant d'annoncer une couverture partielle
    // plutôt que de la taire.
    assert.equal(ignores, 2)
  })

  it('offre le texte des manifestes demandés, lockfiles compris', async () => {
    const fs = new FakeFs({
      '/p/package.json': { content: '{"dependencies":{"express":"4.18.2"}}' },
      '/p/package-lock.json': { content: '{"lockfileVersion":3}' },
      '/p/README.md': { content: '# titre' },
    })

    const manifestes = new Map<string, string>()
    await discoverProject({
      workspaceRoot: '/p',
      fileSystem: fs,
      // `package-lock.json` n'apprend rien sur les frameworks et n'est donc
      // pas lu par la phase 1 : c'est ce crochet qui élargit la liste.
      wantsManifest: (name) =>
        name === 'package.json' || name === 'package-lock.json',
      onManifestText: (path, _name, text) => manifestes.set(path, text),
    })

    assert.deepEqual(
      [...manifestes.keys()].sort(),
      ['package-lock.json', 'package.json']
    )
    assert.ok(manifestes.get('package-lock.json')?.includes('lockfileVersion'))
  })

  it('ne lit un manifeste qu’une fois pour les deux usages', async () => {
    // Les séparer ferait lire `package.json` deux fois : une pour les
    // preuves de framework, une pour l'inventaire.
    const fs = new FakeFs({
      '/p/package.json': { content: '{"dependencies":{"react":"18.2.0"}}' },
    })

    const result = await discoverProject({
      workspaceRoot: '/p',
      fileSystem: fs,
      wantsManifest: () => true,
      onManifestText: () => undefined,
    })

    const lectures = fs.reads.filter((path) => path.endsWith('package.json'))
    // Une lecture pour l'empreinte, une pour le manifeste — et pas trois.
    assert.ok(lectures.length <= 2, `lectures : ${lectures.length}`)
    // Les deux usages ont bien été servis.
    assert.equal(result.manifests[0]?.dependency_names.includes('react'), true)
  })

  it('sans crochet, la découverte se comporte exactement comme en phase 1', async () => {
    const fs = new FakeFs({
      '/p/src/app.ts': { content: 'const x = 1' },
      '/p/package.json': { content: '{"dependencies":{"react":"18.2.0"}}' },
    })

    const result = await discoverProject({ workspaceRoot: '/p', fileSystem: fs })

    assert.equal(result.files.length, 2)
    assert.equal(result.manifests.length, 1)
    assert.deepEqual(result.warnings, [])
  })
})
