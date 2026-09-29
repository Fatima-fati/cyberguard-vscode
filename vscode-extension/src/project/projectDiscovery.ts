/**
 * Découverte locale d'un projet.
 *
 * Parcourt le dossier ouvert et produit un **index de métadonnées** :
 * chemin relatif, taille, empreinte, date. Le backend le classe ensuite.
 *
 * Ce que ce module ne fait jamais
 * ------------------------------
 *
 *     lire un fichier sensible       un `.env` n'est ni ouvert ni haché
 *     suivre un lien symbolique      un lien peut sortir du workspace
 *     lire un binaire                aucune valeur, coût réel
 *     transmettre du contenu         sauf les noms de dépendances
 *
 * Découverte ≠ analyse. L'indexation est rapide et complète ; l'analyse de
 * sécurité reste le travail de `/api/code/scan`, fichier par fichier. Les
 * confondre ferait de l'ouverture d'un monorepo une opération de plusieurs
 * minutes.
 *
 * Bornes, et pourquoi chacune
 * ---------------------------
 *
 *     profondeur       un lien mal détecté ne peut pas boucler
 *     fichiers         un monorepo ne bloque pas l'ouverture
 *     taille de hachage  hacher un fichier de 50 Mo ne dit rien de plus
 *     annulation       fermer le dossier arrête le parcours
 *
 * Aucune borne n'est silencieuse : chaque plafond atteint produit un
 * avertissement remonté à l'utilisateur.
 *
 * Aucune dépendance à `vscode` : ce module est testable en Node pur. Le
 * système de fichiers est injecté, ce qui permet d'exercer des
 * arborescences entières sans en écrire une sur disque.
 */

import * as crypto from 'node:crypto'
import * as nodeFs from 'node:fs/promises'
import * as path from 'node:path'

import { FR } from '../i18n/fr'
import type {
  DiscoveryResult,
  GitMetadata,
  IndexedFile,
  ManifestEvidence,
} from './projectTypes'

// --------------------------------------------------------------------------
// Bornes
// --------------------------------------------------------------------------

/** Plafond de fichiers indexés. Au-delà, l'index est tronqué et le dit. */
export const MAX_INDEXED_FILES = 20_000

/**
 * Profondeur maximale de descente.
 *
 * Seconde ceinture : les liens symboliques sont déjà écartés, mais une
 * jonction Windows mal détectée ne doit pas pouvoir faire boucler le
 * parcours indéfiniment.
 */
export const MAX_DEPTH = 24

/**
 * Au-delà de cette taille, le fichier est indexé sans être haché.
 *
 * L'empreinte sert au cache incrémental des phases suivantes. La calculer
 * sur un fichier de plusieurs mégaoctets coûte une lecture complète pour
 * un gain nul : taille et date suffisent à détecter un changement.
 */
export const MAX_HASH_BYTES = 2_000_000

/** Taille maximale d'un manifeste lu. Au-delà, ce n'est plus un manifeste. */
export const MAX_MANIFEST_BYTES = 512_000

/**
 * Taille maximale d'un fichier de verrouillage lu.
 *
 * Bien plus élevée que celle d'un manifeste, et pour une bonne raison : un
 * `package-lock.json` de projet réel dépasse couramment le mégaoctet. Le
 * plafond du manifeste l'aurait écarté, et l'inventaire aurait perdu
 * précisément les versions exactes — les seules interrogeables.
 */
export const MAX_LOCKFILE_BYTES = 4_000_000

/** Nombre maximum de noms de dépendances extraits par manifeste. */
export const MAX_DEPENDENCY_NAMES = 500

// --------------------------------------------------------------------------
// Exclusions
// --------------------------------------------------------------------------

/**
 * Dossiers jamais parcourus.
 *
 * Reprend les onze motifs de `documentFilter.ts` — qui reste la référence
 * pour ce qui est *envoyé* au backend — et les complète pour le parcours
 * d'un projet entier. La liste vaut quel que soit le `.gitignore` : ces
 * dossiers ne contiennent rien qu'un agent de sécurité doive indexer.
 */
export const EXCLUDED_DIRECTORIES: ReadonlySet<string> = new Set([
  // Déjà dans documentFilter
  'node_modules',
  'dist',
  'build',
  'out',
  '.git',
  '.venv',
  'venv',
  '__pycache__',
  'vendor',
  '.next',
  'coverage',
  // Ajouts pour le parcours complet (audit §9.3)
  'out-test',
  'target',
  'bin',
  'obj',
  '.gradle',
  'Pods',
  '.terraform',
  '.mypy_cache',
  '.pytest_cache',
  '.ruff_cache',
  '.tox',
  'bower_components',
  '.pnpm-store',
  '.yarn',
  '.nuxt',
  '.svelte-kit',
  '.turbo',
  '.parcel-cache',
  '.idea',
  '.vs',
  'logs',
  'tmp',
  'temp',
  '.cache',
  'site-packages',
  'env',
  'virtualenv',
])

/**
 * Fichiers dont le **contenu** n'est jamais lu, quel que soit le besoin.
 *
 * Ils sont bien **indexés** — leur présence est précisément ce que la
 * découverte doit constater — mais ni hachés ni ouverts. Hacher un `.env`
 * demanderait de le lire, et « lire pour calculer une empreinte » reste
 * lire.
 *
 * Doublon volontaire avec `documentFilter.SENSITIVE_PATTERNS` : les deux
 * protègent des chemins différents (envoi d'un document contre parcours du
 * projet), et faire dépendre l'un de l'autre créerait un couplage où un
 * assouplissement d'un côté ouvrirait l'autre sans qu'on le voie.
 */
const NEVER_READ_PATTERNS: readonly RegExp[] = [
  /(^|\/)\.env($|\.)/i,
  /\.pem$/i,
  /\.key$/i,
  /\.p12$/i,
  /\.pfx$/i,
  /\.jks$/i,
  /\.keystore$/i,
  /\.ppk$/i,
  /\.asc$/i,
  /(^|\/)id_(rsa|dsa|ecdsa|ed25519)$/i,
  /(^|\/)\.npmrc$/i,
  /(^|\/)\.pypirc$/i,
  /(^|\/)\.netrc$/i,
  /(^|\/)\.htpasswd$/i,
  /(^|\/)credentials(\.|$)/i,
  /(^|\/)secrets?(\.|$)/i,
]

/** Un `.env.example` est un modèle : son intérêt est d'être vide de valeurs. */
const NEVER_READ_EXEMPT = /\.(example|sample|template|dist)$/i

/**
 * Extensions binaires, médias, archives et bases : jamais hachées.
 *
 * Elles restent dans l'index — un `.db` dans un dépôt est une information
 * de sécurité — mais les lire coûterait cher pour rien.
 */
const BINARY_EXTENSIONS: ReadonlySet<string> = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.webp', '.tiff', '.avif',
  '.svg', '.mp3', '.mp4', '.avi', '.mov', '.mkv', '.wav', '.flac', '.ogg',
  '.webm', '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar', '.jar',
  '.war', '.ear', '.exe', '.dll', '.so', '.dylib', '.bin', '.o', '.a',
  '.obj', '.lib', '.pdb', '.class', '.pyc', '.pyo', '.pyd', '.wasm',
  '.db', '.sqlite', '.sqlite3', '.mdb', '.dat', '.pdf', '.doc', '.docx',
  '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods', '.woff', '.woff2',
  '.ttf', '.otf', '.eot', '.iso', '.dmg', '.vsix', '.node', '.pack',
])

export function isNeverRead(relativePath: string): boolean {
  const normalized = relativePath.replace(/\\/g, '/')
  if (NEVER_READ_EXEMPT.test(normalized)) {
    return false
  }
  return NEVER_READ_PATTERNS.some((pattern) => pattern.test(normalized))
}

export function isBinaryPath(relativePath: string): boolean {
  return BINARY_EXTENSIONS.has(path.extname(relativePath).toLowerCase())
}

export function isExcludedDirectory(name: string): boolean {
  return EXCLUDED_DIRECTORIES.has(name)
}

// --------------------------------------------------------------------------
// Manifestes
// --------------------------------------------------------------------------

/** Manifestes lus pour en extraire des noms de dépendances. */
const MANIFEST_ECOSYSTEMS: Readonly<Record<string, string>> = {
  'package.json': 'npm',
  'requirements.txt': 'pypi',
  'requirements-dev.txt': 'pypi',
  'pyproject.toml': 'pypi',
  'pipfile': 'pypi',
  'composer.json': 'composer',
  'pom.xml': 'maven',
  'build.gradle': 'maven',
  'go.mod': 'go',
  'gemfile': 'rubygems',
}

export function manifestEcosystem(fileName: string): string | undefined {
  return MANIFEST_ECOSYSTEMS[fileName.toLowerCase()]
}

// --------------------------------------------------------------------------
// Système de fichiers injectable
// --------------------------------------------------------------------------

export interface DirectoryEntry {
  readonly name: string
  readonly isDirectory: boolean
  readonly isFile: boolean
  /** Les liens ne sont jamais suivis : ils pourraient sortir du workspace. */
  readonly isSymbolicLink: boolean
}

export interface FileStat {
  readonly size: number
  readonly mtimeMs: number
}

export interface DiscoveryFileSystem {
  readDirectory(directory: string): Promise<DirectoryEntry[]>
  stat(file: string): Promise<FileStat>
  readFile(file: string): Promise<string>
}

/** Implémentation réelle, adossée à `node:fs`. */
export const nodeFileSystem: DiscoveryFileSystem = {
  async readDirectory(directory) {
    const entries = await nodeFs.readdir(directory, { withFileTypes: true })
    return entries.map((entry) => ({
      name: entry.name,
      isDirectory: entry.isDirectory(),
      isFile: entry.isFile(),
      isSymbolicLink: entry.isSymbolicLink(),
    }))
  },
  async stat(file) {
    const info = await nodeFs.stat(file)
    return { size: info.size, mtimeMs: info.mtimeMs }
  },
  readFile(file) {
    return nodeFs.readFile(file, { encoding: 'utf8' })
  },
}

// --------------------------------------------------------------------------
// Options
// --------------------------------------------------------------------------

/** Motif d'exclusion supplémentaire, typiquement issu d'un `.gitignore`. */
export interface IgnoreMatcher {
  ignores(relativePath: string): boolean
}

export interface DiscoveryOptions {
  readonly workspaceRoot: string
  readonly fileSystem?: DiscoveryFileSystem
  /**
   * `.gitignore` du projet. Respecté quand il est lisible.
   *
   * En cas de doute, le fichier est **indexé** plutôt qu'écarté : un
   * fichier indexé à tort coûte une ligne dans un décompte, un fichier
   * manqué à tort crée un angle mort de sécurité.
   */
  readonly ignore?: IgnoreMatcher
  /** Le dossier est-il un dépôt Git ? Fourni par l'appelant. */
  readonly git?: GitMetadata
  readonly maxFiles?: number
  readonly maxDepth?: number
  /** Annulation cooperative, consultée à chaque dossier et chaque fichier. */
  readonly isCancelled?: () => boolean
  /** Progression, pour une barre non bloquante. */
  readonly onProgress?: (indexed: number) => void
  readonly onLog?: (message: string) => void

  // --- Crochets d'analyse (phase 2) ------------------------------------
  //
  // La découverte reste ignorante de ce qu'on fera du texte : elle le
  // passe à qui le demande, et c'est l'appelant qui détient la logique de
  // sécurité. L'inversion n'est pas décorative — elle garde ce module
  // testable seul et empêche la détection de secrets de s'infiltrer dans
  // le parcours.
  //
  // Pourquoi des crochets plutôt qu'une seconde passe : la découverte lit
  // déjà chaque fichier éligible pour en calculer l'empreinte. Rendre ce
  // texte **au moment où il est en main** évite un second parcours
  // complet du disque. Sur un monorepo, c'est la différence entre
  // quelques secondes et plusieurs minutes.

  /**
   * Contenu d'un fichier qui vient d'être lu pour son empreinte.
   *
   * N'est appelé que pour les fichiers réellement lus : un `.env`, un
   * binaire ou un fichier de plus de `MAX_HASH_BYTES` ne passent jamais
   * par ici, parce qu'ils ne sont pas ouverts. La règle « ces fichiers ne
   * sont jamais lus » n'est donc pas assouplie par ce crochet.
   */
  readonly onFileText?: (relativePath: string, text: string) => void
  /** Fichier volontairement non lu : sensible, binaire, ou trop volumineux. */
  readonly onFileSkipped?: (relativePath: string) => void
  /**
   * Ce manifeste intéresse-t-il l'appelant ?
   *
   * Élargit la liste des fichiers lus au-delà de ceux dont la phase 1 tire
   * des noms de dépendances : un `package-lock.json` n'apprend rien sur
   * les frameworks mais porte les versions exactes.
   */
  readonly wantsManifest?: (fileName: string) => boolean
  /** Contenu d'un manifeste qui vient d'être lu. */
  readonly onManifestText?: (
    relativePath: string,
    fileName: string,
    text: string
  ) => void
}

// --------------------------------------------------------------------------
// Parcours
// --------------------------------------------------------------------------

/**
 * Indexe le projet et extrait les preuves des manifestes.
 *
 * Ne lève jamais pour une raison locale : un dossier illisible, un fichier
 * disparu en cours de route ou un manifeste invalide produisent un
 * avertissement, pas un échec. Une découverte qui s'arrête au premier
 * dossier protégé ne servirait à rien.
 */
export async function discoverProject(
  options: DiscoveryOptions
): Promise<DiscoveryResult> {
  const fs = options.fileSystem ?? nodeFileSystem
  const maxFiles = options.maxFiles ?? MAX_INDEXED_FILES
  const maxDepth = options.maxDepth ?? MAX_DEPTH
  const isCancelled = options.isCancelled ?? (() => false)

  const files: IndexedFile[] = []
  const manifests: ManifestEvidence[] = []
  const warnings: string[] = []

  let discoveredCount = 0
  let truncated = false
  let cancelled = false

  let unreadableDirectories = 0
  let unreadableFiles = 0
  let skippedSymlinks = 0
  let depthExceeded = 0

  /** Dossiers déjà visités, par chemin réel : garde-fou anti-boucle. */
  const visited = new Set<string>()

  async function walk(directory: string, relative: string, depth: number): Promise<void> {
    if (cancelled || truncated) {
      return
    }

    if (depth > maxDepth) {
      depthExceeded += 1
      return
    }

    const key = path.normalize(directory).toLowerCase()
    if (visited.has(key)) {
      return
    }
    visited.add(key)

    let entries: DirectoryEntry[]
    try {
      entries = await fs.readDirectory(directory)
    } catch {
      // Dossier protégé, monté ou supprimé pendant le parcours. Compté,
      // jamais fatal.
      unreadableDirectories += 1
      return
    }

    // Ordre stable : deux découvertes du même projet produisent le même
    // index, donc le même contexte.
    entries.sort((a, b) => a.name.localeCompare(b.name))

    for (const entry of entries) {
      if (isCancelled()) {
        cancelled = true
        return
      }
      if (truncated) {
        return
      }

      // Les liens ne sont jamais suivis : un lien peut pointer hors du
      // workspace, y compris vers un dossier système.
      if (entry.isSymbolicLink) {
        skippedSymlinks += 1
        continue
      }

      const childRelative = relative ? `${relative}/${entry.name}` : entry.name
      const childAbsolute = path.join(directory, entry.name)

      if (entry.isDirectory) {
        if (isExcludedDirectory(entry.name)) {
          continue
        }
        if (options.ignore?.ignores(`${childRelative}/`)) {
          continue
        }
        await walk(childAbsolute, childRelative, depth + 1)
        continue
      }

      if (!entry.isFile) {
        // Ni fichier ni dossier : socket, FIFO, périphérique. Rien à
        // indexer, et l'ouvrir pourrait bloquer.
        continue
      }

      if (options.ignore?.ignores(childRelative)) {
        continue
      }

      discoveredCount += 1

      if (files.length >= maxFiles) {
        truncated = true
        return
      }

      const indexed = await indexFile(childAbsolute, childRelative)
      if (indexed === undefined) {
        unreadableFiles += 1
        continue
      }
      files.push(indexed)
      options.onProgress?.(files.length)

      await collectManifest(childAbsolute, childRelative, entry.name)
    }
  }

  async function indexFile(
    absolute: string,
    relative: string
  ): Promise<IndexedFile | undefined> {
    let info: FileStat
    try {
      info = await fs.stat(absolute)
    } catch {
      return undefined
    }

    return {
      path: relative,
      size: info.size,
      mtime: new Date(info.mtimeMs).toISOString(),
      content_hash: await hashIfAppropriate(absolute, relative, info.size),
    }
  }

  /**
   * Empreinte du contenu, quand la calculer a un sens.
   *
   * Trois refus, trois raisons :
   *
   * - fichier sensible : le hacher demanderait de le lire ;
   * - binaire : aucune règle ne s'y applique, la lecture est pure perte ;
   * - trop gros : taille et date suffisent à détecter un changement.
   *
   * `null` signifie « pas d'empreinte », jamais « fichier inchangé » : les
   * phases suivantes doivent pouvoir distinguer les deux.
   */
  async function hashIfAppropriate(
    absolute: string,
    relative: string,
    size: number
  ): Promise<string | null> {
    if (isNeverRead(relative) || isBinaryPath(relative) || size > MAX_HASH_BYTES) {
      options.onFileSkipped?.(relative)
      return null
    }
    if (size === 0) {
      return null
    }

    try {
      const content = await fs.readFile(absolute)
      // Le texte est offert à l'appelant pendant qu'il est en mémoire,
      // puis oublié ici. Ce module n'en conserve que l'empreinte.
      options.onFileText?.(relative, content)
      return crypto.createHash('sha256').update(content, 'utf8').digest('hex')
    } catch {
      // Illisible : l'entrée reste dans l'index sans empreinte plutôt que
      // de disparaître. Un fichier absent du décompte serait un angle mort.
      options.onFileSkipped?.(relative)
      return null
    }
  }

  async function collectManifest(
    absolute: string,
    relative: string,
    fileName: string
  ): Promise<void> {
    const ecosystem = manifestEcosystem(fileName)
    const wanted = options.wantsManifest?.(fileName) ?? false

    // Un seul motif de lecture pour deux besoins : la preuve de framework
    // (phase 1) et l'inventaire des dépendances (phase 2). Les séparer
    // ferait lire `package.json` deux fois.
    if ((ecosystem === undefined && !wanted) || isNeverRead(relative)) {
      return
    }

    const cap = wanted ? MAX_LOCKFILE_BYTES : MAX_MANIFEST_BYTES

    let raw: string
    try {
      const info = await fs.stat(absolute)
      if (info.size > cap) {
        warnings.push(FR.project.warnings.manifestTooLarge(relative))
        return
      }
      raw = await fs.readFile(absolute)
    } catch {
      warnings.push(FR.project.warnings.manifestUnreadable(relative))
      return
    }

    if (wanted) {
      options.onManifestText?.(relative, fileName, raw)
    }

    // L'extraction des noms (phase 1) garde son plafond d'origine : un
    // fichier de plusieurs mégaoctets n'est pas un manifeste au sens où
    // la détection de frameworks l'entend.
    if (ecosystem === undefined || raw.length > MAX_MANIFEST_BYTES) {
      return
    }

    const names = extractDependencyNames(fileName, raw)
    if (names.length > 0) {
      manifests.push({ path: relative, ecosystem, dependency_names: names })
    }
  }

  await walk(options.workspaceRoot, '', 0)

  // --- Avertissements : aucune borne atteinte en silence.

  if (truncated) {
    warnings.push(FR.project.warnings.truncated(files.length, maxFiles))
  }
  if (unreadableDirectories > 0) {
    warnings.push(FR.project.warnings.unreadableDirectories(unreadableDirectories))
  }
  if (unreadableFiles > 0) {
    warnings.push(FR.project.warnings.unreadableFiles(unreadableFiles))
  }
  if (skippedSymlinks > 0) {
    warnings.push(FR.project.warnings.symlinks(skippedSymlinks))
  }
  if (depthExceeded > 0) {
    warnings.push(FR.project.warnings.depth(maxDepth))
  }

  return {
    files,
    manifests,
    git: options.git ?? { detected: false, remote_host: null },
    discoveredCount,
    truncated,
    warnings,
    cancelled,
  }
}

// --------------------------------------------------------------------------
// Extraction des noms de dépendances
// --------------------------------------------------------------------------

/**
 * Noms de dépendances déclarés par un manifeste. **Jamais les versions.**
 *
 * La contrainte n'est pas esthétique : une version seule est inoffensive,
 * mais la ligne qui la porte peut contenir bien plus. Un
 * `requirements.txt` accepte
 * `--index-url https://user:motdepasse@dépôt.example/simple`, un
 * `.npmrc`-style token peut se glisser dans une URL de dépendance Git.
 * N'extraire que des noms de paquets — jetons dépourvus de blancs, de `:`
 * et de `@` en tête — écarte ces cas par construction.
 *
 * Analyse volontairement tolérante : un manifeste mal formé produit une
 * liste partielle, jamais une exception. Les dépendances ne sont pas
 * l'objet de cette phase ; elles ne servent ici qu'à identifier des
 * frameworks.
 */
export function extractDependencyNames(fileName: string, raw: string): string[] {
  const name = fileName.toLowerCase()
  let names: string[] = []

  if (name === 'package.json' || name === 'composer.json') {
    names = fromJsonManifest(raw)
  } else if (name.startsWith('requirements')) {
    names = fromRequirements(raw)
  } else if (name === 'pyproject.toml' || name === 'pipfile') {
    names = fromToml(raw)
  } else if (name === 'pom.xml') {
    names = fromPom(raw)
  } else if (name === 'build.gradle') {
    names = fromGradle(raw)
  } else if (name === 'go.mod') {
    names = fromGoMod(raw)
  } else if (name === 'gemfile') {
    names = fromGemfile(raw)
  }

  return sanitizeNames(names)
}

/**
 * Filtre final, appliqué à toutes les sources.
 *
 * Un nom de paquet ne contient jamais de blanc. Ce seul critère écarte les
 * lignes d'option (`--index-url …`), qui sont précisément celles qui
 * peuvent porter des identifiants.
 */
function sanitizeNames(names: readonly string[]): string[] {
  const unique = new Set<string>()
  for (const candidate of names) {
    const value = candidate.trim()
    if (
      value &&
      value.length <= 214 &&
      !/\s/.test(value) &&
      !value.startsWith('-') &&
      !value.includes('://')
    ) {
      unique.add(value)
    }
    if (unique.size >= MAX_DEPENDENCY_NAMES) {
      break
    }
  }
  return [...unique]
}

function fromJsonManifest(raw: string): string[] {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return []
  }
  if (!parsed || typeof parsed !== 'object') {
    return []
  }

  const sections = [
    'dependencies',
    'devDependencies',
    'peerDependencies',
    'optionalDependencies',
    'require',
    'require-dev',
  ]
  const names: string[] = []
  for (const section of sections) {
    const block = (parsed as Record<string, unknown>)[section]
    if (block && typeof block === 'object' && !Array.isArray(block)) {
      // Les clés sont les noms, les valeurs les contraintes de version :
      // on ne lit que les clés.
      names.push(...Object.keys(block))
    }
  }
  return names
}

function fromRequirements(raw: string): string[] {
  const names: string[] = []
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim()
    // `-r`, `--index-url`, `-e`, commentaires : écartés. C'est ici que se
    // trouveraient d'éventuels identifiants de dépôt privé.
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) {
      continue
    }
    // Le nom s'arrête au premier spécificateur de version ou d'extra.
    const match = /^([A-Za-z0-9._-]+)/.exec(trimmed)
    if (match?.[1]) {
      names.push(match[1])
    }
  }
  return names
}

function fromToml(raw: string): string[] {
  const names: string[] = []
  let inDependencySection = false

  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (trimmed.startsWith('#')) {
      continue
    }

    if (trimmed.startsWith('[')) {
      // `[project.dependencies]`, `[tool.poetry.dependencies]`,
      // `[packages]` (Pipfile)…
      inDependencySection = /dependen|packages|requires/i.test(trimmed)
      continue
    }

    // `dependencies = ["fastapi>=0.100", "uvicorn"]` sur une seule ligne.
    const inline = /^\s*(?:dependencies|requires)\s*=\s*\[(.*)\]/i.exec(line)
    if (inline?.[1]) {
      for (const piece of inline[1].split(',')) {
        const quoted = /["']([A-Za-z0-9._-]+)/.exec(piece)
        if (quoted?.[1]) {
          names.push(quoted[1])
        }
      }
      continue
    }

    if (!inDependencySection || !trimmed) {
      continue
    }

    // `fastapi = "^0.100"` ou `"fastapi>=0.100",`
    const key = /^["']?([A-Za-z0-9._-]+)["']?\s*=/.exec(trimmed)
    if (key?.[1] && key[1].toLowerCase() !== 'python') {
      names.push(key[1])
      continue
    }
    const listItem = /^["']([A-Za-z0-9._-]+)/.exec(trimmed)
    if (listItem?.[1]) {
      names.push(listItem[1])
    }
  }
  return names
}

function fromPom(raw: string): string[] {
  const names: string[] = []
  // `artifactId` seul : c'est lui que porte la table de frameworks.
  const pattern = /<artifactId>\s*([^<\s]+)\s*<\/artifactId>/g
  let match = pattern.exec(raw)
  while (match !== null) {
    if (match[1]) {
      names.push(match[1])
    }
    match = pattern.exec(raw)
  }
  return names
}

function fromGradle(raw: string): string[] {
  const names: string[] = []
  // `implementation 'org.springframework.boot:spring-boot-starter-web:3.0'`
  const pattern = /["']([A-Za-z0-9._-]+):([A-Za-z0-9._-]+)(?::[^"']*)?["']/g
  let match = pattern.exec(raw)
  while (match !== null) {
    if (match[2]) {
      names.push(match[2])
    }
    match = pattern.exec(raw)
  }
  return names
}

function fromGoMod(raw: string): string[] {
  const names: string[] = []
  let inRequireBlock = false

  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (trimmed.startsWith('//') || !trimmed) {
      continue
    }
    if (/^require\s*\($/.test(trimmed)) {
      inRequireBlock = true
      continue
    }
    if (inRequireBlock && trimmed === ')') {
      inRequireBlock = false
      continue
    }

    const single = /^require\s+(\S+)/.exec(trimmed)
    if (single?.[1]) {
      names.push(stripGoMajorSuffix(single[1]))
      continue
    }
    if (inRequireBlock) {
      const module = /^(\S+)/.exec(trimmed)
      if (module?.[1]) {
        names.push(stripGoMajorSuffix(module[1]))
      }
    }
  }
  return names
}

/** `github.com/gin-gonic/gin/v2` → `github.com/gin-gonic/gin`. */
function stripGoMajorSuffix(module: string): string {
  return module.replace(/\/v\d+$/, '')
}

function fromGemfile(raw: string): string[] {
  const names: string[] = []
  const pattern = /^\s*gem\s+["']([A-Za-z0-9._-]+)["']/gm
  let match = pattern.exec(raw)
  while (match !== null) {
    if (match[1]) {
      names.push(match[1])
    }
    match = pattern.exec(raw)
  }
  return names
}
