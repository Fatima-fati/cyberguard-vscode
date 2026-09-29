/**
 * Inventaire des dépendances, lu dans les manifestes et les lockfiles.
 *
 * Ce que ce module ne fait jamais — et c'est la garantie principale
 * ---------------------------------------------------------------------
 *
 * **Il n'installe rien et n'exécute rien.** Pas de `npm install`, pas de
 * `pip download`, pas de `mvn dependency:tree`. Résoudre un arbre de
 * dépendances en lançant le gestionnaire de paquets reviendrait à exécuter
 * du code arbitraire venu d'un dépôt qu'on est précisément en train
 * d'auditer : un `postinstall` suffit. On lit des fichiers texte, un
 * point.
 *
 * La contrepartie est assumée : sans lockfile, les versions transitives
 * restent inconnues. Le contexte le dit alors explicitement plutôt que de
 * présenter une couverture qu'il n'a pas.
 *
 * Manifeste et lockfile ne disent pas la même chose
 * -------------------------------------------------
 *
 *     package.json      "express": "^4.18.0"   une CONTRAINTE
 *     package-lock.json "version": "4.18.2"    un ARTEFACT
 *
 * Seul le second est interrogeable : demander « l'intervalle ^4.18.0
 * est-il vulnérable ? » n'a pas de réponse utile. Les deux sont donc
 * collectés — le manifeste donne la liste des dépendances **directes**, le
 * lockfile donne les versions — et le backend les réconcilie en
 * privilégiant la version exacte.
 *
 * Analyse volontairement tolérante : un fichier mal formé produit une
 * liste partielle, jamais une exception. Un `pom.xml` en cours d'édition
 * ne doit pas faire échouer la découverte du projet entier.
 *
 * Aucune dépendance à `vscode` : ce module est testable en Node pur.
 */

import type {
  DependencyEcosystem,
  DependencyRecord,
  DependencySource,
} from './securityTypes'

/** Version du format d'inventaire, envoyée au backend. */
export const INVENTORY_VERSION = '1.0.0'

/** Au-delà, le fichier n'est plus un manifeste : il n'est pas lu. */
export const MAX_MANIFEST_BYTES = 4_000_000

/** Plafond de dépendances extraites d'un seul fichier. */
export const MAX_DEPENDENCIES_PER_FILE = 5_000

export interface ManifestKind {
  readonly ecosystem: DependencyEcosystem
  readonly source: DependencySource
}

/**
 * Fichiers lus pour l'inventaire, par nom exact (en minuscules).
 *
 * Table distincte de `projectDiscovery.MANIFEST_ECOSYSTEMS`, qui sert à la
 * détection de frameworks (phase 1) et n'extrait que des noms. Les faire
 * dépendre l'une de l'autre coupleraient deux besoins différents : élargir
 * l'inventaire ne doit pas changer ce que la phase 1 transmet.
 */
const MANIFESTS: Readonly<Record<string, ManifestKind>> = {
  // Node.js
  'package.json': { ecosystem: 'npm', source: 'manifest' },
  'package-lock.json': { ecosystem: 'npm', source: 'lockfile' },
  'npm-shrinkwrap.json': { ecosystem: 'npm', source: 'lockfile' },
  'yarn.lock': { ecosystem: 'npm', source: 'lockfile' },
  'pnpm-lock.yaml': { ecosystem: 'npm', source: 'lockfile' },
  // Python
  'requirements.txt': { ecosystem: 'pypi', source: 'manifest' },
  'requirements-dev.txt': { ecosystem: 'pypi', source: 'manifest' },
  'pyproject.toml': { ecosystem: 'pypi', source: 'manifest' },
  'poetry.lock': { ecosystem: 'pypi', source: 'lockfile' },
  'pipfile': { ecosystem: 'pypi', source: 'manifest' },
  'pipfile.lock': { ecosystem: 'pypi', source: 'lockfile' },
  // Java
  'pom.xml': { ecosystem: 'maven', source: 'manifest' },
  'build.gradle': { ecosystem: 'maven', source: 'manifest' },
  'build.gradle.kts': { ecosystem: 'maven', source: 'manifest' },
  // PHP
  'composer.json': { ecosystem: 'composer', source: 'manifest' },
  'composer.lock': { ecosystem: 'composer', source: 'lockfile' },
  // Go
  'go.mod': { ecosystem: 'go', source: 'manifest' },
  'go.sum': { ecosystem: 'go', source: 'lockfile' },
  // Ruby
  'gemfile': { ecosystem: 'rubygems', source: 'manifest' },
  'gemfile.lock': { ecosystem: 'rubygems', source: 'lockfile' },
  // Rust
  'cargo.toml': { ecosystem: 'cargo', source: 'manifest' },
  'cargo.lock': { ecosystem: 'cargo', source: 'lockfile' },
}

/** Ce fichier porte-t-il un inventaire de dépendances ? */
export function manifestKind(fileName: string): ManifestKind | undefined {
  const name = fileName.toLowerCase()
  if (name.startsWith('requirements') && name.endsWith('.txt')) {
    // `requirements-prod.txt`, `requirements/base.txt`… toutes les
    // variantes d'un usage très répandu.
    return { ecosystem: 'pypi', source: 'manifest' }
  }
  return MANIFESTS[name]
}

// --------------------------------------------------------------------------
// Versions
// --------------------------------------------------------------------------

/**
 * Ramène une déclaration de version à une version **exacte**, ou à rien.
 *
 * Le choix binaire est délibéré. Une chaîne vide se propage jusqu'au bout
 * comme « non vérifiable », ce qui est vrai ; inventer une version
 * plausible à partir de `^1.2.0` produirait une réponse — vulnérable ou
 * saine — qui ne décrirait aucun artefact réellement installé.
 */
export function exactVersion(declared: string): string {
  const raw = (declared ?? '').trim()
  if (raw.length === 0) {
    return ''
  }

  // `*`, `latest`, `x`, `any` : aucune version.
  if (/^(\*|x|latest|any|)$/i.test(raw)) {
    return ''
  }

  // `==1.2.3` (Python), `=1.2.3` (Cargo) : contrainte d'égalité, donc
  // exacte.
  const pinned = /^(?:==|=)\s*v?([0-9][^\s,;|]*)$/.exec(raw)
  if (pinned?.[1]) {
    return clean(pinned[1])
  }

  // Version nue : `1.2.3`, `v1.2.3`, `4.18.2-beta.1`, `1.2.3+build`.
  const bare = /^v?([0-9][A-Za-z0-9._+-]*)$/.exec(raw)
  if (bare?.[1]) {
    return clean(bare[1])
  }

  // Tout le reste est un intervalle : `^1.2.0`, `~>2.0`, `>=1,<2`,
  // `[1.0,2.0)`. Non interrogeable.
  return ''
}

function clean(version: string): string {
  return version.replace(/[,;)\]]+$/, '').slice(0, 120)
}

// --------------------------------------------------------------------------
// Point d'entrée
// --------------------------------------------------------------------------

/**
 * Extrait les dépendances d'un fichier déjà lu.
 *
 * Ne lève jamais : un fichier illisible ou mal formé produit une liste
 * vide. L'inventaire d'un monorepo ne doit pas s'arrêter au premier
 * `composer.json` en cours d'édition.
 */
export function parseDependencies(
  fileName: string,
  relativePath: string,
  raw: string
): DependencyRecord[] {
  const kind = manifestKind(fileName)
  if (!kind || !raw) {
    return []
  }

  const name = fileName.toLowerCase()
  let parsed: DependencyRecord[] = []

  try {
    if (name === 'package.json') {
      parsed = fromPackageJson(raw, relativePath)
    } else if (name === 'package-lock.json' || name === 'npm-shrinkwrap.json') {
      parsed = fromPackageLock(raw, relativePath)
    } else if (name === 'yarn.lock') {
      parsed = fromYarnLock(raw, relativePath)
    } else if (name === 'pnpm-lock.yaml') {
      parsed = fromPnpmLock(raw, relativePath)
    } else if (name.startsWith('requirements') && name.endsWith('.txt')) {
      parsed = fromRequirements(raw, relativePath)
    } else if (name === 'pyproject.toml') {
      parsed = fromPyproject(raw, relativePath)
    } else if (name === 'poetry.lock' || name === 'cargo.lock') {
      parsed = fromTomlLock(raw, relativePath, kind.ecosystem)
    } else if (name === 'pipfile') {
      parsed = fromPipfile(raw, relativePath)
    } else if (name === 'pipfile.lock') {
      parsed = fromPipfileLock(raw, relativePath)
    } else if (name === 'pom.xml') {
      parsed = fromPom(raw, relativePath)
    } else if (name === 'build.gradle' || name === 'build.gradle.kts') {
      parsed = fromGradle(raw, relativePath)
    } else if (name === 'composer.json') {
      parsed = fromComposerJson(raw, relativePath)
    } else if (name === 'composer.lock') {
      parsed = fromComposerLock(raw, relativePath)
    } else if (name === 'go.mod') {
      parsed = fromGoMod(raw, relativePath)
    } else if (name === 'go.sum') {
      parsed = fromGoSum(raw, relativePath)
    } else if (name === 'gemfile') {
      parsed = fromGemfile(raw, relativePath)
    } else if (name === 'gemfile.lock') {
      parsed = fromGemfileLock(raw, relativePath)
    } else if (name === 'cargo.toml') {
      parsed = fromCargoToml(raw, relativePath)
    }
  } catch {
    // Un fichier mal formé n'interrompt pas l'inventaire du projet.
    return []
  }

  return sanitize(parsed, kind)
}

/**
 * Filtre final, appliqué à toutes les sources.
 *
 * Un nom de paquet ne contient jamais de blanc. Ce seul critère écarte les
 * lignes d'option (`--index-url https://user:motdepasse@dépôt/simple`),
 * qui sont précisément celles qui peuvent porter des identifiants. La
 * règle est reprise de `projectDiscovery.sanitizeNames` : même risque,
 * même défense, appliquée là aussi plutôt que supposée acquise en amont.
 */
function sanitize(
  records: readonly DependencyRecord[],
  kind: ManifestKind
): DependencyRecord[] {
  const unique = new Map<string, DependencyRecord>()

  for (const record of records) {
    const name = record.name.trim()
    if (
      name.length === 0 ||
      name.length > 300 ||
      /\s/.test(name) ||
      name.includes('://') ||
      name.startsWith('-')
    ) {
      continue
    }

    const key = `${name.toLowerCase()}|${record.version}`
    if (!unique.has(key)) {
      unique.set(key, {
        ...record,
        name,
        ecosystem: kind.ecosystem,
        source: kind.source,
      })
    }
    if (unique.size >= MAX_DEPENDENCIES_PER_FILE) {
      break
    }
  }

  return [...unique.values()]
}

function record(
  name: string,
  version: string,
  direct: boolean,
  manifest: string
): DependencyRecord {
  return {
    name,
    ecosystem: 'unknown',
    version: exactVersion(version),
    direct,
    manifest,
    source: 'manifest',
  }
}

// --------------------------------------------------------------------------
// Node.js
// --------------------------------------------------------------------------

function fromPackageJson(raw: string, manifest: string): DependencyRecord[] {
  const parsed = JSON.parse(raw) as Record<string, unknown>
  const results: DependencyRecord[] = []

  // Toutes les sections sont **directes** : le projet les a écrites
  // lui-même. Les dépendances de développement comptent — une
  // vulnérabilité dans un outil de build est exploitable en CI.
  for (const section of [
    'dependencies',
    'devDependencies',
    'optionalDependencies',
    'peerDependencies',
  ]) {
    const block = parsed?.[section]
    if (block && typeof block === 'object' && !Array.isArray(block)) {
      for (const [name, constraint] of Object.entries(block)) {
        results.push(record(name, String(constraint ?? ''), true, manifest))
      }
    }
  }

  return results
}

function fromPackageLock(raw: string, manifest: string): DependencyRecord[] {
  const parsed = JSON.parse(raw) as Record<string, unknown>
  const results: DependencyRecord[] = []

  // Format v2/v3 : une entrée par chemin d'installation.
  const packages = parsed?.['packages']
  if (packages && typeof packages === 'object') {
    for (const [path, value] of Object.entries(packages as Record<string, unknown>)) {
      if (!path || typeof value !== 'object' || value === null) {
        continue
      }
      const name = path.split('node_modules/').pop() ?? ''
      const version = String((value as { version?: unknown }).version ?? '')
      if (!name || !version) {
        continue
      }
      // Profondeur 1 dans l'arborescence : dépendance directe. Au-delà,
      // elle a été tirée par une autre.
      const depth = path.split('node_modules/').length - 1
      results.push(record(name, version, depth <= 1, manifest))
    }
  }

  // Format v1 : arbre imbriqué sous `dependencies`.
  const tree = parsed?.['dependencies']
  if (results.length === 0 && tree && typeof tree === 'object') {
    walkLockTree(tree as Record<string, unknown>, manifest, true, results)
  }

  return results
}

function walkLockTree(
  tree: Record<string, unknown>,
  manifest: string,
  direct: boolean,
  results: DependencyRecord[]
): void {
  for (const [name, value] of Object.entries(tree)) {
    if (!value || typeof value !== 'object') {
      continue
    }
    const entry = value as { version?: unknown; dependencies?: unknown }
    if (entry.version) {
      results.push(record(name, String(entry.version), direct, manifest))
    }
    if (entry.dependencies && typeof entry.dependencies === 'object') {
      walkLockTree(
        entry.dependencies as Record<string, unknown>,
        manifest,
        false,
        results
      )
    }
  }
}

/**
 * `yarn.lock`, versions 1 et 2+.
 *
 *     "express@^4.18.0":          (v1)      express@npm:^4.18.0:   (berry)
 *       version "4.18.2"                      version: 4.18.2
 *
 * Les deux formats se lisent avec la même mécanique : une clé de bloc, une
 * ligne `version`. On ne cherche pas à distinguer direct et transitif —
 * un lockfile Yarn ne porte pas cette information, et le `package.json`
 * voisin la donne déjà.
 */
function fromYarnLock(raw: string, manifest: string): DependencyRecord[] {
  const results: DependencyRecord[] = []
  let pending: string | undefined

  for (const line of raw.split(/\r?\n/)) {
    if (line.startsWith('#') || line.trim().length === 0) {
      continue
    }

    if (!/^\s/.test(line) && line.trimEnd().endsWith(':')) {
      pending = packageNameFromYarnKey(line.trimEnd().slice(0, -1))
      continue
    }

    const version = /^\s+version:?\s+"?([^"\s]+)"?/.exec(line)
    if (version?.[1] && pending) {
      results.push(record(pending, version[1], false, manifest))
      pending = undefined
    }
  }

  return results
}

/** `"@scope/pkg@^1.0.0, @scope/pkg@^1.1.0"` → `@scope/pkg`. */
function packageNameFromYarnKey(key: string): string | undefined {
  const first = key.split(',')[0]?.trim().replace(/^["']|["']$/g, '')
  if (!first) {
    return undefined
  }
  // Le `@` de portée est en tête : on cherche le séparateur suivant.
  const separator = first.lastIndexOf('@')
  if (separator <= 0) {
    return first
  }
  return first.slice(0, separator)
}

/**
 * `pnpm-lock.yaml`.
 *
 *     /express/4.18.2:        (lockfile v5/v6)
 *     /express@4.18.2:        (lockfile v9)
 */
function fromPnpmLock(raw: string, manifest: string): DependencyRecord[] {
  const results: DependencyRecord[] = []
  let inPackages = false

  for (const line of raw.split(/\r?\n/)) {
    if (/^packages:\s*$/.test(line)) {
      inPackages = true
      continue
    }
    if (inPackages && /^\S/.test(line)) {
      inPackages = false
    }
    if (!inPackages) {
      continue
    }

    const entry = /^\s{2}'?\/(.+?)'?:\s*$/.exec(line)
    const key = entry?.[1]
    if (!key) {
      continue
    }

    // `@scope/name@1.2.3` ou `@scope/name/1.2.3`
    const atForm = /^(@?[^@]+(?:\/[^@]+)?)@([^()]+)$/.exec(key)
    if (atForm?.[1] && atForm[2]) {
      results.push(record(atForm[1], atForm[2], false, manifest))
      continue
    }

    const pieces = key.split('/')
    const version = pieces.pop() ?? ''
    const name = pieces.join('/')
    if (name && version) {
      results.push(record(name, version, false, manifest))
    }
  }

  return results
}

// --------------------------------------------------------------------------
// Python
// --------------------------------------------------------------------------

function fromRequirements(raw: string, manifest: string): DependencyRecord[] {
  const results: DependencyRecord[] = []

  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim()
    // `-r`, `--index-url`, `-e`, commentaires : écartés. C'est ici que se
    // trouveraient d'éventuels identifiants de dépôt privé.
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) {
      continue
    }

    const match = /^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(.*)$/.exec(
      trimmed.split(/\s+[;#]/)[0] ?? trimmed
    )
    if (!match?.[1]) {
      continue
    }
    results.push(record(match[1], match[2] ?? '', true, manifest))
  }

  return results
}

/**
 * `pyproject.toml` : PEP 621 et Poetry.
 *
 *     [project]                          [tool.poetry.dependencies]
 *     dependencies = ["fastapi>=0.1"]    fastapi = "^0.100"
 */
function fromPyproject(raw: string, manifest: string): DependencyRecord[] {
  const results: DependencyRecord[] = []
  let section = ''
  let inArray = false

  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (trimmed.startsWith('#')) {
      continue
    }

    const header = /^\[([^\]]+)\]/.exec(trimmed)
    if (header?.[1]) {
      section = header[1].toLowerCase()
      inArray = false
      continue
    }

    // Tableau PEP 621, sur une ou plusieurs lignes.
    if (/^(?:dependencies|optional-dependencies)\s*=\s*\[/.test(trimmed)) {
      inArray = true
      collectPep621(trimmed, manifest, results)
      if (trimmed.includes(']')) {
        inArray = false
      }
      continue
    }
    if (inArray) {
      collectPep621(trimmed, manifest, results)
      if (trimmed.includes(']')) {
        inArray = false
      }
      continue
    }

    // Table Poetry : `nom = "contrainte"` ou `nom = { version = "…" }`.
    if (!/dependencies|requires/.test(section)) {
      continue
    }
    const keyed = /^["']?([A-Za-z0-9._-]+)["']?\s*=\s*(.+)$/.exec(trimmed)
    if (!keyed?.[1] || keyed[1].toLowerCase() === 'python') {
      continue
    }
    const inline = /version\s*=\s*["']([^"']+)["']/.exec(keyed[2] ?? '')
    const literal = /^["']([^"']+)["']/.exec(keyed[2] ?? '')
    results.push(
      record(keyed[1], inline?.[1] ?? literal?.[1] ?? '', true, manifest)
    )
  }

  return results
}

function collectPep621(
  line: string,
  manifest: string,
  results: DependencyRecord[]
): void {
  const items = line.match(/["']([^"']+)["']/g) ?? []
  for (const item of items) {
    const requirement = item.slice(1, -1)
    const match = /^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(.*)$/.exec(requirement)
    if (match?.[1]) {
      results.push(record(match[1], match[2] ?? '', true, manifest))
    }
  }
}

/** `poetry.lock` et `Cargo.lock` : suite de blocs `[[package]]`. */
function fromTomlLock(
  raw: string,
  manifest: string,
  _ecosystem: DependencyEcosystem
): DependencyRecord[] {
  const results: DependencyRecord[] = []
  let name = ''
  let version = ''

  const flush = (): void => {
    if (name && version) {
      results.push(record(name, version, false, manifest))
    }
    name = ''
    version = ''
  }

  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (trimmed === '[[package]]') {
      flush()
      continue
    }
    const key = /^(name|version)\s*=\s*["']([^"']+)["']/.exec(trimmed)
    if (key?.[1] === 'name') {
      name = key[2] ?? ''
    } else if (key?.[1] === 'version') {
      version = key[2] ?? ''
    }
  }
  flush()

  return results
}

function fromPipfile(raw: string, manifest: string): DependencyRecord[] {
  const results: DependencyRecord[] = []
  let inPackages = false

  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim()
    const header = /^\[([^\]]+)\]/.exec(trimmed)
    if (header?.[1]) {
      inPackages = /packages/i.test(header[1])
      continue
    }
    if (!inPackages || !trimmed || trimmed.startsWith('#')) {
      continue
    }

    const keyed = /^["']?([A-Za-z0-9._-]+)["']?\s*=\s*(.+)$/.exec(trimmed)
    if (!keyed?.[1]) {
      continue
    }
    const inline = /version\s*=\s*["']([^"']+)["']/.exec(keyed[2] ?? '')
    const literal = /^["']([^"']+)["']/.exec(keyed[2] ?? '')
    results.push(
      record(keyed[1], inline?.[1] ?? literal?.[1] ?? '', true, manifest)
    )
  }

  return results
}

function fromPipfileLock(raw: string, manifest: string): DependencyRecord[] {
  const parsed = JSON.parse(raw) as Record<string, unknown>
  const results: DependencyRecord[] = []

  for (const section of ['default', 'develop']) {
    const block = parsed?.[section]
    if (!block || typeof block !== 'object') {
      continue
    }
    for (const [name, value] of Object.entries(block as Record<string, unknown>)) {
      const version = String((value as { version?: unknown })?.version ?? '')
      results.push(record(name, version.replace(/^==/, ''), section === 'default', manifest))
    }
  }

  return results
}

// --------------------------------------------------------------------------
// Java
// --------------------------------------------------------------------------

/**
 * `pom.xml`. Le nom Maven est `groupId:artifactId`, forme attendue par OSV.
 *
 * Une version qui référence une propriété (`${spring.version}`) n'est pas
 * résolue : résoudre les propriétés Maven demanderait de suivre l'héritage
 * des POM parents, éventuellement distants. La version reste donc vide, et
 * la dépendance est comptée non vérifiable — ce qu'elle est.
 */
function fromPom(raw: string, manifest: string): DependencyRecord[] {
  const results: DependencyRecord[] = []
  const blocks = raw.match(/<dependency>[\s\S]*?<\/dependency>/g) ?? []

  for (const block of blocks) {
    const group = /<groupId>\s*([^<\s]+)\s*<\/groupId>/.exec(block)?.[1]
    const artifact = /<artifactId>\s*([^<\s]+)\s*<\/artifactId>/.exec(block)?.[1]
    const version = /<version>\s*([^<\s]+)\s*<\/version>/.exec(block)?.[1] ?? ''
    if (!group || !artifact) {
      continue
    }
    results.push(
      record(
        `${group}:${artifact}`,
        version.startsWith('${') ? '' : version,
        true,
        manifest
      )
    )
  }

  return results
}

/**
 * `build.gradle` et `build.gradle.kts`.
 *
 *     implementation 'org.springframework.boot:spring-boot-starter:3.0.0'
 *     implementation("com.google.guava:guava:32.1.2-jre")
 */
function fromGradle(raw: string, manifest: string): DependencyRecord[] {
  const results: DependencyRecord[] = []
  const pattern =
    /["']([A-Za-z0-9._-]+):([A-Za-z0-9._-]+)(?::([A-Za-z0-9._${}+-]+))?["']/g

  let match = pattern.exec(raw)
  while (match !== null) {
    const group = match[1]
    const artifact = match[2]
    const version = match[3] ?? ''
    if (group && artifact) {
      results.push(
        record(
          `${group}:${artifact}`,
          version.startsWith('$') ? '' : version,
          true,
          manifest
        )
      )
    }
    match = pattern.exec(raw)
  }

  return results
}

// --------------------------------------------------------------------------
// PHP
// --------------------------------------------------------------------------

function fromComposerJson(raw: string, manifest: string): DependencyRecord[] {
  const parsed = JSON.parse(raw) as Record<string, unknown>
  const results: DependencyRecord[] = []

  for (const section of ['require', 'require-dev']) {
    const block = parsed?.[section]
    if (!block || typeof block !== 'object') {
      continue
    }
    for (const [name, constraint] of Object.entries(block as Record<string, unknown>)) {
      // `php`, `ext-json`, `lib-openssl` : contraintes de plateforme, pas
      // des paquets. Les inventorier ferait apparaître des « dépendances »
      // qu'aucune base de vulnérabilités ne connaît.
      if (!name.includes('/')) {
        continue
      }
      results.push(record(name, String(constraint ?? ''), true, manifest))
    }
  }

  return results
}

function fromComposerLock(raw: string, manifest: string): DependencyRecord[] {
  const parsed = JSON.parse(raw) as Record<string, unknown>
  const results: DependencyRecord[] = []

  for (const section of ['packages', 'packages-dev']) {
    const block = parsed?.[section]
    if (!Array.isArray(block)) {
      continue
    }
    for (const entry of block) {
      const name = String((entry as { name?: unknown })?.name ?? '')
      const version = String((entry as { version?: unknown })?.version ?? '')
      if (name) {
        results.push(record(name, version, section === 'packages', manifest))
      }
    }
  }

  return results
}

// --------------------------------------------------------------------------
// Go
// --------------------------------------------------------------------------

/**
 * `go.mod`.
 *
 * Le marqueur `// indirect` distingue explicitement les dépendances
 * transitives : Go est l'un des rares écosystèmes à le donner dans le
 * manifeste lui-même.
 */
function fromGoMod(raw: string, manifest: string): DependencyRecord[] {
  const results: DependencyRecord[] = []
  let inBlock = false

  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('//')) {
      continue
    }
    if (/^require\s*\($/.test(trimmed)) {
      inBlock = true
      continue
    }
    if (inBlock && trimmed === ')') {
      inBlock = false
      continue
    }

    const single = /^require\s+(\S+)\s+(\S+)/.exec(trimmed)
    if (single?.[1] && single[2]) {
      results.push(
        record(stripMajor(single[1]), single[2], !trimmed.includes('// indirect'), manifest)
      )
      continue
    }

    if (inBlock) {
      const entry = /^(\S+)\s+(\S+)/.exec(trimmed)
      if (entry?.[1] && entry[2]) {
        results.push(
          record(
            stripMajor(entry[1]),
            entry[2],
            !trimmed.includes('// indirect'),
            manifest
          )
        )
      }
    }
  }

  return results
}

/**
 * `go.sum`.
 *
 * Deux lignes par module (module et `/go.mod`) : la déduplication de
 * `sanitize` les ramène à une. Tout y est marqué transitif — `go.sum`
 * liste l'intégralité du graphe sans dire ce que le projet a déclaré,
 * et c'est `go.mod` qui porte cette information.
 */
function fromGoSum(raw: string, manifest: string): DependencyRecord[] {
  const results: DependencyRecord[] = []

  for (const line of raw.split(/\r?\n/)) {
    const entry = /^(\S+)\s+(v\S+?)(?:\/go\.mod)?\s+h1:/.exec(line.trim())
    if (entry?.[1] && entry[2]) {
      results.push(record(stripMajor(entry[1]), entry[2], false, manifest))
    }
  }

  return results
}

/** `github.com/gin-gonic/gin/v2` → `github.com/gin-gonic/gin`. */
function stripMajor(module: string): string {
  return module.replace(/\/v\d+$/, '')
}

// --------------------------------------------------------------------------
// Ruby
// --------------------------------------------------------------------------

function fromGemfile(raw: string, manifest: string): DependencyRecord[] {
  const results: DependencyRecord[] = []
  const pattern = /^\s*gem\s+["']([A-Za-z0-9._-]+)["']\s*(?:,\s*["']([^"']+)["'])?/gm

  let match = pattern.exec(raw)
  while (match !== null) {
    if (match[1]) {
      results.push(record(match[1], match[2] ?? '', true, manifest))
    }
    match = pattern.exec(raw)
  }

  return results
}

/**
 * `Gemfile.lock`.
 *
 *     GEM
 *       specs:
 *         rails (7.0.4)
 *           actioncable (= 7.0.4)     ← dépendance d'une dépendance
 */
function fromGemfileLock(raw: string, manifest: string): DependencyRecord[] {
  const results: DependencyRecord[] = []
  let inSpecs = false

  for (const line of raw.split(/\r?\n/)) {
    if (/^\s{2}specs:\s*$/.test(line)) {
      inSpecs = true
      continue
    }
    if (inSpecs && /^\S/.test(line)) {
      inSpecs = false
    }
    if (!inSpecs) {
      continue
    }

    // Quatre espaces : un gem installé, avec sa version résolue. Six
    // espaces : une contrainte d'un autre gem, sans version exacte.
    const entry = /^\s{4}([A-Za-z0-9._-]+)\s+\(([^)]+)\)\s*$/.exec(line)
    if (entry?.[1] && entry[2]) {
      results.push(record(entry[1], entry[2], false, manifest))
    }
  }

  return results
}

// --------------------------------------------------------------------------
// Rust
// --------------------------------------------------------------------------

function fromCargoToml(raw: string, manifest: string): DependencyRecord[] {
  const results: DependencyRecord[] = []
  let inDependencies = false

  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim()
    const header = /^\[([^\]]+)\]/.exec(trimmed)
    if (header?.[1]) {
      inDependencies = /dependencies$/i.test(header[1])
      continue
    }
    if (!inDependencies || !trimmed || trimmed.startsWith('#')) {
      continue
    }

    const keyed = /^["']?([A-Za-z0-9._-]+)["']?\s*=\s*(.+)$/.exec(trimmed)
    if (!keyed?.[1]) {
      continue
    }
    const inline = /version\s*=\s*["']([^"']+)["']/.exec(keyed[2] ?? '')
    const literal = /^["']([^"']+)["']/.exec(keyed[2] ?? '')
    results.push(
      record(keyed[1], inline?.[1] ?? literal?.[1] ?? '', true, manifest)
    )
  }

  return results
}

// --------------------------------------------------------------------------
// Agrégation sur un projet
// --------------------------------------------------------------------------

export interface ProjectInventory {
  readonly dependencies: DependencyRecord[]
  readonly manifestsRead: number
  readonly truncated: boolean
}

/**
 * Accumulateur d'inventaire, alimenté manifeste par manifeste.
 *
 * Même principe que `SecretScanAccumulator` : la découverte lit déjà ces
 * fichiers, et les lui redemander doublerait les entrées/sorties sans rien
 * apporter.
 */
export class DependencyInventoryAccumulator {
  private readonly dependencies: DependencyRecord[] = []
  private manifestsRead = 0
  private truncated = false

  /**
   * Répartition par manifeste, pour la surveillance continue (phase 3).
   *
   * Même raison que `SecretScanAccumulator.perFile()` : quand un seul
   * `package.json` change, il faut pouvoir remplacer **sa** contribution
   * et reconstituer l'inventaire complet sans relire les autres
   * manifestes du projet.
   *
   * Ajout purement additif : `result()` ne change pas, et la phase 2 ne
   * consulte jamais ce registre.
   */
  private readonly byManifest = new Map<string, DependencyRecord[]>()

  private readonly maxDependencies: number

  constructor(maxDependencies = 3_000) {
    this.maxDependencies = maxDependencies
  }

  /** Soumet le contenu d'un manifeste déjà lu par l'appelant. */
  consider(fileName: string, relativePath: string, raw: string): void {
    if (!manifestKind(fileName)) {
      return
    }
    if (this.dependencies.length >= this.maxDependencies) {
      this.truncated = true
      return
    }

    this.manifestsRead += 1
    // Enregistré même vide : un manifeste lu sans dépendance déclarée est
    // une information — c'est ce qui distingue « lu, rien dedans » de
    // « jamais ouvert », et le surveillant a besoin des deux.
    const batch = this.byManifest.get(relativePath) ?? []
    this.byManifest.set(relativePath, batch)

    for (const dependency of parseDependencies(fileName, relativePath, raw)) {
      if (this.dependencies.length >= this.maxDependencies) {
        this.truncated = true
        return
      }
      this.dependencies.push(dependency)
      batch.push(dependency)
    }
  }

  result(): ProjectInventory {
    return {
      dependencies: [...this.dependencies],
      manifestsRead: this.manifestsRead,
      truncated: this.truncated,
    }
  }

  /**
   * Détail par manifeste de ce parcours (phase 3).
   *
   * Consommé par `monitor/securityBaseline.ts`. Les listes sont copiées :
   * le registre du surveillant vit plus longtemps que l'accumulateur.
   */
  perManifest(): {
    dependenciesByManifest: ReadonlyMap<string, readonly DependencyRecord[]>
    truncated: boolean
  } {
    const dependenciesByManifest = new Map<string, readonly DependencyRecord[]>()
    for (const [path, records] of this.byManifest) {
      dependenciesByManifest.set(path, [...records])
    }
    return { dependenciesByManifest, truncated: this.truncated }
  }
}
