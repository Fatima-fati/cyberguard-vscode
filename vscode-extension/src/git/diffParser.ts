/**
 * Lecture d'un diff unifié.
 *
 * Ce que ce module répond, et pourquoi c'est la question centrale de la
 * phase 4 : **quelles lignes le développeur vient-il d'écrire ?**
 *
 * Sans cette réponse, « ce changement introduit-il une faille ? » n'a pas
 * de sens : on ne saurait que dire « ce fichier contient une faille »,
 * ce qui était déjà vrai avant, et ce qui ferait bloquer un `push` pour
 * un problème vieux de deux ans.
 *
 * D'où vient le texte analysé ici
 * -------------------------------
 *
 * De l'API `vscode.git` (`repository.diffWithHEAD()`), **jamais** d'un
 * `git` lancé en sous-processus. Ce module ne lit ni le disque ni un
 * processus : il reçoit une chaîne. C'est ce qui le rend testable sans
 * dépôt, et ce qui garantit qu'il ne peut pas exécuter quoi que ce soit.
 *
 * Ce qu'il extrait, et ce qu'il jette
 * -----------------------------------
 *
 *     GARDÉ    chemins, numéros de ligne ajoutés, volumétrie
 *     JETÉ     le contenu des lignes
 *
 * Le contenu est volontairement abandonné : une ligne ajoutée peut être
 * un secret, et le garder en mémoire dans une structure qui circule
 * jusqu'à l'affichage serait un risque gratuit. Les moteurs de sécurité
 * relisent le fichier eux-mêmes, par les chemins déjà prévus.
 *
 * Tolérance
 * ---------
 *
 * Un diff mal formé ne lève jamais : il produit un résultat partiel. Un
 * analyseur qui s'arrête à la première ligne surprenante perdrait
 * l'intégralité d'un changement à cause d'un fichier binaire ou d'un
 * en-tête inhabituel — et la phase 4 échouerait ouvert **en silence**,
 * ce qui est la pire des combinaisons.
 *
 * Aucune dépendance à `vscode` : ce module est testable en Node pur.
 */

/** Intervalle de lignes, **1-basé et inclusif**, dans le fichier d'arrivée. */
export interface LineRange {
  readonly start: number
  readonly end: number
}

/** Nature du changement subi par un fichier. */
export type FileChangeKind = 'added' | 'modified' | 'deleted' | 'renamed'

/** Ce qu'on retient d'un fichier modifié. Jamais son contenu. */
export interface FileDiff {
  /** Chemin d'arrivée, relatif à la racine du dépôt, séparateurs `/`. */
  readonly path: string
  /** Chemin de départ, présent seulement sur un renommage. */
  readonly previousPath: string | null
  readonly change: FileChangeKind
  /**
   * Lignes ajoutées, dans le fichier d'arrivée, fusionnées en intervalles.
   *
   * Vide pour une suppression : il n'y a plus de fichier d'arrivée où
   * pointer, et attribuer un finding à un fichier supprimé n'aurait pas
   * de sens.
   */
  readonly addedRanges: readonly LineRange[]
  readonly addedCount: number
  readonly removedCount: number
  /** Un binaire n'a pas de lignes : aucun moteur ne s'y applique. */
  readonly binary: boolean
}

export interface DiffParseResult {
  readonly files: readonly FileDiff[]
  /** Volumétrie totale, pour le mode réduit et le résumé. */
  readonly addedCount: number
  readonly removedCount: number
}

/** État mutable d'un fichier pendant l'analyse. */
interface FileAccumulator {
  path: string
  previousPath: string | null
  change: FileChangeKind
  added: number[]
  addedCount: number
  removedCount: number
  binary: boolean
  /** Le fichier a-t-il été vu par un en-tête `---`/`+++` ? */
  sawHeader: boolean
}

/**
 * Analyse un diff unifié produit par Git.
 *
 * Accepte aussi bien la sortie de `git diff` que celle de `git diff
 * --cached`, avec ou sans en-têtes `diff --git`. Les chemins sont
 * normalisés en séparateurs `/` et débarrassés des préfixes `a/` et `b/`.
 */
export function parseUnifiedDiff(raw: string): DiffParseResult {
  if (!raw) {
    return { files: [], addedCount: 0, removedCount: 0 }
  }

  const files: FileAccumulator[] = []
  let current: FileAccumulator | undefined
  /** Prochaine ligne à numéroter dans le fichier d'arrivée. */
  let newLine = 0
  let inHunk = false

  const push = (): void => {
    if (current && (current.sawHeader || current.binary || current.added.length > 0)) {
      files.push(current)
    }
  }

  for (const line of raw.split(/\r?\n/)) {
    // --- Nouvel en-tête de fichier -------------------------------------
    if (line.startsWith('diff --git ')) {
      push()
      current = blank(pathsFromDiffHeader(line))
      inHunk = false
      newLine = 0
      continue
    }

    if (!current) {
      // Un diff sans `diff --git` reste analysable : `--- a/x` suffit à
      // ouvrir un fichier. C'est la forme que produisent certains outils,
      // et la refuser ferait perdre le changement entier.
      if (line.startsWith('--- ')) {
        current = blank({ path: '', previousPath: null })
      } else {
        continue
      }
    }

    // --- Renommages ----------------------------------------------------
    if (line.startsWith('rename from ')) {
      current.previousPath = normalize(line.slice('rename from '.length))
      current.change = 'renamed'
      continue
    }
    if (line.startsWith('rename to ')) {
      current.path = normalize(line.slice('rename to '.length))
      current.change = 'renamed'
      continue
    }

    // --- Binaires ------------------------------------------------------
    if (line.startsWith('Binary files ') || line.startsWith('GIT binary patch')) {
      current.binary = true
      current.sawHeader = true
      continue
    }

    // --- En-têtes de chemin --------------------------------------------
    if (line.startsWith('--- ')) {
      const source = line.slice(4).trim()
      current.sawHeader = true
      if (source === '/dev/null') {
        current.change = 'added'
      } else if (!current.path && current.change !== 'renamed') {
        current.previousPath = null
        current.path = stripPrefix(source)
      }
      inHunk = false
      continue
    }

    if (line.startsWith('+++ ')) {
      const target = line.slice(4).trim()
      current.sawHeader = true
      if (target === '/dev/null') {
        current.change = 'deleted'
      } else if (current.change !== 'renamed') {
        const resolved = stripPrefix(target)
        if (resolved) {
          current.path = resolved
        }
      }
      inHunk = false
      continue
    }

    // --- En-tête de section --------------------------------------------
    const hunk = HUNK.exec(line)
    if (hunk) {
      newLine = Number.parseInt(hunk[1] ?? '1', 10)
      if (!Number.isFinite(newLine) || newLine < 1) {
        newLine = 1
      }
      inHunk = true
      continue
    }

    if (!inHunk) {
      continue
    }

    // --- Contenu d'une section -----------------------------------------
    //
    // Le premier caractère porte toute l'information dont on a besoin.
    // Le reste de la ligne — le code — est délibérément ignoré.
    const marker = line.charAt(0)

    if (marker === '+') {
      current.added.push(newLine)
      current.addedCount += 1
      newLine += 1
      continue
    }

    if (marker === '-') {
      current.removedCount += 1
      continue
    }

    if (marker === '\\') {
      // « \ No newline at end of file » : ne numérote rien.
      continue
    }

    if (marker === ' ' || line === '') {
      // Ligne de contexte. Une ligne vide dans une section est un
      // contexte vide — Git omet parfois l'espace de tête.
      newLine += 1
      continue
    }

    // Tout autre caractère termine la section : `diff --git` suivant,
    // signature de format-patch, texte libre.
    inHunk = false
  }

  push()

  const parsed = files.map(finalize)
  return {
    files: parsed,
    addedCount: parsed.reduce((total, file) => total + file.addedCount, 0),
    removedCount: parsed.reduce((total, file) => total + file.removedCount, 0),
  }
}

// --------------------------------------------------------------------------
// Index des lignes changées
// --------------------------------------------------------------------------

/**
 * Ce que l'attribution consulte : par chemin, les lignes qui viennent
 * d'être écrites.
 *
 * Un `Map` plutôt qu'une liste : l'attribution interroge par chemin, une
 * fois par finding, et une recherche linéaire sur un changement de deux
 * cents fichiers se paierait à chaque appel.
 */
export interface ChangedLineIndex {
  /** Chemin → intervalles ajoutés. Absent = fichier non modifié. */
  readonly byPath: ReadonlyMap<string, readonly LineRange[]>
  /** Fichiers entièrement nouveaux : tout ce qu'ils portent est neuf. */
  readonly addedFiles: ReadonlySet<string>
  /** Fichiers supprimés : plus rien à y attribuer. */
  readonly deletedFiles: ReadonlySet<string>
}

export function buildChangedLineIndex(
  files: readonly FileDiff[]
): ChangedLineIndex {
  const byPath = new Map<string, readonly LineRange[]>()
  const addedFiles = new Set<string>()
  const deletedFiles = new Set<string>()

  for (const file of files) {
    if (file.change === 'deleted') {
      deletedFiles.add(file.path)
      continue
    }
    if (file.change === 'added') {
      addedFiles.add(file.path)
    }
    byPath.set(file.path, file.addedRanges)
  }

  return { byPath, addedFiles, deletedFiles }
}

/** Cet intervalle de lignes touche-t-il une ligne ajoutée ? */
export function intersectsRanges(
  ranges: readonly LineRange[],
  start: number,
  end: number
): boolean {
  const from = Math.min(start, end)
  const to = Math.max(start, end)
  return ranges.some((range) => range.start <= to && range.end >= from)
}

/** Fusionne des numéros de ligne triés en intervalles contigus. */
export function toRanges(lines: readonly number[]): LineRange[] {
  if (lines.length === 0) {
    return []
  }

  const sorted = [...new Set(lines)].sort((a, b) => a - b)
  const ranges: LineRange[] = []
  let start = sorted[0] as number
  let previous = start

  for (const line of sorted.slice(1)) {
    if (line === previous + 1) {
      previous = line
      continue
    }
    ranges.push({ start, end: previous })
    start = line
    previous = line
  }
  ranges.push({ start, end: previous })
  return ranges
}

// --------------------------------------------------------------------------
// Interne
// --------------------------------------------------------------------------

/** `@@ -12,7 +14,9 @@` — seul le second couple nous intéresse. */
const HUNK = /^@@+ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/

function blank(paths: { path: string; previousPath: string | null }): FileAccumulator {
  return {
    path: paths.path,
    previousPath: paths.previousPath,
    change: 'modified',
    added: [],
    addedCount: 0,
    removedCount: 0,
    binary: false,
    sawHeader: false,
  }
}

function finalize(file: FileAccumulator): FileDiff {
  return {
    path: file.path,
    previousPath: file.previousPath,
    change: file.change,
    // Une suppression n'a pas de fichier d'arrivée : aucun intervalle.
    addedRanges: file.change === 'deleted' ? [] : toRanges(file.added),
    addedCount: file.addedCount,
    removedCount: file.removedCount,
    binary: file.binary,
  }
}

/**
 * Chemins d'un en-tête `diff --git a/x b/y`.
 *
 * Le cas difficile est le nom contenant une espace : `a/mon fichier.py`.
 * Git ne délimite rien, et la découpe est ambiguë. On s'appuie sur les
 * préfixes `a/` et `b/`, et on laisse les en-têtes `---`/`+++` corriger
 * quand ils arrivent — eux ne portent qu'un chemin chacun.
 */
function pathsFromDiffHeader(line: string): {
  path: string
  previousPath: string | null
} {
  const rest = line.slice('diff --git '.length).trim()

  // Forme citée : `"a/avec espace.py" "b/avec espace.py"`.
  const quoted = /^"(.*)"\s+"(.*)"$/.exec(rest)
  if (quoted) {
    return { path: stripPrefix(unquote(quoted[2] ?? '')), previousPath: null }
  }

  const split = / b\//.exec(rest)
  if (split && split.index > 0) {
    return { path: normalize(rest.slice(split.index + 3)), previousPath: null }
  }

  // Repli : deux jetons séparés par une espace.
  const parts = rest.split(/\s+/)
  const last = parts[parts.length - 1] ?? ''
  return { path: stripPrefix(last), previousPath: null }
}

/** Retire le préfixe `a/` ou `b/` et les guillemets éventuels. */
function stripPrefix(value: string): string {
  if (!value || value === '/dev/null') {
    return ''
  }
  // Git ajoute parfois une tabulation et un horodatage après le chemin.
  const withoutStamp = value.split('\t')[0] ?? value
  const unquoted = unquote(withoutStamp.trim())
  return normalize(unquoted.replace(/^[ab]\//, ''))
}

function unquote(value: string): string {
  if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
    const inner = value.slice(1, -1)
    // Git échappe `"` et `\` dans les chemins cités.
    return inner.replace(/\\(["\\])/g, '$1')
  }
  return value
}

function normalize(value: string): string {
  return value.trim().replace(/\\/g, '/').replace(/^[ab]\//, '')
}
