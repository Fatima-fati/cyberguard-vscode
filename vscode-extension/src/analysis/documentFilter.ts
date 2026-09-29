/**
 * Décide si un document peut être envoyé au backend.
 *
 * Deux responsabilités distinctes :
 *
 * 1. **Pertinence** : le langage est-il pris en charge, le fichier a-t-il
 *    du contenu, est-il dans un dossier exclu ?
 * 2. **Sécurité** : certains fichiers ne doivent *jamais* partir, même si
 *    l'utilisateur les ouvre — `.env`, clés privées, certificats. Cette
 *    règle est appliquée avant toute autre et n'est pas contournable par
 *    la configuration.
 *
 * Le refus est toujours motivé : l'utilisateur doit comprendre pourquoi
 * son fichier n'a pas été analysé.
 */

import * as fs from 'node:fs'
import * as path from 'node:path'

import { FR } from '../i18n/fr'

/**
 * Langages pris en charge par les règles du backend (phase 1).
 *
 * La clé est l'identifiant de langage VS Code, la valeur celle attendue
 * par `/api/code/scan`. Ajouter un langage se fait ici, en une ligne.
 */
export const SUPPORTED_LANGUAGES: Readonly<Record<string, string>> = {
  python: 'python',
  javascript: 'javascript',
  javascriptreact: 'javascript',
  typescript: 'typescript',
  typescriptreact: 'typescript',
  php: 'php',
  java: 'java',
}

/**
 * Langages reconnus par le backend mais sans règles dédiées pour l'instant.
 *
 * Ils sont volontairement laissés hors de `SUPPORTED_LANGUAGES` : les
 * activer se fera en déplaçant une ligne, quand les règles existeront.
 */
export const PLANNED_LANGUAGES: readonly string[] = [
  'go',
  'csharp',
  'ruby',
  'sql',
  'yaml',
]

/** Fichiers sensibles : jamais transmis, quelle que soit la configuration. */
const SENSITIVE_PATTERNS: readonly RegExp[] = [
  /(^|[/\\])\.env(\.|$)/i,
  /(^|[/\\])\.env$/i,
  /\.pem$/i,
  /\.key$/i,
  /\.p12$/i,
  /\.pfx$/i,
  /\.jks$/i,
  /\.keystore$/i,
  /(^|[/\\])id_(rsa|dsa|ecdsa|ed25519)$/i,
  /(^|[/\\])\.npmrc$/i,
  /(^|[/\\])\.pypirc$/i,
  /(^|[/\\])credentials$/i,
  /(^|[/\\])\.htpasswd$/i,
]

/** Dossiers exclus : bruit, dépendances, artefacts de build. */
const EXCLUDED_PATH_PATTERNS: readonly RegExp[] = [
  /(^|[/\\])node_modules([/\\]|$)/,
  /(^|[/\\])dist([/\\]|$)/,
  /(^|[/\\])build([/\\]|$)/,
  /(^|[/\\])out([/\\]|$)/,
  /(^|[/\\])\.git([/\\]|$)/,
  /(^|[/\\])\.venv([/\\]|$)/,
  /(^|[/\\])venv([/\\]|$)/,
  /(^|[/\\])__pycache__([/\\]|$)/,
  /(^|[/\\])vendor([/\\]|$)/,
  /(^|[/\\])\.next([/\\]|$)/,
  /(^|[/\\])coverage([/\\]|$)/,
]

export interface FilterInput {
  /** Chemin absolu, ou identifiant du document si non enregistré. */
  fsPath: string
  /** Chemin relatif au workspace, séparateurs normalisés en `/`. */
  relativePath: string
  /** Identifiant de langage VS Code. */
  languageId: string
  /** Le document existe-t-il sur le disque ? */
  isUntitled: boolean
  /** Taille du contenu en octets. */
  size: number
  /** Racine du workspace, si connue. */
  workspaceRoot?: string | undefined
}

export type FilterDecision =
  | { accepted: true; language: string }
  | { accepted: false; reason: string; sensitive: boolean }

/** Taille maximale envoyée. Le backend applique sa propre limite. */
export const MAX_CONTENT_BYTES = 400_000

function isSensitive(target: string): boolean {
  return SENSITIVE_PATTERNS.some((pattern) => pattern.test(target))
}

function isExcluded(target: string): boolean {
  return EXCLUDED_PATH_PATTERNS.some((pattern) => pattern.test(target))
}

/**
 * Langage attendu par le backend pour cet identifiant VS Code.
 *
 * `Object.hasOwn` plutôt qu'un accès direct : un identifiant comme
 * `constructor` remonterait sinon une valeur héritée du prototype. La
 * seconde tentative en minuscules couvre les appelants qui transmettent
 * l'identifiant tel qu'affiché (« Python ») plutôt que tel que VS Code le
 * nomme (« python »).
 */
function resolveLanguage(languageId: string): string | undefined {
  if (Object.hasOwn(SUPPORTED_LANGUAGES, languageId)) {
    return SUPPORTED_LANGUAGES[languageId]
  }
  const lowered = languageId.toLowerCase()
  return Object.hasOwn(SUPPORTED_LANGUAGES, lowered)
    ? SUPPORTED_LANGUAGES[lowered]
    : undefined
}

/**
 * Décide du sort d'un document.
 *
 * L'ordre des contrôles n'est pas anodin : la règle de sécurité passe en
 * premier, avant même le langage, pour qu'un `.env` ne puisse jamais
 * partir par un chemin détourné.
 */
export function evaluate(input: FilterInput, gitignore?: GitignoreMatcher): FilterDecision {
  const target = input.relativePath || input.fsPath

  if (isSensitive(target)) {
    return { accepted: false, reason: FR.filter.sensitive, sensitive: true }
  }

  if (input.isUntitled) {
    return { accepted: false, reason: FR.filter.untitled, sensitive: false }
  }

  if (isExcluded(target)) {
    return { accepted: false, reason: FR.filter.excluded, sensitive: false }
  }

  if (gitignore?.ignores(target)) {
    return { accepted: false, reason: FR.filter.gitignored, sensitive: false }
  }

  const language = resolveLanguage(input.languageId)
  if (!language) {
    return {
      accepted: false,
      reason: FR.filter.unsupportedLanguage(input.languageId),
      sensitive: false,
    }
  }

  if (input.size === 0) {
    return { accepted: false, reason: FR.filter.empty, sensitive: false }
  }

  if (input.size > MAX_CONTENT_BYTES) {
    return {
      accepted: false,
      reason: FR.filter.tooLarge(input.size, MAX_CONTENT_BYTES),
      sensitive: false,
    }
  }

  return { accepted: true, language }
}

// --------------------------------------------------------------------------
// .gitignore
// --------------------------------------------------------------------------

/**
 * Lecture volontairement simple du `.gitignore` racine.
 *
 * Aucune dépendance ajoutée : on couvre les motifs courants (dossiers,
 * extensions, préfixes) et on ignore ce qu'on ne sait pas interpréter —
 * la négation `!`, les motifs `**` imbriqués. Un motif mal compris est
 * simplement ignoré : le fichier sera analysé, jamais bloqué à tort.
 */
export class GitignoreMatcher {
  private readonly patterns: RegExp[]

  private constructor(patterns: RegExp[]) {
    this.patterns = patterns
  }

  static empty(): GitignoreMatcher {
    return new GitignoreMatcher([])
  }

  /** Charge le `.gitignore` du dossier donné. Absent = matcher vide. */
  static load(workspaceRoot: string | undefined): GitignoreMatcher {
    if (!workspaceRoot) {
      return GitignoreMatcher.empty()
    }

    const file = path.join(workspaceRoot, '.gitignore')
    let raw: string
    try {
      raw = fs.readFileSync(file, 'utf8')
    } catch {
      // Pas de .gitignore, ou illisible : ce n'est pas une erreur.
      return GitignoreMatcher.empty()
    }

    const patterns: RegExp[] = []
    for (const line of raw.split(/\r?\n/)) {
      const entry = line.trim()
      if (!entry || entry.startsWith('#') || entry.startsWith('!')) {
        continue
      }
      const compiled = compilePattern(entry)
      if (compiled) {
        patterns.push(compiled)
      }
    }

    return new GitignoreMatcher(patterns)
  }

  ignores(relativePath: string): boolean {
    const normalized = relativePath.replace(/\\/g, '/')
    return this.patterns.some((pattern) => pattern.test(normalized))
  }
}

function compilePattern(entry: string): RegExp | null {
  // Motifs trop riches pour cette lecture simple : on s'abstient.
  if (entry.includes('**') || entry.includes('[')) {
    return null
  }

  const anchored = entry.startsWith('/')
  const isDirectory = entry.endsWith('/')
  const body = entry.replace(/^\//, '').replace(/\/$/, '')

  if (!body) {
    return null
  }

  const escaped = body
    .split('/')
    .map((segment) =>
      segment
        .replace(/[.+^${}()|\\]/g, '\\$&')
        .replace(/\*/g, '[^/]*')
        .replace(/\?/g, '[^/]')
    )
    .join('/')

  try {
    if (isDirectory) {
      return new RegExp(anchored ? `^${escaped}/` : `(^|/)${escaped}/`)
    }
    return new RegExp(anchored ? `^${escaped}(/|$)` : `(^|/)${escaped}(/|$)`)
  } catch {
    return null
  }
}
