/**
 * Contrôle de sécurité CI/CD, sans VS Code (phase 8).
 *
 *     dossier du dépôt
 *        → moteurs EXISTANTS (découverte, secrets, API, dépendances : ceux
 *          de l'extension ; règles de code et base de vulnérabilités : ceux
 *          du backend)
 *        → POST /api/project/{uid}/ci-check (politique déterministe)
 *        → rapport JSON + code de sortie
 *
 * **Aucun moteur nouveau.** Ce module enchaîne les pièces que l'extension
 * utilise déjà — `ProjectContextService`, `classifyChange`,
 * `documentFilter.evaluate`, `BackendClient` — et laisse le backend
 * décider du verdict. Il ne connaît ni `vscode`, ni l'IA, ni Wazuh.
 *
 * Codes de sortie
 * ---------------
 *
 *     0   conforme, avertissement, ou contrôle désactivé
 *     1   bloqué par la politique (mode `block`) — les raisons sont dans
 *         le rapport, jamais un échec muet
 *     2   le contrôle n'a pas pu avoir lieu (backend injoignable…) ET le
 *         mode `block` a été demandé : sans verdict, on ne prétend pas
 *         que le pipeline est conforme. En mode `warn` ou `off`, une
 *         panne sort en 0, avec un rapport `status: "error"` explicite.
 *
 * Ce que le rapport ne contient jamais : une valeur de secret, une preuve,
 * un jeton, un chemin absolu. Le rapport vient du backend, qui ne porte
 * que des chemins relatifs validés ; le rapport d'erreur, lui, n'inclut
 * ni le dossier analysé ni l'adresse complète du backend.
 */

import type { CodeScanResult, ScanPayload } from '../api/backendClient'
import { contentHash } from '../analysis/contentHash'
import { evaluate, type GitignoreMatcher } from '../analysis/documentFilter'
import { classifyChange } from '../monitor/changeClassification'
import {
  CI_CONDITIONS,
  normalizeCiMode,
  type CiCheckResult,
  type CiCondition,
  type CiMode,
  type CiPolicyRequest,
} from '../posture/postureTypes'

export const CI_REPORT_VERSION = '1.0'
export const DEFAULT_MAX_CODE_FILES = 300

// --------------------------------------------------------------------------
// Arguments
// --------------------------------------------------------------------------

export interface CiOptions {
  readonly root: string
  readonly backendUrl: string
  readonly allowRemoteBackend: boolean
  /** Jeton fourni par l'environnement. Jamais journalisé. */
  readonly token: string | undefined
  readonly tokenFile: string | undefined
  /** `undefined` = politique configurée côté backend. */
  readonly mode: CiMode | undefined
  readonly failOn: CiCondition[] | undefined
  readonly warnOn: CiCondition[] | undefined
  readonly output: string | undefined
  readonly scan: boolean
  readonly code: boolean
  readonly vulnerabilityCheck: boolean
  readonly maxCodeFiles: number
}

export type ParsedArgs =
  | { ok: true; options: CiOptions }
  | { ok: false; error: string; help: boolean }

export const USAGE = [
  'Usage : wazuh-security-ci [options]',
  '',
  '  --root <dossier>            dépôt à analyser (défaut : dossier courant)',
  '  --backend <url>             backend (défaut : WAZUH_SECURITY_BACKEND_URL ou http://127.0.0.1:8000)',
  '  --allow-remote-backend      autorise un backend hors de la machine',
  '  --token-file <fichier>      jeton du backend (défaut : ~/.wazuh-security/agent-token)',
  '                              ou variable WAZUH_SECURITY_TOKEN',
  '  --policy off|warn|block     politique (défaut : celle du backend, warn)',
  '  --fail-on a,b               conditions bloquantes',
  '  --warn-on a,b               conditions d’avertissement',
  '  --output <fichier>          écrit aussi le rapport JSON dans ce fichier',
  '  --no-scan                   n’analyse pas : évalue l’état déjà connu du backend',
  '  --no-code                   n’envoie aucun fichier source à l’analyse de code',
  '  --no-vulnerability-check    n’interroge pas la base de vulnérabilités',
  '  --max-code-files <n>        plafond de l’analyse de code (défaut : 300)',
  '',
  `Conditions : ${CI_CONDITIONS.join(', ')}`,
  'Sortie : 0 conforme ou avertissement, 1 bloqué, 2 contrôle impossible en mode block.',
].join('\n')

function conditionsOf(raw: string): CiCondition[] | string {
  const items = raw.split(',').map((item) => item.trim()).filter(Boolean)
  const unknown = items.filter((item) => !CI_CONDITIONS.includes(item as CiCondition))
  if (unknown.length > 0) {
    return `condition(s) inconnue(s) : ${unknown.join(', ')}`
  }
  return items as CiCondition[]
}

/** Lit les arguments. Refuse l'inconnu plutôt que de le deviner. */
export function parseCiArgs(
  argv: readonly string[],
  env: Readonly<Record<string, string | undefined>>,
  cwd: string
): ParsedArgs {
  const refuse = (error: string, help = false): ParsedArgs => ({ ok: false, error, help })

  let root = cwd
  let backendUrl = env.WAZUH_SECURITY_BACKEND_URL || 'http://127.0.0.1:8000'
  let allowRemoteBackend = false
  let tokenFile = env.WAZUH_SECURITY_TOKEN_FILE || undefined
  let mode: CiMode | undefined =
    env.WAZUH_SECURITY_CI_POLICY !== undefined ? normalizeCiMode(env.WAZUH_SECURITY_CI_POLICY) : undefined
  let failOn: CiCondition[] | undefined
  let warnOn: CiCondition[] | undefined
  let output: string | undefined
  let scan = true
  let code = true
  let vulnerabilityCheck = true
  let maxCodeFiles = DEFAULT_MAX_CODE_FILES

  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index] ?? ''
    const next = (): string | undefined => {
      const candidate = argv[index + 1]
      if (candidate === undefined || candidate.startsWith('--')) {
        return undefined
      }
      index += 1
      return candidate
    }

    switch (flag) {
      case '--help':
      case '-h':
        return refuse('', true)
      case '--root': {
        const value = next()
        if (!value) return refuse('--root attend un dossier')
        root = value
        break
      }
      case '--backend': {
        const value = next()
        if (!value) return refuse('--backend attend une adresse')
        backendUrl = value
        break
      }
      case '--allow-remote-backend':
        allowRemoteBackend = true
        break
      case '--token-file': {
        const value = next()
        if (!value) return refuse('--token-file attend un fichier')
        tokenFile = value
        break
      }
      case '--policy': {
        const value = next()
        if (value !== 'off' && value !== 'warn' && value !== 'block') {
          return refuse('--policy attend off, warn ou block')
        }
        mode = value
        break
      }
      case '--fail-on':
      case '--warn-on': {
        const value = next()
        if (value === undefined) return refuse(`${flag} attend une liste de conditions`)
        const parsed = conditionsOf(value)
        if (typeof parsed === 'string') return refuse(parsed)
        if (flag === '--fail-on') failOn = parsed
        else warnOn = parsed
        break
      }
      case '--output': {
        const value = next()
        if (!value) return refuse('--output attend un fichier')
        output = value
        break
      }
      case '--no-scan':
        scan = false
        break
      case '--no-code':
        code = false
        break
      case '--no-vulnerability-check':
        vulnerabilityCheck = false
        break
      case '--max-code-files': {
        const value = Number(next())
        if (!Number.isInteger(value) || value < 0) {
          return refuse('--max-code-files attend un entier positif')
        }
        maxCodeFiles = value
        break
      }
      default:
        return refuse(`option inconnue : ${flag}`, true)
    }
  }

  return {
    ok: true,
    options: {
      root,
      backendUrl,
      allowRemoteBackend,
      token: env.WAZUH_SECURITY_TOKEN || undefined,
      tokenFile,
      mode,
      failOn,
      warnOn,
      output,
      scan,
      code,
      vulnerabilityCheck,
      maxCodeFiles,
    },
  }
}

// --------------------------------------------------------------------------
// Exécution
// --------------------------------------------------------------------------

/** Ce que le contrôle attend du backend. Sous-ensemble de `BackendClient`. */
export interface CiBackend {
  health(): Promise<{ project_security_enabled?: boolean }>
  scan(payload: ScanPayload): Promise<CodeScanResult>
  ciCheck(projectUid: string, policy: CiPolicyRequest): Promise<CiCheckResult>
}

export interface CiDiscovery {
  readonly ok: boolean
  readonly projectUid: string | undefined
  readonly message: string
  readonly indexedFiles: readonly { path: string; size: number }[]
}

export interface CiDependencies {
  readonly backend: CiBackend
  /** Découverte + secrets + API + dépendances, par `ProjectContextService`. */
  discover(options: CiOptions): Promise<CiDiscovery>
  /** Projet déjà connu du backend, pour `--no-scan`. */
  identify(options: CiOptions): Promise<string | undefined>
  readText(root: string, relativePath: string): Promise<string | undefined>
  gitignore(root: string): GitignoreMatcher
  log(message: string): void
}

export type CiErrorStage = 'backend' | 'discovery' | 'code' | 'ci-check'

export interface CiErrorReport {
  schema_version: string
  status: 'error'
  generated_at: string
  policy: { mode: CiMode | null }
  exit_decision: 'pass' | 'fail'
  exit_code: number
  error: { stage: CiErrorStage; message: string }
  requires_ai: false
  requires_wazuh: false
}

export interface CiReport {
  schema_version: string
  generated_at: string
  /**
   * Repris du résultat, pour que l'enveloppe soit la même qu'en cas
   * d'erreur : un pipeline lit toujours `.status` et `.exit_code`.
   */
  status: CiCheckResult['status']
  exit_code: number
  scan: {
    performed: boolean
    code_files_submitted: number
    code_files_skipped: number
    /** Vrai quand le plafond d'analyse de code a mordu. */
    code_truncated: boolean
  }
  result: CiCheckResult
}

export interface CiRun {
  readonly report: CiReport | CiErrorReport
  readonly exitCode: number
}

/** Rapport d'échec. N'inclut ni le dossier analysé, ni l'adresse, ni le jeton. */
export function errorReport(mode: CiMode | undefined, stage: CiErrorStage, message: string): CiRun {
  // Sans verdict, le mode `block` ne peut pas conclure « conforme ».
  const exitCode = mode === 'block' ? 2 : 0
  return {
    exitCode,
    report: {
      schema_version: CI_REPORT_VERSION,
      status: 'error',
      generated_at: new Date().toISOString(),
      policy: { mode: mode ?? null },
      exit_decision: exitCode === 0 ? 'pass' : 'fail',
      exit_code: exitCode,
      error: { stage, message },
      requires_ai: false,
      requires_wazuh: false,
    },
  }
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

/** Analyse de code des fichiers source indexés, par la route existante. */
async function scanCode(
  options: CiOptions,
  deps: CiDependencies,
  projectUid: string,
  files: readonly { path: string; size: number }[]
): Promise<{ submitted: number; skipped: number; truncated: boolean }> {
  const ignore = deps.gitignore(options.root)
  let submitted = 0
  let skipped = 0
  let truncated = false

  for (const file of files) {
    const classification = classifyChange(file.path, { ignore })
    if (!classification.analyses.code || !classification.readable || !classification.language) {
      continue
    }
    const decision = evaluate(
      {
        fsPath: file.path,
        relativePath: file.path,
        languageId: classification.language,
        isUntitled: false,
        size: file.size,
        workspaceRoot: options.root,
      },
      ignore
    )
    if (!decision.accepted) {
      skipped += 1
      continue
    }
    if (submitted >= options.maxCodeFiles) {
      truncated = true
      skipped += 1
      continue
    }

    const content = await deps.readText(options.root, file.path)
    if (content === undefined) {
      skipped += 1
      continue
    }
    await deps.backend.scan({
      file_path: file.path,
      language: decision.language,
      content,
      content_hash: contentHash(content),
      workspace: null,
      project_uid: projectUid,
      ai_enrichment: false,
    })
    submitted += 1
  }

  return { submitted, skipped, truncated }
}

/** Contrôle complet. Ne lève jamais : toute panne devient un rapport. */
export async function runCiCheck(options: CiOptions, deps: CiDependencies): Promise<CiRun> {
  try {
    const health = await deps.backend.health()
    if (health.project_security_enabled !== true) {
      return errorReport(options.mode, 'backend', 'Ce backend ne porte pas la sécurité projet.')
    }
  } catch (error) {
    return errorReport(options.mode, 'backend', `Backend injoignable : ${describe(error)}`)
  }

  let projectUid: string | undefined
  let codeFiles = { submitted: 0, skipped: 0, truncated: false }

  if (options.scan) {
    let discovery: CiDiscovery
    try {
      discovery = await deps.discover(options)
    } catch (error) {
      return errorReport(options.mode, 'discovery', describe(error))
    }
    if (!discovery.ok || !discovery.projectUid) {
      return errorReport(options.mode, 'discovery', discovery.message)
    }
    projectUid = discovery.projectUid
    deps.log(discovery.message)

    if (options.code) {
      try {
        codeFiles = await scanCode(options, deps, projectUid, discovery.indexedFiles)
      } catch (error) {
        return errorReport(options.mode, 'code', `Analyse de code impossible : ${describe(error)}`)
      }
      deps.log(`analyse de code : ${codeFiles.submitted} fichier(s) soumis`)
    }
  } else {
    try {
      projectUid = await deps.identify(options)
    } catch (error) {
      return errorReport(options.mode, 'backend', describe(error))
    }
    if (!projectUid) {
      return errorReport(options.mode, 'discovery', 'Projet inconnu du backend : relancez sans --no-scan.')
    }
  }

  let result: CiCheckResult
  try {
    const policy: CiPolicyRequest = {}
    if (options.mode) policy.mode = options.mode
    if (options.failOn) policy.fail_on = options.failOn
    if (options.warnOn) policy.warn_on = options.warnOn
    result = await deps.backend.ciCheck(projectUid, policy)
  } catch (error) {
    return errorReport(options.mode, 'ci-check', describe(error))
  }

  return {
    exitCode: result.exit_code === 1 ? 1 : 0,
    report: {
      schema_version: CI_REPORT_VERSION,
      generated_at: new Date().toISOString(),
      status: result.status,
      exit_code: result.exit_code === 1 ? 1 : 0,
      scan: {
        performed: options.scan,
        code_files_submitted: codeFiles.submitted,
        code_files_skipped: codeFiles.skipped,
        code_truncated: codeFiles.truncated,
      },
      result,
    },
  }
}
