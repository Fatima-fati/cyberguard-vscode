/**
 * Point d'entrée CI/CD (phase 8) : `node dist/ci-check.js [options]`.
 *
 * Mince par construction : lit les arguments, branche les pièces
 * existantes — `ProjectContextService`, `ProjectSecurityService`,
 * `BackendClient`, `AgentToken` — et délègue tout le déroulé à
 * `ciRunner.ts`, testé sans processus ni disque.
 *
 * Rapport JSON sur la sortie standard, journal sur la sortie d'erreur :
 * un pipeline peut rediriger l'un sans l'autre.
 *
 * Aucune dépendance à `vscode`, à l'IA ni à Wazuh. Le backend doit être
 * joignable (il détient la persistance, les règles de code et la base de
 * vulnérabilités) ; il fonctionne lui-même sans clé API ni Wazuh.
 */

import * as fs from 'node:fs'
import * as path from 'node:path'

import { AgentToken, type SecretVault } from '../api/agentToken'
import { BackendClient } from '../api/backendClient'
import { validateBackendUrl } from '../api/backendUrl'
import { GitignoreMatcher } from '../analysis/documentFilter'
import { DISCOVERY_VERSION, ProjectContextService } from '../project/projectContext'
import { projectNameOf, rootHashOf } from '../project/projectIdentity'
import { ProjectSecurityService } from '../security/projectSecurityService'
import { USAGE, errorReport, parseCiArgs, runCiCheck, type CiRun } from './ciRunner'

/** Code de sortie d'une ligne de commande invalide (sysexits EX_USAGE). */
const EXIT_USAGE = 64

/** Coffre en mémoire : le jeton vient de l'environnement, jamais d'un réglage. */
function environmentVault(token: string | undefined): SecretVault {
  return {
    get: async () => token,
    store: async () => undefined,
    delete: async () => undefined,
  }
}

function log(message: string): void {
  process.stderr.write(`[wazuh-security-ci] ${message}\n`)
}

/** Lit un fichier du dépôt, sans jamais sortir de sa racine. */
async function readInside(root: string, relative: string): Promise<string | undefined> {
  const target = path.resolve(root, relative)
  if (target !== root && !target.startsWith(root + path.sep)) {
    return undefined
  }
  try {
    return await fs.promises.readFile(target, 'utf8')
  } catch {
    return undefined
  }
}

function emit(run: CiRun, output: string | undefined): void {
  const json = JSON.stringify(run.report, null, 2)
  process.stdout.write(`${json}\n`)
  if (output) {
    fs.writeFileSync(output, `${json}\n`, 'utf8')
  }
  process.exitCode = run.exitCode
}

async function main(): Promise<void> {
  const parsed = parseCiArgs(process.argv.slice(2), process.env, process.cwd())
  if (!parsed.ok) {
    if (parsed.help && !parsed.error) {
      process.stdout.write(`${USAGE}\n`)
      return
    }
    process.stderr.write(`${parsed.error}\n\n${USAGE}\n`)
    process.exitCode = EXIT_USAGE
    return
  }

  const options = parsed.options
  const root = path.resolve(options.root)
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
    // Le chemin n'est pas recopié : un rapport peut être archivé et publié.
    emit(errorReport(options.mode, 'discovery', 'Dossier à analyser introuvable.'), options.output)
    return
  }

  const url = validateBackendUrl(options.backendUrl, { allowRemote: options.allowRemoteBackend })
  if (!url.ok) {
    // Motif seul : l'adresse refusée peut porter des identifiants.
    emit(
      errorReport(options.mode, 'backend', `Adresse du backend refusée (${url.reason}).`),
      options.output
    )
    return
  }

  const token = new AgentToken({
    vault: environmentVault(options.token),
    ...(options.tokenFile ? { tokenPath: options.tokenFile } : {}),
  })
  const client = new BackendClient({
    baseUrl: url.url,
    // Un projet entier se soumet en plusieurs requêtes lourdes.
    timeoutMs: 120_000,
    authHeader: () => token.authorizationHeader(),
    onUnauthorized: async () => (await token.refresh()).token !== undefined,
  })
  const security = new ProjectSecurityService({ client, log })
  const projects = new ProjectContextService({ client, log, security })

  const run = await runCiCheck(
    { ...options, root },
    {
      backend: client,
      discover: async (current) => {
        const outcome = await projects.discover({
          workspacePath: root,
          git: { detected: fs.existsSync(path.join(root, '.git')), remote_host: null },
          ignore: GitignoreMatcher.load(root),
          security: {
            secrets: true,
            dependencies: true,
            api: true,
            checkVulnerabilities: current.vulnerabilityCheck,
          },
        })
        return {
          ok: outcome.ok,
          projectUid: projects.projectUid(),
          message: outcome.message,
          indexedFiles: outcome.indexedFiles,
        }
      },
      identify: async () => {
        const rootHash = rootHashOf(root)
        const registration = await client.discoverProject({
          root_hash: rootHash,
          project_name: projectNameOf(root, rootHash),
          discovery_version: DISCOVERY_VERSION,
        })
        return registration.project_uid
      },
      readText: (base, relative) => readInside(base, relative),
      gitignore: (base) => GitignoreMatcher.load(base),
      log,
    }
  )

  emit(run, options.output)
}

main().catch((error: unknown) => {
  // Filet ultime : jamais une trace d'exécution brute dans le rapport.
  log(`erreur inattendue : ${error instanceof Error ? error.message : String(error)}`)
  process.exitCode = 2
})
