/**
 * Reprise de l'historique déjà enregistré par le backend.
 *
 * Rien n'est analysé ici : tout vient de `GET /api/code/findings` et de
 * `GET /api/code/scans/{scan_uid}`, deux routes qui existaient avant ce
 * module. Aucune table, aucune base, aucun cache local n'est créé — le
 * backend reste seul dépositaire de l'historique.
 *
 * Le point délicat est la **fraîcheur**. L'historique décrit un fichier
 * tel qu'il était au moment de son analyse ; entre-temps, il a pu être
 * modifié hors de VS Code. On distingue donc deux usages :
 *
 * - la **vue Security** et ses compteurs acceptent une reprise d'historique,
 *   c'est une liste de travail ;
 * - les **diagnostics** ne sont republiés que si le contenu du document
 *   ouvert correspond exactement à celui analysé — vérifié par l'empreinte
 *   du scan. Souligner une ligne qui a bougé serait pire que ne rien
 *   souligner.
 */

import * as path from 'node:path'
import * as vscode from 'vscode'

import {
  BackendClient,
  BackendError,
  type CodeFinding,
} from '../api/backendClient'
import { contentHash } from './contentHash'
import { resolveFindingUri } from './workspacePaths'
import type { DiagnosticsProvider } from '../diagnostics/provider'
import { FindingsStore, latestScanPerFile } from '../state/findingsStore'
import type { StatusBar } from '../ui/statusBar'
import { FR } from '../i18n/fr'

/** Plafond de la reprise. Le backend applique aussi le sien. */
const LIMIT = 500

export interface HistorySyncOptions {
  client: BackendClient
  diagnostics: DiagnosticsProvider
  store: FindingsStore
  statusBar: StatusBar
  log: (message: string) => void
}

export interface HistorySyncSummary {
  /** Findings ouverts renvoyés par le backend. */
  fetched: number
  /** Retenus après filtrage (dernière analyse, fichier présent). */
  kept: number
  /** Écartés : fichier absent du workspace, ou analyse dépassée. */
  ignored: number
  /** Documents ouverts dont les diagnostics ont pu être republiés. */
  documentsSynced: number
  /** Documents ouverts dont le contenu ne correspond plus à l'analyse. */
  documentsStale: number
}

const EMPTY: HistorySyncSummary = {
  fetched: 0,
  kept: 0,
  ignored: 0,
  documentsSynced: 0,
  documentsStale: 0,
}

/**
 * Reprend l'historique et remet l'affichage en cohérence.
 *
 * Utilisée au démarrage (silencieuse) et par la commande
 * « Refresh Findings » (avec un compte rendu).
 */
export async function syncHistory(
  options: HistorySyncOptions,
  settings: {
    notify: boolean
    /**
     * Projet dont on reprend l'historique.
     *
     * Sans lui, `GET /api/code/findings` renvoie les findings de tous les
     * projets analysés par ce backend. Le filtre par chemin qui suit
     * atténue le problème, mais deux projets partageant `src/app.py` se
     * contamineraient : c’est le cas que ce paramètre ferme.
     *
     * `undefined` conserve le comportement antérieur — nécessaire pour un
     * fichier ouvert hors de tout dossier.
     */
    projectUid?: string | undefined
  }
): Promise<HistorySyncSummary> {
  const { client, diagnostics, store, statusBar, log } = options

  let history: CodeFinding[]
  try {
    history = await client.listFindings({
      status: 'open',
      limit: LIMIT,
      // Dernier scan de chaque fichier seulement : un fichier revenu à un
      // contenu sain n'a aucune ligne dans l'historique.
      ...(settings.projectUid ? { project_uid: settings.projectUid, current_only: true } : {}),
    })
  } catch (error) {
    const message = error instanceof BackendError ? error.message : FR.errors.unexpected
    log(`reprise de l'historique impossible — ${message}`)
    if (settings.notify) {
      void vscode.window.showWarningMessage(FR.view.refreshFailed(message))
    }
    return EMPTY
  }

  // 1. Une seule analyse par fichier : l'historique en contient une par
  //    passage, et les reprendre toutes afficherait des doublons.
  const current = latestScanPerFile(history)

  // 2. Seuls les fichiers réellement présents ici. La base est partagée
  //    avec l'interface web et d'autres postes.
  const local: CodeFinding[] = []
  const resolved = new Map<string, vscode.Uri | undefined>()

  for (const finding of current) {
    if (!resolved.has(finding.file_path)) {
      // Un `stat` par chemin distinct, pas par finding.
      resolved.set(finding.file_path, await resolveFindingUri(finding.file_path))
    }
    if (resolved.get(finding.file_path)) {
      local.push(finding)
    }
  }

  // 3. La vue Security et ses compteurs se contentent de l'historique.
  store.merge(local)

  // 4. Les diagnostics exigent davantage : le document ouvert doit être
  //    exactement celui qui a été analysé.
  const { synced, stale } = await republishDiagnostics(options, local)

  refreshStatusBar(diagnostics, statusBar)

  const summary: HistorySyncSummary = {
    fetched: history.length,
    kept: local.length,
    ignored: history.length - local.length,
    documentsSynced: synced,
    documentsStale: stale,
  }

  log(
    `historique repris — ${summary.kept}/${summary.fetched} finding(s) retenus, ` +
      `${summary.documentsSynced} document(s) resynchronisé(s)` +
      `${summary.documentsStale > 0 ? `, ${summary.documentsStale} dépassé(s)` : ''}`
  )

  if (settings.notify) {
    void vscode.window.showInformationMessage(
      FR.view.refreshDone(summary.kept, summary.ignored)
    )
  }

  return summary
}

/**
 * Republie les diagnostics des documents ouverts, quand c'est légitime.
 *
 * Pour chaque document ouvert concerné, l'analyse d'origine est relue par
 * `GET /api/code/scans/{scan_uid}` — la seule source qui porte l'empreinte
 * du contenu analysé. Si elle diffère de ce qui est à l'écran, aucun
 * diagnostic n'est publié : le fichier a changé depuis, et la prochaine
 * sauvegarde produira une analyse à jour.
 */
async function republishDiagnostics(
  options: HistorySyncOptions,
  findings: readonly CodeFinding[]
): Promise<{ synced: number; stale: number }> {
  const { client, diagnostics, statusBar, log } = options

  // Un scan par fichier : `latestScanPerFile` l'a déjà garanti.
  const scanByPath = new Map<string, string>()
  for (const finding of findings) {
    if (!scanByPath.has(finding.file_path)) {
      scanByPath.set(finding.file_path, finding.scan_uid)
    }
  }

  let synced = 0
  let stale = 0

  for (const [filePath, scanUid] of scanByPath) {
    const document = openDocumentFor(filePath)
    if (!document) {
      // Fichier non ouvert : la vue Security suffit, il n'y a pas
      // d'éditeur à décorer.
      continue
    }

    let scan
    try {
      scan = await client.getScan(scanUid)
    } catch (error) {
      const message =
        error instanceof BackendError ? error.message : FR.errors.unexpected
      log(`analyse ${scanUid} illisible — ${message}`)
      continue
    }

    const live = contentHash(document.getText())
    if (scan.content_hash !== live) {
      stale += 1
      log(`${filePath} — historique dépassé, diagnostics non republiés`)
      continue
    }

    // Les findings du scan font foi, y compris ceux déjà écartés : c'est
    // `publish` qui ne rend que les `open`.
    diagnostics.publish(document, scan.findings, scan.content_hash)
    statusBar.setResult(diagnostics.counts(document.uri), path.basename(filePath))
    synced += 1
  }

  return { synced, stale }
}

/** Document ouvert correspondant à ce chemin relatif, s'il y en a un. */
function openDocumentFor(filePath: string): vscode.TextDocument | undefined {
  const normalized = filePath.replace(/\\/g, '/')

  return vscode.workspace.textDocuments.find((document) => {
    if (document.uri.scheme !== 'file') {
      return false
    }
    const documentPath = document.uri.fsPath.replace(/\\/g, '/')
    return documentPath.endsWith(`/${normalized}`) || documentPath === normalized
  })
}

/**
 * Remet la barre d'état en accord avec l'éditeur actif.
 *
 * Sans éditeur actif, ou sans finding pour lui, elle repasse au repos :
 * mieux vaut ne rien annoncer qu'annoncer le compte d'un autre fichier.
 */
function refreshStatusBar(
  diagnostics: DiagnosticsProvider,
  statusBar: StatusBar
): void {
  const active = vscode.window.activeTextEditor?.document
  if (!active) {
    statusBar.setIdle()
    return
  }

  const findings = diagnostics.findingsFor(active.uri)
  if (findings.length === 0) {
    statusBar.setIdle()
    return
  }

  statusBar.setResult(diagnostics.counts(active.uri), path.basename(active.uri.fsPath))
}
