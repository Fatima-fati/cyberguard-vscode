/**
 * Analyse de l'ensemble du workspace.
 *
 * Rien de neuf côté analyse : chaque fichier passe par le `ScanController`
 * existant, donc par le même filtrage, la même route `/api/code/scan` et
 * le même enregistrement dans le store. Ce module ne fait qu'énumérer les
 * fichiers, borner le travail et rendre compte de l'avancement.
 *
 * Trois garde-fous :
 *
 * - **borné** : au-delà de `MAX_FILES`, le reste est annoncé, pas analysé
 *   en silence ;
 * - **annulable** : la barre de progression porte un bouton « Annuler »
 *   qui interrompt la boucle ;
 * - **discret** : aucune notification par fichier ; un seul résumé à la
 *   fin.
 */

import * as vscode from 'vscode'

import { FR } from '../i18n/fr'
import { SUPPORTED_LANGUAGES } from './documentFilter'
import type { ScanController } from './scanController'

/**
 * Plafond d'un balayage.
 *
 * Un dépassement est signalé à l'utilisateur : une troncature silencieuse
 * ferait croire à une couverture complète.
 */
export const MAX_FILES = 300

/** Nombre d'analyses menées de front. Le backend voit un client, pas une rafale. */
const CONCURRENCY = 4

/**
 * Extensions déduites des langages pris en charge.
 *
 * La liste dérive de `SUPPORTED_LANGUAGES` : activer un langage côté
 * filtre suffira, à condition d'ajouter son extension ici.
 */
const EXTENSIONS: Readonly<Record<string, readonly string[]>> = {
  python: ['py'],
  javascript: ['js', 'jsx', 'mjs', 'cjs'],
  typescript: ['ts', 'tsx'],
  php: ['php'],
  java: ['java'],
}

/** Dossiers écartés dès l'énumération : inutile de les ouvrir pour les refuser. */
const EXCLUDE_GLOB =
  '{**/node_modules/**,**/dist/**,**/build/**,**/out/**,**/.git/**,**/.venv/**,' +
  '**/venv/**,**/__pycache__/**,**/vendor/**,**/.next/**,**/coverage/**}'

function includeGlob(): string {
  const extensions = new Set<string>()
  for (const language of new Set(Object.values(SUPPORTED_LANGUAGES))) {
    for (const extension of EXTENSIONS[language] ?? []) {
      extensions.add(extension)
    }
  }
  return `**/*.{${[...extensions].sort().join(',')}}`
}

export interface WorkspaceScanSummary {
  requested: number
  scanned: number
  truncated: boolean
  cancelled: boolean
}

/**
 * Analyse tous les fichiers pris en charge du workspace.
 *
 * Retourne le résumé, déjà affiché à l'utilisateur.
 */
export async function scanWorkspace(
  controller: ScanController,
  log: (message: string) => void
): Promise<WorkspaceScanSummary> {
  const empty: WorkspaceScanSummary = {
    requested: 0,
    scanned: 0,
    truncated: false,
    cancelled: false,
  }

  if (!vscode.workspace.workspaceFolders?.length) {
    void vscode.window.showInformationMessage(FR.view.workspaceScanNoFolder)
    return empty
  }

  // Une unité de plus que le plafond : c'est ainsi qu'on sait qu'il y en
  // avait davantage, sans énumérer tout le dépôt.
  const found = await vscode.workspace.findFiles(
    includeGlob(),
    EXCLUDE_GLOB,
    MAX_FILES + 1
  )

  const truncated = found.length > MAX_FILES
  const targets = truncated ? found.slice(0, MAX_FILES) : found

  if (targets.length === 0) {
    void vscode.window.showInformationMessage(FR.view.workspaceScanEmpty)
    return empty
  }

  if (truncated) {
    log(
      `balayage limité à ${MAX_FILES} fichiers ; les suivants ne sont pas analysés`
    )
  }

  const summary = await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: FR.view.workspaceScanTitle,
      cancellable: true,
    },
    async (progress, token) => {
      let done = 0
      let scanned = 0
      const step = 100 / targets.length
      let next = 0

      /** Un ouvrier consomme la file tant qu'elle n'est pas vide. */
      const worker = async (): Promise<void> => {
        for (;;) {
          if (token.isCancellationRequested) {
            return
          }

          const index = next
          next += 1
          const uri = targets[index]
          if (!uri) {
            return
          }

          try {
            const document = await vscode.workspace.openTextDocument(uri)
            // `scanBatch` : même chemin que le scan à la sauvegarde, mais
            // sans notification ni message d'erreur par fichier.
            const accepted = await controller.scanBatch(document, token)
            if (accepted) {
              scanned += 1
            }
          } catch {
            // Fichier binaire, illisible ou supprimé entre-temps : il est
            // ignoré, le balayage continue.
          }

          done += 1
          progress.report({
            increment: step,
            message: FR.view.workspaceScanProgress(done, targets.length),
          })
        }
      }

      await Promise.all(
        Array.from({ length: Math.min(CONCURRENCY, targets.length) }, () => worker())
      )

      return {
        requested: targets.length,
        scanned,
        truncated,
        cancelled: token.isCancellationRequested,
      }
    }
  )

  log(
    `balayage terminé — ${summary.scanned}/${summary.requested} fichier(s) analysé(s)` +
      `${summary.cancelled ? ' (annulé)' : ''}${truncated ? ', liste tronquée' : ''}`
  )

  void vscode.window.showInformationMessage(
    FR.view.workspaceScanDone(
      summary.scanned,
      summary.requested,
      summary.truncated,
      summary.cancelled
    )
  )

  return summary
}
