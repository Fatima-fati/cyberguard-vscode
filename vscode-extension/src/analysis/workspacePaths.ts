/**
 * Résolution d'un chemin de finding vers un fichier du workspace.
 *
 * Le backend renvoie le chemin **relatif** que l'extension lui a envoyé.
 * Le retraduire en URI est le seul point où l'extension décide quel
 * fichier ouvrir : la règle est donc stricte, et vit ici plutôt que dans
 * la couche d'affichage, qui n'est pas la seule à en avoir besoin.
 */

import * as path from 'node:path'
import * as vscode from 'vscode'

/**
 * Retrouve le fichier d'un finding parmi les dossiers du workspace.
 *
 * Ordre : chemin relatif dans chaque dossier ouvert, puis document déjà
 * ouvert dont le chemin se termine par celui annoncé. Les chemins
 * remontants (`..`) et absolus sont écartés d'emblée.
 */
export async function resolveFindingUri(
  filePath: string
): Promise<vscode.Uri | undefined> {
  if (!filePath) {
    return undefined
  }

  const normalized = filePath.replace(/\\/g, '/')

  if (!path.isAbsolute(normalized) && !normalized.split('/').includes('..')) {
    for (const folder of vscode.workspace.workspaceFolders ?? []) {
      const candidate = vscode.Uri.joinPath(folder.uri, ...normalized.split('/'))
      try {
        const stat = await vscode.workspace.fs.stat(candidate)
        if (stat.type === vscode.FileType.File) {
          return candidate
        }
      } catch {
        // Absent de ce dossier : on essaie le suivant.
      }
    }
  }

  // Repli : un fichier ouvert isolément, hors dossier de travail.
  const base = path.basename(normalized)
  const open = vscode.workspace.textDocuments.find((document) => {
    const documentPath = document.uri.fsPath.replace(/\\/g, '/')
    return documentPath.endsWith(`/${normalized}`) || path.basename(documentPath) === base
  })

  return open?.uri
}
