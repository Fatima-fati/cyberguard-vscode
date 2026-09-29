/**
 * Accès à l'API `vscode.git`, et rien d'autre.
 *
 * La règle, non négociable
 * ------------------------
 *
 * **Aucune commande `git` n'est lancée par cette extension.** Ni
 * `child_process`, ni `exec`, ni `spawn`, ni terminal. Tout passe par
 * l'API que l'extension Git de VS Code expose, comme `detectGit` le
 * faisait déjà depuis la phase 1.
 *
 * Ce n'est pas une préférence de style. Lancer `git` revient à exécuter
 * un binaire choisi par le `PATH` du poste, dans un dossier qui vient
 * d'être cloné, avec une configuration (`core.fsmonitor`, `core.pager`,
 * les hooks) que le dépôt lui-même peut fixer. Un dépôt hostile
 * obtiendrait l'exécution de code par le seul fait qu'on l'analyse — et
 * un agent de sécurité qui se fait exécuter par ce qu'il inspecte n'en
 * est plus un.
 *
 * Un test parcourt le code source de `src/git/` et refuse toute
 * importation de `child_process`.
 *
 * Ce module ne contient aucune logique
 * ------------------------------------
 *
 * Il déclare la forme de l'API réellement utilisée et fournit des accès
 * défensifs. Toute l'intelligence est dans les modules purs voisins —
 * `diffParser`, `changeAttribution`, `prePushPolicy` — qui se testent
 * sans éditeur.
 *
 * L'extension Git peut être absente, désactivée, ou d'une version dont
 * l'API a bougé. Chaque accès le suppose : la phase 4 s'éteint proprement
 * plutôt que de faire tomber l'extension.
 */

import * as vscode from 'vscode'

// Les constantes et prédicats de statut vivent dans `gitStatus.ts`, qui
// n'importe pas `vscode` : ils décident de ce qui est analysé, et doivent
// rester vérifiables hors de l'éditeur. Réexportés ici par commodité.
export { GIT_STATUS, isDeletion, isIgnored, isUntracked } from './gitStatus'

/** Un fichier modifié, tel que l'API le décrit. */
export interface GitChange {
  readonly uri: vscode.Uri
  readonly originalUri?: vscode.Uri
  readonly renameUri?: vscode.Uri
  readonly status: number
}

export interface GitBranch {
  readonly name?: string
  readonly commit?: string
  readonly upstream?: { readonly name?: string; readonly remote?: string }
  readonly ahead?: number
  readonly behind?: number
}

export interface GitRemote {
  readonly name?: string
  readonly fetchUrl?: string
  readonly pushUrl?: string
}

export interface GitRepositoryState {
  readonly HEAD?: GitBranch
  readonly refs?: readonly { readonly name?: string }[]
  readonly remotes?: readonly GitRemote[]
  readonly workingTreeChanges?: readonly GitChange[]
  readonly indexChanges?: readonly GitChange[]
  readonly mergeChanges?: readonly GitChange[]
  readonly onDidChange?: vscode.Event<void>
}

/**
 * Le dépôt, réduit à ce que la phase 4 consomme.
 *
 * `diffWithHEAD(path)` et `diffIndexWithHEAD(path)` renvoient le diff
 * unifié d'un fichier. C'est l'API qui appelle Git, pas nous.
 *
 * **Le chemin est obligatoire ici.** Sans lui, l'API renvoie la liste des
 * changements (`Change[]`), pas un diff : l'appel sans argument ne
 * produisait qu'un diff vide, et plus rien n'était « introduit ».
 */
export interface GitRepository {
  readonly rootUri: vscode.Uri
  readonly state: GitRepositoryState
  /** Diff de l'arbre de travail par rapport à HEAD. */
  diffWithHEAD?: (path: string) => Promise<string>
  /** Diff de l'index par rapport à HEAD — les changements « staged ». */
  diffIndexWithHEAD?: (path: string) => Promise<string>
}

export interface GitApi {
  readonly repositories?: readonly GitRepository[]
  readonly onDidOpenRepository?: vscode.Event<GitRepository>
  readonly onDidCloseRepository?: vscode.Event<GitRepository>
}

interface GitExtensionExports {
  getAPI?: (version: number) => GitApi
}

/**
 * Résout l'API Git, en activant l'extension si besoin.
 *
 * `undefined` quand l'extension Git est absente ou désactivée — ce qui
 * est un état parfaitement normal, pas une panne. Toute la phase 4 le
 * traite comme « pas de dépôt ».
 */
export async function resolveGitApi(): Promise<GitApi | undefined> {
  try {
    const extension =
      vscode.extensions.getExtension<GitExtensionExports>('vscode.git')
    if (!extension) {
      return undefined
    }

    const exports = extension.isActive
      ? extension.exports
      : await extension.activate()

    return exports?.getAPI?.(1)
  } catch {
    // Version d'API inconnue, activation refusée : la phase 4 s'éteint,
    // le reste de l'extension continue.
    return undefined
  }
}

/**
 * Dépôt contenant ce dossier.
 *
 * Le plus **spécifique** l'emporte : dans un monorepo où un sous-dossier
 * est lui-même un dépôt, `repositories` peut en porter plusieurs, et
 * prendre le premier venu ferait analyser le mauvais.
 */
export function findRepository(
  api: GitApi | undefined,
  workspaceRoot: string | undefined
): GitRepository | undefined {
  if (!api?.repositories || !workspaceRoot) {
    return undefined
  }

  const target = normalizeFsPath(workspaceRoot)
  let best: GitRepository | undefined
  let bestLength = -1

  for (const repository of api.repositories) {
    const root = normalizeFsPath(repository.rootUri?.fsPath ?? '')
    if (!root) {
      continue
    }
    // Le dossier ouvert est dans le dépôt, ou l'inverse : les deux cas
    // se produisent selon qu'on ouvre la racine ou un sous-dossier.
    const related = target.startsWith(root) || root.startsWith(target)
    if (related && root.length > bestLength) {
      best = repository
      bestLength = root.length
    }
  }

  return best
}

/** Branche courante, ou `null` en état détaché ou dépôt vide. */
export function branchNameOf(repository: GitRepository | undefined): string | null {
  const head = repository?.state?.HEAD
  if (!head) {
    return null
  }
  return head.name ?? null
}

/**
 * Empreinte de l'état du dépôt, pour détecter un vrai changement.
 *
 * Branche, commit, et volumétrie des changements. `onDidChange` se
 * déclenche très souvent — à chaque frappe dans un fichier suivi — et
 * relancer une analyse à chaque fois coûterait autant qu'un scan continu.
 * Comparer cette empreinte évite l'essentiel de ce travail.
 *
 * Aucun chemin de fichier n'y entre : c'est un discriminant, pas une
 * description, et il finit dans le journal.
 */
export function stateFingerprint(repository: GitRepository | undefined): string {
  const state = repository?.state
  if (!state) {
    return 'no-repository'
  }

  return [
    state.HEAD?.name ?? 'detached',
    state.HEAD?.commit ?? 'none',
    state.workingTreeChanges?.length ?? 0,
    state.indexChanges?.length ?? 0,
    state.mergeChanges?.length ?? 0,
  ].join('|')
}

function normalizeFsPath(value: string): string {
  if (!value) {
    return ''
  }
  // Windows : la casse du lecteur varie selon la source de l'information.
  const normalized = value.replace(/\\/g, '/').replace(/\/+$/, '')
  return process.platform === 'win32' ? normalized.toLowerCase() : normalized
}
