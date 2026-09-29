/**
 * Implémentation de `GitWorkspace` adossée à VS Code.
 *
 * C'est la **seule** pièce de la phase 4 qui parle à l'éditeur, et elle
 * ne contient aucune décision : elle traduit l'état du dépôt dans les
 * types neutres de `gitWorkspace.ts`, et s'arrête là. Tout ce qui juge —
 * quelles lignes ont changé, quel finding est introduit, faut-il bloquer
 * un `push` — vit dans des modules purs, testables sans éditeur.
 *
 * Deux garanties tenues ici, à la frontière
 * -----------------------------------------
 *
 * **Aucune commande `git`.** Le diff vient de `repository.diffWithHEAD()`
 * et `diffIndexWithHEAD()`, c'est-à-dire de l'extension Git de VS Code.
 * Rien dans ce fichier ne lance de processus.
 *
 * **L'URL de remote ne franchit pas cette frontière.** `remoteHostOf` est
 * appliqué ici, au plus près de la source. En aval, personne n'a accès à
 * l'URL brute, donc personne ne peut la journaliser — pas même par
 * accident.
 */

import * as path from 'node:path'

import * as vscode from 'vscode'

import { MAX_HASH_BYTES, isNeverRead } from '../project/projectDiscovery'
import {
  branchNameOf,
  findRepository,
  resolveGitApi,
  stateFingerprint,
  type GitApi,
  type GitChange,
  type GitRepository,
} from './gitApi'
import type {
  GitWorkspace,
  RepositorySnapshot,
  WorkspaceChange,
} from './gitWorkspace'
import { remoteHostOf } from './remoteUrl'

export interface VsCodeGitWorkspaceOptions {
  readonly workspaceRoot: () => string | undefined
  /** Remplaçable pour les tests d'intégration manuels. */
  readonly resolveApi?: () => Promise<GitApi | undefined>
}

export class VsCodeGitWorkspace implements GitWorkspace {
  private readonly options: VsCodeGitWorkspaceOptions

  constructor(options: VsCodeGitWorkspaceOptions) {
    this.options = options
  }

  root(): string | undefined {
    return this.options.workspaceRoot()
  }

  async snapshot(): Promise<RepositorySnapshot | undefined> {
    const root = this.root()
    if (!root) {
      return undefined
    }

    const api = await (this.options.resolveApi ?? resolveGitApi)()
    const repository = findRepository(api, root)
    if (!repository) {
      return undefined
    }

    const state = repository.state ?? {}
    const changes = [
      ...(state.indexChanges ?? []),
      ...(state.workingTreeChanges ?? []),
      ...(state.mergeChanges ?? []),
    ]
    const workspaceChanges = changes
      .map((change) => this.toWorkspaceChange(change, root))
      .filter((change): change is WorkspaceChange => change !== undefined)

    return {
      branch: branchNameOf(repository),
      // Expurgé ici, une fois pour toutes : l'URL brute ne va pas plus
      // loin que cette ligne.
      remoteHost: remoteHostOf(
        state.remotes?.[0]?.fetchUrl ?? state.remotes?.[0]?.pushUrl
      ),
      changes: workspaceChanges,
      fingerprint: stateFingerprint(repository),
      diff: (paths) =>
        readDiff(repository, root, paths ?? workspaceChanges.map((change) => change.path)),
    }
  }

  /**
   * Contenu d'un fichier du projet.
   *
   * Les règles de lecture de la phase 1 sont appliquées ici et ne sont
   * pas négociables : un `.env` n'est pas ouvert, et un fichier au-delà
   * du plafond non plus.
   */
  async readFile(relativePath: string): Promise<string | undefined> {
    const root = this.root()
    if (!root || isNeverRead(relativePath)) {
      return undefined
    }

    try {
      const uri = vscode.Uri.file(path.join(root, relativePath))
      const stat = await vscode.workspace.fs.stat(uri)
      if (stat.size > MAX_HASH_BYTES) {
        return undefined
      }
      const bytes = await vscode.workspace.fs.readFile(uri)
      return Buffer.from(bytes).toString('utf8')
    } catch {
      return undefined
    }
  }

  /**
   * Chemin relatif au dossier ouvert, séparateurs normalisés.
   *
   * `undefined` dès que le fichier est hors du dossier : l'analyse ne
   * déborde jamais du workspace, même si le dépôt est plus large.
   */
  private toWorkspaceChange(
    change: GitChange,
    root: string
  ): WorkspaceChange | undefined {
    const uri = change.uri
    if (!uri || uri.scheme !== 'file') {
      return undefined
    }

    const relative = path.relative(root, uri.fsPath)
    if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) {
      return undefined
    }

    return { path: relative.split(path.sep).join('/'), status: change.status }
  }
}

/**
 * Diff unifié de l'index **et** de l'arbre de travail.
 *
 * Les deux sont demandés parce qu'ils décrivent des choses différentes :
 * ce qui est préparé pour le prochain commit, et ce qui ne l'est pas
 * encore. Un `push` emporte le premier ; l'éditeur montre le second. Les
 * analyser ensemble évite de passer à côté d'un secret indexé mais non
 * encore écrit sur disque, et inversement.
 *
 * Un échec de l'un n'annule pas l'autre : sur un dépôt sans commit
 * initial, `diff ... HEAD` échoue, et c'est un état normal.
 *
 * Fichier par fichier : sans chemin, l'API renvoie la liste des
 * changements et non un diff (voir `GitRepository`). Un fichier jamais lu
 * (`.env`, clé privée) n'est pas demandé : son diff porterait sa valeur,
 * et aucun finding ne peut s'y rattacher.
 */
async function readDiff(
  repository: GitRepository,
  root: string,
  paths: readonly string[]
): Promise<string> {
  const parts: string[] = []

  for (const relative of new Set(paths)) {
    if (isNeverRead(relative)) {
      continue
    }
    const target = path.join(root, relative)
    for (const read of [
      () => repository.diffIndexWithHEAD?.(target),
      () => repository.diffWithHEAD?.(target),
    ]) {
      try {
        const value = await read()
        if (typeof value === 'string' && value) {
          parts.push(value)
        }
      } catch {
        // Dépôt vide, ou API d'une version qui ne porte pas cette méthode.
      }
    }
  }

  return parts.join('\n')
}
