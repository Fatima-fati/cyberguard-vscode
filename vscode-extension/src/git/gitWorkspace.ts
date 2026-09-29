/**
 * Frontière entre l'analyse Git et l'éditeur.
 *
 * Pourquoi cette interface existe
 * -------------------------------
 *
 * Tout ce qui décide — quelles lignes ont changé, quel finding est
 * introduit, faut-il bloquer un `push` — doit être vérifiable sans
 * lancer VS Code. Or l'état du dépôt vient forcément de l'éditeur.
 *
 * `GitWorkspace` est le seul point de contact. Le service d'analyse ne
 * connaît que cette interface ; l'implémentation réelle
 * (`vscodeGitWorkspace.ts`) est la seule pièce de la phase 4 qui importe
 * `vscode`, et elle ne contient aucune décision.
 *
 * Ce que l'interface transporte, et ce qu'elle refuse
 * ---------------------------------------------------
 *
 *     TRANSPORTE   chemins relatifs, statuts, branche, hôte du remote,
 *                  le texte du diff
 *     REFUSE       l'URL de remote brute — l'adaptateur l'a déjà
 *                  expurgée, et rien en aval ne peut donc la divulguer
 *
 * L'hôte est expurgé **à la frontière**, pas plus loin : c'est ce qui
 * garantit qu'aucun code en aval ne peut journaliser un jeton, même par
 * accident, parce qu'il n'y a jamais accès.
 *
 * Aucune dépendance à `vscode` : ce module est testable en Node pur.
 */

/** Un fichier modifié, réduit à ce dont l'analyse a besoin. */
export interface WorkspaceChange {
  /** Chemin relatif à la racine du dossier ouvert, séparateurs `/`. */
  readonly path: string
  /** Statut `vscode.git`. Voir `GIT_STATUS` dans `gitApi.ts`. */
  readonly status: number
}

/** L'état du dépôt à un instant donné, déjà expurgé. */
export interface RepositorySnapshot {
  readonly branch: string | null
  /** Hôte du remote seul. **Jamais** l'URL complète. */
  readonly remoteHost: string | null
  readonly changes: readonly WorkspaceChange[]
  /**
   * Empreinte de l'état, pour éviter de réanalyser à l'identique.
   *
   * Branche, commit, volumétrie. Aucun chemin : elle finit dans le
   * journal.
   */
  readonly fingerprint: string
  /**
   * Diff unifié de l'index **et** de l'arbre de travail.
   *
   * Appelé paresseusement : sur un dépôt sans changement, le calculer
   * serait du travail perdu. Renvoie `''` quand Git ne peut rien dire —
   * un dépôt sans commit initial, par exemple.
   *
   * `paths` (relatifs) borne le diff aux fichiers réellement examinés :
   * l'API Git ne rend un diff unifié que fichier par fichier.
   */
  diff(paths?: readonly string[]): Promise<string>
}

export interface GitWorkspace {
  /** Racine du dossier ouvert, ou `undefined`. */
  root(): string | undefined
  /**
   * Dépôt du dossier ouvert.
   *
   * `undefined` quand il n'y en a pas, ou que l'extension Git est
   * absente : les deux sont des états normaux, pas des pannes.
   */
  snapshot(): Promise<RepositorySnapshot | undefined>
  /**
   * Contenu d'un fichier du projet, par chemin relatif.
   *
   * `undefined` quand il est illisible, trop volumineux, ou que
   * l'appelant n'a pas le droit de le lire. L'implémentation applique
   * les règles de la phase 1 : un `.env` n'est jamais ouvert.
   */
  readFile(relativePath: string): Promise<string | undefined>
}
