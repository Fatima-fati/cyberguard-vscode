/**
 * Statuts de fichier de `vscode.git`, et ce qu'on en déduit.
 *
 * Séparé de `gitApi.ts` pour une raison précise : `gitApi.ts` importe
 * `vscode` — il doit bien, c'est lui qui résout l'extension Git — et tout
 * module qui en dépend devient intestable hors de l'éditeur. Or ces
 * quelques prédicats décident de ce qui est analysé, et ils doivent
 * pouvoir être vérifiés.
 *
 * L'énumération n'est pas exportée à l'exécution par l'extension Git :
 * seules les valeurs numériques traversent l'API. Les recopier est la
 * seule façon de les lire sans dépendre d'un `import` qui n'existe pas.
 *
 * Aucune dépendance à `vscode` : ce module est testable en Node pur.
 */

export const GIT_STATUS = {
  INDEX_MODIFIED: 0,
  INDEX_ADDED: 1,
  INDEX_DELETED: 2,
  INDEX_RENAMED: 3,
  INDEX_COPIED: 4,
  MODIFIED: 5,
  DELETED: 6,
  UNTRACKED: 7,
  IGNORED: 8,
  INTENT_TO_ADD: 9,
  ADDED_BY_US: 10,
  ADDED_BY_THEM: 11,
  DELETED_BY_US: 12,
  DELETED_BY_THEM: 13,
  BOTH_ADDED: 14,
  BOTH_DELETED: 15,
  BOTH_MODIFIED: 16,
} as const

/** Le statut décrit-il une suppression ? */
export function isDeletion(status: number): boolean {
  return (
    status === GIT_STATUS.DELETED ||
    status === GIT_STATUS.INDEX_DELETED ||
    status === GIT_STATUS.BOTH_DELETED
  )
}

/**
 * Le statut décrit-il un fichier que Git ne suit pas encore ?
 *
 * `INTENT_TO_ADD` en fait partie : `git add -N` annonce un fichier sans
 * en enregistrer le contenu, et le diff ne porte alors rien. Le traiter
 * comme non suivi est ce qui permet de l'analyser quand même.
 */
export function isUntracked(status: number): boolean {
  return status === GIT_STATUS.UNTRACKED || status === GIT_STATUS.INTENT_TO_ADD
}

/** Le statut décrit-il un fichier ignoré par `.gitignore` ? */
export function isIgnored(status: number): boolean {
  return status === GIT_STATUS.IGNORED
}
