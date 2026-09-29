/**
 * Choix du document visé par une commande d'analyse.
 *
 * `vscode.window.activeTextEditor` ne désigne pas toujours un fichier
 * source : le panneau **Output** est lui aussi un éditeur de texte, avec
 * le schéma `output` et le langage `Log`. Il suffit d'avoir cliqué dans
 * le canal « Wazuh Security » avant d'ouvrir la palette pour que
 * `activeTextEditor` renvoie ce document — et l'analyse est alors refusée
 * pour un langage que l'utilisateur n'a jamais ouvert.
 *
 * Ce module ne décide de rien d'autre : la pertinence du fichier (langage,
 * taille, exclusions) reste l'affaire de `documentFilter`. Il répond à une
 * seule question — *de quel document parle l'utilisateur ?* — et le fait
 * sans dépendre de `vscode`, donc sous test.
 */

/** Le strict nécessaire d'un `vscode.TextDocument` pour ce choix. */
export interface DocumentLike {
  uri: { scheme: string }
  languageId: string
}

/**
 * Schémas d'URI qui ne désignent jamais un fichier de code.
 *
 * Les variantes du panneau Output cohabitent selon les versions de VS
 * Code : `output` aujourd'hui, `extension-output` sur les plus anciennes.
 */
export const NON_SOURCE_SCHEMES: readonly string[] = [
  'output',
  'extension-output',
  'vscode-output',
  'debug',
  'vscode-terminal',
  'search-editor',
]

/**
 * Identifiant de langage des canaux de sortie.
 *
 * Attention à la casse : `Log` est celui du panneau Output, tandis qu'un
 * vrai fichier `.log` ouvert dans l'éditeur porte `log` en minuscules.
 * Seul le premier est écarté ici ; le second est un fichier comme un
 * autre, refusé plus loin avec le message habituel.
 */
const OUTPUT_LANGUAGE_ID = 'Log'

/** Ce document peut-il être ce que l'utilisateur veut analyser ? */
export function isSourceDocument(document: DocumentLike | undefined): boolean {
  if (!document) {
    return false
  }
  if (NON_SOURCE_SCHEMES.includes(document.uri.scheme)) {
    return false
  }
  return document.languageId !== OUTPUT_LANGUAGE_ID
}

/**
 * Document visé par « Scan Current File ».
 *
 * L'éditeur actif d'abord — c'est celui que l'utilisateur regarde. S'il
 * s'agit d'un panneau de sortie, on se rabat sur le premier éditeur
 * visible qui montre un vrai fichier : le code est toujours à l'écran,
 * seul le focus s'était déplacé.
 *
 * `undefined` si rien ne convient : l'appelant affiche alors le message
 * « aucun fichier ouvert », plutôt que d'analyser un document au hasard.
 */
export function pickScanTarget<T extends DocumentLike>(
  active: T | undefined,
  visible: readonly T[] = []
): T | undefined {
  if (isSourceDocument(active)) {
    return active
  }
  return visible.find((document) => isSourceDocument(document))
}
