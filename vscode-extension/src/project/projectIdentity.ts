/**
 * Identité stable d'un projet.
 *
 * Le besoin : deux workspaces ouverts sur la même machine doivent garder
 * des contextes de sécurité séparés, et le même workspace réouvert demain
 * doit retrouver le sien.
 *
 * Pourquoi pas le nom du dossier
 * ------------------------------
 *
 * C'est ce que faisait `scanController.workspaceName()` — `folders[0].name`
 * — et c'est insuffisant : `~/client-a/backend` et `~/client-b/backend`
 * s'appellent tous les deux « backend ». Leurs findings se mélangeraient,
 * et la question « qu'est-ce qui a changé dans ce projet ? » n'aurait pas
 * de réponse fiable.
 *
 * Pourquoi pas le chemin en clair
 * -------------------------------
 *
 * `C:/Users/prénom.nom/projets/client-a` révèle l'identité de
 * l'utilisateur et l'arborescence de son poste. L'audit l'interdit en base
 * (§9.7) ; `scanController` prenait déjà cette précaution pour le nom, on
 * la généralise.
 *
 * Solution retenue : SHA-256 du chemin racine **normalisé**.
 *
 *     stable      le même dossier donne toujours la même empreinte
 *     distinct    deux dossiers donnent deux empreintes
 *     opaque      l'empreinte ne révèle ni l'utilisateur ni l'arborescence
 *     local       aucun appel réseau, aucun état à conserver
 *
 * Ce qui n'entre **pas** dans le calcul : le contenu d'un fichier, un
 * manifeste, un identifiant de dépôt Git. Un identifiant dérivé d'un
 * `package.json` changerait au premier renommage du paquet ; un
 * identifiant dérivé d'un secret serait un secret.
 *
 * Aucune dépendance à `vscode` : ce module est testable en Node pur.
 */

import * as crypto from 'node:crypto'
import * as path from 'node:path'

/**
 * Normalise un chemin racine avant hachage.
 *
 * Trois normalisations, chacune pour une raison observée :
 *
 * - séparateurs en `/` — le même dossier atteint par `C:\p\q` et `C:/p/q`
 *   doit donner la même empreinte ;
 * - slash final retiré — `~/projet` et `~/projet/` sont le même dossier ;
 * - lettre de lecteur Windows en majuscule — VS Code fournit tantôt `c:`
 *   tantôt `C:` selon le chemin d'appel, et deux empreintes pour un seul
 *   dossier dédoubleraient son contexte.
 *
 * La casse du reste du chemin est **conservée**. L'uniformiser rendrait
 * indistinguables deux dossiers réellement différents sur les systèmes
 * sensibles à la casse — un bug de cloisonnement, exactement ce que cet
 * identifiant doit empêcher.
 */
export function normalizeWorkspacePath(workspacePath: string): string {
  let normalized = path.normalize(workspacePath).replace(/\\/g, '/')

  if (normalized.length > 1) {
    normalized = normalized.replace(/\/+$/, '')
  }

  if (/^[a-z]:/.test(normalized)) {
    normalized = normalized[0]!.toUpperCase() + normalized.slice(1)
  }

  return normalized
}

/**
 * Empreinte de la racine du projet : 64 caractères hexadécimaux.
 *
 * C'est la valeur transmise au backend et la clé de réconciliation d'un
 * projet d'une session à l'autre.
 */
export function rootHashOf(workspacePath: string): string {
  return crypto
    .createHash('sha256')
    .update(normalizeWorkspacePath(workspacePath), 'utf8')
    .digest('hex')
}

/**
 * Identifiant court pour les journaux.
 *
 * Les traces doivent être corrélables sans porter d'information sur le
 * poste : douze caractères suffisent à distinguer les projets d'un même
 * utilisateur, et ne permettent pas de remonter au chemin.
 */
export function shortProjectId(rootHash: string): string {
  return rootHash.slice(0, 12)
}

/**
 * Nom affichable d'un projet.
 *
 * Le dernier segment du chemin, jamais le chemin entier : c'est ce que
 * l'utilisateur reconnaît, et c'est tout ce que le backend a besoin
 * d'afficher. Un repli sur l'empreinte évite un libellé vide à la racine
 * d'un disque.
 */
export function projectNameOf(workspacePath: string, rootHash: string): string {
  const normalized = normalizeWorkspacePath(workspacePath)
  const segments = normalized.split('/').filter((segment) => segment.length > 0)
  const last = segments[segments.length - 1]

  if (!last || /^[A-Za-z]:$/.test(last)) {
    return `projet-${rootHash.slice(0, 8)}`
  }
  return last
}
