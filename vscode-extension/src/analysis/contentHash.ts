/**
 * Empreinte du contenu analysé.
 *
 * Le backend recalcule cette empreinte et refuse la requête si elle ne
 * correspond pas (HTTP 422) : elle sert de clé de cache et garantit que le
 * résultat rendu correspond bien au contenu envoyé.
 *
 * Aucune dépendance à `vscode` ici : ce module est utilisable et testable
 * en dehors de l'éditeur.
 */

import { createHash } from 'node:crypto'

/** SHA-256 hexadécimal du contenu, encodé en UTF-8 comme côté backend. */
export function contentHash(content: string): string {
  return createHash('sha256').update(content, 'utf8').digest('hex')
}

/**
 * Taille en octets du contenu, une fois encodé.
 *
 * Sert au filtrage local avant envoi : inutile de transmettre un fichier
 * que le backend refusera.
 */
export function contentSize(content: string): number {
  return Buffer.byteLength(content, 'utf8')
}

/**
 * Préfixe d'empreinte destiné aux journaux.
 *
 * Le contenu n'est jamais journalisé ; seule cette empreinte tronquée
 * permet de suivre un scan dans les traces.
 */
export function shortHash(hash: string): string {
  return hash.slice(0, 12)
}
